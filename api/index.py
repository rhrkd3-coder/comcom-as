"""
네이버 파워링크 부정클릭 탐지 백엔드 (FastAPI, Vercel Functions 버전)
- 파일 하나로 통합 (database.py / detection.py 내용을 이 파일 안에 합침).
  Vercel이 api/ 폴더 안의 여러 .py 파일 때문에 엔트리포인트를 못 찾는
  문제를 피하기 위한 조치.

[수정사항] 차단완료 표시한 IP는 기본 목록에서 자동으로 빠지도록 변경.
  - db_list_suspicious_ips(include_blocked=False)  : 기본은 미차단만 반환
  - GET /api/suspicious-ips?include_blocked=true   : 차단완료 이력도 같이 조회
  - POST /api/suspicious-ips/{ip}/unblock          : 차단완료 취소(되돌리기)
"""
import csv
import io
import os
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from supabase import create_client, Client

SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_SERVICE_KEY = os.environ.get("SUPABASE_SERVICE_KEY")

_client: Optional[Client] = None


def get_client() -> Client:
    global _client
    if _client is None:
        if not SUPABASE_URL or not SUPABASE_SERVICE_KEY:
            raise RuntimeError(
                "SUPABASE_URL / SUPABASE_SERVICE_KEY 환경변수가 설정되지 않았습니다."
            )
        _client = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)
    return _client


def db_insert_click(row: dict):
    get_client().table("clicks").insert(row).execute()


def db_count_clicks_since(ip: str, since_iso: str) -> int:
    resp = (
        get_client()
        .table("clicks")
        .select("id", count="exact")
        .eq("ip", ip)
        .gte("created_at", since_iso)
        .execute()
    )
    return resp.count or 0


def db_get_last_click(ip: str):
    resp = (
        get_client()
        .table("clicks")
        .select("created_at")
        .eq("ip", ip)
        .order("created_at", desc=True)
        .limit(1)
        .execute()
    )
    return resp.data[0] if resp.data else None


def db_get_suspicious_ip(ip: str):
    resp = get_client().table("suspicious_ips").select("*").eq("ip", ip).limit(1).execute()
    return resp.data[0] if resp.data else None


def db_upsert_suspicious_ip(ip: str, reasons: list, now_iso: str):
    existing = db_get_suspicious_ip(ip)
    reason_str = ", ".join(sorted(set(reasons)))

    if existing is None:
        get_client().table("suspicious_ips").insert({
            "ip": ip,
            "click_count": 1,
            "reasons": reason_str,
            "first_seen": now_iso,
            "last_seen": now_iso,
            "blocked": False,
        }).execute()
    else:
        merged_reasons = set(existing["reasons"].split(", ")) | set(reasons)
        get_client().table("suspicious_ips").update({
            "click_count": existing["click_count"] + 1,
            "reasons": ", ".join(sorted(merged_reasons)),
            "last_seen": now_iso,
        }).eq("ip", ip).execute()


def db_list_clicks_by_ip(ip: str, limit: int = 10):
    resp = (
        get_client()
        .table("clicks")
        .select("ip, keyword, created_at")
        .eq("ip", ip)
        .order("created_at", desc=True)
        .limit(limit)
        .execute()
    )
    return resp.data or []


def db_get_stats() -> dict:
    client = get_client()
    today_start = datetime.utcnow().strftime("%Y-%m-%dT00:00:00")

    total = client.table("clicks").select("id", count="exact").execute().count or 0
    today_count = (
        client.table("clicks").select("id", count="exact").gte("created_at", today_start).execute().count or 0
    )
    suspicious_clicks = (
        client.table("clicks").select("id", count="exact").eq("is_suspicious", True).execute().count or 0
    )
    # [수정] 차단완료(blocked=True) 처리한 IP는 "의심 IP 수"에서 제외 - 대시보드 목록과 숫자를 맞춤
    suspicious_ips = (
        client.table("suspicious_ips").select("ip", count="exact").eq("blocked", False).execute().count or 0
    )

    all_ips = client.table("clicks").select("ip").execute().data or []
    unique_ip = len({r["ip"] for r in all_ips})

    return {
        "total_clicks": total,
        "today_clicks": today_count,
        "unique_ips": unique_ip,
        "suspicious_ips": suspicious_ips,
        "suspicious_clicks": suspicious_clicks,
    }


def db_list_clicks(limit: int = 100, suspicious_only: bool = False):
    q = get_client().table("clicks").select("*").order("created_at", desc=True).limit(limit)
    if suspicious_only:
        q = q.eq("is_suspicious", True)
    return q.execute().data or []


def db_list_suspicious_ips(include_blocked: bool = False):
    """
    [수정] 기본값(include_blocked=False)은 아직 차단 처리 안 한 IP만 반환한다.
    '차단완료 표시'를 누른 IP는 자동으로 빠져서 화면이 계속 깔끔하게 유지된다.
    이력을 보고 싶을 때만 include_blocked=True 로 호출.
    """
    q = get_client().table("suspicious_ips").select("*")
    if not include_blocked:
        q = q.eq("blocked", False)
    resp = q.order("click_count", desc=True).order("last_seen", desc=True).execute()
    return resp.data or []


def db_mark_blocked(ip: str):
    get_client().table("suspicious_ips").update({"blocked": True}).eq("ip", ip).execute()


def db_mark_unblocked(ip: str):
    """[신규] 차단완료 이력에서 실수로 표시한 IP를 다시 활성 목록으로 되돌린다."""
    get_client().table("suspicious_ips").update({"blocked": False}).eq("ip", ip).execute()


SHORT_WINDOW_MINUTES = 5
SHORT_WINDOW_MAX_CLICKS = 3
DAILY_MAX_CLICKS = 10
RAPID_RECLICK_SECONDS = 3

BOT_UA_KEYWORDS = [
    "bot", "crawler", "spider", "headless", "phantomjs",
    "curl", "wget", "python-requests", "scrapy", "puppeteer",
]


def check_click(ip: str, user_agent: str, created_at: datetime):
    reasons = []

    window_start = (created_at - timedelta(minutes=SHORT_WINDOW_MINUTES)).isoformat()
    short_count = db_count_clicks_since(ip, window_start)
    if short_count + 1 >= SHORT_WINDOW_MAX_CLICKS:
        reasons.append(f"{SHORT_WINDOW_MINUTES}분 내 {short_count + 1}회 클릭")

    day_start = created_at.strftime("%Y-%m-%dT00:00:00")
    day_count = db_count_clicks_since(ip, day_start)
    if day_count + 1 >= DAILY_MAX_CLICKS:
        reasons.append(f"당일 {day_count + 1}회 클릭 (일일 기준 {DAILY_MAX_CLICKS}회 초과)")

    last = db_get_last_click(ip)
    if last is not None:
        try:
            last_time_str = last["created_at"].replace("Z", "+00:00")
            last_time = datetime.fromisoformat(last_time_str)
            compare_now = created_at
            if last_time.tzinfo is not None and compare_now.tzinfo is None:
                compare_now = compare_now.replace(tzinfo=last_time.tzinfo)
            if (compare_now - last_time).total_seconds() <= RAPID_RECLICK_SECONDS:
                reasons.append(f"{RAPID_RECLICK_SECONDS}초 이내 재클릭")
        except (ValueError, KeyError):
            pass

    ua_lower = (user_agent or "").lower()
    if any(kw in ua_lower for kw in BOT_UA_KEYWORDS) or not ua_lower:
        reasons.append("봇/비정상 User-Agent")

    return (len(reasons) > 0, reasons)


app = FastAPI(title="Naver Click Guard")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def _client_ip(request: Request) -> str:
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


@app.post("/api/click")
async def record_click(request: Request):
    body = {}
    try:
        body = await request.json()
    except Exception:
        pass

    ip = _client_ip(request)
    user_agent = request.headers.get("user-agent", "")
    referrer = body.get("referrer", "")
    landing_url = body.get("landing_url", "")
    keyword = body.get("keyword", "")
    click_id = body.get("click_id", "")
    session_id = body.get("session_id", "")

    now = datetime.now(timezone.utc)
    now_iso = now.isoformat()

    is_suspicious, reasons = check_click(ip, user_agent, now)

    db_insert_click({
        "ip": ip,
        "user_agent": user_agent,
        "referrer": referrer,
        "landing_url": landing_url,
        "keyword": keyword,
        "click_id": click_id,
        "session_id": session_id,
        "created_at": now_iso,
        "is_suspicious": is_suspicious,
        "reasons": ", ".join(reasons),
    })

    history = []
    if is_suspicious:
        db_upsert_suspicious_ip(ip, reasons, now_iso)
        history = db_list_clicks_by_ip(ip, limit=10)

    return {"ok": True, "suspicious": is_suspicious, "reasons": reasons, "history": history}


@app.get("/api/check")
def check_visitor(request: Request):
    ip = _client_ip(request)
    info = db_get_suspicious_ip(ip)
    history = db_list_clicks_by_ip(ip, limit=10)
    return {
        "ip": ip,
        "flagged": info is not None,
        "click_count": info["click_count"] if info else 0,
        "reasons": info["reasons"] if info else "",
        "history": history,
    }


@app.get("/api/stats")
def get_stats():
    return db_get_stats()


@app.get("/api/clicks")
def list_clicks(limit: int = 100, suspicious_only: bool = False):
    return db_list_clicks(limit=limit, suspicious_only=suspicious_only)


@app.get("/api/suspicious-ips")
def list_suspicious_ips(include_blocked: bool = False):
    return db_list_suspicious_ips(include_blocked=include_blocked)


@app.post("/api/suspicious-ips/{ip}/block")
def mark_blocked(ip: str):
    db_mark_blocked(ip)
    return {"ok": True}


@app.post("/api/suspicious-ips/{ip}/unblock")
def mark_unblocked(ip: str):
    db_mark_unblocked(ip)
    return {"ok": True}


@app.get("/api/export/suspicious-ips.csv")
def export_suspicious_csv():
    rows = db_list_suspicious_ips(include_blocked=True)

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["ip", "click_count", "reasons", "first_seen", "last_seen", "blocked"])
    for r in rows:
        writer.writerow([r["ip"], r["click_count"], r["reasons"], r["first_seen"], r["last_seen"], r["blocked"]])
    buf.seek(0)

    return StreamingResponse(
        buf,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=suspicious_ips.csv"},
    )


@app.get("/api/export/clicks.csv")
def export_clicks_csv(suspicious_only: bool = False):
    rows = db_list_clicks(limit=10000, suspicious_only=suspicious_only)

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["id", "ip", "user_agent", "referrer", "landing_url", "keyword",
                      "click_id", "session_id", "created_at", "is_suspicious", "reasons"])
    for r in rows:
        writer.writerow([r.get("id"), r.get("ip"), r.get("user_agent"), r.get("referrer"), r.get("landing_url"),
                          r.get("keyword"), r.get("click_id"), r.get("session_id"), r.get("created_at"),
                          r.get("is_suspicious"), r.get("reasons")])
    buf.seek(0)

    return StreamingResponse(
        buf,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=clicks.csv"},
    )
