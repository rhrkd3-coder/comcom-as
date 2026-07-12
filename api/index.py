"""
네이버 파워링크 부정클릭 탐지 백엔드 (FastAPI, Vercel Functions 버전)

주요 기능
- POST /api/click        : 랜딩페이지 tracker.js 가 클릭 이벤트를 전송하는 엔드포인트
- GET  /api/stats         : 대시보드 상단 요약 통계
- GET  /api/clicks        : 최근 클릭 로그 목록
- GET  /api/suspicious-ips: 의심 IP 목록 (사유/횟수 포함)
- POST /api/suspicious-ips/{ip}/block : 차단 처리(수동 등록 완료) 표시
- GET  /api/export/suspicious-ips.csv : 의심 IP CSV 다운로드
- GET  /api/export/clicks.csv         : 클릭 로그 CSV 다운로드
- GET  /api/check                    : 이 방문자(IP)가 의심 상태인지 + 최근 방문 이력 반환
                                        (랜딩페이지에 경고 배너 띄울 때 사용)

로컬 실행: cd api && uvicorn index:app --reload
Vercel에서는 vercel.json의 rewrites 설정으로 /api/* 요청이 전부 이 파일로 들어온다.
"""
import csv
import io
import os
import sys
from datetime import datetime, timezone

# Vercel의 Python 런타임은 이 파일을 importlib로 직접 로드하기 때문에,
# 같은 폴더(api/)가 sys.path에 자동으로 잡히지 않아 "import database"가
# ModuleNotFoundError를 일으킨다. 아래 한 줄로 이 파일이 있는 폴더를
# sys.path에 명시적으로 추가해서 해결한다.
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse

import database
import detection

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

    is_suspicious, reasons = detection.check_click(ip, user_agent, now)

    database.insert_click({
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
        database.upsert_suspicious_ip(ip, reasons, now_iso)
        history = database.list_clicks_by_ip(ip, limit=10)

    return {"ok": True, "suspicious": is_suspicious, "reasons": reasons, "history": history}


@app.get("/api/check")
def check_visitor(request: Request):
    """현재 요청자의 IP가 의심 IP 목록에 있는지 + 최근 방문 이력 반환.
    랜딩페이지에서 경고 배너를 띄울지 판단할 때 호출한다."""
    ip = _client_ip(request)
    info = database.get_suspicious_ip(ip)
    history = database.list_clicks_by_ip(ip, limit=10)
    return {
        "ip": ip,
        "flagged": info is not None,
        "click_count": info["click_count"] if info else 0,
        "reasons": info["reasons"] if info else "",
        "history": history,
    }


@app.get("/api/stats")
def get_stats():
    return database.get_stats()


@app.get("/api/clicks")
def list_clicks(limit: int = 100, suspicious_only: bool = False):
    return database.list_clicks(limit=limit, suspicious_only=suspicious_only)


@app.get("/api/suspicious-ips")
def list_suspicious_ips():
    return database.list_suspicious_ips()


@app.post("/api/suspicious-ips/{ip}/block")
def mark_blocked(ip: str):
    database.mark_blocked(ip)
    return {"ok": True}


@app.get("/api/export/suspicious-ips.csv")
def export_suspicious_csv():
    rows = database.list_suspicious_ips()

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
    rows = database.list_clicks(limit=10000, suspicious_only=suspicious_only)

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["id", "ip", "user_agent", "referrer", "landing_url", "keyword",
                      "click_id", "session_id", "created_at", "is_suspicious", "reasons"])
    for r in rows:
        writer.writerow([r.get("id"), r.get("ip"), r.ge