"""
Supabase(Postgres) 기반 데이터 접근 계층.

Vercel 서버리스 함수는 재시작될 때마다 로컬 디스크가 초기화되므로
SQLite 파일을 쓸 수 없다. 대신 Supabase 프로젝트에 클릭 로그를 저장한다.

필요한 환경변수 (Vercel 프로젝트 설정 > Environment Variables 에 등록):
- SUPABASE_URL        : https://xxxx.supabase.co
- SUPABASE_SERVICE_KEY: Supabase 프로젝트의 service_role 키

주의: 이 값은 서버(백엔드) 코드에서만 쓰이고 브라우저로 절대 전달되지 않는다.
tracker.js 는 Supabase를 직접 호출하지 않고 우리 자신의 /api/click 만 호출하므로,
service_role 키가 브라우저에 노출될 일이 없다.
"""
import os
from datetime import datetime
from typing import Optional

from supabase import create_client, Client

SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_SERVICE_KEY = os.environ.get("SUPABASE_SERVICE_KEY")

_client: Optional[Client] = None


def get_client() -> Client:
    global _client
    if _client is None:
        if not SUPABASE_URL or not SUPABASE_SERVICE_KEY:
            raise RuntimeError(
                "SUPABASE_URL / SUPABASE_SERVICE_KEY 환경변수가 설정되지 않았습니다. "
                "Vercel 프로젝트 설정 > Environment Variables 에서 등록해주세요."
            )
        _client = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)
    return _client


def insert_click(row: dict):
    get_client().table("clicks").insert(row).execute()


def count_clicks_since(ip: str, since_iso: str) -> int:
    resp = (
        get_client()
        .table("clicks")
        .select("id", count="exact")
        .eq("ip", ip)
        .gte("created_at", since_iso)
        .execute()
    )
    return resp.count or 0


def get_last_click(ip: str):
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


def get_suspicious_ip(ip: str):
    resp = get_client().table("suspicious_ips").select("*").eq("ip", ip).limit(1).execute()
    return resp.data[0] if resp.data else None


def upsert_suspicious_ip(ip: str, reasons: list, now_iso: str):
    existing = get_suspicious_ip(ip)
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


def list_clicks_by_ip(ip: str, limit: int = 10):
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


def get_stats() -> dict:
    client = get_client()
    today_start = datetime.utcnow().strftime("%Y-%m-%dT00:00:00")

    total = client.table("clicks").select("id", count="exact").execute().count or 0
    today_count = (
        client.table("clicks").select("id", count="exact").gte("created_at", today_start).execute().count or 0
    )
    suspicious_clicks = (
        client.table("clicks").select("id", count="exact").eq("is_suspicious", True).execute().count or 0
    )
    suspicious_ips = client.table("suspicious_ips").select("ip", count="exact").execute().count or 0

    # 고유 IP 수는 Supabase REST에서 distinct count를 바로 못 세므로 전체를 가져와 계산
    all_ips = client.table("clicks").select("ip").execute().data or []
    unique_ip = len({r["ip"] for r in all_ips})

    return {
        "total_clicks": total,
        "today_clicks": today_count,
        "unique_ips": unique_ip,
        "suspicious_ips": suspicious_ips,
        "suspicious_clicks": suspicious_clicks,
    }


def list_clicks(limit: int = 100, suspicious_only: bool = False):
    q = get_client().table("clicks").select("*").order("created_at", desc=True).limit(limit)
    if suspicious_only:
        q = q.eq("is_suspicious", True)
    return q.execute().data or []


def list_suspicious_ips():
    resp = (
        get_client()
        .table("suspicious_ips")
        .select("*")
        .order("click_count", desc=True)
        .order("last_seen", desc=True)
        .execute()
    )
    return resp.data or []


def mark_blocked(ip: str):
    get_client().table("suspicious_ips").update({"blocked":