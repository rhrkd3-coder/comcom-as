"""
부정클릭 판단 규칙(룰 베이스) - Supabase 버전

새 클릭이 들어올 때마다 해당 IP의 최근 이력을 Supabase에 조회해서 아래 규칙을 검사한다.
규칙에 하나라도 걸리면 해당 클릭을 의심클릭으로 표시하고,
suspicious_ips 테이블에 IP를 누적/업데이트한다.

기준값은 필요에 따라 조정 가능하도록 상단에 상수로 뺐다. (원본 SQLite 버전과 동일한 기준)
"""
from datetime import datetime, timedelta

import database

# ---- 탐지 기준값 (여기 숫자만 바꾸면 민감도 조절 가능) ----
SHORT_WINDOW_MINUTES = 5      # 짧은 시간 창
SHORT_WINDOW_MAX_CLICKS = 3   # 그 안에서 허용하는 최대 클릭 수 (이 이상이면 의심)
DAILY_MAX_CLICKS = 10         # 하루 동안 허용하는 최대 클릭 수
RAPID_RECLICK_SECONDS = 3     # 이 초 이내 재클릭이면 의심 (사람이 이렇게 빨리 못 누름)

BOT_UA_KEYWORDS = [
    "bot", "crawler", "spider", "headless", "phantomjs",
    "curl", "wget", "python-requests", "scrapy", "puppeteer",
]


def check_click(ip: str, user_agent: str, created_at: datetime):
    """
    새 클릭 1건에 대해 규칙을 검사하고 (is_suspicious, reasons) 를 반환한다.
    created_at: 이 클릭을 insert 하기 '직전' 시점의 이력 기준으로 판단 (아직 DB에는 안 들어간 상태)
    """
    reasons = []

    # 규칙 1: 짧은 시간 창 내 반복 클릭
    window_start = (created_at - timedelta(minutes=SHORT_WINDOW_MINUTES)).isoformat()
    short_count = database.count_clicks_since(ip, window_start)
    if short_count + 1 >= SHORT_WINDOW_MAX_CLICKS:
        reasons.append(f"{SHORT_WINDOW_MINUTES}분 내 {short_count + 1}회 클릭")

    # 규칙 2: 하루 클릭 수 초과
    day_start = created_at.strftime("%Y-%m-%dT00:00:00")
    day_count = database.count_clicks_since(ip, day_start)
    if day_count + 1 >= DAILY_MAX_CLICKS:
        reasons.append(f"당일 {day_count + 1}회 클릭 (일일 기준 {DAILY_MAX_CLICKS}회 초과)")

    # 규칙 3: 초단위 재클릭
    last = database.get_last_click(ip)
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

    # 규칙 4: 봇 의심 User-Agent
    ua_lower = (user_agent or "").lower()
    if any(kw in ua_lower for kw in BOT_UA_KEYWORDS) or not ua_lower:
        reasons.append("봇/비정상 User-Agent")

    return (len(reasons) > 0, reasons)
