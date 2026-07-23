/**
 * 네이버 파워링크 부정클릭 탐지 - 랜딩페이지 삽입용 추적 스크립트
 *
 * 사용법: 랜딩페이지 </body> 직전에 아래 한 줄만 추가하면 됩니다.
 *
 *   <script src="https://당신의-서버주소/tracker.js" data-api="https://당신의-서버주소"></script>
 *
 * - data-api 속성에 백엔드 주소를 지정하세요. (생략하면 스크립트를 불러온 도메인을 그대로 사용)
 * - 실제 방문자의 IP는 브라우저가 아니라 서버(백엔드)에서 요청 헤더로 자동 수집되므로
 *   이 스크립트에서 IP를 직접 다루지 않습니다.
 */
(function () {
  function getApiBase() {
    var current = document.currentScript;
    if (current && current.getAttribute("data-api")) {
      return current.getAttribute("data-api").replace(/\/$/, "");
    }
    if (current && current.src) {
      var a = document.createElement("a");
      a.href = current.src;
      return a.origin;
    }
    return "";
  }

  function getOrCreateSessionId() {
    var key = "ncg_session_id";
    var existing = document.cookie
      .split("; ")
      .find(function (row) { return row.indexOf(key + "=") === 0; });
    if (existing) return existing.split("=")[1];

    var id = "s_" + Date.now() + "_" + Math.random().toString(36).slice(2, 10);
    document.cookie = key + "=" + id + "; path=/; max-age=" + 60 * 60 * 24 * 30;
    return id;
  }

  function getParam(params, keys) {
    for (var i = 0; i < keys.length; i++) {
      if (params.has(keys[i])) return params.get(keys[i]);
    }
    return "";
  }

  var API_BASE = getApiBase();
  var params = new URLSearchParams(window.location.search);

  var payload = {
    landing_url: window.location.href,
    referrer: document.referrer || "",
    session_id: getOrCreateSessionId(),
    // 네이버 "자동 추적 URL 파라미터"를 켜면 n_keyword 라는 이름으로 실제 검색어가 붙어서 온다.
    // (utm_term / keyword / kw 는 수동으로 직접 넣는 다른 방식용 - 혹시 몰라 후보에 같이 둠)
    keyword: getParam(params, ["n_keyword", "keyword", "utm_term", "kw"]),
    click_id: getParam(params, ["n_ad", "NaPm", "gclid", "click_id", "n_media"]),
    // 파워링크 자동 추적 URL 파라미터가 남기는 부가 정보 (매체/키워드ID/광고그룹 - 있으면 같이 전송)
    n_media: getParam(params, ["n_media"]),
    n_keyword_id: getParam(params, ["n_keyword_id"]),
    n_rank: getParam(params, ["n_rank"]),
  };

  fetch(API_BASE + "/api/click", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
    keepalive: true,
  }).catch(function () {
    // 네트워크 오류는 조용히 무시 (사용자 경험에 영향 없게)
  });
})();
