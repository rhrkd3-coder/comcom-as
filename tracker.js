/**
 * 컴컴 부정클릭 탐지 - 랜딩페이지 삽입용 추적 스크립트
 *
 * 사용법: 랜딩페이지 </body> 직전에 아래 한 줄만 추가하면 됩니다.
 *   <script src="/tracker.js"></script>
 *
 * 동작
 * 1) 페이지 로드시 "부정클릭 방지 시스템 작동중" 배지를 항상 우측 하단에 표시 (CCTV 안내판 같은 억제 효과)
 * 2) 클릭 정보를 서버로 전송하고, 이 방문자가 의심 기준(짧은 시간 반복 클릭 등)에 걸리면
 *    강한 경고 배너를 띄우고 최근 방문 이력을 보여준다.
 * 3) 실제 방문자의 IP는 브라우저가 아니라 서버(백엔드)에서 요청 헤더로 자동 수집되므로
 *    이 스크립트에서 IP를 직접 다루지 않는다.
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

  function formatTime(iso) {
    try {
      var d = new Date(iso);
      var mm = String(d.getMonth() + 1).padStart(2, "0");
      var dd = String(d.getDate()).padStart(2, "0");
      var hh = String(d.getHours()).padStart(2, "0");
      var mi = String(d.getMinutes()).padStart(2, "0");
      return mm + "." + dd + " " + hh + ":" + mi;
    } catch (e) {
      return "";
    }
  }

  function injectBadge() {
    if (document.getElementById("ncg-badge")) return;
    var badge = document.createElement("div");
    badge.id = "ncg-badge";
    badge.style.cssText =
      "position:fixed;right:14px;bottom:14px;z-index:99998;display:flex;align-items:center;gap:6px;" +
      "background:rgba(15,23,42,0.9);border:1px solid rgba(56,189,248,0.35);border-radius:999px;" +
      "padding:6px 12px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;" +
      "font-size:11px;color:#94a3b8;box-shadow:0 2px 8px rgba(0,0,0,0.3);";
    badge.innerHTML =
      '<span style="width:7px;height:7px;border-radius:50%;background:#38bdf8;flex-shrink:0;"></span>' +
      "부정클릭 방지 시스템 작동중";
    document.body.appendChild(badge);
  }

  function injectWarning(history) {
    if (document.getElementById("ncg-warning")) return;

    var overlay = document.createElement("div");
    overlay.id = "ncg-warning";
    overlay.style.cssText =
      "position:fixed;inset:0;z-index:99999;background:rgba(0,0,0,0.6);display:flex;" +
      "align-items:center;justify-content:center;padding:16px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;";

    var rows = "";
    (history || []).slice(0, 5).forEach(function (h) {
      rows +=
        '<div style="display:flex;justify-content:space-between;color:#cbd5e1;font-size:11px;padding:5px 0;border-bottom:1px solid rgba(255,255,255,0.06);">' +
        "<span>" + (h.keyword || "-") + "</span>" +
        '<span style="color:#64748b;">' + formatTime(h.created_at) + "</span>" +
        "</div>";
    });

    overlay.innerHTML =
      '<div style="width:100%;max-width:380px;background:rgba(15,23,42,0.97);border:1px solid rgba(255,255,255,0.12);border-radius:16px;padding:24px;">' +
        '<div style="display:flex;align-items:center;gap:10px;margin-bottom:14px;">' +
          '<div style="width:36px;height:36px;border-radius:50%;background:rgba(56,189,248,0.15);border:1px solid rgba(56,189,248,0.3);display:flex;align-items:center;justify-content:center;color:#38bdf8;font-size:18px;">!</div>' +
          '<p style="color:#fff;font-size:15px;font-weight:600;margin:0;">과다한 광고 클릭 안내</p>' +
        "</div>" +
        '<p style="color:#cbd5e1;font-size:12.5px;line-height:1.6;margin:0 0 10px;">짧은 시간 동안 광고를 반복적으로 클릭하고 계신 것이 확인되었습니다. 광고 클릭은 1회당 비용이 발생하며, 반복 클릭은 다른 고객님께 쓰여야 할 광고비를 낭비시킵니다.</p>' +
        '<p style="color:#fca5a5;font-size:12px;line-height:1.6;margin:0 0 14px;">악의적인 반복 클릭으로 확인될 경우, 사업자 확인을 거쳐 해당 IP는 광고 접속 제한 조치될 수 있습니다.</p>' +
        '<p style="color:#94a3b8;font-size:12px;line-height:1.6;margin:0 0 14px;">다음부터는 즐겨찾기에 추가하시거나 "컴컴"으로 직접 검색해서 방문해주시면 더 빠르게 도와드릴 수 있습니다.</p>' +
        '<button id="ncg-bookmark-btn" style="width:100%;background:#facc15;color:#1e1b0a;border:none;border-radius:10px;padding:10px;font-size:13px;font-weight:600;margin-bottom:14px;cursor:pointer;">즐겨찾기에 추가하기</button>' +
        (rows ?
          '<div style="background:rgba(2,6,23,0.6);border:1px solid rgba(255,255,255,0.08);border-radius:10px;padding:10px 12px;">' +
            '<p style="color:#94a3b8;font-size:11px;margin:0 0 8px;font-weight:600;">최근 방문 이력</p>' +
            rows +
          "</div>"
        : "") +
        '<button id="ncg-close-btn" style="width:100%;background:transparent;color:#64748b;border:none;padding:10px;font-size:12px;margin-top:10px;cursor:pointer;">확인했습니다</button>' +
        '<p style="color:#475569;font-size:10px;text-align:center;margin:8px 0 0;">컴컴 부정클릭 방지 시스템</p>' +
      "</div>";

    document.body.appendChild(overlay);

    document.getElementById("ncg-close-btn").addEventListener("click", function () {
      overlay.remove();
    });
    document.getElementById("ncg-bookmark-btn").addEventListener("click", function () {
      try {
        if (window.sidebar && window.sidebar.addPanel) {
          window.sidebar.addPanel(document.title, window.location.href, "");
        } else if (window.external && "AddFavorite" in window.external) {
          window.external.AddFavorite(window.location.href, document.title);
        } else {
          alert("Ctrl+D(윈도우) 또는 Cmd+D(맥)를 눌러서 즐겨찾기에 추가해주세요.");
        }
      } catch (e) {
        alert("Ctrl+D(윈도우) 또는 Cmd+D(맥)를 눌러서 즐겨찾기에 추가해주세요.");
      }
    });
  }

  var API_BASE = getApiBase();
  var params = new URLSearchParams(window.location.search);

  var payload = {
    landing_url: window.location.href,
    referrer: document.referrer || "",
    session_id: getOrCreateSessionId(),
    keyword: getParam(params, ["keyword", "utm_term", "kw"]),
    click_id: getParam(params, ["NaPm", "gclid", "click_id", "n_ad", "n_media"]),
  };

  function start() {
    injectBadge();

    fetch(API_BASE + "/api/click", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
      keepalive: true,
    })
      .then(function (res) { return res.json(); })
      .then(function (data) {
        if (data && data.suspicious) {
          injectWarning(data.history);
        }
      })
      .catch(function () {
        // 네트워크 오류는 조용히 무시 (사용자 경험에 영향 없게)
      });
  }

  if (document.body) {
    start();
  } else {
    document.addEventListener("DOMContentLoaded", start);
  }
})();
