"""
Блок CONNECT к не-банковским хостам: открытый прокси на VPS (0.0.0.0:8082) ловит сканеры
(739404.cc и т.п.) — шум в логах и лишняя нагрузка.

Отключить: TBANKMITM_BLOCK_NONBANK=0
"""
from __future__ import annotations

import os

from mitmproxy import http

from bank_filter import _BANK_KEYS

# Установка сертификата mitm через прокси (Potatso с первого включения).
_MITM_SETUP_HOSTS = ("mitm.it",)

# CDN для панели /admin (Font Awesome, шрифты, логотипы банков) — иначе иконки не грузятся через прокси.
_PANEL_CDN_HOSTS = (
    "cdnjs.cloudflare.com",
    "cdn.jsdelivr.net",
    "fonts.googleapis.com",
    "fonts.gstatic.com",
    "t-static.ru",
    "bms-logo-prod.t-static.ru",
    "cdn-tinkoff.ru",
    "unic-cdn-prod.cdn-tinkoff.ru",
    "imgproxy.cdn-tinkoff.ru",
    "brands-prod.cdn-tinkoff.ru",
    "brands-static.cdn-tinkoff.ru",
    "t-co.ru",
)

# Легитимные домены экосистемы Т‑Банка, auth/Госуслуги, СБП/НСПК и платёжные шлюзы.
# Хранятся отдельно от bank_filter._BANK_KEYS, чтобы is_bank_flow() не парсил сторонний JSON.
_ECOSYSTEM_ALLOWED_HOSTS = (
    "tcsgroup.io",
    "dev-tcsgroup.io",
    "tcsbank.ru",
    "tinsurance.ru",
    "t-id.ru",
    "tid.ru",
    "t-pay.ru",
    "t-bank.ru",
    "nspk.ru",
    "qr.nspk.ru",
    "esia.gosuslugi.ru",
    "gosuslugi.ru",
    "cloudpayments.mx",
    "cdn.tbank.ru",
    "acdn.tinkoff.ru",
)

# Известные мёртвые/зависающие трекеры и телеметрия (не auth, не платежи, не картинки):
# вместо 30s ERR_TIMED_OUT / Errno 11001 отдаём мгновенный синтетический 204 / 200 {}.
_FAST_DROP_TRACKER_HOSTS = (
    "web2web.diginetica.net",
    "le.tbank.ru",
    "tbank.global",
    "es.tbank.ru",
    "ads-video.t-static.ru",
)

_LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}

_BLOCK = os.environ.get("TBANKMITM_BLOCK_NONBANK", "1").strip().lower() not in (
    "0",
    "false",
    "no",
    "off",
)
_FAST_DROP_TRACKERS = os.environ.get("TBANKMITM_FAST_DROP_DEAD_TRACKERS", "1").strip().lower() not in (
    "0",
    "false",
    "no",
    "off",
)
_DEBUG = os.environ.get("BANK_DEBUG", "").strip().lower() in ("1", "true", "yes", "on")


def _host_is_bank(host: str) -> bool:
    h = (host or "").lower().strip().rstrip(".")
    if not h:
        return False
    return any(k in h for k in _BANK_KEYS)


def _host_matches_domain_list(host: str, domains: tuple[str, ...]) -> bool:
    h = (host or "").lower().strip().rstrip(".")
    if not h:
        return False
    return any(h == allowed or h.endswith("." + allowed) for allowed in domains)


def _host_is_panel_cdn(host: str) -> bool:
    return _host_matches_domain_list(host, _MITM_SETUP_HOSTS) or _host_matches_domain_list(
        host, _PANEL_CDN_HOSTS
    )


def _host_is_ecosystem(host: str) -> bool:
    return _host_matches_domain_list(host, _ECOSYSTEM_ALLOWED_HOSTS)


def _host_is_fast_drop_tracker(host: str) -> bool:
    return _host_matches_domain_list(host, _FAST_DROP_TRACKER_HOSTS)


def _host_is_local(host: str) -> bool:
    h = (host or "").lower().strip().strip("[]").rstrip(".")
    if not h:
        return False
    if h in _LOCAL_HOSTS:
        return True
    pub = (os.environ.get("TBANKMITM_PUBLIC_IP") or "").strip().lower()
    return bool(pub and h == pub)


def _cors_headers_for_flow(flow: http.HTTPFlow) -> dict[str, str]:
    origin = (flow.request.headers.get("Origin") or flow.request.headers.get("origin") or "").strip()
    headers = {
        "Access-Control-Allow-Origin": origin if origin else "*",
        "Access-Control-Allow-Methods": "GET, POST, PUT, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Requested-With, Accept",
        "Cache-Control": "no-store, no-cache, must-revalidate",
    }
    if origin:
        headers["Access-Control-Allow-Credentials"] = "true"
        headers["Vary"] = "Origin"
    return headers


def _handle_connect(flow: http.HTTPFlow) -> None:
    host = (flow.request.host or flow.request.pretty_host or "").strip()
    if _FAST_DROP_TRACKERS and _host_is_fast_drop_tracker(host):
        # Пропускаем CONNECT без блокировки и без установки искусственного flow.response.
        # mitmproxy сам отправит стандартный 'HTTP/1.1 200 Connection established'.
        # При connection_strategy=lazy и tls_clienthello establish_server_tls_first=False
        # mitmproxy локально завершит TLS-хэндшейк, и request() ниже отдаст мгновенный 200 {} / 204.
        if _DEBUG:
            print(f"[nonbank_connect_block] allow CONNECT for fast-drop tracker host={host!r}")
        return
    if not _BLOCK:
        return
    if _host_is_bank(host) or _host_is_panel_cdn(host) or _host_is_ecosystem(host) or _host_is_local(host):
        return
    if _DEBUG:
        print(f"[nonbank_connect_block] reject CONNECT host={host!r}")
    flow.response = http.Response.make(403, b"non-bank CONNECT blocked")


def http_connect(flow: http.HTTPFlow) -> None:
    _handle_connect(flow)


def tls_clienthello(data) -> None:
    if not _FAST_DROP_TRACKERS:
        return
    try:
        sni = (data.client_hello.sni or "").strip()
    except Exception:
        return
    if sni and _host_is_fast_drop_tracker(sni):
        data.establish_server_tls_first = False


def request(flow: http.HTTPFlow) -> None:
    if flow.request.method == "CONNECT":
        _handle_connect(flow)
        return
    if not _FAST_DROP_TRACKERS:
        return
    host = (flow.request.host or flow.request.pretty_host or "").strip().lower().rstrip(".")
    if not _host_is_fast_drop_tracker(host):
        return
    headers = _cors_headers_for_flow(flow)
    method = (flow.request.method or "").upper()
    if method == "OPTIONS" or host == "ads-video.t-static.ru" or host.endswith(".ads-video.t-static.ru"):
        flow.response = http.Response.make(204, b"", headers)
    else:
        headers["Content-Type"] = "application/json; charset=utf-8"
        flow.response = http.Response.make(200, b"{}", headers)
    if _DEBUG:
        print(f"[nonbank_connect_block] fast-drop {method} {flow.request.pretty_url[:120]}")
