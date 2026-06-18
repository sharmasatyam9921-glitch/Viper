"""Tests for the Burp Suite export importer."""
from __future__ import annotations

import base64
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.specialist.burp_import import (  # noqa: E402
    object_urls,
    parse_burp_xml,
    session_headers,
)


def _b64req(path: str, *header_lines: str) -> str:
    raw = f"GET {path} HTTP/1.1\r\nHost: target.test\r\n"
    for h in header_lines:
        raw += h + "\r\n"
    raw += "\r\n"
    return base64.b64encode(raw.encode()).decode()


def _item(url, method, status, b64request):
    return (
        "<item>"
        f"<url>{url}</url>"
        f"<method>{method}</method>"
        f"<status>{status}</status>"
        f'<request base64="true">{b64request}</request>'
        "</item>"
    )


SAMPLE = (
    '<?xml version="1.0"?><items burpVersion="2024">'
    + _item("https://target.test/api/orders/1001", "GET", 200,
            _b64req("/api/orders/1001", "Cookie: session=alice", "Authorization: Bearer AAA"))
    + _item("https://target.test/home", "GET", 200,
            _b64req("/home", "Cookie: session=alice"))                  # no id -> dropped
    + _item("https://target.test/api/orders/2002", "GET", 403,
            _b64req("/api/orders/2002", "Cookie: session=alice"))       # not 2xx -> dropped
    + _item("https://target.test/profile?account=778", "GET", 200,
            _b64req("/profile?account=778", "Cookie: session=alice", "Authorization: Bearer AAA"))
    + "</items>"
)


def test_parse_extracts_items_and_headers():
    items = parse_burp_xml(SAMPLE)
    assert len(items) == 4
    first = items[0]
    assert first.url == "https://target.test/api/orders/1001"
    assert first.method == "GET" and first.status == 200
    assert first.header("cookie") == "session=alice"
    assert first.header("authorization") == "Bearer AAA"


def test_object_urls_keeps_id_bearing_success_only():
    urls = object_urls(parse_burp_xml(SAMPLE))
    assert "https://target.test/api/orders/1001" in urls   # numeric id, 200
    assert "https://target.test/profile?account=778" in urls  # id query, 200
    assert "https://target.test/home" not in urls          # no id
    assert "https://target.test/api/orders/2002" not in urls  # 403


def test_session_headers_picks_dominant_auth():
    sh = session_headers(parse_burp_xml(SAMPLE))
    assert sh.get("Cookie") == "session=alice"
    assert sh.get("Authorization") == "Bearer AAA"


def test_malformed_xml_returns_empty():
    assert parse_burp_xml("not xml <<<") == []
    assert parse_burp_xml("") == []
    assert object_urls([]) == []
    assert session_headers([]) == {}


def test_object_urls_drops_non_http_schemes():
    # A hand-edited / merged export with a file:// (or ftp:) id-bearing URL must
    # never become a replay candidate (would otherwise hit urllib's FileHandler).
    xml = ('<items>'
           '<item><url>file:///C:/secrets/1/data.txt</url><method>GET</method>'
           '<status>200</status></item>'
           '<item><url>ftp://host/files/42</url><method>GET</method>'
           '<status>200</status></item>'
           '<item><url>https://target.test/api/orders/9</url><method>GET</method>'
           '<status>200</status></item>'
           '</items>')
    urls = object_urls(parse_burp_xml(xml))
    assert urls == ["https://target.test/api/orders/9"]


def test_fetch_sync_refuses_non_http_scheme():
    from core.swarm_workers.vuln._http import _fetch_sync
    # Even if a file:// URL reaches the fetcher, it must be refused (no file read).
    assert _fetch_sync("GET", "file:///etc/hostname") is None
    assert _fetch_sync("GET", "ftp://host/x") is None


def test_non_base64_request_body_parsed():
    raw = "GET /api/users/5 HTTP/1.1\nHost: t\nCookie: s=bob\n\n"
    xml = ('<items><item><url>https://t/api/users/5</url><method>GET</method>'
           f'<status>200</status><request>{raw}</request></item></items>')
    items = parse_burp_xml(xml)
    assert items[0].header("cookie") == "s=bob"
    assert object_urls(items) == ["https://t/api/users/5"]
