"""Burp Suite XML: the "Save items" export from Proxy history, Target or Logger.

Field mapping (one <item> per entry):
  url, method       <url>, <method>; when <url> is missing, <protocol>://<host>:<port><path>
  status            <status> (empty: no response)
  request bytes     <request>, base64-decoded when base64="true", otherwise its text (an
                    XML parser turns CR LF into LF there, so line ends are not exact)
  response bytes    <response>, the same way
  time              <time>, as Burp wrote it (Java's date format, with a zone abbreviation)
  label             <comment>
  creator           the burpVersion attribute of <items>
  tool id           none: the export has no id per item

The XML is read with defusedxml: entity declarations and external references are refused,
so an export cannot make the parser read a file, reach a URL or expand entities. Burp's own
export starts with a DOCTYPE that declares only elements and attributes, which is allowed.
Nesting deeper than MAX_XML_DEPTH is refused, and each item is released once it is read.
"""
import io
from xml.etree.ElementTree import ParseError

from defusedxml import DefusedXmlException
from defusedxml.ElementTree import iterparse

from . import (MAX_ENTRIES, MAX_XML_DEPTH, Adapter, Entry, ImportRefused, Parsed, RowError, b64, cut, head,
               http_url, method, status, text)


def detect(data: bytes) -> bool:
    start = head(data, 4096)
    return start.startswith("<") and "<items" in start


def _part(el, name: str, truncated: list[str]) -> bytes | None:
    if el is None or not (el.text or "").strip():
        return None
    if (el.get("base64") or "").lower() == "true":
        return b64(el.text, name, truncated)
    return cut(el.text.encode("utf-8", "surrogateescape"), name, truncated)


def _url(item) -> str:
    url = (item.findtext("url") or "").strip()
    if url:
        return http_url(url)
    proto, host = (item.findtext("protocol") or "").strip(), (item.findtext("host") or "").strip()
    port, path = (item.findtext("port") or "").strip(), (item.findtext("path") or "/").strip()
    default = {"http": "80", "https": "443"}.get(proto)
    return http_url(f"{proto}://{host}{'' if port in ('', default) else ':' + port}{path}")


def _entry(row: int, item) -> Entry:
    truncated: list[str] = []
    url, verb = _url(item), method(item.findtext("method"))
    request = _part(item.find("request"), "request", truncated)
    code = status((item.findtext("status") or "").strip())
    response = _part(item.find("response"), "response", truncated)
    return Entry(row=row, url=url, method=verb, status=code, request=request, response=response,
                 time=text(item.findtext("time"), 64), label=text(item.findtext("comment"), 300),
                 truncated=tuple(truncated))


def parse(data: bytes) -> Parsed:
    out, depth, root, row = Parsed(), 0, None, 0
    try:
        for event, el in iterparse(io.BytesIO(data), events=("start", "end"),
                                   forbid_dtd=False, forbid_entities=True, forbid_external=True):
            if event == "start":
                depth += 1
                if depth > MAX_XML_DEPTH:
                    raise ImportRefused(f"the XML is nested more than {MAX_XML_DEPTH} levels deep; "
                                        "this is not a Burp export")
                if root is None:
                    if el.tag != "items":
                        raise ImportRefused("this is not a Burp Suite XML export: it does not start with <items>")
                    root = el
                    version = (el.get("burpVersion") or "").strip()
                    out.creator = f"Burp Suite {version}"[:200] if version else "Burp Suite"
                continue
            depth -= 1
            if el.tag == "item" and depth == 1:
                row += 1
                if row > MAX_ENTRIES:
                    raise ImportRefused(f"the file has more than {MAX_ENTRIES} items; the limit is "
                                        f"{MAX_ENTRIES} per file")
                try:
                    out.entries.append(_entry(row, el))
                except RowError as err:
                    out.unreadable.append((row, str(err)))
                root.remove(el)                 # keep memory flat on large exports
    except ImportRefused:
        raise
    except DefusedXmlException:
        raise ImportRefused("the XML declares entities or external references, which are refused; "
                            "a Burp export has none") from None
    except (ParseError, ValueError, UnicodeError):
        raise ImportRefused("this is not a readable Burp Suite XML export: the XML is not well formed") from None
    if root is None:
        raise ImportRefused("this is not a Burp Suite XML export")
    return out


ADAPTER = Adapter(id="burp", title="Burp Suite XML", extensions=(".xml",), detect=detect, parse=parse,
                  summary="Items saved from Burp's Proxy history, Target or Logger (Save items), "
                          "with requests and responses in base64.")
