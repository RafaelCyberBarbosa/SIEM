"""
Log parsers: turn raw text lines from arbitrary sources (syslog, files, agents)
into a normalized dict matching the Event schema. Each parser returns None if
the line does not match its format, so callers can try parsers in order.
"""
import json
import re
from datetime import datetime, timedelta, timezone

IP_RE = r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"

# --- RFC3164 / traditional syslog: "<PRI>Mon dd hh:mm:ss host tag[pid]: message"
RFC3164_RE = re.compile(
    r"^(?:<(?P<pri>\d+)>)?"
    r"(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<tag>[^:\[\s]+)(?:\[(?P<pid>\d+)\])?:\s*"
    r"(?P<message>.*)$"
)

# --- RFC5424: "<PRI>1 TIMESTAMP HOST APP PROCID MSGID [SD] MSG"
RFC5424_RE = re.compile(
    r"^<(?P<pri>\d+)>(?P<version>\d)\s+"
    r"(?P<ts>\S+)\s+(?P<host>\S+)\s+(?P<app>\S+)\s+(?P<procid>\S+)\s+(?P<msgid>\S+)\s+"
    r"(?:\[[^\]]*\]\s*)?(?P<message>.*)$"
)

# --- CEF: "CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|Extension"
CEF_RE = re.compile(
    r"^(?:.*?)CEF:0\|(?P<vendor>[^|]*)\|(?P<product>[^|]*)\|(?P<version>[^|]*)\|"
    r"(?P<sig>[^|]*)\|(?P<name>[^|]*)\|(?P<severity>[^|]*)\|(?P<extension>.*)$"
)

# --- SSH auth.log lines ---
SSH_FAILED_RE = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from " + IP_RE + r" port (?P<port>\d+)"
)
SSH_ACCEPTED_RE = re.compile(
    r"Accepted (?:password|publickey) for (?P<user>\S+) from " + IP_RE + r" port (?P<port>\d+)"
)
SSH_INVALID_USER_RE = re.compile(r"Invalid user (?P<user>\S+) from " + IP_RE)
SUDO_RE = re.compile(r"sudo:\s*(?P<user>\S+)\s*:.*COMMAND=(?P<command>.*)")
USERADD_RE = re.compile(r"new user:\s*name=(?P<user>\S+)")
USERMOD_ADMIN_RE = re.compile(r"add '(?P<user>\S+)' to group '(?:sudo|wheel|admin)'")

# --- Combined / common log format (nginx/apache access log) ---
ACCESS_LOG_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) (?P<httpver>[^"]+)" '
    r'(?P<status>\d{3}) (?P<size>\S+)'
    r'(?: "(?P<referrer>[^"]*)" "(?P<agent>[^"]*)")?'
)

# --- Windows Security Event (from agent, semi-structured "Key: Value" lines) ---
WIN_EVENTID_RE = re.compile(r"EventID[:=]\s*(?P<id>\d+)")

SEVERITY_MAP_SYSLOG = {
    0: "critical", 1: "critical", 2: "critical", 3: "high",
    4: "medium", 5: "low", 6: "info", 7: "info",
}

WIN_SECURITY_EVENT_MAP = {
    "4625": ("authentication", "login_failure", "failure", "medium"),
    "4624": ("authentication", "login_success", "success", "info"),
    "4720": ("account_management", "user_created", "success", "medium"),
    "4732": ("account_management", "user_added_to_privileged_group", "success", "high"),
    "4728": ("account_management", "user_added_to_privileged_group", "success", "high"),
    "4740": ("authentication", "account_locked_out", "failure", "medium"),
    "4648": ("authentication", "explicit_credential_logon", "success", "medium"),
    "1102": ("system", "audit_log_cleared", "success", "high"),
    "7045": ("system", "service_installed", "success", "medium"),
    "4688": ("process", "process_start", "success", "info"),
    "4698": ("system", "scheduled_task_created", "success", "medium"),
    "4719": ("system", "audit_policy_changed", "success", "medium"),
}


def _now():
    return datetime.now(timezone.utc)


def _base_event(raw: str, host: str = "") -> dict:
    return {
        "timestamp": _now(),
        "host": host,
        "category": "other",
        "action": "",
        "outcome": "unknown",
        "severity": "info",
        "user": "",
        "src_ip": "",
        "src_port": None,
        "dst_ip": "",
        "dst_port": None,
        "protocol": "",
        "message": raw.strip(),
        "raw": raw,
        "tags": [],
        "extra": {},
    }


def parse_json_line(raw: str) -> dict | None:
    raw_stripped = raw.strip()
    if not raw_stripped.startswith("{"):
        return None
    try:
        data = json.loads(raw_stripped)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    ev = _base_event(raw)
    for key in ("host", "category", "action", "outcome", "severity", "user",
                "src_ip", "dst_ip", "protocol", "message"):
        if key in data and data[key] is not None:
            ev[key] = data[key]
    for key in ("src_port", "dst_port"):
        if key in data and data[key] is not None:
            try:
                ev[key] = int(data[key])
            except (TypeError, ValueError):
                pass
    if "timestamp" in data:
        ts = _parse_timestamp(str(data["timestamp"]))
        if ts:
            ev["timestamp"] = ts
    if "tags" in data and isinstance(data["tags"], list):
        ev["tags"] = data["tags"]
    extra = {k: v for k, v in data.items() if k not in ev}
    ev["extra"] = extra
    if not ev["message"]:
        ev["message"] = raw_stripped
    return ev


def _parse_timestamp(ts_str: str) -> datetime | None:
    fmts = [
        "%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%d %H:%M:%S", "%b %d %H:%M:%S",
    ]
    for fmt in fmts:
        try:
            dt = datetime.strptime(ts_str, fmt)
            if dt.tzinfo is None:
                if "%Y" not in fmt:
                    now = _now()
                    dt = dt.replace(year=now.year, tzinfo=timezone.utc)
                    # RFC3164 has no year field; if the guessed date lands more than a
                    # day in the future (e.g. "Jan 1" logged while today is in December),
                    # it almost certainly belongs to the previous year.
                    if dt > now + timedelta(days=1):
                        dt = dt.replace(year=now.year - 1)
                else:
                    dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    return None


def parse_cef(raw: str) -> dict | None:
    m = CEF_RE.search(raw)
    if not m:
        return None
    ev = _base_event(raw)
    ext = {}
    for pair in re.findall(r"(\w+)=((?:[^=\s]|(?<=\\)=)+(?:\s(?!\w+=)[^=\s]*)*)", m.group("extension")):
        ext[pair[0]] = pair[1].strip()
    ev["message"] = m.group("name") or raw
    ev["extra"] = {"vendor": m.group("vendor"), "product": m.group("product"), **ext}
    ev["src_ip"] = ext.get("src", "")
    ev["dst_ip"] = ext.get("dst", "")
    try:
        sev = int(m.group("severity"))
        ev["severity"] = "critical" if sev >= 9 else "high" if sev >= 7 else "medium" if sev >= 4 else "low"
    except ValueError:
        ev["severity"] = "medium"
    ev["category"] = "network"
    ev["action"] = m.group("sig") or ""
    return ev


def parse_access_log(raw: str) -> dict | None:
    m = ACCESS_LOG_RE.search(raw)
    if not m:
        return None
    ev = _base_event(raw)
    ev["category"] = "web"
    ev["src_ip"] = m.group("ip")
    status = int(m.group("status"))
    ev["action"] = f"{m.group('method')} {m.group('path')}"
    ev["outcome"] = "success" if status < 400 else "failure"
    ev["severity"] = "high" if status in (401, 403) else "medium" if status >= 500 else "info"
    ev["extra"] = {
        "http_status": status, "http_method": m.group("method"), "path": m.group("path"),
        "referrer": m.group("referrer") or "", "user_agent": m.group("agent") or "",
        "size": m.group("size"),
    }
    ev["message"] = f"{m.group('method')} {m.group('path')} -> {status}"
    return ev


def parse_ssh_auth(raw: str, host: str = "") -> dict | None:
    m = SSH_FAILED_RE.search(raw)
    if m:
        ev = _base_event(raw, host)
        ev.update(category="authentication", action="login_failure", outcome="failure",
                   severity="low", user=m.group("user"), src_ip=m.group(2),
                   src_port=int(m.group("port")), message=raw.strip())
        return ev

    m = SSH_ACCEPTED_RE.search(raw)
    if m:
        ev = _base_event(raw, host)
        ev.update(category="authentication", action="login_success", outcome="success",
                   severity="info", user=m.group("user"), src_ip=m.group(2),
                   src_port=int(m.group("port")), message=raw.strip())
        return ev

    m = SSH_INVALID_USER_RE.search(raw)
    if m:
        ev = _base_event(raw, host)
        ev.update(category="authentication", action="login_invalid_user", outcome="failure",
                   severity="medium", user=m.group("user"), src_ip=m.group(2), message=raw.strip())
        return ev

    m = SUDO_RE.search(raw)
    if m:
        ev = _base_event(raw, host)
        ev.update(category="process", action="sudo_command", outcome="success", severity="low",
                   user=m.group("user"), message=raw.strip(),
                   extra={"command": m.group("command").strip()})
        return ev

    m = USERADD_RE.search(raw)
    if m:
        ev = _base_event(raw, host)
        ev.update(category="account_management", action="user_created", outcome="success",
                   severity="medium", user=m.group("user"), message=raw.strip())
        return ev

    m = USERMOD_ADMIN_RE.search(raw)
    if m:
        ev = _base_event(raw, host)
        ev.update(category="account_management", action="user_added_to_privileged_group",
                   outcome="success", severity="high", user=m.group("user"), message=raw.strip())
        return ev

    return None


def parse_windows_event(raw: str, host: str = "") -> dict | None:
    m = WIN_EVENTID_RE.search(raw)
    if not m:
        return None
    event_id = m.group("id")
    mapping = WIN_SECURITY_EVENT_MAP.get(event_id)
    ev = _base_event(raw, host)
    user_m = re.search(r"(?:Account Name|TargetUserName|User)[:=]\s*([^\s,;]+)", raw)
    ip_m = re.search(r"(?:Source Network Address|IpAddress)[:=]\s*" + IP_RE, raw)
    if mapping:
        category, action, outcome, severity = mapping
        ev.update(category=category, action=action, outcome=outcome, severity=severity)
    else:
        ev.update(category="system", action=f"windows_event_{event_id}")
    if user_m:
        ev["user"] = user_m.group(1)
    if ip_m:
        ev["src_ip"] = ip_m.group(1)
    ev["extra"]["windows_event_id"] = event_id
    ev["message"] = raw.strip()
    return ev


def parse_rfc5424(raw: str) -> dict | None:
    m = RFC5424_RE.search(raw)
    if not m:
        return None
    ev = _base_event(raw, m.group("host"))
    ts = _parse_timestamp(m.group("ts"))
    if ts:
        ev["timestamp"] = ts
    ev["message"] = m.group("message")
    ev["extra"]["app"] = m.group("app")
    pri = int(m.group("pri"))
    severity_code = pri % 8
    ev["severity"] = SEVERITY_MAP_SYSLOG.get(severity_code, "info")
    return ev


def parse_rfc3164(raw: str) -> dict | None:
    m = RFC3164_RE.search(raw)
    if not m:
        return None
    ev = _base_event(raw, m.group("host"))
    ts = _parse_timestamp(m.group("ts"))
    if ts:
        ev["timestamp"] = ts
    ev["message"] = m.group("message")
    ev["extra"]["tag"] = m.group("tag")
    if m.group("pri"):
        pri = int(m.group("pri"))
        severity_code = pri % 8
        ev["severity"] = SEVERITY_MAP_SYSLOG.get(severity_code, "info")
    return ev


# Ordered pipeline of parsers tried against a raw line. First match wins.
LINE_PARSERS = [parse_json_line, parse_cef, parse_access_log, parse_rfc5424, parse_rfc3164]


def parse_log_line(raw: str, default_host: str = "") -> dict:
    """Best-effort parse of a single raw log line into a normalized event dict.
    Falls back to a generic event carrying the raw text as the message."""
    if not raw or not raw.strip():
        return _base_event(raw, default_host)

    for parser in LINE_PARSERS:
        result = parser(raw)
        if result:
            if not result.get("host"):
                result["host"] = default_host
            # Layer syslog-message-body specific parsers (ssh/windows) on top
            body = result.get("message", raw)
            enrich = parse_ssh_auth(body, result.get("host", default_host)) or parse_windows_event(body, result.get("host", default_host))
            if enrich:
                enrich["timestamp"] = result["timestamp"]
                enrich["host"] = result.get("host") or default_host
                enrich["raw"] = raw
                return enrich
            return result

    enrich = parse_ssh_auth(raw, default_host) or parse_windows_event(raw, default_host)
    if enrich:
        return enrich

    return _base_event(raw, default_host)
