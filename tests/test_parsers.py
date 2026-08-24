from app.ingestion.parsers import parse_log_line, parse_ssh_auth, parse_access_log, parse_json_line


def test_ssh_failed_login():
    line = "Failed password for root from 203.0.113.5 port 51322 ssh2"
    ev = parse_ssh_auth(line)
    assert ev["category"] == "authentication"
    assert ev["action"] == "login_failure"
    assert ev["outcome"] == "failure"
    assert ev["user"] == "root"
    assert ev["src_ip"] == "203.0.113.5"


def test_ssh_accepted_login():
    line = "Accepted password for alice from 10.0.0.5 port 44122 ssh2"
    ev = parse_ssh_auth(line)
    assert ev["action"] == "login_success"
    assert ev["outcome"] == "success"
    assert ev["user"] == "alice"


def test_access_log():
    line = '203.0.113.9 - - [10/Oct/2023:13:55:36 -0700] "GET /admin HTTP/1.1" 403 287 "-" "curl/7.68"'
    ev = parse_access_log(line)
    assert ev["category"] == "web"
    assert ev["src_ip"] == "203.0.113.9"
    assert ev["extra"]["http_status"] == 403
    assert ev["severity"] == "high"


def test_json_line():
    line = '{"category": "network", "action": "connection", "src_ip": "1.2.3.4", "message": "conn established"}'
    ev = parse_json_line(line)
    assert ev["category"] == "network"
    assert ev["src_ip"] == "1.2.3.4"


def test_generic_fallback():
    ev = parse_log_line("some totally unstructured log line", default_host="myhost")
    assert ev["host"] == "myhost"
    assert ev["message"] == "some totally unstructured log line"
    assert ev["category"] == "other"


def test_privileged_group_change_detected():
    ev = parse_log_line("usermod: add 'bob' to group 'sudo'", default_host="h1")
    assert ev["action"] == "user_added_to_privileged_group"
    assert ev["severity"] == "high"
