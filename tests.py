import pytest
import sys
import os
import re

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from generator import (
    ssh_brute_force, port_scan, sql_injection, ddos,
    syn_flood, directory_traversal, privilege_escalation,
    xss, log4shell, reverse_shell, credential_stuffing,
    dns_amplification, arp_spoofing, ransomware_activity,
    lateral_movement, normal_traffic, normal_ssh, normal_system,
    random_ip, ts
)


SYSLOG_PATTERN = re.compile(
    r"^\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}\s+\S+\s+\S+:"
)

NGINX_PATTERN = re.compile(
    r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3} - - \[\d{2}/\w+/\d{4}:\d{2}:\d{2}:\d{2} \+\d{4}\] "'
)

IP_PATTERN = re.compile(
    r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
)


def read_last_line(filepath):
    """read the last written line from a log file"""
    with open(filepath) as f:
        lines = [l.strip() for l in f.readlines() if l.strip()]
    return lines[-1] if lines else ""


def test_random_ip_returns_string():
    ip = random_ip()
    assert isinstance(ip, str)


def test_random_ip_valid_format():
    ip = random_ip()
    assert IP_PATTERN.match(ip), f"invalid ip format: {ip}"


def test_random_ip_not_private():
    for _ in range(20):
        ip = random_ip()
        assert not ip.startswith("10.")
        assert not ip.startswith("127.")
        assert not ip.startswith("192.168.")


def test_ts_returns_string():
    result = ts()
    assert isinstance(result, str)


def test_ts_has_time_format():
    result = ts()
    assert re.match(r"\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}", result), \
        f"unexpected timestamp format: {result}"


def test_ssh_brute_force_writes_to_auth_log():
    ssh_brute_force()
    assert os.path.exists("logs/system/auth.log")


def test_ssh_brute_force_syslog_format():
    ssh_brute_force()
    line = read_last_line("logs/system/auth.log")
    assert SYSLOG_PATTERN.match(line), f"unexpected format: {line}"


def test_ssh_brute_force_contains_sshd():
    ssh_brute_force()
    line = read_last_line("logs/system/auth.log")
    assert "sshd" in line


def test_ssh_brute_force_contains_password_event():
    ssh_brute_force()
    line = read_last_line("logs/system/auth.log")
    assert any(keyword in line for keyword in [
        "Failed password", "Accepted password", "Connection closed"
    ]), f"no password event found in: {line}"


def test_port_scan_writes_to_syslog():
    port_scan()
    assert os.path.exists("logs/system/syslog")


def test_port_scan_syslog_format():
    port_scan()
    line = read_last_line("logs/system/syslog")
    assert SYSLOG_PATTERN.match(line), f"unexpected format: {line}"


def test_port_scan_contains_block_or_refused():
    port_scan()
    line = read_last_line("logs/system/syslog")
    assert any(keyword in line for keyword in [
        "UFW BLOCK", "refused connect", "SYN flooding"
    ]), f"no scan event found in: {line}"


def test_sql_injection_writes_to_nginx_log():
    sql_injection()
    assert os.path.exists("logs/nginx/access.log")


def test_sql_injection_nginx_format():
    sql_injection()
    line = read_last_line("logs/nginx/access.log")
    assert NGINX_PATTERN.match(line), f"unexpected format: {line}"


def test_sql_injection_contains_payload():
    sql_injection()
    line = read_last_line("logs/nginx/access.log")
    assert any(payload in line for payload in [
        "UNION", "SELECT", "DROP", "1=1", "ORDER BY", "admin'"
    ]), f"no sql payload found in: {line}"


def test_sql_injection_has_error_status():
    sql_injection()
    line = read_last_line("logs/nginx/access.log")
    assert any(code in line for code in ["400", "403", "500"]), \
        f"no error status code in: {line}"


def test_ddos_writes_to_nginx_log():
    ddos()
    assert os.path.exists("logs/nginx/access.log")


def test_ddos_nginx_format():
    ddos()
    line = read_last_line("logs/nginx/access.log")
    assert NGINX_PATTERN.match(line), f"unexpected format: {line}"


def test_ddos_contains_429_status():
    ddos()
    line = read_last_line("logs/nginx/access.log")
    assert "429" in line, f"no 429 status in ddos line: {line}"


def test_syn_flood_writes_to_kern_log():
    syn_flood()
    assert os.path.exists("logs/system/kern.log")


def test_syn_flood_syslog_format():
    syn_flood()
    line = read_last_line("logs/system/kern.log")
    assert SYSLOG_PATTERN.match(line), f"unexpected format: {line}"


def test_syn_flood_contains_kernel_event():
    syn_flood()
    line = read_last_line("logs/system/kern.log")
    assert "kernel" in line, f"no kernel event in: {line}"


def test_syn_flood_contains_flood_or_block():
    syn_flood()
    line = read_last_line("logs/system/kern.log")
    assert any(keyword in line for keyword in [
        "SYN flooding", "UFW BLOCK", "nf_conntrack"
    ]), f"no flood event in: {line}"


def test_directory_traversal_writes_to_nginx_log():
    directory_traversal()
    line = read_last_line("logs/nginx/access.log")
    assert NGINX_PATTERN.match(line), f"unexpected format: {line}"


def test_directory_traversal_contains_path():
    directory_traversal()
    line = read_last_line("logs/nginx/access.log")
    assert any(path in line for path in [
        "../", "etc/passwd", "etc/shadow", "etc/hosts",
        "proc/self", "%2e%2e"
    ]), f"no traversal path in: {line}"


def test_privilege_escalation_writes_to_auth_log():
    privilege_escalation()
    line = read_last_line("logs/system/auth.log")
    assert SYSLOG_PATTERN.match(line), f"unexpected format: {line}"


def test_privilege_escalation_contains_sudo_or_su():
    privilege_escalation()
    line = read_last_line("logs/system/auth.log")
    assert any(keyword in line for keyword in [
        "sudo", "su["
    ]), f"no sudo/su event in: {line}"


def test_xss_writes_to_nginx_log():
    xss()
    line = read_last_line("logs/nginx/access.log")
    assert NGINX_PATTERN.match(line), f"unexpected format: {line}"


def test_xss_contains_script_payload():
    xss()
    line = read_last_line("logs/nginx/access.log")
    assert any(payload in line for payload in [
        "script", "onerror", "javascript:", "onload", "alert("
    ]), f"no xss payload in: {line}"


def test_log4shell_writes_to_nginx_log():
    log4shell()
    line = read_last_line("logs/nginx/access.log")
    assert NGINX_PATTERN.match(line), f"unexpected format: {line}"


def test_log4shell_contains_jndi():
    log4shell()
    line = read_last_line("logs/nginx/access.log")
    assert any(keyword in line for keyword in [
        "jndi", "ldap", "rmi", "dns:", "lower:j", "lower:l"
    ]), f"no log4shell payload in: {line}"

def test_reverse_shell_writes_to_auth_log():
    reverse_shell()
    line = read_last_line("logs/system/auth.log")
    assert SYSLOG_PATTERN.match(line), f"unexpected format: {line}"


def test_credential_stuffing_writes_to_nginx_log():
    credential_stuffing()
    line = read_last_line("logs/nginx/access.log")
    assert NGINX_PATTERN.match(line), f"unexpected format: {line}"


def test_credential_stuffing_is_post_request():
    credential_stuffing()
    line = read_last_line("logs/nginx/access.log")
    assert "POST" in line, f"credential stuffing should use POST: {line}"


def test_dns_amplification_writes_to_syslog():
    dns_amplification()
    line = read_last_line("logs/system/syslog")
    assert SYSLOG_PATTERN.match(line), f"unexpected format: {line}"


def test_dns_amplification_contains_dns_event():
    dns_amplification()
    line = read_last_line("logs/system/syslog")
    assert any(keyword in line for keyword in [
        "named", "DNS", "denied", "too many"
    ]), f"no dns event in: {line}"


def test_arp_spoofing_writes_to_kern_log():
    arp_spoofing()
    line = read_last_line("logs/system/kern.log")
    assert SYSLOG_PATTERN.match(line), f"unexpected format: {line}"


def test_arp_spoofing_contains_arp_event():
    arp_spoofing()
    line = read_last_line("logs/system/kern.log")
    assert any(keyword in line.lower() for keyword in [
        "arp", "neighbour", "arpwatch"
    ]), f"no arp event in: {line}"


def test_ransomware_writes_to_syslog():
    ransomware_activity()
    line = read_last_line("logs/system/syslog")
    assert SYSLOG_PATTERN.match(line), f"unexpected format: {line}"


def test_ransomware_contains_file_event():
    ransomware_activity()
    line = read_last_line("logs/system/syslog")
    assert any(keyword in line for keyword in [
        "encrypted", "locked", "crypto", "ransom", "renamed"
    ]), f"no ransomware event in: {line}"


def test_lateral_movement_writes_to_auth_log():
    lateral_movement()
    line = read_last_line("logs/system/auth.log")
    assert SYSLOG_PATTERN.match(line), f"unexpected format: {line}"


def test_lateral_movement_contains_internal_ip():
    lateral_movement()
    line = read_last_line("logs/system/auth.log")
    assert "192.168." in line, f"no internal ip in lateral movement: {line}"


def test_normal_traffic_writes_to_nginx_log():
    normal_traffic()
    line = read_last_line("logs/nginx/access.log")
    assert NGINX_PATTERN.match(line), f"unexpected format: {line}"


def test_normal_traffic_has_success_status():
    normal_traffic()
    line = read_last_line("logs/nginx/access.log")
    assert any(code in line for code in ["200", "301", "304"]), \
        f"normal traffic should return success status: {line}"


def test_normal_ssh_writes_to_auth_log():
    normal_ssh()
    line = read_last_line("logs/system/auth.log")
    assert SYSLOG_PATTERN.match(line), f"unexpected format: {line}"


def test_normal_ssh_contains_session_event():
    normal_ssh()
    line = read_last_line("logs/system/auth.log")
    assert any(keyword in line for keyword in [
        "Accepted publickey", "session opened", "session closed"
    ]), f"no session event in: {line}"


def test_normal_system_writes_to_syslog():
    normal_system()
    line = read_last_line("logs/system/syslog")
    assert SYSLOG_PATTERN.match(line), f"unexpected format: {line}"


def test_normal_system_contains_system_event():
    normal_system()
    line = read_last_line("logs/system/syslog")
    assert any(keyword in line for keyword in [
        "CRON", "systemd", "NetworkManager", "kernel"
    ]), f"no system event in: {line}"


def test_all_attack_functions_write_non_empty_lines():
    functions = [
        (ssh_brute_force, "logs/system/auth.log"),
        (port_scan,       "logs/system/syslog"),
        (sql_injection,   "logs/nginx/access.log"),
        (ddos,            "logs/nginx/access.log"),
        (syn_flood,       "logs/system/kern.log"),
    ]
    for fn, filepath in functions:
        fn()
        line = read_last_line(filepath)
        assert len(line) > 20, f"{fn.__name__} wrote too short a line: {line}"


def test_log_files_exist_after_generation():
    ssh_brute_force()
    port_scan()
    sql_injection()
    syn_flood()

    assert os.path.exists("logs/system/auth.log")
    assert os.path.exists("logs/system/syslog")
    assert os.path.exists("logs/system/kern.log")
    assert os.path.exists("logs/nginx/access.log")


def test_random_ip_first_octet_is_external():
    allowed_first_octets = {45, 91, 185, 194, 212, 77, 103, 139}
    for _ in range(50):
        ip = random_ip()
        first = int(ip.split(".")[0])
        assert first in allowed_first_octets, \
            f"unexpected first octet {first} in ip {ip}"