import time
import requests
from datetime import datetime, timezone, timedelta


ES_URL   = "http://localhost:9200"
INDEX    = "security-logs-*"
INTERVAL = 60
WINDOW = 86400 

RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
BLUE   = "\033[94m"
RESET  = "\033[0m"
BOLD   = "\033[1m"


def count_events(attack_type, since_ts):
    """count events of a given attack type after a timestamp"""
    query = {
        "query": {
            "bool": {
                "must": [
                    {"match": {"attack_type": attack_type}},
                    {"bool": {
                        "should": [
                            {"range": {"@timestamp": {"gte": since_ts}}},
                            {"range": {"timestamp": {"gte": since_ts}}}
                        ],
                        "minimum_should_match": 1
                    }}
                ]
            }
        }
    }
    try:
        resp = requests.post(
            f"{ES_URL}/{INDEX}/_count",
            json=query,
            timeout=10
        )
        return resp.json().get("count", 0)
    except Exception as e:
        print(f"  [error] elasticsearch query failed: {e}")
        return 0

def count_normal_traffic(since_ts):
    """count normal traffic events after a timestamp"""
    query = {
        "query": {
            "bool": {
                "must": [
                    {"term": {"traffic_type.keyword": "normal"}},
                    {"range": {"@timestamp": {"gte": since_ts}}}
                ]
            }
        }
    }
    try:
        resp = requests.post(
            f"{ES_URL}/{INDEX}/_count",
            json=query,
            timeout=10
        )
        return resp.json().get("count", 0)
    except Exception as e:
        return 0


def rule_kill_chain_pattern(since_ts):
    """
    rule 1 kill chain pattern detected
    fires when port scan + ssh brute force + privilege escalation
    appear within the same time window, classic attack progression
    """
    alerts = []

    recon    = count_events("port_scan",            since_ts)
    brute    = count_events("ssh_brute_force",      since_ts)
    escalate = count_events("privilege_escalation", since_ts)
    lateral  = count_events("lateral_movement",     since_ts)

    if recon > 0 and brute > 5 and escalate > 0:
        stages = ["reconnaissance"]
        if brute > 0:
            stages.append("initial access")
        if escalate > 0:
            stages.append("privilege escalation")
        if lateral > 0:
            stages.append("lateral movement")

        alerts.append({
            "rule":        "kill chain pattern",
            "severity":    "critical",
            "ip":          "multiple",
            "stages":      stages,
            "description": (
                f"kill chain progression detected: "
                f"{recon} port scans, {brute} brute force, "
                f"{escalate} escalation attempts"
            )
        })

    return alerts


def rule_multi_surface_attack(since_ts):
    """
    rule 2 simultaneous attacks on multiple surfaces
    fires when nginx and system logs both show attack traffic
    """
    alerts = []

    nginx_attacks  = count_events("sql_injection",       since_ts)
    nginx_attacks += count_events("ddos",                since_ts)
    nginx_attacks += count_events("xss",                 since_ts)
    nginx_attacks += count_events("directory_traversal", since_ts)

    system_attacks  = count_events("ssh_brute_force", since_ts)
    system_attacks += count_events("syn_flood",       since_ts)

    if nginx_attacks > 10 and system_attacks > 10:
        alerts.append({
            "rule":        "multi-surface attack",
            "severity":    "high",
            "ip":          "multiple",
            "description": (
                f"simultaneous attacks on web ({nginx_attacks} events) "
                f"and system ({system_attacks} events)"
            )
        })

    return alerts


def rule_brute_then_success(since_ts):
    """
    rule 3 brute force followed by successful login
    the most dangerous pattern, attacker got in
    """
    alerts = []

    brute   = count_events("ssh_brute_force", since_ts)
    success = count_events("ssh_success",     since_ts)

    if brute > 5 and success > 0:
        alerts.append({
            "rule":        "brute force success",
            "severity":    "critical",
            "ip":          "unknown",
            "description": (
                f"ssh brute force ({brute} attempts) followed by "
                f"successful login ({success} times), system may be compromised"
            )
        })

    return alerts


def rule_ransomware_detected(since_ts):
    """
    rule 4 ransomware activity with lateral movement
    most severe combination possible
    """
    alerts = []

    ransomware = count_events("ransomware",       since_ts)
    lateral    = count_events("lateral_movement", since_ts)

    if ransomware > 0:
        severity = "critical" if lateral > 0 else "high"
        alerts.append({
            "rule":        "ransomware activity",
            "severity":    severity,
            "ip":          "internal",
            "description": (
                f"ransomware file activity detected ({ransomware} events)" +
                (f" with lateral movement ({lateral} events)" if lateral > 0 else "")
            )
        })

    return alerts


def rule_apt_indicators(since_ts):
    """
    rule 5 advanced persistent threat indicators
    log4shell + reverse shell = sophisticated attacker
    """
    alerts = []

    log4shell     = count_events("log4shell",        since_ts)
    reverse_shell = count_events("reverse_shell",    since_ts)
    lateral       = count_events("lateral_movement", since_ts)

    if log4shell > 0 and reverse_shell > 0:
        alerts.append({
            "rule":        "apt indicators",
            "severity":    "critical",
            "ip":          "unknown",
            "description": (
                f"apt-like attack: log4shell exploit ({log4shell}) + "
                f"reverse shell ({reverse_shell}) + "
                f"lateral movement ({lateral})"
            )
        })

    return alerts


def print_alert(alert):
    """print a formatted correlation alert to terminal"""
    severity = alert.get("severity", "medium")
    color    = RED if severity == "critical" else YELLOW

    print(f"\n{color}{BOLD}{'='*60}{RESET}")
    print(f"{color}{BOLD}  correlation alert: {alert['rule'].upper()}{RESET}")
    print(f"{color}{BOLD}{'='*60}{RESET}")
    print(f"  severity:    {color}{severity.upper()}{RESET}")
    print(f"  description: {alert['description']}")

    if "stages" in alert:
        print(f"  kill chain:  {' > '.join(alert['stages'])}")
    if "attack_types" in alert:
        print(f"  attack types: {', '.join(alert['attack_types'])}")
    if "log_types" in alert:
        print(f"  log sources: {', '.join(alert['log_types'])}")

    print(f"  detected at: {datetime.now().strftime('%H:%M:%S')}")
    print(f"{color}{'='*60}{RESET}")


def run():
    """main correlator loop"""
    print(f"\n{BOLD}{'='*60}{RESET}")
    print(f"{BOLD}  security correlator{RESET}")
    print(f"{BOLD}{'='*60}{RESET}")
    print(f"  elasticsearch: {ES_URL}")
    print(f"  check interval: {INTERVAL}s")
    print(f"  lookback window: {WINDOW}s")
    print(f"  rules: 5 correlation rules")
    print(f"  stop: ctrl+c")
    print(f"{'='*60}\n")

    rules = [
        ("kill chain pattern",     rule_kill_chain_pattern),
        ("multi surface attack",   rule_multi_surface_attack),
        ("brute force success",    rule_brute_then_success),
        ("ransomware activity",    rule_ransomware_detected),
        ("apt indicators",         rule_apt_indicators),
    ]

    iteration = 0

    try:
        while True:
            iteration += 1
            now      = datetime.now(timezone.utc)
            since_ts = (now - timedelta(seconds=WINDOW)).isoformat()

            print(f"{BLUE}[{now.strftime('%H:%M:%S')}] running correlation check #{iteration}...{RESET}")

            total_alerts = 0
            for rule_name, rule_fn in rules:
                alerts = rule_fn(since_ts)
                for alert in alerts:
                    print_alert(alert)
                    total_alerts += 1

            if total_alerts == 0:
                print(f"  {GREEN}no correlation alerts{RESET}")
            else:
                print(f"\n  {RED}{BOLD}total alerts: {total_alerts}{RESET}")

            print(f"  next check in {INTERVAL}s...\n")
            time.sleep(INTERVAL)

    except KeyboardInterrupt:
        print(f"\n\n  correlator stopped")


if __name__ == "__main__":
    try:
        requests.get(ES_URL, timeout=5)
    except Exception:
        print(f"{RED}error: elasticsearch not available at {ES_URL}{RESET}")
        print("make sure docker compose is running: docker compose up -d")
        exit(1)

    run()