import time
import requests
import subprocess
import os
import sys
from datetime import datetime, timezone

KIBANA_URL  = "http://localhost:5601"
ES_URL      = "http://localhost:9200"
INDEX       = "security-logs-*"

# seconds to wait after attack before checking alert
WAIT_AFTER_ATTACK = 90

# seconds to measure normal traffic for false positive rate
NORMAL_TRAFFIC_DURATION = 120

GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
BLUE   = "\033[94m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

def count_events(attack_type, since_ts):
    """count events of a given attack_type after a timestamp"""
    query = {
        "query": {
            "bool": {
                "must": [
                    {"match": {"attack_type": attack_type}},
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
        print(f"  [error] elasticsearch query failed: {e}")
        return 0


def count_normal_alerts(since_ts):
    """count false positives — attacks detected during normal traffic"""
    query = {
        "query": {
            "bool": {
                "must": [
                    {"match": {"traffic_type": "attack"}},
                    {"range": {"@timestamp": {"gte": since_ts}}}
                ],
                "must_not": [
                    {"match": {"attack_type": "unknown"}}
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


def check_kibana_rule_status(rule_name):
    """check if a kibana alert rule is active"""
    try:
        resp = requests.get(
            f"{KIBANA_URL}/api/alerting/rules/_find?search={rule_name}&search_fields=name",
            headers={"kbn-xsrf": "true"},
            timeout=10
        )
        rules = resp.json().get("data", [])
        for rule in rules:
            if rule_name.lower() in rule.get("name", "").lower():
                status = rule.get("execution_status", {}).get("status", "unknown")
                return status
        return "not found"
    except Exception as e:
        print(f"  [error] kibana api failed: {e}")
        return "error"

def run_attack(attack_env, duration=60):
    """run attack via generator in subprocess"""
    env = os.environ.copy()
    env["ATTACK"]   = attack_env
    env["INTERVAL"] = "0.2"   # fast generation for testing

    proc = subprocess.Popen(
        ["python3", "generator.py"],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    time.sleep(duration)
    proc.terminate()
    proc.wait()

SCENARIOS = [
    {
        "name":        "ssh brute force",
        "attack_env":  "ssh_brute",
        "attack_type": "ssh_brute_force",
        "rule_name":   "ssh brute force",
        "duration":    60,
    },
    {
        "name":        "ddos flood",
        "attack_env":  "ddos",
        "attack_type": "ddos",
        "rule_name":   "ddos attack",
        "duration":    60,
    },
    {
        "name":        "sql injection",
        "attack_env":  "sql_injection",
        "attack_type": "sql_injection",
        "rule_name":   "sql injection",
        "duration":    60,
    },
    {
        "name":        "directory traversal",
        "attack_env":  "directory_traversal",
        "attack_type": "directory_traversal",
        "rule_name":   "directory traversal",
        "duration":    60,
    },
    {
        "name":        "privilege escalation",
        "attack_env":  "privilege_escalation",
        "attack_type": "privilege_escalation",
        "rule_name":   "privilege escalation",
        "duration":    60,
    },
    {
        "name":        "syn flood",
        "attack_env":  "syn_flood",
        "attack_type": "syn_flood",
        "rule_name":   "syn flood",
        "duration":    60,
    },
    {
        "name":        "xss attack",
        "attack_env":  "xss",
        "attack_type": "xss",
        "rule_name":   "xss attack",
        "duration":    60,
    },
    {
        "name":        "log4shell exploit",
        "attack_env":  "log4shell",
        "attack_type": "log4shell",
        "rule_name":   "log4shell",
        "duration":    60,
    },
    {
        "name":        "ransomware activity",
        "attack_env":  "ransomware",
        "attack_type": "ransomware",
        "rule_name":   "ransomware",
        "duration":    60,
    },
    {
        "name":        "lateral movement",
        "attack_env":  "lateral_movement",
        "attack_type": "lateral_movement",
        "rule_name":   "lateral movement",
        "duration":    60,
    },
]

def run_tests():
    print(f"\n{BOLD}{'='*60}{RESET}")
    print(f"{BOLD}  security monitoring test framework{RESET}")
    print(f"{BOLD}{'='*60}{RESET}")
    print(f"  kibana:        {KIBANA_URL}")
    print(f"  elasticsearch: {ES_URL}")
    print(f"  scenarios:     {len(SCENARIOS)}")
    print(f"{'='*60}\n")

    results = []

    # false positive test 
    print(f"{BLUE}{BOLD}[false positive test]{RESET}")
    print(f"  running normal traffic for {NORMAL_TRAFFIC_DURATION} seconds...")

    fp_start = datetime.now(timezone.utc).isoformat()

    fp_env = os.environ.copy()
    fp_env["ATTACK"]   = "normal_only"
    fp_env["INTERVAL"] = "0.3"
    fp_proc = subprocess.Popen(
        ["python3", "generator.py"],
        env=fp_env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    time.sleep(NORMAL_TRAFFIC_DURATION)
    fp_proc.terminate()
    fp_proc.wait()

    time.sleep(10)
    fp_count = count_normal_alerts(fp_start)
    fp_rate = round(fp_count / (NORMAL_TRAFFIC_DURATION / 60), 2)
    print(f"  false positives detected: {fp_count} ({fp_rate}/min)\n")

    # attack scenarios 
    for i, scenario in enumerate(SCENARIOS, 1):
        name       = scenario["name"]
        attack_env = scenario["attack_env"]
        atype      = scenario["attack_type"]
        rule_name  = scenario["rule_name"]
        duration   = scenario["duration"]

        print(f"{BLUE}{BOLD}[{i}/{len(SCENARIOS)}] {name}{RESET}")

        # record start time
        attack_start = datetime.now(timezone.utc)
        attack_start_iso = attack_start.isoformat()
        print(f"  started at:  {attack_start.strftime('%H:%M:%S')}")

        # run attack
        print(f"  running attack for {duration} seconds...")
        run_attack(attack_env, duration)

        # wait for logstash + kibana to process
        print(f"  waiting {WAIT_AFTER_ATTACK}s for siem to process...")
        time.sleep(WAIT_AFTER_ATTACK)

        # measure latency — find first event
        attack_end = datetime.now(timezone.utc)
        total_time = (attack_end - attack_start).seconds
        event_count = count_events(atype, attack_start_iso)

        # check kibana rule status
        rule_status = check_kibana_rule_status(rule_name)
        detected = event_count > 0

        # calculate latency (rough estimate)
        latency = total_time - duration if detected else None

        # store result
        result = {
            "name":        name,
            "detected":    detected,
            "event_count": event_count,
            "rule_status": rule_status,
            "latency_sec": latency,
        }
        results.append(result)

        # print result
        status_icon = f"{GREEN}✓ detected{RESET}" if detected else f"{RED}✗ missed{RESET}"
        print(f"  result:      {status_icon}")
        print(f"  events:      {event_count}")
        print(f"  rule:        {rule_status}")
        if latency:
            print(f"  latency:     ~{latency}s")
        print()

    # final report 
    print(f"\n{BOLD}{'='*60}{RESET}")
    print(f"{BOLD}  test report{RESET}")
    print(f"{BOLD}{'='*60}{RESET}\n")

    detected_count = sum(1 for r in results if r["detected"])
    total          = len(results)
    detection_rate = round(detected_count / total * 100, 1)
    missed         = total - detected_count
    fn_rate        = round(missed / total * 100, 1)

    avg_latency = None
    latencies = [r["latency_sec"] for r in results if r["latency_sec"] is not None]
    if latencies:
        avg_latency = round(sum(latencies) / len(latencies), 1)

    print(f"  {'scenario':<30} {'detected':<12} {'events':<10} {'latency'}")
    print(f"  {'-'*60}")
    for r in results:
        icon    = f"{GREEN}✓{RESET}" if r["detected"] else f"{RED}✗{RESET}"
        latency = f"~{r['latency_sec']}s" if r["latency_sec"] else "—"
        print(f"  {r['name']:<30} {icon}  {'':<9} {r['event_count']:<10} {latency}")

    print(f"\n  {BOLD}summary:{RESET}")
    print(f"  total scenarios:     {total}")
    print(f"  detected:            {GREEN}{detected_count}{RESET}")
    print(f"  missed:              {RED}{missed}{RESET}")
    print(f"  detection rate:      {GREEN if detection_rate >= 80 else RED}{detection_rate}%{RESET}")
    print(f"  false negative rate: {fn_rate}%")
    print(f"  false positive rate: {fp_rate}/min")
    if avg_latency:
        print(f"  avg alert latency:   ~{avg_latency}s")
    print(f"\n  tested at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}\n")

    # save report to file
    report_path = f"test_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    with open(report_path, "w") as f:
        f.write("security monitoring test report\n")
        f.write(f"date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write(f"total scenarios:     {total}\n")
        f.write(f"detected:            {detected_count}\n")
        f.write(f"missed:              {missed}\n")
        f.write(f"detection rate:      {detection_rate}%\n")
        f.write(f"false negative rate: {fn_rate}%\n")
        f.write(f"false positive rate: {fp_rate}/min\n")
        if avg_latency:
            f.write(f"avg alert latency:   ~{avg_latency}s\n")
        f.write("\ndetailed results:\n")
        for r in results:
            f.write(f"  {r['name']}: {'detected' if r['detected'] else 'missed'} "
                    f"({r['event_count']} events)\n")

    print(f"  report saved: {report_path}\n")


if __name__ == "__main__":
    # check elasticsearch is available
    try:
        requests.get(ES_URL, timeout=5)
    except Exception:
        print(f"{RED}error: elasticsearch not available at {ES_URL}{RESET}")
        print("make sure docker compose is running: docker compose up -d")
        sys.exit(1)

    run_tests()