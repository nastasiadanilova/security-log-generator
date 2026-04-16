import requests
import random
import os
import time

FEEDS = {
    "ipsum": "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt",
    "firehol": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
    "blocklist_de": "https://lists.blocklist.de/lists/all.txt",
}

CACHE_FILE = ".threat_intel_cache.txt"
CACHE_TTL  = 3600   # refresh cache every 1 hour (seconds)

def fetch_ipsum(url):
    """parse ipsum.txt — format: ip<tab>score"""
    ips = []
    try:
        resp = requests.get(url, timeout=15)
        for line in resp.text.splitlines():
            line = line.strip()
            if line.startswith("#") or not line:
                continue
            parts = line.split()
            if parts:
                ips.append(parts[0])   # first column is ip
    except Exception as e:
        print(f"  [warn] ipsum feed failed: {e}")
    return ips


def fetch_netset(url):
    """parse firehol .netset — lines are ip or cidr, skip comments"""
    ips = []
    try:
        resp = requests.get(url, timeout=15)
        for line in resp.text.splitlines():
            line = line.strip()
            if line.startswith("#") or not line:
                continue
            if "/" in line:
                continue   # skip cidr ranges, keep only single ips
            ips.append(line)
    except Exception as e:
        print(f"  [warn] firehol feed failed: {e}")
    return ips


def fetch_blocklist_de(url):
    """parse blocklist.de — one ip per line"""
    ips = []
    try:
        resp = requests.get(url, timeout=15)
        for line in resp.text.splitlines():
            line = line.strip()
            if line.startswith("#") or not line:
                continue
            ips.append(line)
    except Exception as e:
        print(f"  [warn] blocklist.de feed failed: {e}")
    return ips


def load_threat_ips(verbose=True):
    """
    load malicious ips from all feeds.
    uses local cache to avoid hitting feeds every run.
    returns list of ip strings.
    """
    # check cache
    if os.path.exists(CACHE_FILE):
        age = time.time() - os.path.getmtime(CACHE_FILE)
        if age < CACHE_TTL:
            with open(CACHE_FILE) as f:
                ips = [line.strip() for line in f if line.strip()]
            if verbose:
                print(f"  [threat intel] loaded {len(ips)} ips from cache")
            return ips

    # fetch from all feeds
    if verbose:
        print("  [threat intel] fetching ip feeds...")

    all_ips = []

    ipsum_ips = fetch_ipsum(FEEDS["ipsum"])
    if verbose:
        print(f"  [threat intel] ipsum:        {len(ipsum_ips)} ips")
    all_ips.extend(ipsum_ips)

    firehol_ips = fetch_netset(FEEDS["firehol"])
    if verbose:
        print(f"  [threat intel] firehol:      {len(firehol_ips)} ips")
    all_ips.extend(firehol_ips)

    blocklist_ips = fetch_blocklist_de(FEEDS["blocklist_de"])
    if verbose:
        print(f"  [threat intel] blocklist.de: {len(blocklist_ips)} ips")
    all_ips.extend(blocklist_ips)

    # deduplicate
    all_ips = list(set(all_ips))

    if verbose:
        print(f"  [threat intel] total unique malicious ips: {len(all_ips)}")

    # save cache
    with open(CACHE_FILE, "w") as f:
        for ip in all_ips:
            f.write(ip + "\n")

    return all_ips

class ThreatIntel:
    """
    singleton class that loads threat ip pool once
    and provides random malicious ips for attack scenarios
    """
    _ips = []
    _loaded = False

    @classmethod
    def load(cls, verbose=True):
        if not cls._loaded:
            cls._ips = load_threat_ips(verbose=verbose)
            cls._loaded = True
        return cls

    @classmethod
    def random_ip(cls):
        """return a random malicious ip from the pool"""
        if cls._ips:
            return random.choice(cls._ips)
        # fallback to generated ip if feeds unavailable
        first = random.choice([45, 91, 185, 194, 212, 77, 103, 139])
        return f"{first}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

    @classmethod
    def count(cls):
        return len(cls._ips)