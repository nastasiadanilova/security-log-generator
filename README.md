# security log generator

a tool for simulating linux security events and testing monitoring systems.
generates realistic log files based on 15 attack scenarios and sends them to two siem systems — kibana and graylog.
all alert rules are created automatically on startup.

---

## overview

### stack

| component | image | purpose | port |
|---|---|---|---|
| log-generator | python:3.12-alpine | generates security logs | — |
| filebeat | elastic/filebeat:8.13.0 | collects and ships logs | — |
| logstash | elastic/logstash:8.13.0 | parses and enriches logs | 5044 |
| elasticsearch | elastic/elasticsearch:8.13.0 | stores and indexes events | 9200 |
| kibana | elastic/kibana:8.13.0 | dashboards and alerts (siem 1) | 5601 |
| kibana-setup | curlimages/curl | auto-creates 15 alert rules | — |
| graylog | graylog/graylog:5.1 | second siem, search and alerts | 9000 |
| graylog-setup | curlimages/curl | auto-creates 15 alert rules | — |
| opensearch | opensearch:2.11.0 | storage backend for graylog | 9201 |
| mongodb | mongo:6.0 | config storage for graylog | 27017 |

### data flow

```
log-generator → logs/ volume → filebeat → logstash → elasticsearch → kibana
                                                     ↘ graylog (gelf udp)
```

---

## quick start

### requirements

- docker desktop (apple silicon / intel / windows)
- 8 gb ram allocated to docker (settings → resources → memory)
- free ports: 5601, 9200, 9000, 9201, 5044, 12201

### run

```bash
# clone the repository
git clone <repo-url>
cd log-generator

# start the full stack
docker compose up -d --build
```

wait 2-3 minutes for all containers to start:

```bash
docker compose ps
```

check generator output:

```bash
docker compose logs -f log-generator
```

### web interfaces

| service | url | login | password |
|---|---|---|---|
| kibana | http://localhost:5601 | — | — |
| elasticsearch | http://localhost:9200 | — | — |
| graylog | http://localhost:9000 | admin | admin |

### stop

```bash
# stop but keep data
docker compose down

# stop and delete all data (full reset)
docker compose down -v
```

---

## attack scenarios

| # | scenario | log file | description |
|---|---|---|---|
| 1 | ssh brute force | auth.log | password guessing on ssh port |
| 2 | port scan | syslog | port scanning like nmap |
| 3 | sql injection | nginx/access.log | malicious queries via url parameters |
| 4 | ddos / http flood | nginx/access.log | flood requests from a single ip |
| 5 | syn flood | kern.log | tcp-level kernel attack |
| 6 | directory traversal | nginx/access.log | attempts to read system files |
| 7 | privilege escalation | auth.log | attempts to gain root access |
| 8 | xss | nginx/access.log | cross-site scripting via url |
| 9 | log4shell (cve-2021-44228) | nginx/access.log | log4j vulnerability exploitation |
| 10 | reverse shell | auth.log | attempts to establish reverse connection |
| 11 | credential stuffing | nginx/access.log | automated login attempts with leaked credentials |
| 12 | dns amplification | syslog | traffic amplification via dns |
| 13 | arp spoofing | kern.log | arp cache poisoning |
| 14 | ransomware activity | syslog | file encryption activity simulation |
| 15 | lateral movement | auth.log | attacker hopping between internal hosts |

### generator modes

| attack env variable | description |
|---|---|
| `ssh_brute` | only ssh brute force |
| `port_scan` | only port scanning |
| `sql_injection` | only sql injection |
| `ddos` | only ddos flood |
| `syn_flood` | only syn flood |
| `directory_traversal` | only directory traversal |
| `privilege_escalation` | only privilege escalation |
| `xss` | only xss attacks |
| `log4shell` | only log4shell exploits |
| `reverse_shell` | only reverse shell attempts |
| `credential_stuffing` | only credential stuffing |
| `dns_amplification` | only dns amplification |
| `arp_spoofing` | only arp spoofing |
| `ransomware` | only ransomware activity |
| `lateral_movement` | only lateral movement |
| `all` | all attacks randomly mixed (default) |
| `mixed` | 80% normal traffic + 20% attacks |

### changing the mode

edit `docker-compose.yml`:

```yaml
environment:
  - ATTACK=mixed    # choose attack mode
  - INTERVAL=0.3    # seconds between log lines
```

restart the generator:

```bash
docker compose restart log-generator
```

---

## alert rules

rules are created **automatically** on every `docker compose up` via kibana-setup and graylog-setup containers.

### kibana — stack management → rules

| rule | threshold | window |
|---|---|---|
| ssh brute force detected | > 5 events | 1 minute |
| ddos attack detected | > 50 events | 1 minute |
| sql injection detected | > 3 events | 1 minute |
| syn flood detected | > 3 events | 1 minute |
| successful ssh break-in detected | > 1 event | 5 minutes |
| xss attack detected | > 3 events | 1 minute |
| log4shell exploit detected | > 1 event | 5 minutes |
| reverse shell attempt detected | > 1 event | 5 minutes |
| credential stuffing detected | > 5 events | 1 minute |
| dns amplification detected | > 3 events | 1 minute |
| arp spoofing detected | > 2 events | 1 minute |
| ransomware activity detected | > 1 event | 5 minutes |
| lateral movement detected | > 2 events | 5 minutes |
| directory traversal detected | > 3 events | 1 minute |
| privilege escalation detected | > 2 events | 1 minute |

### graylog — alerts → event definitions

the same 15 rules are created automatically via graylog api.

---

## project structure

```
log-generator/
├── generator.py          # main generator script (15 attacks + normal traffic)
├── Dockerfile            # container image for generator
├── docker-compose.yml    # full infrastructure definition
├── requirements.txt      # python dependencies
├── .dockerignore
├── .gitignore
├── README.md
├── filebeat/
│   └── filebeat.yml      # log collection config
├── kibana/
│   └── setup.sh          # auto-creates 15 rules in kibana via api
├── graylog/
│   └── setup.sh          # auto-creates 15 rules in graylog via api
└── logstash/
    ├── Dockerfile        # logstash image with gelf plugin
    └── pipeline.conf     # log parsing and classification rules
```

---

## running the generator manually (without docker)

```bash
cd log-generator
python3 -m venv .venv
source .venv/bin/activate   # on windows: .venv\Scripts\activate
python3 generator.py
```

or via environment variables (no menu):

```bash
ATTACK=ssh_brute INTERVAL=0.5 python3 generator.py
```

---

## useful commands

```bash
# status of all containers
docker compose ps

# generator logs in real time
docker compose logs -f log-generator

# logstash parsing logs
docker compose logs -f logstash

# kibana rule creation logs
docker compose logs -f kibana-setup

# graylog rule creation logs
docker compose logs -f graylog-setup

# count events in elasticsearch
curl localhost:9200/security-logs-*/_count

# list all elasticsearch indices
curl localhost:9200/_cat/indices?v

# rebuild and restart everything
docker compose down && docker compose up -d --build
```

---

## notes

- logs are generated in real linux format (`/var/log/auth.log`, `syslog`, `kern.log`, `nginx/access.log`)
- logstash classifies every event with `attack_type` and `traffic_type` fields
- data flows to both kibana and graylog simultaneously via dual logstash output (elasticsearch + gelf udp)
- `docker compose down -v` deletes all data — rules are recreated on next startup
- graylog uses opensearch as its storage backend to avoid port conflicts with elasticsearch
