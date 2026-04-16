# security log generator

a tool for simulating linux security events and testing monitoring systems.
generates realistic log files based on 15 attack scenarios and sends them to two siem systems: kibana and graylog.
all alert rules are created automatically on startup.

---

## what this project does

the generator simulates real linux security events and writes them to log files in the exact same format as a real linux server would produce. filebeat picks up these logs, logstash parses and classifies them, and the data flows into two siem systems simultaneously: kibana (elk stack) and graylog.

on top of that there is a correlation engine (correlator.py) that runs separately and finds complex attack patterns that simple rules cannot detect, and a test framework (tester.py) that measures how well the monitoring system performs.

---

## stack

| component | image | purpose | port |
|---|---|---|---|
| log-generator | python:3.12-alpine | generates 15 types of security logs | none |
| filebeat | elastic/filebeat:8.13.0 | collects log files and ships them | none |
| logstash | elastic/logstash:8.13.0 | parses and classifies events | 5044 |
| elasticsearch | elastic/elasticsearch:8.13.0 | stores and indexes all events | 9200 |
| kibana | elastic/kibana:8.13.0 | dashboards and alerts (siem 1) | 5601 |
| kibana-setup | curlimages/curl | auto-creates 15 rules and dashboards | none |
| graylog | graylog/graylog:5.1 | second siem with search and alerts | 9000 |
| graylog-setup | curlimages/curl | auto-creates 15 rules and inputs | none |
| opensearch | opensearch:2.11.0 | storage backend for graylog | 9201 |
| mongodb | mongo:6.0 | config storage for graylog | 27017 |

## data flow

```
log-generator
     |
     v
logs/ volume (auth.log, syslog, kern.log, nginx/access.log)
     |
     v
filebeat (reads files, ships to logstash)
     |
     v
logstash (parses, classifies attack_type and traffic_type)
     |
     +----------> elasticsearch --> kibana
     |
     +----------> graylog (via gelf udp)
```

---

## quick start

### requirements

before starting make sure you have:

- docker desktop installed (apple silicon, intel, or windows)
- at least 8 gb ram allocated to docker: docker desktop settings > resources > memory > 8gb
- free ports: 5601, 9200, 9000, 9201

### run everything

```bash
git clone <repo-url>
cd log-generator
docker compose up -d --build
```

wait about 2 to 3 minutes for all containers to start. check the status:

```bash
docker compose ps
```

all containers should show status "up". then open the web interfaces.

### web interfaces

| service | url | login | password |
|---|---|---|---|
| kibana | http://localhost:5601 | none required | none required |
| elasticsearch api | http://localhost:9200 | none required | none required |
| graylog | http://localhost:9000 | admin | admin |

in kibana go to: analytics > dashboards > security monitoring dashboard

in graylog go to: alerts > event definitions to see the 15 rules

### stop

```bash
# stop but keep all data
docker compose down

# stop and delete all data (full reset)
docker compose down -v
```

---

## attack scenarios

| number | scenario | log file | description |
|---|---|---|---|
| 1 | ssh brute force | auth.log | password guessing on ssh port |
| 2 | port scan | syslog | port scanning similar to nmap |
| 3 | sql injection | nginx/access.log | malicious queries via url parameters |
| 4 | ddos flood | nginx/access.log | flood requests from a single ip |
| 5 | syn flood | kern.log | tcp level kernel attack |
| 6 | directory traversal | nginx/access.log | attempts to read system files |
| 7 | privilege escalation | auth.log | attempts to get root access |
| 8 | xss | nginx/access.log | cross-site scripting via url |
| 9 | log4shell cve-2021-44228 | nginx/access.log | log4j vulnerability exploitation |
| 10 | reverse shell | auth.log | attempts to establish reverse connection |
| 11 | credential stuffing | nginx/access.log | automated login with leaked credentials |
| 12 | dns amplification | syslog | traffic amplification via dns |
| 13 | arp spoofing | kern.log | arp cache poisoning |
| 14 | ransomware activity | syslog | file encryption simulation |
| 15 | lateral movement | auth.log | attacker hopping between internal hosts |
| 16 | kill chain | all files | full 7-stage attack sequence from one ip |

---

## generator modes

change the mode in docker-compose.yml under the log-generator environment section:

```yaml
environment:
  - ATTACK=mixed
  - INTERVAL=0.3
```

| attack value | description |
|---|---|
| ssh-brute | only ssh brute force |
| port-scan | only port scanning |
| sql-injection | only sql injection |
| ddos | only ddos flood |
| syn-flood | only syn flood |
| directory-traversal | only directory traversal |
| privilege-escalation | only privilege escalation |
| xss | only xss attacks |
| log4shell | only log4shell exploits |
| reverse-shell | only reverse shell attempts |
| credential-stuffing | only credential stuffing |
| dns-amplification | only dns amplification |
| arp-spoofing | only arp spoofing |
| ransomware | only ransomware activity |
| lateral-movement | only lateral movement |
| kill-chain | full attack sequence (7 stages) |
| all | all attacks randomly mixed (default) |
| mixed | 80 percent normal traffic and 20 percent attacks |
| normal-only | only normal traffic (for testing false positives) |

after changing restart the generator:

```bash
docker compose restart log-generator
```

---

## alert rules

rules are created automatically every time you run docker compose up via kibana-setup and graylog-setup containers. you do not need to do anything manually.

### kibana rules

go to: stack management > rules

| rule | threshold | window |
|---|---|---|
| ssh brute force detected | more than 5 events | 1 minute |
| ddos attack detected | more than 50 events | 1 minute |
| sql injection detected | more than 3 events | 1 minute |
| syn flood detected | more than 3 events | 1 minute |
| successful ssh break-in detected | more than 1 event | 5 minutes |
| xss attack detected | more than 3 events | 1 minute |
| log4shell exploit detected | more than 1 event | 5 minutes |
| reverse shell attempt detected | more than 1 event | 5 minutes |
| credential stuffing detected | more than 5 events | 1 minute |
| dns amplification detected | more than 3 events | 1 minute |
| arp spoofing detected | more than 2 events | 1 minute |
| ransomware activity detected | more than 1 event | 5 minutes |
| lateral movement detected | more than 2 events | 5 minutes |
| directory traversal detected | more than 3 events | 1 minute |
| privilege escalation detected | more than 2 events | 1 minute |

### graylog rules

go to: alerts > event definitions

the same 15 rules are created automatically via graylog api.

---

## correlation engine

the correlator finds complex multi-stage attack patterns that simple rules miss.

### how to run

make sure docker compose is running, then in a separate terminal:

```bash
source .venv/bin/activate
python3 correlator.py
```

it checks elasticsearch every 60 seconds and prints alerts to the terminal.

### correlation rules

| rule | what it detects |
|---|---|
| kill chain pattern | port scan and brute force and escalation in same window |
| multi-surface attack | simultaneous attacks on web and system logs |
| brute force success | brute force attempts followed by successful login |
| ransomware activity | ransomware events with lateral movement |
| apt indicators | log4shell plus reverse shell combination |

---

## test framework

tester.py measures how well the monitoring system detects attacks.

### how to run

```bash
source .venv/bin/activate
python3 tester.py
```

the test runs all 10 scenarios one by one. each scenario takes about 2.5 minutes so the full run takes around 25 to 30 minutes. you can run it in the background:

```bash
python3 tester.py > test_report.txt 2>&1 &
cat test_report.txt
```

### what it measures

- detection rate: how many attack types were detected out of total
- false positive rate: how many alerts fire on normal traffic per minute
- false negative rate: how many attacks were not detected
- latency: how long it takes from attack start to alert

---

## threat intelligence

the generator uses real malicious ip addresses from public threat intelligence feeds. on first run it downloads the feeds and caches them locally. on subsequent runs it loads from cache (valid for 1 hour).

sources used:

- ipsum: github.com/stamparm/ipsum (updated daily)
- firehol: github.com/firehol/blocklist-ipsets
- blocklist.de: lists.blocklist.de

total pool size: approximately 120000 unique malicious ip addresses.

---

## running the generator manually without docker

```bash
cd log-generator
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 generator.py
```

or with environment variables to skip the menu:

```bash
ATTACK=ssh_brute INTERVAL=0.5 python3 generator.py
```

---

## project structure

```
log-generator/
  generator.py          main generator script with 16 attack modes
  threat_intel.py       threat intelligence ip feed loader
  correlator.py         correlation engine with 5 rules
  tester.py             test framework with metrics
  Dockerfile            container image for generator
  docker-compose.yml    full stack configuration
  requirements.txt      python dependencies
  .dockerignore
  .gitignore
  README.md
  filebeat/
    filebeat.yml        log collection configuration
  kibana/
    setup.sh            auto-creates 15 rules and 4 dashboards
  graylog/
    setup.sh            auto-creates 15 rules and gelf input
  logstash/
    Dockerfile          logstash image with gelf output plugin
    pipeline.conf       log parsing and classification rules
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

# count total events in elasticsearch
curl localhost:9200/security-logs-*/_count

# list all elasticsearch indices
curl localhost:9200/_cat/indices?v

# rebuild and restart everything
docker compose down && docker compose up -d --build

# run kill chain attack
docker compose stop log-generator
# edit docker-compose.yml: ATTACK=kill_chain
docker compose up -d log-generator
```

---

## notes

- logs are generated in real linux format matching /var/log/auth.log, syslog, kern.log and nginx/access.log
- logstash classifies every event with attack-type and traffic-type fields
- data flows to both kibana and graylog simultaneously via dual logstash output
- elk images are native arm64 and run without rosetta on apple silicon m1 through m4
- graylog uses opensearch as its storage backend to avoid port conflicts with elasticsearch
- running docker compose down -v deletes all data and rules are recreated on next startup
- all containers except log-generator use timezone utc so timestamps may differ from local time by 3 hours in moscow timezone
