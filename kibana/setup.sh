#!/bin/bash

# wait for kibana to be fully ready
echo "waiting for kibana..."
until curl -s http://kibana:5601/api/status | grep -q '"level":"available"'; do
  echo "still waiting..."
  sleep 5
done
echo "kibana is ready, creating rules..."

# rule 1 — ssh brute force
curl -s -X POST http://kibana:5601/api/alerting/rule \
  -H "Content-Type: application/json" \
  -H "kbn-xsrf: true" \
  -d '{"name":"ssh brute force detected","consumer":"alerts","rule_type_id":".es-query","schedule":{"interval":"1m"},"params":{"index":["security-logs-*"],"timeField":"@timestamp","esQuery":"{\"query\":{\"match\":{\"attack_type\":\"ssh_brute_force\"}}}","size":100,"threshold":[5],"thresholdComparator":">","timeWindowSize":1,"timeWindowUnit":"m","searchType":"esQuery"},"actions":[]}'
echo "" && echo "rule 1 created: ssh brute force"

# rule 2 — ddos
curl -s -X POST http://kibana:5601/api/alerting/rule \
  -H "Content-Type: application/json" \
  -H "kbn-xsrf: true" \
  -d '{"name":"ddos attack detected","consumer":"alerts","rule_type_id":".es-query","schedule":{"interval":"1m"},"params":{"index":["security-logs-*"],"timeField":"@timestamp","esQuery":"{\"query\":{\"match\":{\"attack_type\":\"ddos\"}}}","size":100,"threshold":[50],"thresholdComparator":">","timeWindowSize":1,"timeWindowUnit":"m","searchType":"esQuery"},"actions":[]}'
echo "" && echo "rule 2 created: ddos"

# rule 3 — sql injection
curl -s -X POST http://kibana:5601/api/alerting/rule \
  -H "Content-Type: application/json" \
  -H "kbn-xsrf: true" \
  -d '{"name":"sql injection detected","consumer":"alerts","rule_type_id":".es-query","schedule":{"interval":"1m"},"params":{"index":["security-logs-*"],"timeField":"@timestamp","esQuery":"{\"query\":{\"match\":{\"attack_type\":\"sql_injection\"}}}","size":100,"threshold":[3],"thresholdComparator":">","timeWindowSize":1,"timeWindowUnit":"m","searchType":"esQuery"},"actions":[]}'
echo "" && echo "rule 3 created: sql injection"

# rule 4 — syn flood
curl -s -X POST http://kibana:5601/api/alerting/rule \
  -H "Content-Type: application/json" \
  -H "kbn-xsrf: true" \
  -d '{"name":"syn flood detected","consumer":"alerts","rule_type_id":".es-query","schedule":{"interval":"1m"},"params":{"index":["security-logs-*"],"timeField":"@timestamp","esQuery":"{\"query\":{\"match\":{\"attack_type\":\"syn_flood\"}}}","size":100,"threshold":[3],"thresholdComparator":">","timeWindowSize":1,"timeWindowUnit":"m","searchType":"esQuery"},"actions":[]}'
echo "" && echo "rule 4 created: syn flood"

# rule 5 — ssh success
curl -s -X POST http://kibana:5601/api/alerting/rule \
  -H "Content-Type: application/json" \
  -H "kbn-xsrf: true" \
  -d '{"name":"successful ssh break-in detected","consumer":"alerts","rule_type_id":".es-query","schedule":{"interval":"1m"},"params":{"index":["security-logs-*"],"timeField":"@timestamp","esQuery":"{\"query\":{\"match\":{\"attack_type\":\"ssh_success\"}}}","size":100,"threshold":[1],"thresholdComparator":">","timeWindowSize":5,"timeWindowUnit":"m","searchType":"esQuery"},"actions":[]}'
echo "" && echo "rule 5 created: ssh break-in"

# rule 6 — xss
curl -s -X POST http://kibana:5601/api/alerting/rule \
  -H "Content-Type: application/json" \
  -H "kbn-xsrf: true" \
  -d '{"name":"xss attack detected","consumer":"alerts","rule_type_id":".es-query","schedule":{"interval":"1m"},"params":{"index":["security-logs-*"],"timeField":"@timestamp","esQuery":"{\"query\":{\"match\":{\"attack_type\":\"xss\"}}}","size":100,"threshold":[3],"thresholdComparator":">","timeWindowSize":1,"timeWindowUnit":"m","searchType":"esQuery"},"actions":[]}'
echo "" && echo "rule 6 created: xss"

# rule 7 — log4shell
curl -s -X POST http://kibana:5601/api/alerting/rule \
  -H "Content-Type: application/json" \
  -H "kbn-xsrf: true" \
  -d '{"name":"log4shell exploit attempt detected","consumer":"alerts","rule_type_id":".es-query","schedule":{"interval":"1m"},"params":{"index":["security-logs-*"],"timeField":"@timestamp","esQuery":"{\"query\":{\"match\":{\"attack_type\":\"log4shell\"}}}","size":100,"threshold":[1],"thresholdComparator":">","timeWindowSize":5,"timeWindowUnit":"m","searchType":"esQuery"},"actions":[]}'
echo "" && echo "rule 7 created: log4shell"

# rule 8 — reverse shell
curl -s -X POST http://kibana:5601/api/alerting/rule \
  -H "Content-Type: application/json" \
  -H "kbn-xsrf: true" \
  -d '{"name":"reverse shell attempt detected","consumer":"alerts","rule_type_id":".es-query","schedule":{"interval":"1m"},"params":{"index":["security-logs-*"],"timeField":"@timestamp","esQuery":"{\"query\":{\"match\":{\"attack_type\":\"reverse_shell\"}}}","size":100,"threshold":[1],"thresholdComparator":">","timeWindowSize":5,"timeWindowUnit":"m","searchType":"esQuery"},"actions":[]}'
echo "" && echo "rule 8 created: reverse shell"

# rule 9 — credential stuffing
curl -s -X POST http://kibana:5601/api/alerting/rule \
  -H "Content-Type: application/json" \
  -H "kbn-xsrf: true" \
  -d '{"name":"credential stuffing detected","consumer":"alerts","rule_type_id":".es-query","schedule":{"interval":"1m"},"params":{"index":["security-logs-*"],"timeField":"@timestamp","esQuery":"{\"query\":{\"match\":{\"attack_type\":\"credential_stuffing\"}}}","size":100,"threshold":[5],"thresholdComparator":">","timeWindowSize":1,"timeWindowUnit":"m","searchType":"esQuery"},"actions":[]}'
echo "" && echo "rule 9 created: credential stuffing"

# rule 10 — dns amplification
curl -s -X POST http://kibana:5601/api/alerting/rule \
  -H "Content-Type: application/json" \
  -H "kbn-xsrf: true" \
  -d '{"name":"dns amplification detected","consumer":"alerts","rule_type_id":".es-query","schedule":{"interval":"1m"},"params":{"index":["security-logs-*"],"timeField":"@timestamp","esQuery":"{\"query\":{\"match\":{\"attack_type\":\"dns_amplification\"}}}","size":100,"threshold":[3],"thresholdComparator":">","timeWindowSize":1,"timeWindowUnit":"m","searchType":"esQuery"},"actions":[]}'
echo "" && echo "rule 10 created: dns amplification"

# rule 11 — arp spoofing
curl -s -X POST http://kibana:5601/api/alerting/rule \
  -H "Content-Type: application/json" \
  -H "kbn-xsrf: true" \
  -d '{"name":"arp spoofing detected","consumer":"alerts","rule_type_id":".es-query","schedule":{"interval":"1m"},"params":{"index":["security-logs-*"],"timeField":"@timestamp","esQuery":"{\"query\":{\"match\":{\"attack_type\":\"arp_spoofing\"}}}","size":100,"threshold":[2],"thresholdComparator":">","timeWindowSize":1,"timeWindowUnit":"m","searchType":"esQuery"},"actions":[]}'
echo "" && echo "rule 11 created: arp spoofing"

# rule 12 — ransomware
curl -s -X POST http://kibana:5601/api/alerting/rule \
  -H "Content-Type: application/json" \
  -H "kbn-xsrf: true" \
  -d '{"name":"ransomware activity detected","consumer":"alerts","rule_type_id":".es-query","schedule":{"interval":"1m"},"params":{"index":["security-logs-*"],"timeField":"@timestamp","esQuery":"{\"query\":{\"match\":{\"attack_type\":\"ransomware\"}}}","size":100,"threshold":[1],"thresholdComparator":">","timeWindowSize":5,"timeWindowUnit":"m","searchType":"esQuery"},"actions":[]}'
echo "" && echo "rule 12 created: ransomware"

# rule 13 — lateral movement
curl -s -X POST http://kibana:5601/api/alerting/rule \
  -H "Content-Type: application/json" \
  -H "kbn-xsrf: true" \
  -d '{"name":"lateral movement detected","consumer":"alerts","rule_type_id":".es-query","schedule":{"interval":"1m"},"params":{"index":["security-logs-*"],"timeField":"@timestamp","esQuery":"{\"query\":{\"match\":{\"attack_type\":\"lateral_movement\"}}}","size":100,"threshold":[2],"thresholdComparator":">","timeWindowSize":5,"timeWindowUnit":"m","searchType":"esQuery"},"actions":[]}'
echo "" && echo "rule 13 created: lateral movement"

# rule 14 — directory traversal
curl -s -X POST http://kibana:5601/api/alerting/rule \
  -H "Content-Type: application/json" \
  -H "kbn-xsrf: true" \
  -d '{"name":"directory traversal detected","consumer":"alerts","rule_type_id":".es-query","schedule":{"interval":"1m"},"params":{"index":["security-logs-*"],"timeField":"@timestamp","esQuery":"{\"query\":{\"match\":{\"attack_type\":\"directory_traversal\"}}}","size":100,"threshold":[3],"thresholdComparator":">","timeWindowSize":1,"timeWindowUnit":"m","searchType":"esQuery"},"actions":[]}'
echo "" && echo "rule 14 created: directory traversal"

# rule 15 — privilege escalation
curl -s -X POST http://kibana:5601/api/alerting/rule \
  -H "Content-Type: application/json" \
  -H "kbn-xsrf: true" \
  -d '{"name":"privilege escalation detected","consumer":"alerts","rule_type_id":".es-query","schedule":{"interval":"1m"},"params":{"index":["security-logs-*"],"timeField":"@timestamp","esQuery":"{\"query\":{\"match\":{\"attack_type\":\"privilege_escalation\"}}}","size":100,"threshold":[2],"thresholdComparator":">","timeWindowSize":1,"timeWindowUnit":"m","searchType":"esQuery"},"actions":[]}'
echo "" && echo "rule 15 created: privilege escalation"

echo ""
echo "all 15 rules created successfully!"