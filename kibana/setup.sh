#!/bin/bash

# wait for kibana to be fully ready
echo "waiting for kibana..."
until curl -s http://kibana:5601/api/status | grep -q '"level":"available"'; do
  echo "still waiting..."
  sleep 5
done
echo "kibana is ready, creating rules..."

# rule 1 ssh brute force
curl -s -X POST http://kibana:5601/api/alerting/rule \
  -H "Content-Type: application/json" \
  -H "kbn-xsrf: true" \
  -d '{"name":"ssh brute force detected","consumer":"alerts","rule_type_id":".es-query","schedule":{"interval":"1m"},"params":{"index":["security-logs-*"],"timeField":"@timestamp","esQuery":"{\"query\":{\"match\":{\"attack_type\":\"ssh_brute_force\"}}}","size":100,"threshold":[5],"thresholdComparator":">","timeWindowSize":1,"timeWindowUnit":"m","searchType":"esQuery"},"actions":[]}'
echo "" && echo "rule 1 created: ssh brute force"

# rule 2 ddos
curl -s -X POST http://kibana:5601/api/alerting/rule \
  -H "Content-Type: application/json" \
  -H "kbn-xsrf: true" \
  -d '{"name":"ddos attack detected","consumer":"alerts","rule_type_id":".es-query","schedule":{"interval":"1m"},"params":{"index":["security-logs-*"],"timeField":"@timestamp","esQuery":"{\"query\":{\"match\":{\"attack_type\":\"ddos\"}}}","size":100,"threshold":[50],"thresholdComparator":">","timeWindowSize":1,"timeWindowUnit":"m","searchType":"esQuery"},"actions":[]}'
echo "" && echo "rule 2 created: ddos"

# rule 3 sql injection
curl -s -X POST http://kibana:5601/api/alerting/rule \
  -H "Content-Type: application/json" \
  -H "kbn-xsrf: true" \
  -d '{"name":"sql injection detected","consumer":"alerts","rule_type_id":".es-query","schedule":{"interval":"1m"},"params":{"index":["security-logs-*"],"timeField":"@timestamp","esQuery":"{\"query\":{\"match\":{\"attack_type\":\"sql_injection\"}}}","size":100,"threshold":[3],"thresholdComparator":">","timeWindowSize":1,"timeWindowUnit":"m","searchType":"esQuery"},"actions":[]}'
echo "" && echo "rule 3 created: sql injection"

# rule 4 syn flood
curl -s -X POST http://kibana:5601/api/alerting/rule \
  -H "Content-Type: application/json" \
  -H "kbn-xsrf: true" \
  -d '{"name":"syn flood detected","consumer":"alerts","rule_type_id":".es-query","schedule":{"interval":"1m"},"params":{"index":["security-logs-*"],"timeField":"@timestamp","esQuery":"{\"query\":{\"match\":{\"attack_type\":\"syn_flood\"}}}","size":100,"threshold":[3],"thresholdComparator":">","timeWindowSize":1,"timeWindowUnit":"m","searchType":"esQuery"},"actions":[]}'
echo "" && echo "rule 4 created: syn flood"

# rule 5 ssh success
curl -s -X POST http://kibana:5601/api/alerting/rule \
  -H "Content-Type: application/json" \
  -H "kbn-xsrf: true" \
  -d '{"name":"successful ssh break-in detected","consumer":"alerts","rule_type_id":".es-query","schedule":{"interval":"1m"},"params":{"index":["security-logs-*"],"timeField":"@timestamp","esQuery":"{\"query\":{\"match\":{\"attack_type\":\"ssh_success\"}}}","size":100,"threshold":[1],"thresholdComparator":">","timeWindowSize":5,"timeWindowUnit":"m","searchType":"esQuery"},"actions":[]}'
echo "" && echo "rule 5 created: ssh break-in"

# rule 6 xss
curl -s -X POST http://kibana:5601/api/alerting/rule \
  -H "Content-Type: application/json" \
  -H "kbn-xsrf: true" \
  -d '{"name":"xss attack detected","consumer":"alerts","rule_type_id":".es-query","schedule":{"interval":"1m"},"params":{"index":["security-logs-*"],"timeField":"@timestamp","esQuery":"{\"query\":{\"match\":{\"attack_type\":\"xss\"}}}","size":100,"threshold":[3],"thresholdComparator":">","timeWindowSize":1,"timeWindowUnit":"m","searchType":"esQuery"},"actions":[]}'
echo "" && echo "rule 6 created: xss"

# rule 7 log4shell
curl -s -X POST http://kibana:5601/api/alerting/rule \
  -H "Content-Type: application/json" \
  -H "kbn-xsrf: true" \
  -d '{"name":"log4shell exploit attempt detected","consumer":"alerts","rule_type_id":".es-query","schedule":{"interval":"1m"},"params":{"index":["security-logs-*"],"timeField":"@timestamp","esQuery":"{\"query\":{\"match\":{\"attack_type\":\"log4shell\"}}}","size":100,"threshold":[1],"thresholdComparator":">","timeWindowSize":5,"timeWindowUnit":"m","searchType":"esQuery"},"actions":[]}'
echo "" && echo "rule 7 created: log4shell"

# rule 8 reverse shell
curl -s -X POST http://kibana:5601/api/alerting/rule \
  -H "Content-Type: application/json" \
  -H "kbn-xsrf: true" \
  -d '{"name":"reverse shell attempt detected","consumer":"alerts","rule_type_id":".es-query","schedule":{"interval":"1m"},"params":{"index":["security-logs-*"],"timeField":"@timestamp","esQuery":"{\"query\":{\"match\":{\"attack_type\":\"reverse_shell\"}}}","size":100,"threshold":[1],"thresholdComparator":">","timeWindowSize":5,"timeWindowUnit":"m","searchType":"esQuery"},"actions":[]}'
echo "" && echo "rule 8 created: reverse shell"

# rule 9 credential stuffing
curl -s -X POST http://kibana:5601/api/alerting/rule \
  -H "Content-Type: application/json" \
  -H "kbn-xsrf: true" \
  -d '{"name":"credential stuffing detected","consumer":"alerts","rule_type_id":".es-query","schedule":{"interval":"1m"},"params":{"index":["security-logs-*"],"timeField":"@timestamp","esQuery":"{\"query\":{\"match\":{\"attack_type\":\"credential_stuffing\"}}}","size":100,"threshold":[5],"thresholdComparator":">","timeWindowSize":1,"timeWindowUnit":"m","searchType":"esQuery"},"actions":[]}'
echo "" && echo "rule 9 created: credential stuffing"

# rule 10 dns amplification
curl -s -X POST http://kibana:5601/api/alerting/rule \
  -H "Content-Type: application/json" \
  -H "kbn-xsrf: true" \
  -d '{"name":"dns amplification detected","consumer":"alerts","rule_type_id":".es-query","schedule":{"interval":"1m"},"params":{"index":["security-logs-*"],"timeField":"@timestamp","esQuery":"{\"query\":{\"match\":{\"attack_type\":\"dns_amplification\"}}}","size":100,"threshold":[3],"thresholdComparator":">","timeWindowSize":1,"timeWindowUnit":"m","searchType":"esQuery"},"actions":[]}'
echo "" && echo "rule 10 created: dns amplification"

# rule 11 arp spoofing
curl -s -X POST http://kibana:5601/api/alerting/rule \
  -H "Content-Type: application/json" \
  -H "kbn-xsrf: true" \
  -d '{"name":"arp spoofing detected","consumer":"alerts","rule_type_id":".es-query","schedule":{"interval":"1m"},"params":{"index":["security-logs-*"],"timeField":"@timestamp","esQuery":"{\"query\":{\"match\":{\"attack_type\":\"arp_spoofing\"}}}","size":100,"threshold":[2],"thresholdComparator":">","timeWindowSize":1,"timeWindowUnit":"m","searchType":"esQuery"},"actions":[]}'
echo "" && echo "rule 11 created: arp spoofing"

# rule 12 ransomware
curl -s -X POST http://kibana:5601/api/alerting/rule \
  -H "Content-Type: application/json" \
  -H "kbn-xsrf: true" \
  -d '{"name":"ransomware activity detected","consumer":"alerts","rule_type_id":".es-query","schedule":{"interval":"1m"},"params":{"index":["security-logs-*"],"timeField":"@timestamp","esQuery":"{\"query\":{\"match\":{\"attack_type\":\"ransomware\"}}}","size":100,"threshold":[1],"thresholdComparator":">","timeWindowSize":5,"timeWindowUnit":"m","searchType":"esQuery"},"actions":[]}'
echo "" && echo "rule 12 created: ransomware"

# rule 13 lateral movement
curl -s -X POST http://kibana:5601/api/alerting/rule \
  -H "Content-Type: application/json" \
  -H "kbn-xsrf: true" \
  -d '{"name":"lateral movement detected","consumer":"alerts","rule_type_id":".es-query","schedule":{"interval":"1m"},"params":{"index":["security-logs-*"],"timeField":"@timestamp","esQuery":"{\"query\":{\"match\":{\"attack_type\":\"lateral_movement\"}}}","size":100,"threshold":[2],"thresholdComparator":">","timeWindowSize":5,"timeWindowUnit":"m","searchType":"esQuery"},"actions":[]}'
echo "" && echo "rule 13 created: lateral movement"

# rule 14 directory traversal
curl -s -X POST http://kibana:5601/api/alerting/rule \
  -H "Content-Type: application/json" \
  -H "kbn-xsrf: true" \
  -d '{"name":"directory traversal detected","consumer":"alerts","rule_type_id":".es-query","schedule":{"interval":"1m"},"params":{"index":["security-logs-*"],"timeField":"@timestamp","esQuery":"{\"query\":{\"match\":{\"attack_type\":\"directory_traversal\"}}}","size":100,"threshold":[3],"thresholdComparator":">","timeWindowSize":1,"timeWindowUnit":"m","searchType":"esQuery"},"actions":[]}'
echo "" && echo "rule 14 created: directory traversal"

# rule 15 privilege escalation
curl -s -X POST http://kibana:5601/api/alerting/rule \
  -H "Content-Type: application/json" \
  -H "kbn-xsrf: true" \
  -d '{"name":"privilege escalation detected","consumer":"alerts","rule_type_id":".es-query","schedule":{"interval":"1m"},"params":{"index":["security-logs-*"],"timeField":"@timestamp","esQuery":"{\"query\":{\"match\":{\"attack_type\":\"privilege_escalation\"}}}","size":100,"threshold":[2],"thresholdComparator":">","timeWindowSize":1,"timeWindowUnit":"m","searchType":"esQuery"},"actions":[]}'
echo "" && echo "rule 15 created: privilege escalation"

# ============================================================
# create or get data view
# ============================================================
echo "getting data view id..."
sleep 3

# try to get existing data view
DATAVIEW_ID=$(curl -s http://kibana:5601/api/data_views \
  -H "kbn-xsrf: true" | \
  grep -o '"id":"[^"]*"' | \
  grep -v "kibana-event\|security-solution" | \
  head -1 | cut -d'"' -f4)

# create if not exists
if [ -z "$DATAVIEW_ID" ]; then
  echo "creating data view..."
  DATAVIEW_RESPONSE=$(curl -s -X POST http://kibana:5601/api/data_views/data_view \
    -H "Content-Type: application/json" \
    -H "kbn-xsrf: true" \
    -d '{
      "data_view": {
        "title": "security-logs-*",
        "timeFieldName": "@timestamp",
        "name": "security-logs"
      }
    }')
  DATAVIEW_ID=$(echo $DATAVIEW_RESPONSE | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
fi
echo "data view id: $DATAVIEW_ID"

# ============================================================
# create visualizations and dashboard
# ============================================================
echo "creating kibana dashboard..."

# helper to build references json
build_ref() {
  echo "{\"name\": \"kibanaSavedObjectMeta.searchSourceJSON.index\", \"type\": \"index-pattern\", \"id\": \"$DATAVIEW_ID\"}"
}

# visualization 1 — attacks by type (bar chart)
VIS1=$(curl -s -X POST http://kibana:5601/api/saved_objects/visualization \
  -H "Content-Type: application/json" \
  -H "kbn-xsrf: true" \
  -d "{
    \"attributes\": {
      \"title\": \"attacks by type\",
      \"visState\": \"{\\\"title\\\":\\\"attacks by type\\\",\\\"type\\\":\\\"histogram\\\",\\\"aggs\\\":[{\\\"id\\\":\\\"1\\\",\\\"enabled\\\":true,\\\"type\\\":\\\"count\\\",\\\"schema\\\":\\\"metric\\\",\\\"params\\\":{}},{\\\"id\\\":\\\"2\\\",\\\"enabled\\\":true,\\\"type\\\":\\\"terms\\\",\\\"schema\\\":\\\"segment\\\",\\\"params\\\":{\\\"field\\\":\\\"attack_type.keyword\\\",\\\"size\\\":15,\\\"order\\\":\\\"desc\\\",\\\"orderBy\\\":\\\"1\\\"}}],\\\"params\\\":{\\\"type\\\":\\\"histogram\\\",\\\"addTooltip\\\":true,\\\"addLegend\\\":true,\\\"legendPosition\\\":\\\"right\\\"}}\",
      \"uiStateJSON\": \"{}\",
      \"description\": \"count of security events grouped by attack type\",
      \"version\": 1,
      \"kibanaSavedObjectMeta\": {
        \"searchSourceJSON\": \"{\\\"query\\\":{\\\"query\\\":\\\"\\\",\\\"language\\\":\\\"kuery\\\"},\\\"filter\\\":[],\\\"indexRefName\\\":\\\"kibanaSavedObjectMeta.searchSourceJSON.index\\\"}\"
      }
    },
    \"references\": [$(build_ref)]
  }")
VIS1_ID=$(echo $VIS1 | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
echo "visualization 1 created: $VIS1_ID"

# visualization 2 — attacks over time (line chart)
VIS2=$(curl -s -X POST http://kibana:5601/api/saved_objects/visualization \
  -H "Content-Type: application/json" \
  -H "kbn-xsrf: true" \
  -d "{
    \"attributes\": {
      \"title\": \"attacks over time\",
      \"visState\": \"{\\\"title\\\":\\\"attacks over time\\\",\\\"type\\\":\\\"line\\\",\\\"aggs\\\":[{\\\"id\\\":\\\"1\\\",\\\"enabled\\\":true,\\\"type\\\":\\\"count\\\",\\\"schema\\\":\\\"metric\\\",\\\"params\\\":{}},{\\\"id\\\":\\\"2\\\",\\\"enabled\\\":true,\\\"type\\\":\\\"date_histogram\\\",\\\"schema\\\":\\\"segment\\\",\\\"params\\\":{\\\"field\\\":\\\"@timestamp\\\",\\\"interval\\\":\\\"auto\\\",\\\"min_doc_count\\\":1}},{\\\"id\\\":\\\"3\\\",\\\"enabled\\\":true,\\\"type\\\":\\\"terms\\\",\\\"schema\\\":\\\"group\\\",\\\"params\\\":{\\\"field\\\":\\\"attack_type.keyword\\\",\\\"size\\\":10,\\\"order\\\":\\\"desc\\\",\\\"orderBy\\\":\\\"1\\\"}}],\\\"params\\\":{\\\"type\\\":\\\"line\\\",\\\"addTooltip\\\":true,\\\"addLegend\\\":true,\\\"legendPosition\\\":\\\"right\\\"}}\",
      \"uiStateJSON\": \"{}\",
      \"description\": \"security events over time by attack type\",
      \"version\": 1,
      \"kibanaSavedObjectMeta\": {
        \"searchSourceJSON\": \"{\\\"query\\\":{\\\"query\\\":\\\"\\\",\\\"language\\\":\\\"kuery\\\"},\\\"filter\\\":[],\\\"indexRefName\\\":\\\"kibanaSavedObjectMeta.searchSourceJSON.index\\\"}\"
      }
    },
    \"references\": [$(build_ref)]
  }")
VIS2_ID=$(echo $VIS2 | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
echo "visualization 2 created: $VIS2_ID"

# visualization 3 — top attacker ips (pie chart)
VIS3=$(curl -s -X POST http://kibana:5601/api/saved_objects/visualization \
  -H "Content-Type: application/json" \
  -H "kbn-xsrf: true" \
  -d "{
    \"attributes\": {
      \"title\": \"top attacker ips\",
      \"visState\": \"{\\\"title\\\":\\\"top attacker ips\\\",\\\"type\\\":\\\"pie\\\",\\\"aggs\\\":[{\\\"id\\\":\\\"1\\\",\\\"enabled\\\":true,\\\"type\\\":\\\"count\\\",\\\"schema\\\":\\\"metric\\\",\\\"params\\\":{}},{\\\"id\\\":\\\"2\\\",\\\"enabled\\\":true,\\\"type\\\":\\\"terms\\\",\\\"schema\\\":\\\"segment\\\",\\\"params\\\":{\\\"field\\\":\\\"src_ip.keyword\\\",\\\"size\\\":10,\\\"order\\\":\\\"desc\\\",\\\"orderBy\\\":\\\"1\\\"}}],\\\"params\\\":{\\\"type\\\":\\\"pie\\\",\\\"addTooltip\\\":true,\\\"addLegend\\\":true,\\\"legendPosition\\\":\\\"right\\\",\\\"isDonut\\\":true}}\",
      \"uiStateJSON\": \"{}\",
      \"description\": \"top 10 source ip addresses by event count\",
      \"version\": 1,
      \"kibanaSavedObjectMeta\": {
        \"searchSourceJSON\": \"{\\\"query\\\":{\\\"query\\\":\\\"\\\",\\\"language\\\":\\\"kuery\\\"},\\\"filter\\\":[],\\\"indexRefName\\\":\\\"kibanaSavedObjectMeta.searchSourceJSON.index\\\"}\"
      }
    },
    \"references\": [$(build_ref)]
  }")
VIS3_ID=$(echo $VIS3 | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
echo "visualization 3 created: $VIS3_ID"

# visualization 4 — attack vs normal traffic (pie chart)
VIS4=$(curl -s -X POST http://kibana:5601/api/saved_objects/visualization \
  -H "Content-Type: application/json" \
  -H "kbn-xsrf: true" \
  -d "{
    \"attributes\": {
      \"title\": \"attack vs normal traffic\",
      \"visState\": \"{\\\"title\\\":\\\"attack vs normal traffic\\\",\\\"type\\\":\\\"pie\\\",\\\"aggs\\\":[{\\\"id\\\":\\\"1\\\",\\\"enabled\\\":true,\\\"type\\\":\\\"count\\\",\\\"schema\\\":\\\"metric\\\",\\\"params\\\":{}},{\\\"id\\\":\\\"2\\\",\\\"enabled\\\":true,\\\"type\\\":\\\"terms\\\",\\\"schema\\\":\\\"segment\\\",\\\"params\\\":{\\\"field\\\":\\\"traffic_type.keyword\\\",\\\"size\\\":5,\\\"order\\\":\\\"desc\\\",\\\"orderBy\\\":\\\"1\\\"}}],\\\"params\\\":{\\\"type\\\":\\\"pie\\\",\\\"addTooltip\\\":true,\\\"addLegend\\\":true,\\\"legendPosition\\\":\\\"right\\\",\\\"isDonut\\\":false,\\\"labels\\\":{\\\"show\\\":true,\\\"values\\\":true}}}\",
      \"uiStateJSON\": \"{}\",
      \"description\": \"ratio of attack events to normal traffic\",
      \"version\": 1,
      \"kibanaSavedObjectMeta\": {
        \"searchSourceJSON\": \"{\\\"query\\\":{\\\"query\\\":\\\"\\\",\\\"language\\\":\\\"kuery\\\"},\\\"filter\\\":[],\\\"indexRefName\\\":\\\"kibanaSavedObjectMeta.searchSourceJSON.index\\\"}\"
      }
    },
    \"references\": [$(build_ref)]
  }")
VIS4_ID=$(echo $VIS4 | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
echo "visualization 4 created: $VIS4_ID"

# create main dashboard
echo "creating main dashboard..."
curl -s -X POST http://kibana:5601/api/saved_objects/dashboard \
  -H "Content-Type: application/json" \
  -H "kbn-xsrf: true" \
  -d "{
    \"attributes\": {
      \"title\": \"security monitoring dashboard\",
      \"hits\": 0,
      \"description\": \"main security monitoring dashboard with attack analytics\",
      \"panelsJSON\": \"[{\\\"version\\\":\\\"8.13.0\\\",\\\"type\\\":\\\"visualization\\\",\\\"gridData\\\":{\\\"x\\\":0,\\\"y\\\":0,\\\"w\\\":24,\\\"h\\\":15,\\\"i\\\":\\\"1\\\"},\\\"panelIndex\\\":\\\"1\\\",\\\"embeddableConfig\\\":{},\\\"panelRefName\\\":\\\"panel_1\\\"},{\\\"version\\\":\\\"8.13.0\\\",\\\"type\\\":\\\"visualization\\\",\\\"gridData\\\":{\\\"x\\\":24,\\\"y\\\":0,\\\"w\\\":24,\\\"h\\\":15,\\\"i\\\":\\\"2\\\"},\\\"panelIndex\\\":\\\"2\\\",\\\"embeddableConfig\\\":{},\\\"panelRefName\\\":\\\"panel_2\\\"},{\\\"version\\\":\\\"8.13.0\\\",\\\"type\\\":\\\"visualization\\\",\\\"gridData\\\":{\\\"x\\\":0,\\\"y\\\":15,\\\"w\\\":24,\\\"h\\\":15,\\\"i\\\":\\\"3\\\"},\\\"panelIndex\\\":\\\"3\\\",\\\"embeddableConfig\\\":{},\\\"panelRefName\\\":\\\"panel_3\\\"},{\\\"version\\\":\\\"8.13.0\\\",\\\"type\\\":\\\"visualization\\\",\\\"gridData\\\":{\\\"x\\\":24,\\\"y\\\":15,\\\"w\\\":24,\\\"h\\\":15,\\\"i\\\":\\\"4\\\"},\\\"panelIndex\\\":\\\"4\\\",\\\"embeddableConfig\\\":{},\\\"panelRefName\\\":\\\"panel_4\\\"}]\",
      \"optionsJSON\": \"{\\\"useMargins\\\":true,\\\"syncColors\\\":false,\\\"hidePanelTitles\\\":false}\",
      \"version\": 1,
      \"timeRestore\": false,
      \"kibanaSavedObjectMeta\": {
        \"searchSourceJSON\": \"{\\\"query\\\":{\\\"query\\\":\\\"\\\",\\\"language\\\":\\\"kuery\\\"},\\\"filter\\\":[]}\"
      }
    },
    \"references\": [
      {\"name\": \"panel_1\", \"type\": \"visualization\", \"id\": \"$VIS1_ID\"},
      {\"name\": \"panel_2\", \"type\": \"visualization\", \"id\": \"$VIS2_ID\"},
      {\"name\": \"panel_3\", \"type\": \"visualization\", \"id\": \"$VIS3_ID\"},
      {\"name\": \"panel_4\", \"type\": \"visualization\", \"id\": \"$VIS4_ID\"}
    ]
  }"
echo "" && echo "dashboard created!"

echo ""
echo "all 15 rules and dashboard created successfully!"