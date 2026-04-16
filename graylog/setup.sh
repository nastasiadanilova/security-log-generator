#!/bin/bash

# wait for graylog to be fully ready
echo "waiting for graylog..."
until curl -s -u admin:admin http://graylog:9000/api/system/lbstatus | grep -q "ALIVE"; do
  echo "still waiting..."
  sleep 5
done
echo "graylog is ready, setting up..."
sleep 5

# get default index set id
INDEX_SET_ID=$(curl -s -u admin:admin http://graylog:9000/api/system/indices/index_sets \
  -H "X-Requested-By: setup-script" | \
  grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
echo "index set id: $INDEX_SET_ID"

# create gelf udp input
echo "creating gelf udp input..."
curl -s -X POST http://graylog:9000/api/system/inputs \
  -u admin:admin \
  -H "Content-Type: application/json" \
  -H "X-Requested-By: setup-script" \
  -d '{
    "title": "security-logs-gelf",
    "type": "org.graylog2.inputs.gelf.udp.GELFUDPInput",
    "global": true,
    "configuration": {
      "bind_address": "0.0.0.0",
      "port": 12201,
      "recv_buffer_size": 262144,
      "number_worker_threads": 8,
      "override_source": null,
      "decompress_size_limit": 8388608
    }
  }'
echo "" && echo "input created"

# create stream for attack events
echo "creating attacks stream..."
STREAM_RESPONSE=$(curl -s -X POST http://graylog:9000/api/streams \
  -u admin:admin \
  -H "Content-Type: application/json" \
  -H "X-Requested-By: setup-script" \
  -d "{
    \"title\": \"security attacks\",
    \"description\": \"all detected security attack events\",
    \"matching_type\": \"AND\",
    \"remove_matches_from_default_stream\": false,
    \"index_set_id\": \"$INDEX_SET_ID\",
    \"rules\": [
      {
        \"field\": \"traffic_type\",
        \"value\": \"attack\",
        \"type\": 1,
        \"inverted\": false,
        \"description\": \"only attack events\"
      }
    ]
  }")
STREAM_ID=$(echo $STREAM_RESPONSE | grep -o '"stream_id":"[^"]*"' | cut -d'"' -f4)
echo "stream id: $STREAM_ID"

# resume stream
if [ -n "$STREAM_ID" ]; then
  curl -s -X POST http://graylog:9000/api/streams/$STREAM_ID/resume \
    -u admin:admin \
    -H "X-Requested-By: setup-script"
  echo "" && echo "stream resumed"
fi

# helper function to create alert
create_alert() {
  local title="$1"
  local description="$2"
  local query="$3"
  local threshold="$4"
  local window="$5"
  local priority="$6"

  curl -s -X POST http://graylog:9000/api/events/definitions \
    -u admin:admin \
    -H "Content-Type: application/json" \
    -H "X-Requested-By: setup-script" \
    -d "{
      \"title\": \"$title\",
      \"description\": \"$description\",
      \"priority\": $priority,
      \"alert\": true,
      \"config\": {
        \"type\": \"aggregation-v1\",
        \"query\": \"$query\",
        \"query_parameters\": [],
        \"streams\": [],
        \"group_by\": [],
        \"series\": [
          {
            \"id\": \"count-1\",
            \"function\": \"count\",
            \"field\": null
          }
        ],
        \"conditions\": {
          \"expression\": {
            \"expr\": \">\",
            \"left\": {\"expr\": \"number-ref\", \"ref\": \"count-1\"},
            \"right\": {\"expr\": \"number\", \"value\": $threshold}
          }
        },
        \"search_within_ms\": $window,
        \"execute_every_ms\": 60000
      },
      \"field_spec\": {},
      \"key_spec\": [],
      \"notification_settings\": {
        \"grace_period_ms\": 60000,
        \"backlog_size\": 10
      },
      \"notifications\": [],
      \"storage\": []
    }"
}

# create all 15 alert rules
echo "creating alert rules..."

create_alert "ssh brute force detected" \
  "more than 5 ssh brute force attempts in 1 minute" \
  "attack_type:ssh_brute_force" "5.0" "60000" "3"
echo "" && echo "alert 1 created: ssh brute force"

create_alert "ddos attack detected" \
  "more than 50 ddos requests in 1 minute" \
  "attack_type:ddos" "50.0" "60000" "3"
echo "" && echo "alert 2 created: ddos"

create_alert "sql injection detected" \
  "more than 3 sql injection attempts in 1 minute" \
  "attack_type:sql_injection" "3.0" "60000" "3"
echo "" && echo "alert 3 created: sql injection"

create_alert "syn flood detected" \
  "more than 3 syn flood packets in 1 minute" \
  "attack_type:syn_flood" "3.0" "60000" "3"
echo "" && echo "alert 4 created: syn flood"

create_alert "successful ssh break-in detected" \
  "any successful ssh login after brute force" \
  "attack_type:ssh_success" "1.0" "300000" "5"
echo "" && echo "alert 5 created: ssh break-in"

create_alert "xss attack detected" \
  "more than 3 xss attempts in 1 minute" \
  "attack_type:xss" "3.0" "60000" "3"
echo "" && echo "alert 6 created: xss"

create_alert "log4shell exploit detected" \
  "any log4shell exploit attempt" \
  "attack_type:log4shell" "1.0" "300000" "5"
echo "" && echo "alert 7 created: log4shell"

create_alert "reverse shell attempt detected" \
  "any reverse shell attempt" \
  "attack_type:reverse_shell" "1.0" "300000" "5"
echo "" && echo "alert 8 created: reverse shell"

create_alert "credential stuffing detected" \
  "more than 5 credential stuffing attempts in 1 minute" \
  "attack_type:credential_stuffing" "5.0" "60000" "3"
echo "" && echo "alert 9 created: credential stuffing"

create_alert "dns amplification detected" \
  "more than 3 dns amplification events in 1 minute" \
  "attack_type:dns_amplification" "3.0" "60000" "3"
echo "" && echo "alert 10 created: dns amplification"

create_alert "arp spoofing detected" \
  "any arp spoofing activity" \
  "attack_type:arp_spoofing" "2.0" "60000" "4"
echo "" && echo "alert 11 created: arp spoofing"

create_alert "ransomware activity detected" \
  "any ransomware file activity" \
  "attack_type:ransomware" "1.0" "300000" "5"
echo "" && echo "alert 12 created: ransomware"

create_alert "lateral movement detected" \
  "any lateral movement between internal hosts" \
  "attack_type:lateral_movement" "2.0" "300000" "4"
echo "" && echo "alert 13 created: lateral movement"

create_alert "directory traversal detected" \
  "more than 3 directory traversal attempts in 1 minute" \
  "attack_type:directory_traversal" "3.0" "60000" "3"
echo "" && echo "alert 14 created: directory traversal"

create_alert "privilege escalation detected" \
  "more than 2 privilege escalation attempts in 1 minute" \
  "attack_type:privilege_escalation" "2.0" "60000" "4"
echo "" && echo "alert 15 created: privilege escalation"

echo ""
echo "graylog setup completed!"
echo "open http://localhost:9000 — login: admin / admin"