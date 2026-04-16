# генератор логов безопасности

инструмент для симуляции событий безопасности linux и тестирования систем мониторинга.
генерирует реалистичные лог-файлы на основе 15 сценариев атак и отправляет их в две siem-системы: kibana и graylog.
все правила алертинга, дашборды и входные каналы создаются автоматически при запуске.

---

## что делает этот проект

генератор симулирует реальные события безопасности linux и записывает их в лог-файлы в точно таком же формате, как настоящий linux-сервер. filebeat подхватывает эти логи, logstash их парсит и классифицирует, а данные поступают одновременно в две siem-системы: kibana (elk стек) и graylog.

помимо этого есть движок корреляций (correlator.py), который запускается отдельно и находит сложные паттерны атак, которые одиночные правила не видят, а также тест-фреймворк (tester.py) для измерения качества работы системы мониторинга.

---

## стек

| компонент | образ | назначение | порт |
|---|---|---|---|
| log-generator | python:3.12-alpine | генерирует 15 типов логов безопасности | нет |
| filebeat | elastic/filebeat:8.13.0 | собирает лог-файлы и отправляет их | нет |
| logstash | elastic/logstash:8.13.0 | парсит и классифицирует события | 5044 |
| elasticsearch | elastic/elasticsearch:8.13.0 | хранит и индексирует все события | 9200 |
| kibana | elastic/kibana:8.13.0 | дашборды и алерты (siem 1) | 5601 |
| kibana-setup | curlimages/curl | автоматически создаёт 15 правил и дашборды | нет |
| graylog | graylog/graylog:5.1 | второй siem с поиском и алертами | 9000 |
| graylog-setup | curlimages/curl | автоматически создаёт 15 правил и input | нет |
| opensearch | opensearch:2.11.0 | хранилище для graylog | 9201 |
| mongodb | mongo:6.0 | хранение конфигурации graylog | 27017 |

## поток данных

```
log-generator
     |
     v
том logs/ (auth.log, syslog, kern.log, nginx/access.log)
     |
     v
filebeat (читает файлы, отправляет в logstash)
     |
     v
logstash (парсит, классифицирует attack_type и traffic_type)
     |
     +----------> elasticsearch --> kibana
     |
     +----------> graylog (через gelf udp)
```

---

## быстрый старт

### требования

перед запуском убедись что установлено:

- docker desktop (apple silicon, intel или windows)
- минимум 8 гб ram выделено docker: настройки docker desktop > resources > memory > 8gb
- свободные порты: 5601, 9200, 9000, 9201

### запуск

```bash
git clone <url-репозитория>
cd log-generator
docker compose up -d --build
```

подожди 2-3 минуты пока все контейнеры запустятся. проверь статус:

```bash
docker compose ps
```

все контейнеры должны показывать статус "up". затем открывай веб-интерфейсы.

### веб-интерфейсы

| сервис | адрес | логин | пароль |
|---|---|---|---|
| kibana | http://localhost:5601 | не требуется | не требуется |
| elasticsearch api | http://localhost:9200 | не требуется | не требуется |
| graylog | http://localhost:9000 | admin | admin |

в kibana перейди: analytics > dashboards > security monitoring dashboard

в graylog перейди: alerts > event definitions чтобы увидеть 15 правил

### остановка

```bash
# остановить но сохранить все данные
docker compose down

# остановить и удалить все данные (полный сброс)
docker compose down -v
```

---

## сценарии атак

| номер | сценарий | лог-файл | описание |
|---|---|---|---|
| 1 | ssh brute force | auth.log | перебор паролей на ssh порт |
| 2 | port scan | syslog | сканирование портов как nmap |
| 3 | sql injection | nginx/access.log | вредоносные запросы через параметры url |
| 4 | ddos flood | nginx/access.log | флуд запросы с одного ip |
| 5 | syn flood | kern.log | tcp атака на уровне ядра |
| 6 | directory traversal | nginx/access.log | попытки читать системные файлы |
| 7 | privilege escalation | auth.log | попытки получить права root |
| 8 | xss | nginx/access.log | межсайтовый скриптинг через url |
| 9 | log4shell cve-2021-44228 | nginx/access.log | эксплуатация уязвимости log4j |
| 10 | reverse shell | auth.log | попытки установить обратное соединение |
| 11 | credential stuffing | nginx/access.log | автоматизированный вход с утёкшими данными |
| 12 | dns amplification | syslog | усиление трафика через dns |
| 13 | arp spoofing | kern.log | отравление arp-кэша |
| 14 | ransomware activity | syslog | симуляция шифрования файлов |
| 15 | lateral movement | auth.log | перемещение атакующего по внутренней сети |
| 16 | kill chain | все файлы | полная цепочка атаки из 7 этапов с одного ip |

---

## режимы генератора

измени режим в docker-compose.yml в секции environment генератора:

```yaml
environment:
  - ATTACK=mixed
  - INTERVAL=0.3
```

| значение attack | описание |
|---|---|
| ssh-brute | только ssh brute force |
| port-scan | только сканирование портов |
| sql-injection | только sql injection |
| ddos | только ddos флуд |
| syn-flood | только syn flood |
| directory-traversal | только directory traversal |
| privilege-escalation | только privilege escalation |
| xss | только xss атаки |
| log4shell | только log4shell эксплойты |
| reverse-shell | только reverse shell |
| credential-stuffing | только credential stuffing |
| dns-amplification | только dns amplification |
| arp-spoofing | только arp spoofing |
| ransomware | только ransomware |
| lateral-movement | только lateral movement |
| kill-chain | полная цепочка атаки (7 этапов) |
| all | все атаки вперемешку (по умолчанию) |
| mixed | 80% обычный трафик и 20% атаки |
| normal-only | только обычный трафик (для тестирования ложных срабатываний) |

после изменения перезапусти генератор:

```bash
docker compose restart log-generator
```

---

## правила алертинга

правила создаются автоматически при каждом запуске docker compose up через контейнеры kibana-setup и graylog-setup. вручную ничего делать не нужно.

### правила в kibana

перейди: stack management > rules

| правило | порог | окно |
|---|---|---|
| ssh brute force detected | более 5 событий | 1 минута |
| ddos attack detected | более 50 событий | 1 минута |
| sql injection detected | более 3 событий | 1 минута |
| syn flood detected | более 3 событий | 1 минута |
| successful ssh break-in detected | более 1 события | 5 минут |
| xss attack detected | более 3 событий | 1 минута |
| log4shell exploit detected | более 1 события | 5 минут |
| reverse shell attempt detected | более 1 события | 5 минут |
| credential stuffing detected | более 5 событий | 1 минута |
| dns amplification detected | более 3 событий | 1 минута |
| arp spoofing detected | более 2 событий | 1 минута |
| ransomware activity detected | более 1 события | 5 минут |
| lateral movement detected | более 2 событий | 5 минут |
| directory traversal detected | более 3 событий | 1 минута |
| privilege escalation detected | более 2 событий | 1 минута |

### правила в graylog

перейди: alerts > event definitions

те же 15 правил создаются автоматически через graylog api.

---

## движок корреляций

correlator.py находит сложные многоэтапные паттерны атак которые простые правила не замечают.

### как запустить

убедись что docker compose запущен, затем в отдельном терминале:

```bash
source .venv/bin/activate
python3 correlator.py
```

каждые 60 секунд он проверяет elasticsearch и выводит алерты в терминал.

### правила корреляции

| правило | что обнаруживает |
|---|---|
| kill chain pattern | сканирование портов и брутфорс и эскалация в одном окне |
| multi-surface attack | одновременные атаки на веб и системные логи |
| brute force success | попытки брутфорса с последующим успешным входом |
| ransomware activity | события ransomware с lateral movement |
| apt indicators | комбинация log4shell и reverse shell |

---

## тест-фреймворк

tester.py измеряет насколько хорошо система мониторинга обнаруживает атаки.

### как запустить

```bash
source .venv/bin/activate
python3 tester.py
```

тест прогоняет 10 сценариев по очереди. каждый сценарий занимает около 2.5 минут, полный прогон около 25-30 минут. можно запустить в фоне:

```bash
python3 tester.py > test_report.txt 2>&1 &
cat test_report.txt
```

### что измеряется

- detection rate: сколько типов атак обнаружено из общего числа
- false positive rate: сколько алертов срабатывает на обычном трафике в минуту
- false negative rate: сколько атак не обнаружено
- latency: сколько времени от начала атаки до алерта

---

## threat intelligence

генератор использует реальные вредоносные ip-адреса из публичных threat intelligence фидов. при первом запуске скачивает фиды и кэширует локально. при последующих запусках загружает из кэша (действует 1 час).

используемые источники:

- ipsum: github.com/stamparm/ipsum (обновляется ежедневно)
- firehol: github.com/firehol/blocklist-ipsets
- blocklist.de: lists.blocklist.de

общий размер пула: около 120 000 уникальных вредоносных ip-адресов.

---

## запуск генератора вручную без docker

```bash
cd log-generator
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 generator.py
```

или через переменные окружения чтобы пропустить меню:

```bash
ATTACK=ssh_brute INTERVAL=0.5 python3 generator.py
```

---

## структура проекта

```
log-generator/
  generator.py          главный скрипт генератора с 16 режимами атак
  threat_intel.py       загрузчик threat intelligence ip фидов
  correlator.py         движок корреляций с 5 правилами
  tester.py             тест-фреймворк с метриками
  Dockerfile            образ контейнера для генератора
  docker-compose.yml    конфигурация всей инфраструктуры
  requirements.txt      зависимости python
  .dockerignore
  .gitignore
  README.md
  filebeat/
    filebeat.yml        конфигурация сбора логов
  kibana/
    setup.sh            автосоздание 15 правил и 4 дашбордов
  graylog/
    setup.sh            автосоздание 15 правил и gelf input
  logstash/
    Dockerfile          образ logstash с плагином gelf output
    pipeline.conf       правила парсинга и классификации логов
```

---

## полезные команды

```bash
# статус всех контейнеров
docker compose ps

# логи генератора в реальном времени
docker compose logs -f log-generator

# логи парсинга logstash
docker compose logs -f logstash

# логи создания правил kibana
docker compose logs -f kibana-setup

# логи создания правил graylog
docker compose logs -f graylog-setup

# общее количество событий в elasticsearch
curl localhost:9200/security-logs-*/_count

# список всех индексов elasticsearch
curl localhost:9200/_cat/indices?v

# пересобрать и перезапустить всё
docker compose down && docker compose up -d --build

# запустить kill chain атаку
docker compose stop log-generator
# изменить в docker-compose.yml: ATTACK=kill_chain
docker compose up -d log-generator
```

---

## примечания

- логи генерируются в реальном linux-формате как /var/log/auth.log, syslog, kern.log и nginx/access.log
- logstash классифицирует каждое событие полями attack-type и traffic-type
- данные поступают в kibana и graylog одновременно через двойной output logstash
- образы elk нативные arm64 и работают без rosetta на apple silicon от m1 до m4
- graylog использует opensearch как хранилище чтобы не конфликтовать с elasticsearch по портам
- docker compose down -v удаляет все данные, правила создаются заново при следующем запуске
- все контейнеры кроме log-generator работают в часовом поясе utc, поэтому временные метки отличаются от московского времени на 3 часа
