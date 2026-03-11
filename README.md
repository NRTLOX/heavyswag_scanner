# Heavy Swag Scanner

![banner](https://github.com/zhabii/heavyswag_public/blob/main/images/banner.jpg)

Модульный сканер безопасности для анализа сетевой/веб инфраструктуры

## Содержание 

- Структура
- Архитектура
- Функционал
- Установка
- Запуск
- Демонстрация

## Структура

```bash
.
└── scanner
   ├── __init__.py
   ├── __main__.py
   ├── cli.py   # точка входа CLI  
   ├── models   # модели данных для вывода
   │  ├── __init__.py
   │  └── scan_results.py
   ├── analysis   # ИИ анализ
   │  ├── __init__.py
   │  └── perplexity_analyzer.py
   ├── modules  # подключаемые модули
   │  ├── __init__.py
   │  ├── osint  # пассивная разведка
   │  │  ├── __init__.py
   │  │  ├── dns_lookup.py  
   │  │  ├── whitebox_analyzer.py
   │  │  └── whois_lookup.py
   │  ├── post  # скрипты пост-эксплуатации
   │  │  └── post.sh
   │  ├── scanners  # универсальные сканеры
   │  │  ├── __init__.py
   │  │  ├── banner_grubber.py
   │  │  ├── os_fingerprint.py
   │  │  ├── port_scanner.py
   │  │  └── web_vulnerability_scanner.py
   │  └── services  # сервис-ориентированные сканеры
   │     ├── __init__.py
   │     ├── base_checker.py
   │     ├── ftp_checker.py
   │     ├── http_checker.py
   │     ├── service_manager.py  # менеджер сканеров
   │     └── snmp_checker.py
   ├── orchestrator.py  # точка соединения модулей
   ├── output  # результаты сканирования
   │  ├── __init__.py
   │  └── json_output.py 
   └── utils  # вспомогательные утилиты
      ├── __init__.py
      ├── cve_mixin.py
      └── verbose_mixin.py
```

## Архитектура 

### Схема взаимодействия
```
┌─────────────────────────────────────────────────────────────┐
│                     Orchestrator                            │
│  (координатор всего процесса сканирования)                  │
└──────────────────────────────┬──────────────────────────────┘
                               │
    ┌──────────────────────────┼──────────────────────────┐
    │                          │                          │
    ▼                          ▼                          ▼
┌─────────┐              ┌───────────┐              ┌───────────┐
│ OSINT   │              │ Scanning  │              │ Service   │
│ Module  │              │ Module    │              │ Module    │
└─────────┘              └───────────┘              └───────────┘
    │                          │                          │
    ├─ DNSLookup               ├─ PortScanner             ├─ ServiceManager
    ├─ WhoisLookup             ├─ OSFingerprint           ├─ BaseServiceChecker ←
    └─ WhiteboxAnalyzer        └─ BannerGrubber           │  ├─ FTPChecker
                                                          │  ├─ HTTPChecker
                                                          │  ├─ SNMPChecker
                                                          │  └─ [Custom Checkers]
                                                          │
                                                          ▼
                                               ┌────────────────────┐
                                               │ WebVulnerability   │
                                               │ Scanner            │
                                               └────────────────────┘
                                                          │
                                                          ▼
                                               ┌────────────────────┐
                                               │   AI Analysis      │
                                               │ Perplexity Analyzer│
                                               └────────────────────┘
```

### Координатор сканирования Orchestrator
```python
class Orchestrator()
	def scan_host(self) -> ScanResults:
			# 1. Пассивная разведка (whois, DNS)
			self._run_osint()
	
			# 2. OS Fingerprinting
			self._run_os_fingerprint()
	
			# 3. Сканирование портов
			open_ports = self._run_port_scanning()
			# прочие проверки
```

### Диспетчек сервисов ServiceManager
```python
class ServiceManager(VerboseMixin, CVEMixin):
    def __init__(self, host: str, verbose: bool = True):
        # Обработчики
        self.service_handlers = {
            21: self._check_ftp,
            80: self._check_http,
            #...

    def process_ports(self, open_ports: Dict[str, List[int]]) -> Dict[str, Any]:
        services = {}
        banners = {}

        for protocol, ports in open_ports.items():
            self.verbose_print(f"[*] Обработка {protocol.upper()} портов: {ports}")
            
            for port in ports:
                # нятие баннера
                banner = self._grab_banner(port, protocol)
                if banner:
                    banners[port] = banner

                # Перехват специальных сервисов
                if port in self.service_handlers:
                    service_data = self.service_handlers[port](port, protocol)
                    services[port] = {"protocol": protocol, "service": service_data}
                    self.verbose_print(f"[+] Обработан сервис {protocol.upper()}/{port}")
                else:
                    self.verbose_print(f"[-] {protocol.upper()}/{port}: нет специального обработчика")

        return {"services": services, "banners": banners}
```

### Абстракция BaseServiceChecker

```python
class BaseServiceChecker(ABC, VerboseMixin, CVEMixin):
    # Обязательные для реализации методы
    def get_service_payloads(self) -> List[str]:
        """Вернуть специфичные пэйлоады для сервиса"""
        pass
        
    @abstractmethod 
    def _check_service_specific(self, ports: List[int]) -> Dict[str, Any]:
        """Специфичная проверка сервиса"""
        pass
    
    # Готовые реализации
    def run(self, ports: List[int] = None) -> Dict[str, Any]:
        """Шаблонный метод - общая логика для всех чекеров"""
        # 1. Сбор баннеров (общее для всех)
        result['banners'] = self._grab_banners(ports, payloads)
        
        # 2. Специфичная проверка (реализуется в дочерних классах)
        result['service_info'] = self._check_service_specific(ports)
        
        # 3. Поиск CVE (общее для всех через миксин)
        result['vulnerabilities'] = self._check_vulnerabilities(result['banners'])
        
        return result
```

Позволяет писать собственные обработчики


## Функционал

### OSINT
- DNS анализ
- WHOIS анализ
- Source code анализ

**OS Fingerprinting**
- Определение целевой ОС по Echo Reply TTL

**Сканирование портов**
- TCP-SYN/UDP сканирование
- Настраиваемые диапазоны
- Многопоточность

**Сканирование сервисов**
- FTP 
	- анонимный доступ
	- листинг директорий
- HTTP
	- методы
	- заголовки 
- SNMP
	- community string
	- системная информация
- Баннеры 
	- автоматическое снятие со всех портов
	- поиск в NVD информации о CVE

### Веб сканирование
- Краулинг
- SQL Injection
- Path Traversal
- File Upload
	- Подготовленные reverse shell пэйлоады

### ИИ-анализ
- Интеграция perplexity-ИИ 
### Вывод результата 
- Консольный вывод
- JSON экспорт
- Сводка сканирования

## Установка 

### Требования
- Python 3.8+
- Linux/Unix система (рекомендуется)
- Права root для SYN сканирования

### Обычная установка
```bash
git clone <repo>
cd heavyswag_scanner
rm -rf .venv
python3 -m venv .venv
source .venv/bin/activate 
pip install -r requirements.txt
```


## Использование 

### Запуск отдельных модулей
```bash
python -m scanner.modules.osint.dns_lookup.py
```
![gif](https://github.com/zhabii/heavyswag_public/blob/main/images/module_run.gif)

### Запуск через оркестратор
```bash
python -m scanner.orchestrator | tee ~/scanner_results.txt 
```
![gif](https://github.com/zhabii/heavyswag_public/blob/main/images/run_orc.gif)

### Запуск дополнительных функций
```python
orch = Orchestrator(TARGET, is_verbose=True)
results = orch.scan_host()

# Печатаем сводку
orch.print_summary()

# Perplexity AI анализ
orch.analyze_with_perplexity(api_key="my_api_key")
```




### Демонстрация вывода

```
[*] Начало сканирования demo-airtickets.local...

[=== OSINT РАЗВЕДКА ===]
[*] DNS lookup для demo-airtickets.local...
[*] WHOIS поиск по demo-airtickets.local...
[+] WHOIS lookup завершен

[=== OS FINGERPRINTING ===]

[=== СКАНИРОВАНИЕ ПОРТОВ ===]
[*] demo-airtickets.local:80 TCP open (reason: SYN-ACK)
[*] demo-airtickets.local:888 TCP open (reason: SYN-ACK)
[*] demo-airtickets.local:999 TCP open (reason: SYN-ACK)
[*] demo-airtickets.local:68 UDP open/filtered (reason: no answer)
[*] demo-airtickets.local:161 UDP open/filtered (reason: no answer)
[*] demo-airtickets.local:139 UDP open/filtered (reason: no answer)
[*] demo-airtickets.local:138 UDP open/filtered (reason: no answer)
[*] demo-airtickets.local:162 UDP open/filtered (reason: no answer)
[*] demo-airtickets.local:445 UDP open/filtered (reason: no answer)
[*] demo-airtickets.local:514 UDP open/filtered (reason: no answer)
[*] demo-airtickets.local:520 UDP open/filtered (reason: no answer)
[*] demo-airtickets.local:631 UDP open/filtered (reason: no answer)
[*] demo-airtickets.local:1434 UDP open/filtered (reason: no answer)
[*] demo-airtickets.local:49152 UDP open/filtered (reason: no answer)
[+] Найдено TCP портов: 3
[+] Найдено UDP портов: 11

[=== АНАЛИЗ СЕРВИСОВ ===]
[*] Обработка TCP портов: [80, 888, 999]
[*] TCP/80 пробуем пэйлоад: 'OPTIONS / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n'
[+] demo-airtickets.local:80/TCP-CF -> HTTP/1.1 405 Not Allowed Server: nginx/1.24.0 (Ubuntu) Date: Sun, 16 Nov 2025 08:27:08 GMT Content-Type: text/html Content-Length: 166 Connection: close <html> <head><title>405 Not Allowed</title></head> <body> <center><h1>405 Not Allowed</h1></center> <hr><center>nginx/1.24.0 (Ubuntu)</center> </body> </html>
[+] Баннер TCP/80: HTTP/1.1 405 Not Allowed Server: nginx/1.24.0 (Ubuntu) Date: Sun, 16 Nov 2025 08:27:08 GMT Content-T...
[*] Поиск CVE по ключевому слову: 'HTTP/1.1 405 Not Allowed Server: nginx/1.24.0 (Ubuntu) Date: Sun, 16 Nov 2025 08:27:08 GMT Content-Type: text/html Content-Length: 166 Connection: close <html> <head><title>405 Not Allowed</title></head> <body> <center><h1>405 Not Allowed</h1></center> <hr><center>nginx/1.24.0 (Ubuntu)</center> </body> </html>'
[+] Найдено 0 CVE записей
[*] TCP/80 пробуем пэйлоад: 'GET / HTTP/1.1\r\nHost: {}\r\n\r\n'
[+] demo-airtickets.local:80/TCP-CF -> HTTP/1.1 403 Forbidden Server: nginx/1.24.0 (Ubuntu) Date: Sun, 16 Nov 2025 08:27:13 GMT Content-Type: text/html Content-Length: 162 Connection: keep-alive <html> <head><title>403 Forbidden</title></head> <body> <center><h1>403 Forbidden</h1></center> <hr><center>nginx/1.24.0 (Ubuntu)</center> </body> </html>
[+] HTTP 80: доступные методы ['GET', 'OPTIONS', 'HEAD', 'POST']

==================================================
[?] Обнаружен веб-сервер на порту 80
[?] Хотите запустить углубленное веб-сканирование?
1 = да, 0 = нет: [*] Запуск веб-сканирования: http://demo-airtickets.local:80
[*] Начало веб-сканирования: http://demo-airtickets.local:80
[*] Анализ страницы: http://demo-airtickets.local:80
[*] Тестирование формы: http://demo-airtickets.local:80
[!] Обнаружена SQLi в поле 'to'
[*] Анализ страницы: http://demo-airtickets.local:80/upload.php
[*] Тестирование формы: http://demo-airtickets.local:80/upload.php
[?] Обнаружена форма загрузки файлов. Загрузить реверс-шелл? (y/n): [*] Обнаружена форма загрузки файлов: http://demo-airtickets.local:80/upload.php
[?] Введите ваш IP для реверс-шелла: [?] Введите порт для реверс-шелла: [?] Выберите тип шелла (php/python/bash/nc/perl, по умолчанию php): [+] Реверс-шелл успешно отправлен! Код ответа: 200
[*] Анализ страницы: http://demo-airtickets.local:80/index.php
[*] Тестирование формы: http://demo-airtickets.local:80/index.php
[!] Обнаружена SQLi в поле 'to'
[*] Анализ страницы: http://demo-airtickets.local:80/view.php?file=sample.txt
[!] Обнаружен Path Traversal в параметре 'file'

📁 СТРУКТУРА ДИРЕКТОРИЙ:
🌐 demo-airtickets.local:80/
├── upload.php
├── view.php
└── index.php
[+] Веб-сканирование завершено. Найдено 4 уязвимости(ей)
[+] Веб-сканирование порта 80 завершено
[*] Анализ баннера порта 80: HTTP/1.1 403 Forbidden Server: nginx/1.24.0 (Ubuntu) Date: Sun, 16 Nov 2025 08:27:13 GMT Content-Typ...
[*] Извлечены термины для поиска: ['Ubuntu', 'Ubuntu', 'nginx 1.24.0']
[*] Поиск CVE для: 'Ubuntu'
[*] Поиск CVE по ключевому слову: 'Ubuntu'
[+] Найдено 5 CVE записей
[+] Найдено 5 CVE для 'Ubuntu'
[*] Поиск CVE для: 'Ubuntu'
[*] Поиск CVE по ключевому слову: 'Ubuntu'
[+] Найдено 5 CVE записей
[+] Найдено 5 CVE для 'Ubuntu'
[*] Поиск CVE для: 'nginx 1.24.0'
[*] Поиск CVE по ключевому слову: 'nginx 1.24.0'
[+] Найдено 0 CVE записей
[+] Обработан сервис TCP/80
[+] demo-airtickets.local:888/TCP-SF -> 220 ProFTPD Server (ProFTPD 1.3.3c Server) [::ffff:192.168.31.81]
[+] Баннер TCP/888: 220 ProFTPD Server (ProFTPD 1.3.3c Server) [::ffff:192.168.31.81]...
[*] Поиск CVE по ключевому слову: '220 ProFTPD Server (ProFTPD 1.3.3c Server) [::ffff:192.168.31.81]'
[+] Найдено 0 CVE записей
[-] TCP/888: нет специального обработчика
[+] demo-airtickets.local:999/TCP-SF -> 220 220 (vsFTPd 2.3.4)
[+] Баннер TCP/999: 220 220 (vsFTPd 2.3.4)...
[*] Поиск CVE по ключевому слову: '220 220 (vsFTPd 2.3.4)'
[+] Найдено 0 CVE записей
[-] TCP/999: нет специального обработчика
[*] Обработка UDP портов: [68, 138, 139, 161, 162, 445, 514, 520, 631, 1434, 49152]
[*] UDP/68 пробуем пэйлоад: '\x00'
[-] UDP/68: нет специального обработчика
[*] UDP/138 пробуем пэйлоад: '\x00'
[-] UDP/138: нет специального обработчика
[*] UDP/139 пробуем пэйлоад: '\x00'
[-] UDP/139: нет специального обработчика
[*] UDP/161 пробуем пэйлоад: '\x00'
[*] TCP/161 пробуем пэйлоад: 'public'
[*] TCP/161 пробуем пэйлоад: 'private'
[*] TCP/161 пробуем пэйлоад: 'secret'
[*] TCP/161 пробуем пэйлоад: 'community'
[*] TCP/161 пробуем пэйлоад: 'read'
[+] SNMP 161: community "public" доступен
[+] SNMP 161: community "private" доступен
[-] SNMP 161: community "secret" недоступен
[-] SNMP 161: community "community" недоступен
[-] SNMP 161: community "read" недоступен
[+] Обработан сервис UDP/161
[*] UDP/162 пробуем пэйлоад: '\x00'
[-] UDP/162: нет специального обработчика
[*] UDP/445 пробуем пэйлоад: '\x00'
[-] UDP/445: нет специального обработчика
[*] UDP/514 пробуем пэйлоад: '\x00'
[-] UDP/514: нет специального обработчика
[*] UDP/520 пробуем пэйлоад: '\x00'
[-] UDP/520: нет специального обработчика
[*] UDP/631 пробуем пэйлоад: '\x00'
[-] UDP/631: нет специального обработчика
[*] UDP/1434 пробуем пэйлоад: '\x00'
[-] UDP/1434: нет специального обработчика
[*] UDP/49152 пробуем пэйлоад: '\x00'
[-] UDP/49152: нет специального обработчика
[+] Обработано сервисов: 2
[+] Собрано баннеров: 3

============================================================
СВОДКА СКАНИРОВАНИЯ: demo-airtickets.local
============================================================
ОС: Linux/Unix
Открытые порты: TCP=3, UDP=11
Обнаружено сервисов: 2
Собрано баннеров: 3
============================================================

============================================================
PERPLEXITY AI АНАЛИЗ БЕЗОПАСНОСТИ
============================================================
Пробуем модель: sonar-pro
### 1. Критические уязвимости

**a) Сервисы с известными CVE:**
- **Порт 80 (HTTP, nginx/1.24.0 (Ubuntu)):**
  - В отчёте указаны CVE: CVE-2005-0080, CVE-2006-0176, CVE-2006-0458, CVE-2006-1183, CVE-2006-3378. Все они относятся к уязвимостям, обнаруженным более 15 лет назад, и не связаны с nginx 1.24.0, а характерны для устаревших версий Apache и других компонентов. Это может быть ошибкой сканера или некорректной интерпретацией баннера. Однако, если nginx действительно уязвим, требуется ручная проверка соответствия версий и патчей.
  - **Веб-уязвимости:**  
    - SQL Injection (index.php, поле to)
    - Path Traversal (view.php, параметр file)
    - Reverse Shell Upload (upload.php, успешная загрузка bash-оболочки)
  - **Это критические уязвимости, позволяющие полный компромисс сервера.**
- **Порт 888 (ProFTPD 1.3.3c):**
  - ProFTPD 1.3.3c — устаревшая версия, содержит ряд известных критических уязвимостей, включая возможность обхода аутентификации и удалённого выполнения кода (например, CVE-2010-3867, CVE-2015-3306).
- **Порт 999 (vsFTPd 2.3.4):**
  - vsFTPd 2.3.4 — также устаревшая версия, известна уязвимость backdoor (CVE-2011-2523), позволяющая получить шелл через специальный логин.
- **Порт 161 (SNMP):**
  - Открыты community-строки "public" и "private" — это стандартные значения, часто используемые для атак. SNMP v2c небезопасен, может привести к утечке информации о системе и сети.

**b) Сервисы с устаревшими версиями:**
- **ProFTPD 1.3.3c** и **vsFTPd 2.3.4** — критически устаревшие.
- **nginx 1.24.0** — актуальная версия на момент 2025 года, но наличие уязвимостей зависит от конфигурации и наличия патчей.

**c) Признаки известных уязвимостей:**
- **Успешная загрузка реверс-шелла** — признак полной компрометации.
- **SQL Injection** и **Path Traversal** — позволяют атакующему получить доступ к данным и файлам системы.
- **SNMP с открытыми community** — утечка информации, возможна эскалация.

---

### 2. Сетевая безопасность

**Анализ открытых портов:**
- **TCP:** 80 (HTTP), 888 (FTP), 999 (FTP)
- **UDP:** 68 (DHCP), 138/139/445 (NetBIOS/SMB), 161/162 (SNMP), 514 (Syslog), 520 (RIP), 631 (IPP), 1434 (MS SQL Monitor), 49152 (динамический порт)

**Оценка конфигурации:**
- **FTP-сервисы** (888, 999) открыты и используют устаревшие версии, что критично.
- **SNMP** (161/162) открыт с дефолтными community — высокая вероятность утечки информации.
- **NetBIOS/SMB** (138, 139, 445) — не должны быть открыты на сервере, не предназначенном для файлового обмена, особенно в публичной сети.
- **Syslog (514 UDP)** — может быть использован для DoS-атак.
- **DHCP (68 UDP)** — обычно не должен быть открыт на сервере.
- **MS SQL Monitor (1434 UDP)** — если не используется, должен быть закрыт.

**Риски по протоколам:**
- **FTP** — передача данных в открытом виде, уязвимости в ПО.
- **SNMP v2c** — небезопасен, утечка информации.
- **NetBIOS/SMB** — распространённые цели для атак (EternalBlue, WannaCry).
- **Path Traversal, SQL Injection, Reverse Shell** — прямой путь к компрометации.

---

### 3. Векторы атаки

**Наиболее вероятные:**
- **Веб-уязвимости:** SQL Injection, Path Traversal, Reverse Shell Upload — позволяют получить доступ к данным и выполнить произвольный код.
- **FTP:** Устаревшие версии, возможность обхода аутентификации и получения шелла.
- **SNMP:** Получение информации о системе, сетевых интерфейсах, процессах.
- **SMB/NetBIOS:** Возможность распространения вредоносного ПО, получения доступа к файлам.

**Сервисы, требующие немедленного внимания:**
- **upload.php** (Reverse Shell)
- **FTP (888, 999)**
- **SNMP (161)**
- **SMB/NetBIOS (138, 139, 445)**

**Возможности эскалации привилегий:**
- Через загруженный реверс-шелл.
- Через уязвимости FTP/SMB.
- Через SNMP — получение информации для дальнейших атак.

---

### 4. Практические рекомендации

**Конкретные шаги:**
- **Critical:**
  - Немедленно отключить или ограничить доступ к FTP (888, 999) и обновить до последних версий.
  - Закрыть SNMP или сменить community на уникальные, использовать SNMPv3.
  - Исправить SQL Injection, Path Traversal, Reverse Shell Upload в веб-приложении.
  - Закрыть неиспользуемые UDP-порты (138, 139, 445, 514, 520, 631, 1434, 49152).
- **High:**
  - Провести аудит конфигурации nginx, убедиться в отсутствии уязвимостей.
  - Ограничить доступ к веб-приложению по IP или VPN.
- **Medium:**
  - Внедрить WAF для защиты веб-приложения.
  - Включить логирование и мониторинг подозрительных действий.
- **Low:**
  - Провести регулярное сканирование на уязвимости.
  - Обновлять ОС и ПО.

**Рекомендации по харденингу:**
- Отключить все неиспользуемые сервисы и порты.
- Использовать firewall для ограничения доступа.
- Внедрить двухфакторную аутентификацию для админ-доступа.
- Регулярно обновлять ПО и ОС.
- Использовать безопасные протоколы (SFTP вместо FTP, SNMPv3 вместо v2c).

---

### 5. Общая оценка безопасности

**Оценка: 2/10 (Критически небезопасно)**

**Обоснование:**
- Наличие критических уязвимостей (SQL Injection, Path Traversal, Reverse Shell Upload).
- Устаревшие и уязвимые версии FTP-серверов.
- Открытые SNMP с дефолтными community.
- Открытые SMB/NetBIOS порты.
- Успешная загрузка реверс-шелла — признак полной компрометации.
- Отсутствие базового харденинга и сегментации сервисов.

**Сервер требует немедленного вмешательства и комплексного аудита безопасности.**
============================================================

Детальные результаты:
{'banners': {80: 'HTTP/1.1 405 Not Allowed Server: nginx/1.24.0 (Ubuntu) Date: '
                 'Sun, 16 Nov 2025 08:27:08 GMT Content-Type: text/html '
                 'Content-Length: 166 Connection: close <html> '
                 '<head><title>405 Not Allowed</title></head> <body> '
                 '<center><h1>405 Not Allowed</h1></center> '
                 '<hr><center>nginx/1.24.0 (Ubuntu)</center> </body> </html>',
             888: '220 ProFTPD Server (ProFTPD 1.3.3c Server) '
                  '[::ffff:192.168.31.81]',
             999: '220 220 (vsFTPd 2.3.4)'},
 'host': 'demo-airtickets.local',
 'open_ports': {'tcp': [80, 888, 999],
                'udp': [68,
                        138,
                        139,
                        161,
                        162,
                        445,
                        514,
                        520,
                        631,
                        1434,
                        49152]},
 'os_info': {'method': 'ICMP TTL', 'os': 'Linux/Unix', 'ttl': 64},
 'osint': {'dns': {'target': 'demo-airtickets.local'},
           'whois': {'creation_date': None,
                     'domain_name': None,
                     'expiration_date': None,
                     'name_servers': None,
                     'registrar': None}},
 'services': {80: {'protocol': 'tcp',
                   'service': {'banners': {80: 'HTTP/1.1 403 Forbidden Server: '
                                               'nginx/1.24.0 (Ubuntu) Date: '
                                               'Sun, 16 Nov 2025 08:27:13 GMT '
                                               'Content-Type: text/html '
                                               'Content-Length: 162 '
                                               'Connection: keep-alive <html> '
                                               '<head><title>403 '
                                               'Forbidden</title></head> '
                                               '<body> <center><h1>403 '
                                               'Forbidden</h1></center> '
                                               '<hr><center>nginx/1.24.0 '
                                               '(Ubuntu)</center> </body> '
                                               '</html>'},
                               'ports': [80],
                               'service': 'http',
                               'service_info': {'headers': {80: {'Connection': 'keep-alive',
                                                                 'Content-Type': 'text/html; '
                                                                                 'charset=UTF-8',
                                                                 'Date': 'Sun, '
                                                                         '16 '
                                                                         'Nov '
                                                                         '2025 '
                                                                         '08:27:16 '
                                                                         'GMT',
                                                                 'Server': 'nginx/1.24.0 '
                                                                           '(Ubuntu)',
                                                                 'Transfer-Encoding': 'chunked'}},
                                                'http_methods': ['GET',
                                                                 'OPTIONS',
                                                                 'HEAD',
                                                                 'POST'],
                                                'redirects': [],
                                                'server_info': {80: {'content_length': 'Unknown',
                                                                     'content_type': 'text/html; '
                                                                                     'charset=UTF-8',
                                                                     'powered_by': 'Unknown',
                                                                     'server': 'nginx/1.24.0 '
                                                                               '(Ubuntu)'}},
                                                'status_codes': {80: {'GET': 200,
                                                                      'HEAD': 200,
                                                                      'OPTIONS': 405,
                                                                      'POST': 200}},
                                                'web_vulnerabilities': {80: {'crawled_pages': 4,
                                                                             'directory_structure': {'index.php': {},
                                                                                                     'upload.php': {},
                                                                                                     'view.php': {}},
                                                                             'forms_tested': ['http://demo-airtickets.local:80',
                                                                                              'http://demo-airtickets.local:80/index.php'],
                                                                             'vulnerabilities': [{'field': 'to',
                                                                                                  'payload': "' "
                                                                                                             'OR '
                                                                                                             "'1'='1",
                                                                                                  'type': 'SQL '
                                                                                                          'Injection',
                                                                                                  'url': 'http://demo-airtickets.local:80'},
                                                                                                 {'attacker_ip': '192.168.31.88',
                                                                                                  'attacker_port': '4424',
                                                                                                  'details': 'Успешная '
                                                                                                             'загрузка '
                                                                                                             'реверс-шелла '
                                                                                                             '(bash) '
                                                                                                             'на '
                                                                                                             '192.168.31.88:4424',
                                                                                                  'shell_type': 'bash',
                                                                                                  'type': 'Reverse '
                                                                                                          'Shell '
                                                                                                          'Upload',
                                                                                                  'url': 'http://demo-airtickets.local:80/upload.php'},
                                                                                                 {'field': 'to',
                                                                                                  'payload': "' "
                                                                                                             'OR '
                                                                                                             "'1'='1",
                                                                                                  'type': 'SQL '
                                                                                                          'Injection',
                                                                                                  'url': 'http://demo-airtickets.local:80/index.php'},
                                                                                                 {'parameter': 'file',
                                                                                                  'type': 'Path '
                                                                                                          'Traversal',
                                                                                                  'url': 'http://demo-airtickets.local:80/view.php?file=..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd'}]}}},
                               'vulnerabilities': [{'cve': 'CVE-2005-0080',
                                                    'published': '2005-05-02T04:00:00.000',
                                                    'severity': 'MEDIUM',
                                                    'url': 'https://nvd.nist.gov/vuln/detail/CVE-2005-0080'},
                                                   {'cve': 'CVE-2006-0176',
                                                    'published': '2006-01-11T21:03:00.000',
                                                    'severity': 'HIGH',
                                                    'url': 'https://nvd.nist.gov/vuln/detail/CVE-2006-0176'},
                                                   {'cve': 'CVE-2006-0458',
                                                    'published': '2006-03-06T23:02:00.000',
                                                    'severity': 'MEDIUM',
                                                    'url': 'https://nvd.nist.gov/vuln/detail/CVE-2006-0458'},
                                                   {'cve': 'CVE-2006-1183',
                                                    'published': '2006-03-13T12:18:00.000',
                                                    'severity': 'HIGH',
                                                    'url': 'https://nvd.nist.gov/vuln/detail/CVE-2006-1183'},
                                                   {'cve': 'CVE-2006-3378',
                                                    'published': '2006-07-06T20:05:00.000',
                                                    'severity': 'HIGH',
                                                    'url': 'https://nvd.nist.gov/vuln/detail/CVE-2006-3378'},
                                                   {'cve': 'CVE-2005-0080',
                                                    'published': '2005-05-02T04:00:00.000',
                                                    'severity': 'MEDIUM',
                                                    'url': 'https://nvd.nist.gov/vuln/detail/CVE-2005-0080'},
                                                   {'cve': 'CVE-2006-0176',
                                                    'published': '2006-01-11T21:03:00.000',
                                                    'severity': 'HIGH',
                                                    'url': 'https://nvd.nist.gov/vuln/detail/CVE-2006-0176'},
                                                   {'cve': 'CVE-2006-0458',
                                                    'published': '2006-03-06T23:02:00.000',
                                                    'severity': 'MEDIUM',
                                                    'url': 'https://nvd.nist.gov/vuln/detail/CVE-2006-0458'},
                                                   {'cve': 'CVE-2006-1183',
                                                    'published': '2006-03-13T12:18:00.000',
                                                    'severity': 'HIGH',
                                                    'url': 'https://nvd.nist.gov/vuln/detail/CVE-2006-1183'},
                                                   {'cve': 'CVE-2006-3378',
                                                    'published': '2006-07-06T20:05:00.000',
                                                    'severity': 'HIGH',
                                                    'url': 'https://nvd.nist.gov/vuln/detail/CVE-2006-3378'}]}},
              161: {'protocol': 'udp',
                    'service': {'banners': {},
                                'ports': [161],
                                'service': 'snmp',
                                'service_info': {'available_communities': ['public',
                                                                           'private'],
                                                 'errors': [],
                                                 'network_interfaces': ['lo',
                                                                        'enp0s3'],
                                                 'processes': ['systemd',
                                                               'kthreadd',
                                                               'pool_workqueue_release',
                                                               'kworker/R-rcu_g',
                                                               'kworker/R-rcu_p',
                                                               'kworker/R-slub_',
                                                               'kworker/R-netns',
                                                               'kworker/R-mm_pe',
                                                               'rcu_tasks_kthread',
                                                               'rcu_tasks_rude_kthread',
                                                               'rcu_tasks_trace_kthread',
                                                               'ksoftirqd/0',
                                                               'rcu_preempt',
                                                               'migration/0',
                                                               'idle_inject/0'],
                                                 'system_info': {'contact': '\\"admin@example.com\\',
                                                                 'description': 'Linux '
                                                                                'server '
                                                                                '6.8.0-87-generic '
                                                                                '#88-Ubuntu '
                                                                                'SMP '
                                                                                'PREEMPT_DYNAMIC '
                                                                                'Sat '
                                                                                'Oct '
                                                                                '11 '
                                                                                '09:28:41 '
                                                                                'UTC '
                                                                                '2025 '
                                                                                'x86_64',
                                                                 'location': '\\"Test '
                                                                             'Server\\',
                                                                 'name': '\\"snmp-server\\'}},
                                'vulnerabilities': []}}}}

```
---
## Отказ от ответственности  

**Heavy Swag Scanner** является инструментом для тестирования на проникновение и безопасности, разработанным в образовательных и исследовательских целях.

Использование включает исключительно
- Тестирование собственной инфраструктуры
- Образовательные цели - изучение методов сетевой разведки и тестирования безопасности
- **Профессиональный пентест** при наличии письменного разрешения владельца целевой системы

Пользователь несет **полную ответсвенность** за все действия, совершенные с использованием инструмента. Сканирование может нарушать работу целевых сервисов и быть обнаружено системами обнаружения вторжений


## Roadmap
- [ ] Поддержка сканирования популярных сервисов
	- [x] HTTP
	- [x] FTP
	- [x] SNMP
	- [ ] SSH
	- [ ] SMB
	- [ ] NFT
	- [ ] POP3
	- [ ] IMAP
	- [ ] SNMP
- [x] Интеграция Perplexity 
- [ ] Docker образ
- [ ] Гибкий CLI интерфейс
- [ ] Внутренний HTTP сервер для  post exploitation скриптов
- [ ] Документация программирования собственного ServiceChecker
- [ ] Web-GUI
