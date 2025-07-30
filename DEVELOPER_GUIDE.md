# Руководство разработчика JetCSIRT_Scanner

---

## Оглавление
1. [Общая архитектура](#архитектура)
2. [Структура проекта](#структура)
3. [Описание всех классов и функций](#классы-и-функции)
4. [Добавление нового модуля](#новый-модуль)
5. [Рекомендации по расширению](#рекомендации)
6. [Взаимодействие между компонентами и потоки данных](#взаимодействие-между-компонентами-и-потоки-данных)

---

<a name="архитектура"></a>
## 1. Общая архитектура

JetCSIRT_Scanner — модульная система для автоматизированного сканирования и анализа безопасности Windows-систем. Каждый тип сканирования реализован как отдельный модуль, который легко добавить или отключить через конфигурацию.

---

<a name="структура"></a>
## 2. Структура проекта

```
JetCSIRT_Scanner/
├── __main__.py
├── core/
├── modules/
├── config/
│   ├── scan_manager.yaml
│   ├── file_scanners/
│   │   ├── yara_scanner.yaml
│   │   └── filesystem_scanner.yaml
│   ├── memory_scanners/
│   │   └── memory_scanner.yaml
│   ├── network_scanners/
│   │   └── network_scanner.yaml
│   ├── ioc_scanners/
│   │   └── ioc_scanner.yaml
│   ├── registry_scanners/
│   │   └── registry_scanner.yaml
│   ├── system_scanners/
│   │   └── system_scanner.yaml
│   └── log_scanners/
│       └── sigma_scanner.yaml
├── rules/
```

- **__main__.py** — CLI-точка входа, запуск сканирования.
- **core/** — ядро: базовые классы, менеджеры, сборщик артефактов.
- **modules/** — все сканеры, сгруппированные по направлениям.
- **config/** — главный конфиг-менеджер (scan_manager.yaml) и подпапки с YAML-конфигами для каждого сканера.
- **rules/** — правила для сканеров (YARA, Sigma, IOC, реестр и др.).

---

<a name="классы-и-функции"></a>
## 3. Описание всех классов и функций

### __main__.py
- **main()** — основной цикл запуска, инициализация, запуск сканеров, сбор результатов.
- **parse_args()** — парсинг аргументов командной строки.
- **setup_logging(log_dir)** — настройка логирования.
- **load_config(config_file)** — загрузка основного конфига (обычно JSON).
- **create_scanners(config, artifact_collector)** — создание экземпляров сканеров.

### jetcsirt.py
- Вспомогательные функции для быстрого запуска или тестирования (опционально).

### core/

#### core/scanner_base.py
- **class ScannerBase**
  - Абстрактный базовый класс для всех сканеров.
  - Методы:
    - **__init__(self, config)** — инициализация сканера с конфигом.
    - **scan(self)** — основной метод сканирования (абстрактный).
    - **collect_artifacts(self, findings)** — сбор артефактов (абстрактный).
    - **save_results(self, output_dir)** — сохранение результатов (абстрактный).

#### core/scan_manager.py
- **class ScanManager**
  - Менеджер сканирования.
  - Методы:
    - **__init__(self, config_path)** — загрузка конфига, инициализация сканеров.
    - **_load_config(self, config_path)** — загрузка YAML-конфига.
    - **_initialize_scanners(self)** — создание экземпляров сканеров.
    - **run_all(self)** — запуск всех активных сканеров.
    - **get_results(self)** — сбор всех результатов.

#### core/artifact_collector.py
- **class ArtifactCollector**
  - Сбор и управление артефактами.
  - Методы:
    - **__init__(self, case_id, encryption_key)** — инициализация.
    - **add_artifact(self, artifact)** — добавить артефакт.
    - **create_manifest(self)** — создать манифест артефактов.

#### core/recovery_manager.py
- **class RecoveryManager**
  - Логика восстановления или обработки угроз.
  - Методы:
    - **__init__(self, ...)** — инициализация.
    - **recover(self, ...)** — восстановление изменений.

#### core/scanner.py
- Вспомогательные функции для сканирования.

---

### modules/

#### modules/base_scanner.py
- **class BaseScanner(ScannerBase)**
  - Базовый класс для сканеров, расширяет ScannerBase.

#### modules/file_scanners/filesystem_scanner.py
- **class FileSystemScanner(BaseScanner)**
  - Сканирование файловой системы.
  - Методы:
    - **scan(self)** — логика поиска подозрительных файлов.
    - **collect_artifacts(self, findings)**
    - **save_results(self, output_dir)**

#### modules/file_scanners/yara_scanner.py
- **class YaraScanner(BaseScanner)**
  - Сканирование файлов с помощью YARA-правил.
  - Методы аналогичны.

#### modules/forensic_scanners/forensic_scanner.py
- **class ForensicScanner(BaseScanner)**
  - Сбор форензических артефактов.

#### modules/ioc_scanners/ioc_scanner.py
- **class IOCScanner(BaseScanner)**
  - Сканирование по индикаторам компрометации.

#### modules/log_scanners/sigma_scanner.py
- **class SigmaScanner(BaseScanner)**
  - Анализ логов с помощью Sigma-правил.

#### modules/memory_scanners/memory_scanner.py
- **class MemoryScanner(BaseScanner)**
  - Анализ памяти процессов.

#### modules/memory_scanners/memory_utils.py
- Вспомогательные функции для работы с памятью.

#### modules/memory_scanners/ram_scanner/scanner.py
- **class RamScanner(BaseScanner)**
  - Низкоуровневое сканирование RAM.

#### modules/network_scanners/network_scanner.py
- **class NetworkScanner(BaseScanner)**
  - Анализ сетевой активности.

#### modules/network_scanners/kraken/scanner.py
- **class KrakenScanner(BaseScanner)**
  - Специализированный сетевой сканер.

#### modules/registry_scanner.py
- **class RegistryScanner(BaseScanner)**
  - Универсальный сканер реестра.

#### modules/registry_scanners/registry_change_tracker.py
- **class RegistryChangeTracker(BaseScanner)**
  - Отслеживание изменений в реестре.

#### modules/registry_scanners/registry_scanner.py
- **class RegistryScanner(BaseScanner)**
  - Расширенный сканер реестра.

#### modules/scanner_manager.py
- **class ScannerManager**
  - Менеджер для управления сканерами (альтернативная реализация).

#### modules/system_scanners/system_scanner.py
- **class SystemScanner(BaseScanner)**
  - Сканирование системных параметров.

#### modules/system_scanners/registry_scanner.py
- **class SystemRegistryScanner(BaseScanner)**
  - Сканер реестра для системных задач.

#### modules/system_scanners/hayabusa/scanner.py
- **class HayabusaScanner(BaseScanner)**
  - Интеграция с инструментом Hayabusa для анализа логов.

#### modules/ti_integrations/ti_client.py
- **class TIClient(BaseScanner)**
  - Интеграция с внешними Threat Intelligence платформами.

#### modules/yara_scanner.py
- (дополнительная реализация YARA-сканера)

---

### config/
- scan_manager.yaml — главный конфиг-менеджер.
- file_scanners/yara_scanner.yaml — конфиг для YaraScanner.
- file_scanners/filesystem_scanner.yaml — конфиг для файлового сканера.
- memory_scanners/memory_scanner.yaml — конфиг для MemoryScanner.
- network_scanners/network_scanner.yaml — конфиг для NetworkScanner.
- ioc_scanners/ioc_scanner.yaml — конфиг для IOCScanner.
- registry_scanners/registry_scanner.yaml — конфиг для RegistryScanner.
- system_scanners/system_scanner.yaml — конфиг для SystemScanner.
- log_scanners/sigma_scanner.yaml — конфиг для SigmaScanner.

---

### rules/
- YARA, Sigma, IOC, реестр и др. — все правила для сканеров.

---

<a name="новый-модуль"></a>
## 4. Добавление нового модуля (сканера)

1. Создайте новый модуль в modules/ (например, modules/cloud_scanners/cloud_scanner.py).
2. Наследуйте класс от BaseScanner или ScannerBase.
3. Реализуйте методы scan(), collect_artifacts(), save_results().
4. Добавьте конфиг для сканера в config/.
5. Пропишите сканер в config/scan_manager.yaml.
6. Добавьте класс в scanner_classes в core/scan_manager.py.
7. (Опционально) Добавьте правила в rules/.

---

<a name="рекомендации"></a>
## 5. Рекомендации по расширению

- Используйте базовые классы для единообразия интерфейса.
- Для новых типов правил создавайте отдельные подпапки в rules/.
- Документируйте параметры в YAML-конфигах.
- Следуйте PEP8 и принципам SOLID.

---

Если нужно подробное описание кода любого класса или функции — откройте соответствующий файл и смотрите docstring или комментарии. Все основные классы и методы снабжены описаниями для быстрого понимания их назначения.

---

## 6. Взаимодействие между компонентами и потоки данных

### Общая схема взаимодействия

1. **__main__.py** — Точка входа:
   - Парсит аргументы, настраивает логирование.
   - Загружает основной конфиг (обычно config/scan_manager.yaml или config/scanners.json).
   - Инициализирует **ScanManager** (core/scan_manager.py).

2. **ScanManager**:
   - Загружает список сканеров и их конфиги.
   - Для каждого активного сканера:
     - Импортирует нужный класс из modules/ (например, MemoryScanner, YaraScanner и т.д.).
     - Передает ему его индивидуальный конфиг.
     - Сохраняет экземпляр сканера во внутреннем списке.
   - Управляет запуском всех сканеров (вызывает их scan()).
   - Собирает результаты и возвращает их в main().

3. **Сканеры (modules/...)**:
   - Каждый сканер реализует методы scan(), collect_artifacts(), save_results().
   - В процессе работы могут обращаться к:
     - **ArtifactCollector** (core/artifact_collector.py) — для сохранения артефактов.
     - **rules/** — для загрузки правил (YARA, Sigma, IOC и др.).
     - **config/** — для чтения своих параметров.
   - Некоторые сканеры могут использовать вспомогательные утилиты (например, memory_utils.py).

4. **ArtifactCollector**:
   - Получает артефакты от сканеров.
   - Сохраняет их на диск, формирует манифест.

5. **Формирование отчета**:
   - После завершения всех сканеров ScanManager или main() собирает все результаты.
   - Итоговый отчет сохраняется в JSON.

### Текстовая схема (Mermaid)

```mermaid
graph TD;
    A[__main__.py] --> B(ScanManager)
    B --> C1[MemoryScanner]
    B --> C2[YaraScanner]
    B --> C3[NetworkScanner]
    B --> C4[IOCScanner]
    B --> C5[ForensicScanner]
    B --> C6[SigmaScanner]
    C1 --> D[ArtifactCollector]
    C2 --> D
    C3 --> D
    C4 --> D
    C5 --> D
    C6 --> D
    C1 --> E1[rules/]
    C2 --> E2[rules/]
    C3 --> E3[rules/]
    C4 --> E4[rules/]
    C5 --> E5[rules/]
    C6 --> E6[rules/]
    C1 --> F1[config/]
    C2 --> F2[config/]
    C3 --> F3[config/]
    C4 --> F4[config/]
    C5 --> F5[config/]
    C6 --> F6[config/]
    D --> G[Диск/Манифест]
    B --> H[main()]
    H --> I[Отчет JSON]
```

### Краткие пояснения
- **__main__.py** управляет всем процессом, но не взаимодействует напрямую со сканерами — только через ScanManager.
- **ScanManager** — центральный диспетчер: инициализирует, запускает и собирает результаты со всех сканеров.
- **Сканеры** используют свои конфиги и правила, а также могут сохранять артефакты через ArtifactCollector.
- **ArtifactCollector** — единая точка для сбора и хранения артефактов.
- Все результаты и артефакты в конце собираются и сохраняются в отчет.

### Детальное взаимодействие для каждого сканера (без дублирования)

#### MemoryScanner
**Жизненный цикл:**
- Инициализируется ScanManager с config/memory_scanner.yaml.
- Загружает YARA-правила из rules/memory/.
- scan():
  - Перебирает процессы, делает дампы, применяет YARA.
  - Использует memory_utils.py для работы с памятью.
- collect_artifacts():
  - Сохраняет дампы подозрительных процессов через ArtifactCollector.
- save_results():
  - Сохраняет результаты анализа.
**Взаимодействие:**
- ArtifactCollector — для дампов.
- ScanManager — для возврата findings.
**Особенности:**
- Глубокий анализ памяти, интеграция с YARA.

#### YaraScanner
**Жизненный цикл:**
- Инициализация с config/yara_scanner.yaml.
- Загружает YARA-правила из rules/yara/.
- scan():
  - Сканирует файлы по путям, применяет YARA.
- collect_artifacts():
  - Сохраняет подозрительные файлы.
- save_results():
  - Сохраняет результаты.
**Взаимодействие:**
- ArtifactCollector — для файлов.
- ScanManager — для возврата findings.
**Особенности:**
- Гибкая фильтрация по путям и размерам файлов.

#### NetworkScanner
**Жизненный цикл:**
- Инициализация с config/network_scanner.yaml.
- Использует списки портов/доменов из rules/c2_domains/.
- scan():
  - Анализирует сетевые соединения, DNS, порты.
- collect_artifacts():
  - Может сохранять дампы трафика.
- save_results():
  - Сохраняет результаты.
**Взаимодействие:**
- ArtifactCollector — для сетевых артефактов.
- ScanManager — для возврата findings.
**Особенности:**
- Проверка на подозрительные соединения и DNS.

#### IOCScanner
**Жизненный цикл:**
- Инициализация с config/ioc_scanner.yaml.
- Загружает индикаторы из rules/ioc/.
- scan():
  - Ищет совпадения по IOC в файлах, реестре, процессах.
- collect_artifacts():
  - Сохраняет найденные объекты.
- save_results():
  - Сохраняет результаты.
**Взаимодействие:**
- ArtifactCollector — для IOC-артефактов.
- ScanManager — для возврата findings.
**Особенности:**
- Гибкая поддержка разных типов индикаторов.

#### ForensicScanner
**Жизненный цикл:**
- Инициализация с config/forensic_scanner.yaml.
- Список артефактов и путей из конфига.
- scan():
  - Собирает артефакты (журналы, prefetch, temp-файлы и др.).
- collect_artifacts():
  - Сохраняет их через ArtifactCollector.
- save_results():
  - Сохраняет результаты.
**Взаимодействие:**
- ArtifactCollector — для хранения артефактов.
- ScanManager — для возврата findings.
**Особенности:**
- Сбор широкого спектра форензических данных.

#### SigmaScanner
**Жизненный цикл:**
- Инициализация с config/sigma_scanner.yaml.
- Загружает Sigma-правила из rules/sigma/.
- scan():
  - Анализирует логи Windows по правилам Sigma.
- collect_artifacts():
  - Может сохранять найденные логи.
- save_results():
  - Сохраняет результаты.
**Взаимодействие:**
- ArtifactCollector — для логов.
- ScanManager — для возврата findings.
**Особенности:**
- Гибкая поддержка различных источников логов.

#### RegistryScanner
**Жизненный цикл:**
- Инициализация с config/registry_scanner.yaml.
- Загружает правила из rules/registry/ и registry_rules.json.
- scan():
  - Анализирует ключи и значения реестра.
- collect_artifacts():
  - Сохраняет подозрительные ветки/ключи.
- save_results():
  - Сохраняет результаты.
**Взаимодействие:**
- ArtifactCollector — для экспорта веток реестра.
- ScanManager — для возврата findings.
**Особенности:**
- Глубокий анализ автозапуска, персистентности и безопасности.

#### SystemScanner
**Жизненный цикл:**
- Инициализация с config/system_scanner.yaml.
- Использует параметры из конфига.
- scan():
  - Анализирует службы, процессы, автозапуск и др.
- collect_artifacts():
  - Сохраняет найденные объекты.
- save_results():
  - Сохраняет результаты.
**Взаимодействие:**
- ArtifactCollector — для системных артефактов.
- ScanManager — для возврата findings.
**Особенности:**
- Комплексный анализ системных настроек и процессов.

---

Если нужно добавить схему для конкретного сканера или описать взаимодействие между отдельными модулями — дайте знать! 

### Пример изменения конфига для сканирования других дисков

```yaml
scan_paths:
  - "C:\\"
  - "D:\\"
  - "E:\\"
``` 

### Пример добавления механизма динамического whitelist

```python
import json

with open('user_whitelist.json', 'r', encoding='utf-8') as f:
    whitelist = json.load(f)
# При анализе:
if file_path in whitelist['files']:
    continue  # Пропустить 
```

### Пример изменения конфига для запуска отдельного сканера

```bash
python __main__.py --config config/scan_manager.yaml --scanner memory_scanner
```

### Пример изменения функции parse_args в __main__.py

```python
parser.add_argument(
    "--scanner",
    help="Имя сканера для запуска (например, memory_scanner)"
)
```

### Пример изменения конфига для улучшения управления false positives

```yaml
scan_paths:
  - "C:\\"
  - "D:\\"
  - "E:\\"
```

### Пример добавления механизма динамического whitelist

```python
import json

with open('user_whitelist.json', 'r', encoding='utf-8') as f:
    whitelist = json.load(f)
# При анализе:
if file_path in whitelist['files']:
    continue  # Пропустить
```

### Пример изменения конфига для улучшения гибкости запуска и настройки

```python
if args.scanner:
    # Оставить только выбранный сканер в конфиге
    config['scanners'] = {args.scanner: config['scanners'][args.scanner]}
```

### Пример изменения для параллельного запуска сканеров

```python
import multiprocessing

def run_scanner(scanner):
    return scanner.scan()

# scanners — список экземпляров сканеров
with multiprocessing.Pool(processes=4) as pool:
    results = pool.map(run_scanner, scanners)
``` 