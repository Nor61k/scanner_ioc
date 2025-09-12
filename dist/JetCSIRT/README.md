# JetCSIRT Scanner (scanner_ioc)

Инструмент для быстрой триажи: файловая система, память, сеть, реестр, IOC и логи (Sigma/Chainsaw). Формирует детальный HTML‑отчёт и JSON‑результаты.

## Установка

- Python 3.9+ на машине анализа
- Установите зависимости:
```bash
python -m pip install -r requirements.txt
```

Альтернатива: используйте собранный бинарник `JetCSIRT_Scanner.exe` (без Python).

## Быстрый запуск (Windows PowerShell/CMD)

Запуск всех сканеров параллельно и построение отчёта:
```bat
python main.py --config config\scan_manager.yaml --output output
```
или исполняемый файл:
```bat
JetCSIRT_Scanner.exe --config config\scan_manager.yaml --output output
```

- HTML‑отчёт: `output\scan_report.html`
- Логи: `logs\scan.log`

Рекомендуется запуск от имени администратора (для чтения EVTX, системных артефактов и т.п.).

## Ключевые параметры

- `--config` путь к конфигурации (по умолчанию `config/scan_manager.yaml`)
- `--output` директория результатов (по умолчанию `output`)
- `--logs` директория логов (по умолчанию `logs`)
- `--case-id` произвольный идентификатор кейса
- `--encryption-key` ключ шифрования артефактов (опционально)
- `--scanner` запуск одного сканера: `yara_scanner`, `filesystem_scanner`, `memory_scanner`, `network_scanner`, `registry_scanner`, `ioc_scanner`, `system_scanner`, `sigma_scanner`
- `--max-cpu` ограничение потоков/процессов
- `--max-ram` ограничение RAM в МБ

Sigma (доп. флаги):
- `--sigma` включить офлайновый Sigma‑скан
- `--sigma-rules` путь к правилам Sigma (файл или каталог)
- `--sigma-pipeline` pipeline (например `windows`, `winlogbeat`)
- `--sigma-input` входные логи/папки (повторяемый флаг)
- `--sigma-recursive` рекурсивно обходить папки

## Структура конфигураций

Главный файл: `config/scan_manager.yaml`
- Раздел `scanners` — включает/отключает сканеры и указывает их подконфиги:
  - `config/file_scanners/filesystem_scanner.yaml`
  - `config/file_scanners/yara_scanner.yaml`
  - `config/memory_scanners/memory_scanner.yaml`
  - `config/network_scanners/network_scanner.yaml`
  - `config/registry_scanners/registry_scanner.yaml`
  - `config/ioc_scanners/ioc_scanner.yaml`
  - `config/system_scanners/system_scanner.yaml`
  - `config/log_scanners/sigma_scanner.yaml` (Chainsaw/Sigma)

Включение/отключение сканера:
```yaml
scanners:
  yara_scanner:
    enabled: true
    config_file: "config/file_scanners/yara_scanner.yaml"
```

## Где хранить правила / индикаторы

- YARA (файлы):
  - Каталог: `rules/yara` (подкаталоги допустимы)
  - Расширения: `.yar`, `.yara`
  - Конфиг: `config/file_scanners/yara_scanner.yaml`

- Память (YARA для RAM):
  - Каталог: `rules/memory`
  - Конфиг: `config/memory_scanners/memory_scanner.yaml`

- IOC:
  - JSON/CSV: `rules/ioc/indicators.json`, `rules/ioc/indicators.csv`
  - Конфиг: `config/ioc_scanners/ioc_scanner.yaml`

- Реестр (правила):
  - Каталог: `rules/registry/*.yaml` (готовые шаблоны есть в репозитории)
  - Дополнительно: `rules/registry_rules.json` (если используется)
  - Конфиг: `config/registry_scanners/registry_scanner.yaml`

- Sigma (логи):
  - Каталог правил: `rules/sigma` (включены правила SigmaHQ под Windows)
  - Маппинги Chainsaw: `chainsaw/mappings/` (используется `sigma-event-logs-all.yml`)
  - Конфиг: `config/log_scanners/sigma_scanner.yaml`
    - `chainsaw_path`: путь к `chainsaw.exe`
    - `chainsaw_mapping`: путь к каталогу `chainsaw/mappings` (файл будет выбран автоматически)
    - `rules`: путь к правилам (`rules/sigma` по умолчанию)
    - `evtx_export`: `all|critical|off` — при `all/critical` перед запуском выгружаются EVTX в `output/evtx_all`

## Результаты и отчёты

- Основной HTML: `output/scan_report.html`
- Общие JSON: `output/findings_<scanner>.json` для каждого сканера
- Sigma:
  - `output/sigma_findings.json` — сырой отчёт (используется для сводки в HTML)
  - `output/findings_sigma_scanner.json` — унифицированная обёртка
  - `output/chainsaw/chainsaw_results.json` — выгрузка Chainsaw (если использовался)

В HTML по Sigma выводится минимальная сводка:
- “Sigma Scan Passed — OK/FAIL”
- Alerts: High / Medium / Low / Info
- Ссылка на `sigma_findings.json`

## Примеры запуска

- Все сканеры параллельно:
```bat
python main.py --config config\scan_manager.yaml --output output
```

- Один сканер (пример: сеть):
```bat
python main.py --scanner network_scanner --output output
```

- Sigma офлайн (указать входы/правила при необходимости):
```bat
python main.py --sigma --sigma-input "C:\\Windows\\System32\\winevt\\Logs" --sigma-rules rules\sigma --sigma-pipeline windows --output output
```

- Ограничение ресурсов:
```bat
python main.py --max-cpu 4 --max-ram 2048
```

- Бинарник:
```bat
JetCSIRT_Scanner.exe --config config\scan_manager.yaml --output output
```

## Редактирование конфигов по сканерам

- Откройте соответствующий YAML в `config/<группа>/<сканер>.yaml` и измените пути/опции (правила, маски, лимиты).
- Изменения вступают в силу при следующем запуске.

## Troubleshooting

- Запускайте от администратора, если нет доступа к системным файлам/журналам.
- Chainsaw ошибка “Unable to write to specified output file” — убедитесь, что путь `output\chainsaw` доступен на запись (утилита пишет в файл `chainsaw_results.json`).
- Если в HTML у Sigma статус FAIL — откройте `output\sigma_findings.json`, раздел `meta.errors` для деталей.
- Антивирус может блокировать `chainsaw.exe`/правила — добавьте исключение на каталог проекта.
