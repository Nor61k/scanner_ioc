# JetCSIRT scanner_ioc

Минимальный набор команд и примеров для актуальной версии с оптимизированным запуском и HTML-отчётом.

## Быстрый старт

- Установка зависимостей:
```bash
python -m pip install -r requirements.txt
```

- Запуск (все сканеры параллельно) и вывод отчёта:
```bash
python __main_optimized__.py --config config/scan_manager.yaml --output output
```

- Отчёт: файл `output/scan_report.html`. Промежуточные JSON автоматически удаляются, каталог `artifacts/` очищается после генерации отчёта.

## Ключевые параметры
- `--config`: путь к конфигурации (`config/scan_manager.yaml`)
- `--output`: каталог вывода (по умолчанию `output`)
- `--logs`: каталог логов (по умолчанию `logs`)
- `--case-id`: идентификатор кейса
- `--encryption-key`: ключ шифрования для артефактов
- `--scanner`: запуск одного сканера
  - значения: `yara_scanner`, `memory_scanner`, `network_scanner`, `registry_scanner`, `ioc_scanner`, `system_scanner`
  - также доступен: `sigma_scanner` (анализ логов по правилам Sigma)
- `--max-cpu`: ограничение потоков/процессов (число)
- `--max-ram`: ограничение RAM в МБ

## Примеры запуска (macOS/Linux)
- Ограничить CPU:
```bash
python __main_optimized__.py --max-cpu 4
```

- Ограничить RAM (МБ):
```bash
python __main_optimized__.py --max-ram 2048
```

- Комбинация параметров:
```bash
python __main_optimized__.py --config config/scan_manager.yaml --output output --logs logs --max-cpu 2 --max-ram 1024
```

- Запуск одного сканера (пример: YARA):
```bash
python __main_optimized__.py --scanner yara_scanner --max-cpu 2
```

- Запуск Sigma сканера (пример):
```bash
python __main_optimized__.py --scanner sigma_scanner --config config/scan_manager.yaml --output output
```

- Запуск в фоне:
```bash
nohup python __main_optimized__.py --max-cpu 2 --max-ram 1024 > logs/scan.log 2>&1 &
```

- Шифрование артефактов и кастомный кейс:
```bash
python __main_optimized__.py --encryption-key mysecretkey --case-id incident_2024_001 --max-cpu 2 --max-ram 1024
```

## Примеры запуска (Windows CMD/PowerShell)
- Базовый запуск:
```bat
python __main_optimized__.py --config config\scan_manager.yaml --output output
```

- С ограничением ресурсов:
```bat
python __main_optimized__.py --max-cpu 2 --max-ram 1024 --logs logs
```

- Один сканер (память):
```bat
python __main_optimized__.py --scanner memory_scanner --max-ram 1024
```

- Один сканер (Sigma):
```bat
python __main_optimized__.py --scanner sigma_scanner --output output
```

- С шифрованием и case-id:
```bat
python __main_optimized__.py --encryption-key mysecretkey --case-id critical_scan
```

## Что в отчёте
- Разделы по каждому сканеру. “Alerts” используется для детектов; у `system_scanner` раздел помечен как “Info” (информационные данные).
- Для YARA алертов — компактная таблица, кликабельные строки раскрывают детали: путь, хеш (MD5), владелец, даты создания/изменения, размер файла.
- Для сетевого сканера — компактная таблица (`Src IP`, `Dst IP`, `Proc`, `Status`, `Risk`), статус кликабелен и раскрывает список соединений/портов.
- Секции артефактов сворачиваются по умолчанию и могут быть раскрыты.

## Примечания
- Ограничения `--max-cpu` и `--max-ram` прокидываются во все сканеры через конфигурации.
- Для YARA предусмотрена автоматическая адаптация правил под версию YARA. При ошибках компиляции выполняется повторная загрузка без адаптации.
- Путь к правилам памяти можно переопределить через ключ `memory_rules_dir` в конфиге сканера памяти.