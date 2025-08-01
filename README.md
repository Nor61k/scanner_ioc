# scanner_ioc

## Примеры запуска с ограничением ресурсов

Ограничить количество потоков/процессов (CPU):

```
python __main__.py --max-cpu 4
```

Ограничить использование оперативной памяти (RAM, в мегабайтах):

```
python __main__.py --max-ram 2048
```

Комбинированный пример (ограничение и CPU, и RAM):

```
python __main__.py --max-cpu 4 --max-ram 2048
```

Остальные параметры можно комбинировать по необходимости:

```
python __main__.py --config config/scan_manager.yaml --output output --logs logs --max-cpu 2
```

## Дополнительные примеры запуска

### Запуск отдельного сканера

Запустить только YARA сканер:

```
python __main__.py --scanner yara_scanner --max-cpu 2
```

Запустить только сканер памяти:

```
python __main__.py --scanner memory_scanner --max-ram 1024
```

### Запуск с шифрованием артефактов

```
python __main__.py --encryption-key mysecretkey --max-cpu 4
```

### Запуск с пользовательским case ID

```
python __main__.py --case-id incident_2024_001 --max-cpu 2 --max-ram 1024
```

### Запуск с ограниченными ресурсами для больших систем

```
python __main__.py --max-cpu 1 --max-ram 512 --output /path/to/results
```

### Запуск в фоновом режиме (Linux/macOS)

```
nohup python __main__.py --max-cpu 2 --max-ram 1024 > scan.log 2>&1 &
```

### Запуск с мониторингом ресурсов

```
python __main__.py --max-cpu 4 --max-ram 2048 --logs detailed_logs
```

### Примеры для различных конфигураций

Минимальные ресурсы для тестирования:

```
python __main__.py --max-cpu 1 --max-ram 256
```

Оптимальные ресурсы для production:

```
python __main__.py --max-cpu 8 --max-ram 4096
```

Ресурсы для критических систем:

```
python __main__.py --max-cpu 2 --max-ram 1024 --case-id critical_scan
```