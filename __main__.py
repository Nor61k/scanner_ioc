"""
Основной модуль для запуска сканирования
"""

import argparse
import logging
import os
from datetime import datetime
from typing import Dict, Any, List
import json
import multiprocessing
import yaml  # Добавлено для поддержки YAML
import subprocess
import sys
from pathlib import Path

from core.artifact_collector import ArtifactCollector
from modules.file_scanners.yara_scanner import YaraScanner
from modules.memory_scanners.memory_scanner import MemoryScanner
from modules.ioc_scanners.ioc_scanner import IOCScanner
from modules.network_scanners.network_scanner import NetworkScanner
from modules.system_scanners.system_scanner import SystemScanner
# from modules.log_scanners.sigma_scanner import SigmaScanner  # если нужен Sigma
# from modules.registry_scanners.registry_scanner import RegistryScanner  # если нужен Registry
from config.config import (
    LOG_FORMAT,
    LOG_LEVEL,
    OUTPUT_DIR,
    LOGS_DIR
)

def path_to_str(obj):
    if isinstance(obj, dict):
        return {k: path_to_str(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [path_to_str(x) for x in obj]
    elif isinstance(obj, Path):
        return str(obj)
    else:
        return obj

def setup_logging(log_dir: str) -> None:
    """
    Настройка логирования
    
    Args:
        log_dir: Директория для логов
    """
    os.makedirs(log_dir, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = os.path.join(log_dir, f"scan_{timestamp}.log")
    
    logging.basicConfig(
        level=getattr(logging, LOG_LEVEL),
        format=LOG_FORMAT,
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )

def load_config(config_file: str) -> Dict[str, Any]:
    """
    Загрузка конфигурации
    
    Args:
        config_file: Путь к файлу конфигурации
        
    Returns:
        Dict: Конфигурация сканеров
    """
    try:
        with open(config_file, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f)
    except Exception as e:
        logging.error(f"Failed to load config from {config_file}: {str(e)}")
        return {}

def create_scanners(config: Dict[str, Any], artifact_collector: ArtifactCollector, user_whitelist: Dict[str, Any] = {}) -> List[Any]:
    """
    Создание экземпляров сканеров
    
    Args:
        config: Конфигурация сканеров
        artifact_collector: Коллектор артефактов
        user_whitelist: Пользовательский whitelist
        
    Returns:
        List: Список инициализированных сканеров
    """
    scanners = []
    scanners_config = config.get("scanners", {})
    if scanners_config.get("memory_scanner", {}).get("enabled", False):
        scanners.append(MemoryScanner(scanners_config["memory_scanner"], artifact_collector, user_whitelist))
    if scanners_config.get("ioc_scanner", {}).get("enabled", False):
        scanners.append(IOCScanner(scanners_config["ioc_scanner"], artifact_collector, user_whitelist))
    if scanners_config.get("yara_scanner", {}).get("enabled", False):
        scanners.append(YaraScanner(scanners_config["yara_scanner"], artifact_collector, user_whitelist))
    if scanners_config.get("network_scanner", {}).get("enabled", False):
        scanners.append(NetworkScanner(scanners_config["network_scanner"], artifact_collector))
    if scanners_config.get("system_scanner", {}).get("enabled", False):
        scanners.append(SystemScanner(scanners_config["system_scanner"], artifact_collector))
    # if scanners_config.get("sigma_scanner", {}).get("enabled", False):
    #     scanners.append(SigmaScanner(scanners_config["sigma_scanner"], artifact_collector, user_whitelist))
    # if scanners_config.get("registry_scanner", {}).get("enabled", False):
    #     scanners.append(RegistryScanner(scanners_config["registry_scanner"], artifact_collector, user_whitelist))
    # ... добавьте другие сканеры по мере необходимости ...
    print(f"[DEBUG] Scanners to run: {[s.name for s in scanners]}")
    return scanners

def parse_args() -> argparse.Namespace:
    """Парсинг аргументов командной строки"""
    parser = argparse.ArgumentParser(
        description="RuScan - Инструмент для быстрой проверки ИТ-инфраструктуры"
    )
    
    parser.add_argument(
        "--config",
        default="config/scanners.json",
        help="Путь к файлу конфигурации"
    )
    
    parser.add_argument(
        "--output",
        default=str(OUTPUT_DIR),
        help="Директория для результатов"
    )
    
    parser.add_argument(
        "--logs",
        default=str(LOGS_DIR),
        help="Директория для логов"
    )
    
    parser.add_argument(
        "--case-id",
        default=datetime.now().strftime("%Y%m%d_%H%M%S"),
        help="Идентификатор кейса"
    )
    
    parser.add_argument(
        "--encryption-key",
        help="Ключ шифрования для артефактов"
    )
    
    parser.add_argument(
        "--scanner",
        help="Имя сканера для запуска (например, memory_scanner)"
    )
    
    return parser.parse_args()

def run_scanner(args):
    scanner, output_dir = args
    print(f"[INFO] Starting {scanner.name}")
    logging.info(f"Starting {scanner.name}")
    try:
        findings = scanner.scan()
        scanner.collect_artifacts(findings)
        scanner.save_results(output_dir)
        print(f"[INFO] Finished {scanner.name}")
        logging.info(f"Finished {scanner.name}")
    except Exception as e:
        print(f"[ERROR] Error in {scanner.name}: {str(e)}")
        logging.error(f"Error in {scanner.name}: {str(e)}")

def main() -> int:
    """Основная функция"""
    args = parse_args()
    setup_logging(args.logs)
    
    # Загружаем конфигурацию
    config = load_config(args.config)
    if not config:
        logging.error("Failed to load configuration. Exiting.")
        return 1
        
    # Если указан --scanner, запускаем только один сканер (старое поведение)
    if args.scanner:
        if args.scanner in config.get('scanners', {}):
            config['scanners'] = {args.scanner: config['scanners'][args.scanner]}
        else:
            logging.error(f"Scanner {args.scanner} not found in config.")
            return 1
        # ... остальной код одиночного запуска ...
        # (оставляем существующую логику создания и запуска сканеров)
        user_whitelist = {}
        if os.path.exists('user_whitelist.json'):
            try:
                with open('user_whitelist.json', 'r', encoding='utf-8') as f:
                    user_whitelist = json.load(f)
            except Exception as e:
                logging.warning(f"Не удалось загрузить user_whitelist.json: {e}")
        artifact_collector = ArtifactCollector(args.case_id, args.encryption_key)
        scanners = create_scanners(config, artifact_collector, user_whitelist)
        if not scanners:
            logging.error("No scanners enabled. Exiting.")
            return 1
        for scanner in scanners:
            findings = scanner.scan()
            artifacts = scanner.collect_artifacts(findings) if findings else {}
            scanner.save_results(args.output)
            # --- Сохраняем findings и артефакты в отдельный JSON-файл для агрегации ---
            try:
                import json
                json_path = os.path.join(args.output, f'findings_{scanner.name}.json')
                with open(json_path, 'w', encoding='utf-8') as jf:
                    json.dump(path_to_str({"findings": findings, "artifacts": artifacts}), jf, ensure_ascii=False, indent=2)
                print(f"[INFO] Результаты сохранены: {json_path}")
            except Exception as e:
                print(f"[ERROR] Не удалось сохранить findings JSON: {e}")
            # --- Удаляем артефакты после создания отчёта ---
            try:
                import shutil
                artifacts_dir = os.path.join('artifacts', args.case_id)
                if os.path.exists(artifacts_dir):
                    shutil.rmtree(artifacts_dir)
                    print(f"[INFO] Артефакты удалены: {artifacts_dir}")
            except Exception as e:
                print(f"[ERROR] Не удалось удалить артефакты: {e}")
        return 0

    # Если --scanner не указан — запускаем каждый enabled-сканер отдельным процессом
    enabled_scanners = [name for name, sc_cfg in config.get('scanners', {}).items() if sc_cfg.get('enabled', False)]
    if not enabled_scanners:
        logging.error("No scanners enabled. Exiting.")
        return 1
    processes = []
    for scanner_name in enabled_scanners:
        if getattr(sys, 'frozen', False):
            # Если запущено как exe, не добавляем __file__
            cmd = [sys.executable, '--scanner', scanner_name, '--config', args.config, '--output', args.output, '--logs', args.logs, '--case-id', args.case_id]
        else:
        cmd = [sys.executable, __file__, '--scanner', scanner_name, '--config', args.config, '--output', args.output, '--logs', args.logs, '--case-id', args.case_id]
        if args.encryption_key:
            cmd += ['--encryption-key', args.encryption_key]
        p = subprocess.Popen(cmd)
        processes.append(p)
    # Ждём завершения всех подпроцессов
    exit_codes = [p.wait() for p in processes]
    print("[DEBUG] Все подпроцессы завершены, начинаем агрегацию отчёта")
    if any(code != 0 for code in exit_codes):
        logging.error("One or more scanners failed.")
    # --- Агрегация findings из всех сканеров и формирование единого HTML-отчёта ---
    try:
        import glob
        import json
        from collections import Counter
        findings_dict = {}
        json_files = glob.glob(os.path.join(args.output, 'findings_*.json'))
        for jf in json_files:
            scanner_name = os.path.splitext(os.path.basename(jf))[0].replace('findings_', '')
            with open(jf, 'r', encoding='utf-8') as f:
                try:
                    data = json.load(f)
                except Exception as e:
                    print(f"[ERROR] Не удалось прочитать {jf}: {e}")
                    data = {}
                if not isinstance(data, (dict, list)):
                    print(f"[ERROR] Некорректный формат данных в {jf}: {type(data)}")
                    data = {}
                findings_dict[scanner_name] = path_to_str(data)  # теперь data = {findings, artifacts}, все пути - строки

        # --- Формируем HTML-отчёт ---
        def html_escape(text):
            import html
            return html.escape(str(text))

        def make_table(headers, rows):
            ths = ''.join(f'<th>{html_escape(h)}</th>' for h in headers)
            trs = ''
            for row in rows:
                tds = ''.join(f'<td>{html_escape(cell)}</td>' for cell in row)
                trs += f'<tr>{tds}</tr>'
            return f'<table class="table table-bordered table-sm table-hover"><thead><tr>{ths}</tr></thead><tbody>{trs}</tbody></table>'

        # --- Оглавление ---
        toc = [
            '<ul class="nav flex-column">',
            '<li><a href="#summary">Общая сводка</a></li>',
            '<li><a href="#system">Система</a></li>',
            '<li><a href="#yara">YARA-сработки</a></li>',
            '<li><a href="#ioc">IOC</a></li>',
            '<li><a href="#network">Сетевые соединения</a></li>',
            '<li><a href="#artifacts">Артефакты</a></li>',
            '</ul>'
        ]
        toc_html = '\n'.join(toc)

        # --- Общая сводка ---
        summary_rows = []
        total_findings = 0
        scanner_counts = {}
        yara_severity = Counter()
        for scanner, data in findings_dict.items():
            findings = data.get('findings', []) if isinstance(data, dict) else data
            if isinstance(findings, list):
                # --- Исправленный подсчёт для YARA ---
                if scanner == 'yara_scanner' and findings and all(isinstance(x, dict) and 'rule' in x for x in findings):
                    count = len(findings)
                    scanner_counts[scanner] = count
                    total_findings += count
                    for f in findings:
                        sev = f.get('severity', 'unknown')
                        yara_severity[sev] += 1
                else:
                    count = sum(len(x.get('findings', [])) if isinstance(x, dict) else 1 for x in findings)
                    scanner_counts[scanner] = count
                    total_findings += count
                    if scanner == 'yara_scanner':
                        for x in findings:
                            for f in x.get('findings', []) if isinstance(x, dict) else []:
                                sev = f.get('severity', 'unknown')
                                yara_severity[sev] += 1
            else:
                scanner_counts[scanner] = 0
        summary_rows.append(["Всего угроз", total_findings])
        for scanner, count in scanner_counts.items():
            summary_rows.append([scanner, count])
        summary_table = make_table(["Сканер", "Количество угроз"], summary_rows)

        # --- YARA pie/bar data ---
        # Удаляем генерацию данных для диаграмм и сами canvas
        # yara_labels = list(yara_severity.keys())
        # yara_values = [yara_severity[k] for k in yara_labels]

        # --- Информация о системе: только имя компьютера и IP ---
        system_info = findings_dict.get('system_scanner', {})
        sys_findings = system_info.get('findings', []) if isinstance(system_info, dict) else system_info
        computer_name = ''
        ip_address = ''
        for entry in sys_findings:
            if entry.get('type') == 'system_info':
                data = entry.get('data', {})
                computer_name = data.get('hostname', '')
        # Если ip_address не найден в system_info, пробуем взять из network_scanner
        if not ip_address:
            net_data = findings_dict.get('network_scanner', {})
            net_findings = net_data.get('findings', []) if isinstance(net_data, dict) else net_data
            for entry in net_findings:
                if entry.get('type') == 'network_connections':
                    for conn in entry.get('data', []):
                        ip = conn.get('local_ip')
                        if ip and ip != '127.0.0.1' and not ip.startswith('169.254.'):
                            ip_address = ip
                            break
                if ip_address:
                    break
        system_table = ''
        if computer_name or ip_address:
            rows = []
            if computer_name:
                rows.append(["Имя компьютера", computer_name])
            if ip_address:
                rows.append(["IP адрес", ip_address])
            system_table = make_table(["Параметр", "Значение"], rows)

        # --- YARA-сработки ---
        yara_data = findings_dict.get('yara_scanner', {})
        yara_findings = yara_data.get('findings', []) if isinstance(yara_data, dict) else yara_data
        yara_rows = []
        # --- Исправленная обработка для разных структур YARA findings ---
        if yara_findings and isinstance(yara_findings, list):
            # Если это список dict, где каждый dict — это сработка (нет вложенного 'findings')
            if all(isinstance(x, dict) and 'rule' in x for x in yara_findings):
                for f in yara_findings:
                    yara_rows.append([
                        f.get('rule', ''),
                        f.get('severity', ''),
                        f.get('process', f.get('process_name', '')),
                        f.get('address', ''),
                        f.get('size', ''),
                        ', '.join(f.get('tags', [])),
                        str(f.get('meta', ''))
                    ])
            else:
                # Старый вариант: список процессов с вложенными findings
                for entry in yara_findings:
                    proc = entry.get('name', '')
                    for f in entry.get('findings', []) if isinstance(entry, dict) else []:
                        yara_rows.append([
                            f.get('rule', ''),
                            f.get('severity', ''),
                            proc,
                            f.get('address', ''),
                            f.get('size', ''),
                            ', '.join(f.get('tags', [])),
                            str(f.get('meta', ''))
                        ])
        yara_table = make_table(["Правило", "Severity", "Процесс", "Адрес", "Размер", "Теги", "Meta"], yara_rows)

        # --- IOC ---
        ioc_data = findings_dict.get('ioc_scanner', {})
        ioc_findings = ioc_data.get('findings', []) if isinstance(ioc_data, dict) else ioc_data
        ioc_rows = []
        for entry in ioc_findings:
            for f in entry.get('findings', []) if isinstance(entry, dict) else []:
                ioc_rows.append([
                    f.get('indicator', ''),
                    f.get('type', ''),
                    f.get('location', ''),
                    f.get('description', '')
                ])
        ioc_table = make_table(["Индикатор", "Тип", "Где найдено", "Описание"], ioc_rows)

        # --- Сетевые соединения ---
        net_data = findings_dict.get('network_scanner', {})
        net_findings = net_data.get('findings', []) if isinstance(net_data, dict) else net_data
        net_rows = []
        for entry in net_findings:
            for f in entry.get('data', []) if isinstance(entry, dict) else []:
                net_rows.append([
                    f.get('process_name', ''),
                    f.get('local_ip', ''),
                    f.get('remote_ip', ''),
                    f.get('local_port', ''),
                    f.get('status', ''),
                    f.get('description', '')
                ])
        net_table = make_table(["Процесс", "Локальный адрес", "Удалённый адрес", "Порт", "Статус", "Описание"], net_rows)

        # --- Артефакты ---
        art_rows = []
        for scanner, data in findings_dict.items():
            artifacts = data.get('artifacts', {}) if isinstance(data, dict) else {}
            for art_name, art_path in artifacts.items():
                art_rows.append([
                    scanner,
                    str(art_path),
                    art_name
                ])
        art_table = make_table(["Сканер", "Путь", "Категория/Имя"], art_rows)

        # --- Рекомендации (заглушка) ---
        recommendations = "<ul><li>Проверьте найденные угрозы вручную.</li><li>Изолируйте подозрительные процессы и файлы.</li><li>Обновите антивирусные базы.</li></ul>"

        # --- HTML шаблон ---
        html_report = f'''
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <title>JetCSIRT Отчёт</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.3.0/dist/chart.umd.min.js"></script>
    <style>
        body {{ padding: 2rem; }}
        .toc {{ position: fixed; left: 0; top: 0; width: 250px; background: #f8f9fa; height: 100%; padding: 2rem 1rem; overflow-y: auto; }}
        .content {{ margin-left: 270px; }}
        h2 {{ margin-top: 2rem; }}
    </style>
</head>
<body>
    <div class="toc">
        <h4>Оглавление</h4>
        {toc_html}
    </div>
    <div class="content">
        <h1>JetCSIRT Отчёт</h1>
        <h2 id="summary">Общая сводка</h2>
        {summary_table}
        <h2 id="system">Система</h2>
        {system_table}
        <h2 id="yara">YARA-сработки</h2>
        <h3>Результаты</h3>
        {yara_table}
        <h2 id="ioc">IOC</h2>
        <h3>Результаты</h3>
        {ioc_table}
        <h2 id="network">Сетевые соединения</h2>
        <h3>Результаты</h3>
        {net_table}
        <h2 id="artifacts">Артефакты</h2>
        <h3>Результаты</h3>
        {art_table}
    </div>
    <script>
        // Удаляем скрипты для диаграмм
    </script>
</body>
</html>
'''
        html_path = os.path.join(args.output, 'scan_report.html')
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(html_report)
        print(f"[INFO] Единый HTML-отчёт сохранён: {html_path}")
        # --- Удаляем артефакты после создания отчёта ---
        import shutil
        artifacts_dir = os.path.join('artifacts', args.case_id)
        if os.path.exists(artifacts_dir):
            shutil.rmtree(artifacts_dir)
            print(f"[INFO] Артефакты удалены: {artifacts_dir}")
        print("[DEBUG] Единый HTML-отчёт сформирован, завершаем работу")
    except Exception as e:
        print(f"[ERROR] Не удалось агрегировать findings и сохранить единый HTML-отчёт: {e}")
    return 0

if __name__ == "__main__":
    sys.exit(main()) 