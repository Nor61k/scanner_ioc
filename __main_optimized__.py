"""
Оптимизированный основной модуль для запуска сканирования
"""

import argparse
import logging
import os
import sys
import time
from datetime import datetime
from typing import Dict, Any, List
import json
import multiprocessing
import subprocess
from pathlib import Path

from core.scanner_factory import ScannerFactory
from core.config_manager import ConfigManager
from core.error_handler import error_handler
from core.logger import jetcsirt_logger
from core.artifact_collector import ArtifactCollector

def setup_environment():
    """Настройка окружения"""
    # Устанавливаем кодировку
    if sys.platform == "win32":
        import locale
        locale.setlocale(locale.LC_ALL, '')
    
    # Настраиваем multiprocessing
    multiprocessing.set_start_method('spawn', force=True)

def load_user_whitelist() -> Dict[str, Any]:
    """Загрузка пользовательского whitelist"""
    whitelist = {}
    whitelist_path = Path('user_whitelist.json')
    
    if whitelist_path.exists():
        try:
            with open(whitelist_path, 'r', encoding='utf-8') as f:
                whitelist = json.load(f)
            logging.info("User whitelist loaded successfully")
        except Exception as e:
            logging.warning(f"Failed to load user whitelist: {e}")
    
    return whitelist

def run_single_scanner(scanner_name: str, config: Dict[str, Any], args: argparse.Namespace) -> int:
    """Запуск одного сканера"""
    try:
        # Инициализируем компоненты
        config_manager = ConfigManager()
        artifact_collector = ArtifactCollector(args.case_id, args.encryption_key)
        user_whitelist = load_user_whitelist()
        
        # Применяем лимиты ресурсов к конфигурации
        if args.max_cpu:
            for scanner_cfg in config.get('scanners', {}).values():
                scanner_cfg['thread_count'] = args.max_cpu
        if args.max_ram:
            for scanner_cfg in config.get('scanners', {}).values():
                scanner_cfg['max_ram'] = args.max_ram * 1024 * 1024  # в байтах
        
        # Создаем сканеры
        scanners = ScannerFactory.create_scanners(config, artifact_collector, user_whitelist)
        
        if not scanners:
            logging.error("No scanners enabled. Exiting.")
            return 1
        
        # Запускаем сканер
        for scanner in scanners:
            if scanner.name == scanner_name:
                start_time = time.time()
                
                # Логируем начало сканирования
                scanner_config = config.get("scanners", {}).get(scanner_name, {})
                jetcsirt_logger.log_scan_start(scanner.name, scanner_config)
                
                try:
                    findings = scanner.scan()
                    artifacts_result = scanner.collect_artifacts(findings) if findings else {}
                    # Убеждаемся, что artifacts_result - это словарь
                    if artifacts_result is None:
                        artifacts_result = {}
                    elif not isinstance(artifacts_result, dict):
                        artifacts_result = {}
                    
                    scanner.save_results(args.output)
                    
                    # Логируем завершение
                    duration = time.time() - start_time
                    jetcsirt_logger.log_scan_complete(scanner.name, len(findings), duration)
                    
                    # Сохраняем результаты в JSON
                    json_path = Path(args.output) / f'findings_{scanner.name}.json'
                    with open(json_path, 'w', encoding='utf-8') as f:
                        json.dump({
                            "findings": findings,
                            "artifacts": {str(k): str(v) for k, v in artifacts_result.items()}
                        }, f, ensure_ascii=False, indent=2)
                    
                    logging.info(f"Results saved: {json_path}")
                    
                except Exception as e:
                    jetcsirt_logger.log_error(scanner.name, e)
                    logging.error(f"Error in scanner {scanner.name}: {e}")
                    return 1
                
                break
        
        return 0
        
    except Exception as e:
        logging.error(f"Error running single scanner: {e}")
        return 1

def run_parallel_scanners(config: Dict[str, Any], args: argparse.Namespace) -> int:
    """Запуск сканеров в параллельном режиме"""
    try:
        config_manager = ConfigManager()
        enabled_scanners = config_manager.get_enabled_scanners()
        
        if not enabled_scanners:
            logging.error("No scanners enabled. Exiting.")
            return 1
        
        processes = []
        
        # Запускаем каждый сканер в отдельном процессе
        for scanner_name in enabled_scanners:
            # Определяем правильный путь к файлу
            if getattr(sys, 'frozen', False):
                # Если запущено как exe
                script_path = sys.executable
            else:
                # Если запущено как Python скрипт
                script_path = sys.executable
                script_file = __file__
            
            cmd = [
                script_path, 
                script_file, 
                '--scanner', scanner_name,
                '--config', args.config,
                '--output', args.output,
                '--logs', args.logs,
                '--case-id', args.case_id
            ]
            
            if args.encryption_key:
                cmd.extend(['--encryption-key', args.encryption_key])
            
            if args.max_cpu:
                cmd.extend(['--max-cpu', str(args.max_cpu)])
            
            if args.max_ram:
                cmd.extend(['--max-ram', str(args.max_ram)])
            
            logging.info(f"Starting scanner: {scanner_name}")
            p = subprocess.Popen(cmd)
            processes.append(p)
        
        # Ждем завершения всех процессов
        exit_codes = [p.wait() for p in processes]
        
        if any(code != 0 for code in exit_codes):
            logging.error("One or more scanners failed.")
            return 1
        
        # Агрегируем результаты
        aggregate_results(args.output)
        
        return 0
        
    except Exception as e:
        logging.error(f"Error running parallel scanners: {e}")
        return 1

def aggregate_results(output_dir: str):
    """Агрегация результатов всех сканеров"""
    try:
        import glob
        
        findings_dict = {}
        json_files = glob.glob(os.path.join(output_dir, 'findings_*.json'))
        
        for json_file in json_files:
            scanner_name = Path(json_file).stem.replace('findings_', '')
            
            try:
                with open(json_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    findings_dict[scanner_name] = data
            except Exception as e:
                logging.error(f"Failed to read {json_file}: {e}")
        
        # Генерируем HTML отчет
        generate_html_report(findings_dict, output_dir)
        
        # Очищаем промежуточные JSON файлы
        cleanup_json_files(output_dir)
        
        # Очищаем артефакты
        cleanup_artifacts()
        
    except Exception as e:
        logging.error(f"Error aggregating results: {e}")

def generate_html_report(findings_dict: Dict[str, Any], output_dir: str):
    """Генерация подробного HTML отчета"""
    try:
        # Получаем системную информацию
        import platform
        import socket
        import getpass
        
        hostname = platform.node()
        try:
            ip_address = socket.gethostbyname(hostname)
        except:
            ip_address = "Unknown"
        
        current_user = getpass.getuser()
        build_number = "1.0.0"  # Можно вынести в конфиг
        
        # Создаем оглавление
        toc_items = []
        for scanner_name, data in findings_dict.items():
            findings_count = len(data.get('findings', []))
            if findings_count > 0:
                                    toc_items.append(f'<li><a href="#{scanner_name}">{scanner_name} ({findings_count} alerts)</a></li>')
        
        # Начинаем HTML
        html_content = f"""
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <title>JetCSIRT Scan Report</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.4/css/all.min.css" rel="stylesheet">
    <style>
        .scanner-section {{
            margin-bottom: 3rem;
            padding: 2rem;
            border: 1px solid #dee2e6;
            border-radius: 0.5rem;
            background-color: #f8f9fa;
        }}
        .findings-table {{
            margin-top: 1rem;
            width: 100%;
            table-layout: fixed;
        }}
        .findings-table th:nth-child(1) {{ width: 40%; }}  /* Rule */
        .findings-table th:nth-child(2) {{ width: 60%; }}  /* File */
        .clickable-rule:hover, .clickable-file:hover {{
            color: #0056b3 !important;
            text-decoration: underline;
        }}
        .artifacts-table {{
            margin-top: 1rem;
        }}
        .table-responsive {{
            overflow-x: auto;
            max-width: 100%;
        }}
        .table {{
            width: 100%;
            min-width: 600px;
        }}
        .table th {{
            white-space: nowrap;
            position: sticky;
            top: 0;
            background-color: #f8f9fa;
            z-index: 1;
            font-weight: bold;
            text-align: center;
            padding: 0.5rem;
            border-bottom: 2px solid #dee2e6;
            min-width: 80px;
            max-width: 200px;
        }}
        .table td {{
            vertical-align: middle;
            padding: 0.5rem;
            word-wrap: break-word;
            max-width: 200px;
            overflow: hidden;
            text-overflow: ellipsis;
        }}
        .network-table {{
            min-width: 400px !important;
        }}
        .network-table th {{
            min-width: 60px !important;
            max-width: 150px !important;
        }}
        .network-table td {{
            max-width: 150px !important;
            font-size: 0.9rem;
        }}
        .table-dark th {{
            background-color: #343a40 !important;
            color: white !important;
            border-color: #454d55 !important;
        }}
        .table td {{
            vertical-align: middle;
        }}
        .text-truncate {{
            max-width: 200px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }}
        .severity-high {{
            background-color: #ffeaa7 !important;
            color: #d63031 !important;
        }}
        .severity-medium {{
            background-color: #fff3cd !important;
            color: #856404 !important;
        }}
        .severity-low {{
            background-color: #d1ecf1 !important;
            color: #0c5460 !important;
        }}
        .severity-none {{
            background-color: #e9ecef !important;
            color: #495057 !important;
        }}
        .toc {{
            background-color: #e9ecef;
            padding: 1rem;
            border-radius: 0.5rem;
            margin-bottom: 2rem;
        }}
        .summary-card {{
            margin-bottom: 2rem;
        }}
        .scanner-header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 1rem;
            border-radius: 0.5rem;
            margin-bottom: 1rem;
        }}
        .system-info {{
            background: linear-gradient(135deg, rgba(0, 123, 255, 0.9) 0%, rgba(0, 191, 255, 0.9) 100%);
            color: white;
            padding: 1.5rem;
            border-radius: 0.5rem;
            margin-bottom: 2rem;
            position: relative;
            overflow: hidden;
        }}
        .system-info::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background-image: url('data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMzAwIiBoZWlnaHQ9IjEwMCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KICA8ZGVmcz4KICAgIDxsaW5lYXJHcmFkaWVudCBpZD0iZ3JhZGllbnQiIHgxPSIwJSIgeTE9IjAlIiB4Mj0iMTAwJSIgeTI9IjEwMCUiPgogICAgICA8c3RvcCBvZmZzZXQ9IjAlIiBzdHlsZT0ic3RvcC1jb2xvcjojMDAwOyBzdG9wLW9wYWNpdHk6MC4xIiAvPgogICAgICA8c3RvcCBvZmZzZXQ9IjEwMCUiIHN0eWxlPSJzdG9wLWNvbG9yOiMwMDA7IHN0b3Atb3BhY2l0eTowLjA1IiAvPgogICAgPC9saW5lYXJHcmFkaWVudD4KICA8L2RlZnM+CiAgPHJlY3Qgd2lkdGg9IjEwMCUiIGhlaWdodD0iMTAwJSIgZmlsbD0idXJsKCNncmFkaWVudCkiIC8+CiAgPHRleHQgeD0iNTAlIiB5PSI1MCUiIGZvbnQtZmFtaWx5PSJBcmlhbCwgc2Fucy1zZXJpZiIgZm9udC1zaXplPSI0OCIgZm9udC13ZWlnaHQ9ImJvbGQiIHRleHQtYW5jaG9yPSJtaWRkbGUiIGR5PSIuM2VtIiBmaWxsPSIjZmZmIj5KRVQ8L3RleHQ+CiAgPHRleHQgeD0iNTAlIiB5PSI1MCUiIGZvbnQtZmFtaWx5PSJBcmlhbCwgc2Fucy1zZXJpZiIgZm9udC1zaXplPSI0OCIgZm9udC13ZWlnaHQ9ImJvbGQiIHRleHQtYW5jaG9yPSJtaWRkbGUiIGR5PSIuOWVtIiBmaWxsPSIjMDBiZmYiPkNTSVJUPC90ZXh0Pgo8L3N2Zz4=');
            background-size: contain;
            background-repeat: no-repeat;
            background-position: 120% 50%;
            opacity: 0.1;
            z-index: 0;
        }}
        .system-info > * {{
            position: relative;
            z-index: 1;
        }}
        .collapsible {{
            cursor: pointer;
            padding: 0.5rem;
            border-radius: 0.25rem;
            transition: background-color 0.2s;
        }}
        .collapsible:hover {{
            background-color: rgba(0,0,0,0.1);
        }}
        .collapsible-content {{
            display: none;
            padding: 1rem;
            background-color: #f8f9fa;
            border-radius: 0.25rem;
            margin-top: 0.5rem;
            border-left: 3px solid #007bff;
            border: 1px solid #dee2e6;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .collapsible-content.show {{
            display: block !important;
        }}
        .collapsible-icon {{
            transition: transform 0.2s;
        }}
        .collapsible-icon.rotated {{
            transform: rotate(180deg);
        }}
    </style>
</head>
<body>
    <div class="container mt-4">
        <!-- Системная информация -->
        <div class="system-info">
            <div class="row">
                <div class="col-12">
                    <h2 class="text-center mb-3">
                        <i class="fas fa-server"></i> System Information
                    </h2>
                </div>
            </div>
            <div class="row">
                <div class="col-md-3">
                    <strong>Hostname:</strong><br>
                    <code>{hostname}</code>
                </div>
                <div class="col-md-3">
                    <strong>IP Address:</strong><br>
                    <code>{ip_address}</code>
                </div>
                <div class="col-md-3">
                    <strong>Build:</strong><br>
                    <code>{build_number}</code>
                </div>
                <div class="col-md-3">
                    <strong>OS:</strong><br>
                    <code>{platform.system()} {platform.release()}</code>
                </div>
            </div>
            <div class="row mt-2">
                <div class="col-md-4">
                    <strong>Scan Started:</strong><br>
                    <code>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</code>
                </div>
                <div class="col-md-4">
                    <strong>User:</strong><br>
                    <code>{current_user}</code>
                </div>
                <div class="col-md-4">
                    <strong>Scan Completed:</strong><br>
                    <code>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</code>
                </div>
            </div>
        </div>
        
        <div class="row">
            <div class="col-12">
                <h1 class="text-center mb-4 text-break">
                    <span><i class="fas fa-shield-alt"></i> JetCSIRT Scan Report</span>
                </h1>
            </div>
        </div>
        
        <!-- Сводная таблица -->
        <div class="row summary-card">
            <div class="col-12">
                <div class="card">
                    <div class="card-header">
                        <h2><i class="fas fa-chart-bar"></i> Summary</h2>
                    </div>
                    <div class="card-body">
                        <table class="table table-striped table-hover">
                            <thead class="table-dark">
                                <tr>
                                    <th>Scanner</th>
                                    <th>Alerts</th>
                                    <th>Artifacts</th>
                                    <th>Status</th>
                                </tr>
                            </thead>
                            <tbody>
        """
        
        # Добавляем сводную таблицу
        for scanner_name, data in findings_dict.items():
            findings_count = len(data.get('findings', []))
            artifacts_count = len(data.get('artifacts', {}))
            
            if findings_count > 0:
                status = "🔴 Found"
                status_class = "bg-warning"
            else:
                status = "🟢 Clean"
                status_class = "bg-success"
            
            html_content += f"""
                                <tr>
                                    <td><strong>{scanner_name}</strong></td>
                                    <td><span class="badge bg-primary">{findings_count}</span></td>
                                    <td><span class="badge bg-info">{artifacts_count}</span></td>
                                    <td><span class="badge {status_class}">{status}</span></td>
                                </tr>
            """
        
        html_content += """
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Оглавление -->
        <div class="row">
            <div class="col-12">
                <div class="toc">
                    <h3><i class="fas fa-list"></i> Table of Contents</h3>
                    <ul class="nav nav-pills flex-column">
        """
        
        # Добавляем оглавление
        for item in toc_items:
            html_content += f"                        {item}\n"
        
        html_content += """
                    </ul>
                </div>
            </div>
        </div>
        
        <!-- Детальные секции для каждого сканера -->
        """
        
        # Добавляем детальные секции для каждого сканера
        for scanner_name, data in findings_dict.items():
            findings = data.get('findings', [])
            artifacts = data.get('artifacts', {})
            artifacts_count = len(artifacts)
            
            if len(findings) == 0:
                continue
                
            html_content += f"""
        <div class="scanner-section" id="{scanner_name}">
            <div class="scanner-header">
                <h3><i class="fas fa-search"></i> {scanner_name.replace('_', ' ').title()}</h3>
                <p class="mb-0">Found {len(findings)} alerts, {len(artifacts)} artifacts</p>
            </div>
            
            <!-- Находки -->
            <div class="findings-section">
                <h4 class="collapsible" onclick="toggleSection('findings-{scanner_name}')">
                    <i class="fas fa-exclamation-triangle"></i> Alerts 
                    <span class="badge bg-primary">{len(findings)}</span>
                    <i class="fas fa-chevron-down collapsible-icon" id="findings-{scanner_name}-icon"></i>
                </h4>
                <div class="collapsible-content show" id="findings-{scanner_name}">
                    <div class="table-responsive" style="overflow-x: auto; max-width: 100%;">
                        <table class="table table-bordered table-sm findings-table{' network-table' if scanner_name == 'network_scanner' else ''}" style="min-width: 600px;">
                        <thead class="table-dark">
                            <tr>
            """
            
            # Определяем заголовки таблицы в зависимости от типа сканера
            if scanner_name == 'yara_scanner':
                html_content += """
                                <th>Rule</th>
                                <th>File</th>
                """
            elif scanner_name == 'memory_scanner':
                html_content += """
                                <th>Process</th>
                                <th>PID</th>
                                <th>Rule</th>
                                <th>Severity</th>
                                <th>Memory Region</th>
                                <th>Offset</th>
                """
            elif scanner_name == 'ioc_scanner':
                html_content += """
                                <th>Type</th>
                                <th>Value</th>
                                <th>Source</th>
                                <th>Confidence</th>
                                <th>Description</th>
                """
            elif scanner_name == 'network_scanner':
                html_content += """
                                <th>Local Address</th>
                                <th>Remote Address</th>
                                <th>Status</th>
                                <th>Process</th>
                                <th>Risk Level</th>
                """
            elif scanner_name == 'system_scanner':
                html_content += """
                                <th>Component</th>
                                <th>Name</th>
                                <th>Status</th>
                                <th>Details</th>
                                <th>Type</th>
                """
            elif scanner_name == 'registry_scanner':
                html_content += """
                                <th>Key</th>
                                <th>Value</th>
                                <th>Type</th>
                                <th>Risk Level</th>
                                <th>Description</th>
                """
            else:
                html_content += """
                                <th>Finding</th>
                                <th>Details</th>
                                <th>Severity</th>
                """
            
            html_content += """
                            </tr>
                        </thead>
                        <tbody>
            """
            
            # Добавляем строки с находками
            for finding in findings:
                html_content += "<tr>"
                
                if scanner_name == 'yara_scanner':
                    rule_name = finding.get('rule', 'Unknown')
                    file_path = finding.get('file', 'Unknown')
                    severity = finding.get('severity', 'medium')
                    file_hash = finding.get('file_hash', 'Unknown')
                    file_owner = finding.get('file_owner', 'Unknown')
                    file_modified = finding.get('file_modified', 'Unknown')
                    file_created = finding.get('file_created', 'Unknown')
                    strings = finding.get('strings', [])
                    
                    # Пропускаем дубликаты - если файл уже был обработан
                    if not hasattr(generate_html_report, '_processed_files'):
                        generate_html_report._processed_files = set()
                    if file_path in generate_html_report._processed_files:
                        continue
                    generate_html_report._processed_files.add(file_path)
                    
                    # Форматируем дату модификации
                    try:
                        if file_modified and file_modified != 'Unknown':
                            modified_date = datetime.fromisoformat(file_modified.replace('Z', '+00:00'))
                            formatted_date = modified_date.strftime('%Y-%m-%d %H:%M')
                        else:
                            formatted_date = 'Unknown'
                    except:
                        formatted_date = 'Unknown'
                    
                    # Форматируем дату создания
                    try:
                        if file_created and file_created != 'Unknown':
                            created_date = datetime.fromisoformat(file_created.replace('Z', '+00:00'))
                            formatted_created_date = created_date.strftime('%Y-%m-%d %H:%M')
                        else:
                            formatted_created_date = 'Unknown'
                    except:
                        formatted_created_date = 'Unknown'
                    
                    # Формируем детали срабатывания
                    match_details = []
                    for i, string_match in enumerate(strings[:5], 1):  # Показываем первые 5 совпадений
                        identifier = string_match.get('identifier', 'Unknown')
                        offset = string_match.get('offset', 0)
                        data = string_match.get('data', '')
                        
                        # Обрабатываем данные в зависимости от типа
                        try:
                            if isinstance(data, str):
                                if data.startswith('0x') or all(c in '0123456789abcdefABCDEF' for c in data):
                                    # Это hex данные, конвертируем в ASCII
                                    hex_data = data.replace('0x', '')
                                    if len(hex_data) % 2 == 0:
                                        try:
                                            ascii_data = bytes.fromhex(hex_data).decode('utf-8', errors='ignore')
                                            data_display = f"{data} ({ascii_data})"
                                        except:
                                            data_display = data
                                    else:
                                        data_display = data
                                else:
                                    data_display = data
                            elif isinstance(data, bytes):
                                # Байтовые данные
                                try:
                                    ascii_data = data.decode('utf-8', errors='ignore')
                                    hex_data = data.hex()
                                    data_display = f"0x{hex_data} ({ascii_data})"
                                except:
                                    data_display = f"0x{data.hex()}"
                            else:
                                data_display = str(data)
                        except:
                            data_display = str(data)
                        
                        # Ограничиваем длину данных для читаемости
                        if len(data_display) > 150:
                            data_display = data_display[:150] + "..."
                        
                        # Форматируем детали совпадения
                        match_details.append(f"<strong>{identifier}:</strong> {data_display} <code>at 0x{offset:x}</code>")
                    
                    match_details_text = "<br>".join(match_details) if match_details else "Нет деталей совпадения"
                    
                    # Добавляем отладочную информацию о количестве совпадений
                    if strings:
                        match_details_text = f"<strong>Найдено совпадений:</strong> {len(strings)}<br><br>" + match_details_text
                    
                    # Добавляем описание угрозы из метаданных
                    meta = finding.get('meta', {})
                    threat_description = meta.get('description', meta.get('threat', ''))
                    if threat_description:
                        match_details_text = f"<strong>Описание:</strong> {threat_description}<br><br>" + match_details_text
                    

                    
                    # Создаем уникальный ID для сворачиваемого блока
                    details_id = f"yara-details-{abs(hash(file_path))}"
                    
                    # Красиво форматируем путь к файлу
                    file_name = file_path.split('\\')[-1] if '\\' in file_path else file_path.split('/')[-1]
                    
                    html_content += f"""
                                <td>
                                    <strong class="clickable-rule" onclick="toggleDetails('{details_id}')" style="cursor: pointer; color: #007bff;">
                                        {rule_name}
                                        <i class="fas fa-chevron-down" style="margin-left: 5px;"></i>
                                    </strong>
                                </td>
                                <td>
                                    <div class="d-flex flex-column">
                                        <code class="text-truncate clickable-file" onclick="toggleDetails('{details_id}')" style="cursor: pointer; color: #007bff; max-width: 300px;" title="{file_path}">{file_name}</code>
                                        <small class="text-muted">{file_path}</small>
                                    </div>
                                </td>
                            </tr>
                            <tr>
                                <td colspan="2" class="p-0">
                                    <div class="collapsible-content" id="{details_id}">
                                        <div class="row p-3">
                                            <div class="col-md-12">
                                                <h6><i class="fas fa-file"></i> Информация о файле</h6>
                                                <table class="table table-sm">
                                                    <tr><td><strong>Путь:</strong></td><td><code>{file_path}</code></td></tr>
                                                    <tr><td><strong>Хеш (MD5):</strong></td><td><code>{file_hash}</code></td></tr>
                                                    <tr><td><strong>Владелец:</strong></td><td><code>{file_owner}</code></td></tr>
                                                    <tr><td><strong>Создан:</strong></td><td><code>{formatted_created_date}</code></td></tr>
                                                    <tr><td><strong>Изменен:</strong></td><td><code>{formatted_date}</code></td></tr>
                                                    <tr><td><strong>Размер:</strong></td><td><code>{finding.get('file_size', 'Unknown')} bytes</code></td></tr>
                                                </table>
                                            </div>
                                        </div>
                                        <div class="row px-3 pb-3">
                                            <div class="col-12">
                                                <h6><i class="fas fa-shield-alt"></i> Информация о правиле</h6>
                                                <table class="table table-sm">
                                                    <tr><td><strong>Правило:</strong></td><td><code>{rule_name}</code></td></tr>
                                                    <tr><td><strong>Важность:</strong></td><td><span class="badge severity-{severity}">{severity.upper()}</span></td></tr>
                                                    <tr><td><strong>Теги:</strong></td><td><code>{', '.join(finding.get('tags', []))}</code></td></tr>
                                                </table>
                                            </div>
                                        </div>
                                        <div class="row px-3 pb-3">
                                            <div class="col-12">
                                                <h6><i class="fas fa-info-circle"></i> Мета-информация</h6>
                                                <table class="table table-sm">
                                                    <tr><td><strong>Описание:</strong></td><td><code>{finding.get('meta', {}).get('description', 'Не указано')}</code></td></tr>
                                                    <tr><td><strong>Оценка:</strong></td><td><code>{finding.get('meta', {}).get('score', 'Не указано')}</code></td></tr>
                                                    <tr><td><strong>Дата:</strong></td><td><code>{finding.get('meta', {}).get('date', 'Не указано')}</code></td></tr>
                                                    <tr><td><strong>Автор:</strong></td><td><code>{finding.get('meta', {}).get('author', 'Не указано')}</code></td></tr>
                                                </table>
                                            </div>
                                        </div>
                                        <div class="row px-3 pb-3">
                                            <div class="col-12">
                                                <h6><i class="fas fa-search"></i> Технические детали совпадения</h6>
                                                <div class="alert alert-info">
                                                    <p><strong>Правило сработало на следующие элементы:</strong></p>
                                                    {match_details_text}
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                </td>
                            </tr>
                    """
                    
                elif scanner_name == 'memory_scanner':
                    process_name = finding.get('name', 'Unknown')
                    pid = finding.get('pid', 'N/A')
                    rule_name = finding.get('rule', 'Unknown')
                    severity = finding.get('severity', 'medium')
                    memory_region = finding.get('memory_region', 'N/A')
                    offset = finding.get('offset', 'N/A')
                    
                    html_content += f"""
                                <td><strong>{process_name}</strong></td>
                                <td><code>{pid}</code></td>
                                <td><strong>{rule_name}</strong></td>
                                <td><span class="badge severity-{severity}">{severity.upper()}</span></td>
                                <td><code>{memory_region}</code></td>
                                <td><code>{offset}</code></td>
                    """
                    
                elif scanner_name == 'ioc_scanner':
                    ioc_type = finding.get('type', 'Unknown')
                    value = finding.get('value', 'Unknown')
                    source = finding.get('source', 'Unknown')
                    confidence = finding.get('confidence', 'medium')
                    description = finding.get('description', '')
                    
                    html_content += f"""
                                <td><span class="badge bg-warning">{ioc_type}</span></td>
                                <td><code>{value}</code></td>
                                <td><small>{source}</small></td>
                                <td><span class="badge bg-info">{confidence}</span></td>
                                <td><small>{description}</small></td>
                    """
                    
                elif scanner_name == 'network_scanner':
                    # Network scanner возвращает данные в формате {'type': '...', 'data': [...]}
                    finding_type = finding.get('type', 'Unknown')
                    data = finding.get('data', [])
                    

                    
                    # Определяем детали и примеры
                    if isinstance(data, list) and len(data) > 0:
                        count = len(data)
                        # Формируем примеры для разных типов
                        if finding_type == 'network_connections':
                            # Для сетевых соединений
                            local_examples = []
                            remote_examples = []
                            process_examples = []
                            
                            for item in data[:3]:  # Показываем первые 3 примера
                                local_ip = item.get('local_ip', 'N/A')
                                local_port = item.get('local_port', 'N/A')
                                remote_ip = item.get('remote_ip', 'N/A')
                                remote_port = item.get('remote_port', 'N/A')
                                proc = item.get('process_name', 'N/A')
                                
                                local_examples.append(f"{local_ip}:{local_port}")
                                remote_examples.append(f"{remote_ip}:{remote_port}")
                                process_examples.append(proc)
                            
                            local_addr = "<br>".join(local_examples) if local_examples else "N/A"
                            remote_addr = "<br>".join(remote_examples) if remote_examples else "N/A"
                            process_name = "<br>".join(process_examples) if process_examples else "N/A"
                            status = f"Active ({count} connections)"
                            risk_level = 'low' if count < 10 else 'medium' if count < 100 else 'high'
                            
                        elif finding_type == 'listening_ports':
                            # Для слушающих портов
                            ip_examples = []
                            port_examples = []
                            process_examples = []
                            
                            for item in data[:3]:  # Показываем первые 3 примера
                                ip = item.get('ip', 'N/A')
                                port = item.get('port', 'N/A')
                                proc = item.get('process_name', 'N/A')
                                
                                ip_examples.append(ip)
                                port_examples.append(str(port))
                                process_examples.append(proc)
                            
                            local_addr = "<br>".join(ip_examples) if ip_examples else "N/A"
                            remote_addr = "<br>".join(port_examples) if port_examples else "N/A"
                            process_name = "<br>".join(process_examples) if process_examples else "N/A"
                            status = f"Listening ({count} ports)"
                            risk_level = 'low' if count < 10 else 'medium' if count < 100 else 'high'
                            
                        else:
                            # Для других типов
                            local_addr = f"{count} items"
                            remote_addr = "N/A"
                            process_name = "N/A"
                            status = "Unknown"
                            risk_level = 'low'
                    else:
                        # Если данных нет или они в неправильном формате
                        local_addr = "N/A"
                        remote_addr = "N/A"
                        process_name = "N/A"
                        status = "No data"
                        risk_level = 'low'
                    
                    html_content += f"""
                                <td><code>{local_addr}</code></td>
                                <td><code>{remote_addr}</code></td>
                                <td><span class="badge bg-info">{status}</span></td>
                                <td><small>{process_name}</small></td>
                                <td><span class="badge severity-{risk_level}">{risk_level.upper()}</span></td>
                    """
                    
                elif scanner_name == 'system_scanner':
                    # System scanner возвращает данные в формате {'type': '...', 'data': [...]}
                    finding_type = finding.get('type', 'Unknown')
                    data = finding.get('data', [])
                    
                    if isinstance(data, list):
                        # Если data - это список, показываем количество элементов
                        count = len(data)
                        details = f"Found {count} items"
                        data_type = "List"
                    else:
                        # Если data - это словарь, показываем ключи
                        count = len(data.keys()) if isinstance(data, dict) else 0
                        details = f"Found {count} properties"
                        data_type = "Dictionary"
                    
                    html_content += f"""
                                <td><strong>{finding_type.replace('_', ' ').title()}</strong></td>
                                <td><code>{finding_type}</code></td>
                                <td><span class="badge bg-success">Collected</span></td>
                                <td><small>{details}</small></td>
                                <td><span class="badge bg-info">{data_type}</span></td>
                    """
                    
                elif scanner_name == 'registry_scanner':
                    key = finding.get('key', 'Unknown')
                    value = finding.get('value', 'Unknown')
                    value_type = finding.get('type', 'Unknown')
                    risk_level = finding.get('risk_level', 'medium')
                    description = finding.get('description', '')
                    
                    html_content += f"""
                                <td><code>{key}</code></td>
                                <td><code>{value}</code></td>
                                <td><span class="badge bg-secondary">{value_type}</span></td>
                                <td><span class="badge severity-{risk_level}">{risk_level.upper()}</span></td>
                                <td><small>{description}</small></td>
                    """
                    
                else:
                    # Общий случай
                    finding_text = finding.get('finding', 'Unknown')
                    details = finding.get('details', '')
                    severity = finding.get('severity', 'medium')
                    
                    html_content += f"""
                                <td><strong>{finding_text}</strong></td>
                                <td><small>{details}</small></td>
                                <td><span class="badge severity-{severity}">{severity.upper()}</span></td>
                    """
                
                html_content += "</tr>"
            
            html_content += """
                        </tbody>
                    </table>
                    </div>
                </div>
            </div>
            """
 
            
            # Формируем HTML для артефактов
            html_content += f"""
<div class="artifacts-section">
    <h4 class="collapsible" onclick="toggleSection('artifacts-{scanner_name}')">
        <i class="fas fa-file-archive"></i> Artifacts
        <span class="badge bg-secondary">{artifacts_count}</span>
        <i class="fas fa-chevron-down" id="artifacts-{scanner_name}-icon"></i>
    </h4>
    <div class="collapsible-content" id="artifacts-{scanner_name}">
        <div class="table-responsive">
            <table class="table table-bordered table-sm artifacts-table">
                <thead class="table-dark">
                    <tr>
                        <th>Artifact</th>
                        <th>Type</th>
                        <th>Path</th>
                        <th>Size</th>
                        <th>Description</th>
                    </tr>
                </thead>
                <tbody>
"""
            # Добавляем артефакты
            for artifact_name, artifact_path in artifacts.items():
                try:
                    import os
                    size = os.path.getsize(artifact_path) if os.path.exists(artifact_path) else 0
                    size_str = f"{size:,} bytes" if size < 1024 else f"{size/1024:.1f} KB"
                except:
                    size_str = "Unknown"
                html_content += f"""
                    <tr>
                        <td><strong>{artifact_name}</strong></td>
                        <td><span class="badge bg-info">File</span></td>
                        <td><code>{artifact_path}</code></td>
                        <td><small>{size_str}</small></td>
                        <td><small>Collected during {scanner_name} scan</small></td>
                    </tr>
"""
            html_content += """
                </tbody>
            </table>
        </div>
    </div>
</div>
        </div>
        """

        # Закрываем HTML
        html_content += """
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.4/js/all.min.js"></script>
    <script>
        function toggleSection(sectionId) {
            const content = document.getElementById(sectionId);
            const icon = document.getElementById(sectionId + '-icon');
            
            if (content.classList.contains('show')) {
                content.classList.remove('show');
                icon.classList.remove('fa-chevron-up');
                icon.classList.add('fa-chevron-down');
                icon.classList.remove('rotated');
            } else {
                content.classList.add('show');
                icon.classList.remove('fa-chevron-down');
                icon.classList.add('fa-chevron-up');
                icon.classList.add('rotated');
            }
        }
        
        function toggleDetails(detailsId) {
            console.log('toggleDetails called with:', detailsId);
            const content = document.getElementById(detailsId);
            if (!content) {
                console.error('Element not found:', detailsId);
                return;
            }
            
            console.log('Content element found:', content);
            console.log('Current classes:', content.classList.toString());
            
            // Находим родительскую строку и иконку
            const parentRow = content.parentElement.previousElementSibling;
            const icon = parentRow ? parentRow.querySelector('i') : null;
            
            console.log('Parent row:', parentRow);
            console.log('Icon found:', icon);
            
            if (content.classList.contains('show')) {
                console.log('Hiding content');
                content.classList.remove('show');
                if (icon) {
                    icon.classList.remove('fa-chevron-up');
                    icon.classList.add('fa-chevron-down');
                }
            } else {
                console.log('Showing content');
                content.classList.add('show');
                if (icon) {
                    icon.classList.remove('fa-chevron-down');
                    icon.classList.add('fa-chevron-up');
                }
            }
            
            console.log('Final classes:', content.classList.toString());
        }
        
        // Простая тестовая функция
        function testClick() {
            console.log('Test click function called!');
            alert('JavaScript is working!');
        }
        
        // Инициализация при загрузке страницы
        document.addEventListener('DOMContentLoaded', function() {
            // Находим все секции alerts и показываем их по умолчанию
            const findingsSections = document.querySelectorAll('.findings-section');
            findingsSections.forEach(section => {
                const content = section.querySelector('.collapsible-content');
                const icon = section.querySelector('.collapsible-icon');
                if (content && icon) {
                    content.classList.add('show');
                    icon.classList.remove('fa-chevron-down');
                    icon.classList.add('fa-chevron-up');
                    icon.classList.add('rotated');
                }
            });
            
            // Артефакты по умолчанию скрыты (уже в CSS)
            const artifactsSections = document.querySelectorAll('.artifacts-section');
            artifactsSections.forEach(section => {
                const content = section.querySelector('.collapsible-content');
                const icon = section.querySelector('.collapsible-icon');
                if (content && icon) {
                    content.classList.remove('show');
                    icon.classList.remove('fa-chevron-up');
                    icon.classList.add('fa-chevron-down');
                    icon.classList.remove('rotated');
                }
            });
        });
    </script>
</body>
</html>
        """
        
        report_path = Path(output_dir) / 'scan_report.html'
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        logging.info(f"Detailed HTML report generated: {report_path}")
        
    except Exception as e:
        logging.error(f"Error generating HTML report: {e}")

def cleanup_artifacts():
    """Очистка артефактов после создания отчета"""
    try:
        import shutil
        artifacts_dir = Path('artifacts')
        if artifacts_dir.exists():
            shutil.rmtree(artifacts_dir)
            logging.info("Artifacts cleaned up")
    except Exception as e:
        logging.error(f"Error cleaning up artifacts: {e}")

def cleanup_json_files(output_dir: str):
    """Очистка промежуточных JSON файлов после создания отчета"""
    try:
        import glob
        output_path = Path(output_dir)
        
        # Удаляем все JSON файлы в output директории
        json_files = list(output_path.glob("*.json"))
        json_files.extend(list(output_path.glob("**/*.json")))  # Рекурсивно
        
        deleted_count = 0
        for json_file in json_files:
            try:
                if json_file.exists():
                    json_file.unlink()
                    deleted_count += 1
                    logging.debug(f"Deleted JSON file: {json_file}")
            except Exception as e:
                logging.debug(f"Could not delete {json_file}: {e}")
        
        if deleted_count > 0:
            logging.info(f"Cleaned up {deleted_count} JSON files from output directory")
        else:
            logging.info("No JSON files found to clean up")
            
    except Exception as e:
        logging.error(f"Error cleaning up JSON files: {e}")

def parse_args() -> argparse.Namespace:
    """Парсинг аргументов командной строки"""
    parser = argparse.ArgumentParser(
        description="JetCSIRT Scanner - Optimized IOC Scanner"
    )
    
    parser.add_argument(
        "--config",
        default="config/scan_manager.yaml",
        help="Path to configuration file"
    )
    
    parser.add_argument(
        "--output",
        default="output",
        help="Output directory"
    )
    
    parser.add_argument(
        "--logs",
        default="logs",
        help="Logs directory"
    )
    
    parser.add_argument(
        "--case-id",
        default=datetime.now().strftime("%Y%m%d_%H%M%S"),
        help="Case identifier"
    )
    
    parser.add_argument(
        "--encryption-key",
        help="Encryption key for artifacts"
    )
    
    parser.add_argument(
        "--scanner",
        help="Single scanner to run"
    )
    
    parser.add_argument(
        "--max-cpu",
        type=int,
        default=None,
        help="Maximum number of threads/processes for scanning"
    )
    
    parser.add_argument(
        "--max-ram",
        type=int,
        default=None,
        help="Maximum RAM usage (MB) for scanner"
    )
    
    return parser.parse_args()

def main() -> int:
    """Основная функция"""
    try:
        # Настройка окружения
        setup_environment()
        
        # Парсинг аргументов
        args = parse_args()
        
        # Настройка логирования
        os.makedirs(args.logs, exist_ok=True)
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(os.path.join(args.logs, 'scan.log')),
                logging.StreamHandler()
            ]
        )
        
        # Инициализируем jetcsirt_logger
        jetcsirt_logger.log_dir = args.logs
        
        # Загрузка конфигурации
        config_manager = ConfigManager()
        config = config_manager.load_config("scan_manager")
        
        if not config:
            logging.error("Failed to load configuration. Exiting.")
            return 1
        
        # Валидация конфигурации
        if not config_manager.validate_config(config):
            logging.error("Invalid configuration. Exiting.")
            return 1
        
        # Создание выходной директории
        Path(args.output).mkdir(parents=True, exist_ok=True)
        
        # Запуск сканирования
        if args.scanner:
            return run_single_scanner(args.scanner, config, args)
        else:
            return run_parallel_scanners(config, args)
            
    except KeyboardInterrupt:
        logging.info("Scan interrupted by user")
        return 1
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main()) 