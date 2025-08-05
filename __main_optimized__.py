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
                toc_items.append(f'<li><a href="#{scanner_name}">{scanner_name} ({findings_count} findings)</a></li>')
        
        # Начинаем HTML
        html_content = f"""
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <title>JetCSIRT Scan Report</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
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
        }}
        .artifacts-table {{
            margin-top: 1rem;
        }}
        .severity-high {{
            background-color: #f8d7da !important;
            color: #721c24 !important;
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
            background-position: center right;
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
        }}
        .collapsible-content.show {{
            display: block;
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
                    <strong>User:</strong><br>
                    <code>{current_user}</code>
                </div>
                <div class="col-md-3">
                    <strong>Build:</strong><br>
                    <code>{build_number}</code>
                </div>
            </div>
            <div class="row mt-3">
                <div class="col-md-6">
                    <strong>Scan Started:</strong><br>
                    <code>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</code>
                </div>
                <div class="col-md-6">
                    <strong>Scan Completed:</strong><br>
                    <code>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</code>
                </div>
            </div>
        </div>
        
        <div class="row">
            <div class="col-12">
                <h1 class="text-center mb-4">
                    <i class="fas fa-shield-alt"></i> JetCSIRT Scan Report
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
                                    <th>Findings</th>
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
                status_class = "bg-danger"
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
                <p class="mb-0">Found {len(findings)} findings, {len(artifacts)} artifacts</p>
            </div>
            
            <!-- Находки -->
            <div class="findings-section">
                <h4 class="collapsible" onclick="toggleSection('findings-{scanner_name}')">
                    <i class="fas fa-exclamation-triangle"></i> Findings 
                    <span class="badge bg-primary">{len(findings)}</span>
                    <i class="fas fa-chevron-down collapsible-icon" id="findings-{scanner_name}-icon"></i>
                </h4>
                <div class="collapsible-content show" id="findings-{scanner_name}">
                    <div class="table-responsive">
                        <table class="table table-bordered table-sm findings-table">
                        <thead class="table-dark">
                            <tr>
            """
            
            # Определяем заголовки таблицы в зависимости от типа сканера
            if scanner_name == 'yara_scanner':
                html_content += """
                                <th>File</th>
                                <th>Rule</th>
                                <th>Severity</th>
                                <th>Tags</th>
                                <th>Meta</th>
                                <th>Offset</th>
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
                                <th>Connection</th>
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
                    tags = ', '.join(finding.get('tags', []))
                    meta = finding.get('meta', {})
                    offset = finding.get('offset', 'N/A')
                    
                    html_content += f"""
                                <td><code>{file_path}</code></td>
                                <td><strong>{rule_name}</strong></td>
                                <td><span class="badge severity-{severity}">{severity.upper()}</span></td>
                                <td><small>{tags}</small></td>
                                <td><small>{str(meta)}</small></td>
                                <td><code>{offset}</code></td>
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
                    if isinstance(data, list):
                        count = len(data)
                        # Формируем примеры
                        examples = []
                        for i, item in enumerate(data[:3]):
                            if finding_type == 'network_connections':
                                local = f"{item.get('local_ip', '-')}:" + (str(item.get('local_port', '-')) if item.get('local_port') else '-')
                                remote = f"{item.get('remote_ip', '-')}:" + (str(item.get('remote_port', '-')) if item.get('remote_port') else '-')
                                proc = item.get('process_name', '-')
                                examples.append(f"{local} → {remote} ({proc})")
                            elif finding_type == 'listening_ports':
                                ip = item.get('ip', '-')
                                port = item.get('port', '-')
                                proc = item.get('process_name', '-')
                                examples.append(f"{ip}:{port} ({proc})")
                            elif finding_type == 'suspicious_activity':
                                reason = item.get('reason', '-')
                                conn = item.get('connection', {})
                                local = f"{conn.get('local_ip', '-')}:" + (str(conn.get('local_port', '-')) if conn.get('local_port') else '-')
                                remote = f"{conn.get('remote_ip', '-')}:" + (str(conn.get('remote_port', '-')) if conn.get('remote_port') else '-')
                                examples.append(f"{local} → {remote} | {reason}")
                            else:
                                examples.append(str(item))
                        details = f"{count} items. Примеры: " + ", ".join(examples)
                        risk_level = 'low' if count < 10 else 'medium' if count < 100 else 'high'
                    else:
                        details = str(data)
                        risk_level = 'low'
                    
                    html_content += f"""
                                <td><strong>{finding_type.replace('_', ' ').title()}</strong></td>
                                <td colspan=4><small>{details}</small></td>
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
                </div> """
            </div>
            
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
"""

        # Закрываем HTML
        html_content += """
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://kit.fontawesome.com/a076d05399.js"></script>
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
        
        // Инициализация при загрузке страницы
        document.addEventListener('DOMContentLoaded', function() {
            // Находим все секции findings и показываем их по умолчанию
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