#!/usr/bin/env python3
"""
Простой тестовый скрипт для проверки основных компонентов
"""

import sys
import os
import logging
from pathlib import Path

# Добавляем корневую директорию в путь
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_imports():
    """Тестирование импортов основных модулей"""
    try:
        from core.scanner_factory import ScannerFactory
        print("✓ ScannerFactory imported successfully")
        
        from core.config_manager import ConfigManager
        print("✓ ConfigManager imported successfully")
        
        from core.error_handler import error_handler
        print("✓ ErrorHandler imported successfully")
        
        from core.logger import jetcsirt_logger
        print("✓ JetCSIRTLogger imported successfully")
        
        from core.artifact_collector import ArtifactCollector
        print("✓ ArtifactCollector imported successfully")
        
        return True
    except Exception as e:
        print(f"✗ Import error: {e}")
        return False

def test_config_loading():
    """Тестирование загрузки конфигурации"""
    try:
        from core.config_manager import ConfigManager
        
        config_manager = ConfigManager()
        config = config_manager.load_config("scan_manager")
        
        if config and "scanners" in config:
            print("✓ Configuration loaded successfully")
            enabled_scanners = config_manager.get_enabled_scanners()
            print(f"✓ Found {len(enabled_scanners)} enabled scanners")
            return True
        else:
            print("✗ Configuration loading failed")
            return False
    except Exception as e:
        print(f"✗ Configuration error: {e}")
        return False

def test_scanner_creation():
    """Тестирование создания сканеров"""
    try:
        from core.scanner_factory import ScannerFactory
        from core.config_manager import ConfigManager
        from core.artifact_collector import ArtifactCollector
        
        config_manager = ConfigManager()
        config = config_manager.load_config("scan_manager")
        artifact_collector = ArtifactCollector("test_case", None)
        
        scanners = ScannerFactory.create_scanners(config, artifact_collector, {})
        
        if scanners:
            print(f"✓ Created {len(scanners)} scanners successfully")
            for scanner in scanners:
                print(f"  - {scanner.name}")
            return True
        else:
            print("✗ No scanners created")
            return False
    except Exception as e:
        print(f"✗ Scanner creation error: {e}")
        return False

def main():
    """Основная функция тестирования"""
    print("Testing scanner_ioc components...")
    print("=" * 50)
    
    tests = [
        ("Import test", test_imports),
        ("Config loading test", test_config_loading),
        ("Scanner creation test", test_scanner_creation),
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"\nRunning {test_name}...")
        if test_func():
            passed += 1
        else:
            print(f"✗ {test_name} failed")
    
    print("\n" + "=" * 50)
    print(f"Tests passed: {passed}/{total}")
    
    if passed == total:
        print("✓ All tests passed!")
        return 0
    else:
        print("✗ Some tests failed!")
        return 1

if __name__ == "__main__":
    sys.exit(main()) 