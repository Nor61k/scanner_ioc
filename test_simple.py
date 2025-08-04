#!/usr/bin/env python3
"""
Простой тест для проверки основного функционала
"""

import sys
import os
import logging
from pathlib import Path

# Добавляем корневую директорию в путь
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_basic_functionality():
    """Тестирование базового функционала"""
    try:
        # Тест 1: Проверка импортов
        print("Testing imports...")
        from core.config_manager import ConfigManager
        print("✓ ConfigManager imported")
        
        # Тест 2: Загрузка конфигурации
        print("Testing config loading...")
        config_manager = ConfigManager()
        config = config_manager.load_config("scan_manager")
        if config:
            print("✓ Config loaded successfully")
        else:
            print("✗ Config loading failed")
            return False
        
        # Тест 3: Проверка сканеров
        print("Testing scanner creation...")
        from core.scanner_factory import ScannerFactory
        from core.artifact_collector import ArtifactCollector
        
        artifact_collector = ArtifactCollector("test_case", None)
        scanners = ScannerFactory.create_scanners(config, artifact_collector, {})
        
        if scanners:
            print(f"✓ Created {len(scanners)} scanners")
            for scanner in scanners:
                print(f"  - {scanner.name}")
        else:
            print("✗ No scanners created")
            return False
        
        # Тест 4: Проверка одного сканера
        print("Testing single scanner...")
        if scanners:
            scanner = scanners[0]
            print(f"Testing scanner: {scanner.name}")
            
            try:
                findings = scanner.scan()
                print(f"✓ Scanner {scanner.name} completed with {len(findings)} findings")
                
                artifacts = scanner.collect_artifacts(findings)
                print(f"✓ Collected {len(artifacts)} artifacts")
                
            except Exception as e:
                print(f"✗ Scanner {scanner.name} failed: {e}")
                return False
        
        return True
        
    except Exception as e:
        print(f"✗ Test failed: {e}")
        return False

def main():
    """Основная функция"""
    print("Simple functionality test")
    print("=" * 40)
    
    if test_basic_functionality():
        print("\n✓ All tests passed!")
        return 0
    else:
        print("\n✗ Tests failed!")
        return 1

if __name__ == "__main__":
    sys.exit(main()) 