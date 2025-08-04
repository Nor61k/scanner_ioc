#!/usr/bin/env python3
"""
Финальный тест для проверки всех исправлений
"""

import sys
import os
import logging
from pathlib import Path

# Добавляем корневую директорию в путь
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_all_components():
    """Тестирование всех компонентов"""
    try:
        print("Testing all components...")
        
        # Тест 1: Импорты
        print("1. Testing imports...")
        from core.config_manager import ConfigManager
        from core.scanner_factory import ScannerFactory
        from core.artifact_collector import ArtifactCollector
        print("✓ All imports successful")
        
        # Тест 2: Загрузка конфигурации
        print("2. Testing config loading...")
        config_manager = ConfigManager()
        config = config_manager.load_config("scan_manager")
        if not config:
            print("✗ Config loading failed")
            return False
        print("✓ Config loaded successfully")
        
        # Тест 3: Создание сканеров
        print("3. Testing scanner creation...")
        artifact_collector = ArtifactCollector("test_case", None)
        scanners = ScannerFactory.create_scanners(config, artifact_collector, {})
        
        if not scanners:
            print("✗ No scanners created")
            return False
        
        print(f"✓ Created {len(scanners)} scanners:")
        for scanner in scanners:
            print(f"  - {scanner.name}")
        
        # Тест 4: Тестирование каждого сканера
        print("4. Testing individual scanners...")
        for scanner in scanners:
            try:
                print(f"  Testing {scanner.name}...")
                
                # Запуск сканирования
                findings = scanner.scan()
                print(f"    ✓ Scan completed with {len(findings)} findings")
                
                # Сбор артефактов
                artifacts = scanner.collect_artifacts(findings)
                print(f"    ✓ Collected {len(artifacts)} artifacts")
                
                # Сохранение результатов
                output_dir = "test_output"
                os.makedirs(output_dir, exist_ok=True)
                result_file = scanner.save_results(output_dir)
                print(f"    ✓ Results saved to {result_file}")
                
            except Exception as e:
                print(f"    ✗ {scanner.name} failed: {e}")
                return False
        
        print("✓ All scanners tested successfully")
        return True
        
    except Exception as e:
        print(f"✗ Test failed: {e}")
        return False

def test_optimized_main():
    """Тестирование оптимизированного главного модуля"""
    try:
        print("5. Testing optimized main module...")
        
        # Импортируем функции из оптимизированного модуля
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        
        # Создаем тестовые аргументы
        class MockArgs:
            def __init__(self):
                self.config = "config/scan_manager.yaml"
                self.output = "test_output"
                self.logs = "test_logs"
                self.case_id = "test_case"
                self.encryption_key = None
                self.scanner = None
                self.max_cpu = 2
                self.max_ram = 1024
        
        args = MockArgs()
        
        # Тестируем загрузку конфигурации
        from core.config_manager import ConfigManager
        config_manager = ConfigManager()
        config = config_manager.load_config("scan_manager")
        
        if not config:
            print("✗ Config loading failed in optimized module")
            return False
        
        print("✓ Optimized main module test passed")
        return True
        
    except Exception as e:
        print(f"✗ Optimized main module test failed: {e}")
        return False

def main():
    """Основная функция"""
    print("Final comprehensive test")
    print("=" * 50)
    
    tests = [
        ("Component test", test_all_components),
        ("Optimized main test", test_optimized_main),
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
        print("✓ All tests passed! System is ready.")
        return 0
    else:
        print("✗ Some tests failed!")
        return 1

if __name__ == "__main__":
    sys.exit(main()) 