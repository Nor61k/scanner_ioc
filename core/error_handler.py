"""
Централизованный обработчик ошибок
"""

import logging
import traceback
import sys
from typing import Dict, Any, Optional, Callable
from datetime import datetime
from functools import wraps

class ErrorHandler:
    """Централизованный обработчик ошибок"""
    
    def __init__(self):
        self.logger = logging.getLogger("JetCSIRT.ErrorHandler")
        self.error_callbacks = {}
        self.recovery_strategies = {}
        
    def register_error_callback(self, error_type: str, callback: Callable) -> None:
        """
        Регистрация callback для обработки ошибок
        
        Args:
            error_type: Тип ошибки
            callback: Функция обработки
        """
        self.error_callbacks[error_type] = callback
        
    def register_recovery_strategy(self, error_type: str, strategy: Callable) -> None:
        """
        Регистрация стратегии восстановления
        
        Args:
            error_type: Тип ошибки
            strategy: Функция восстановления
        """
        self.recovery_strategies[error_type] = strategy
        
    def handle_error(self, error: Exception, context: Dict[str, Any] = None) -> bool:
        """
        Обработка ошибки
        
        Args:
            error: Исключение
            context: Контекст ошибки
            
        Returns:
            bool: True если ошибка обработана успешно
        """
        error_type = type(error).__name__
        error_msg = str(error)
        
        # Логируем ошибку
        self.logger.error(f"Error {error_type}: {error_msg}")
        self.logger.debug(f"Error context: {context}")
        self.logger.debug(f"Traceback: {traceback.format_exc()}")
        
        # Вызываем callback если зарегистрирован
        if error_type in self.error_callbacks:
            try:
                self.error_callbacks[error_type](error, context)
            except Exception as e:
                self.logger.error(f"Error in error callback: {str(e)}")
                
        # Пытаемся восстановиться
        if error_type in self.recovery_strategies:
            try:
                return self.recovery_strategies[error_type](error, context)
            except Exception as e:
                self.logger.error(f"Error in recovery strategy: {str(e)}")
                
        return False
        
    def safe_execute(self, func: Callable, *args, **kwargs) -> Optional[Any]:
        """
        Безопасное выполнение функции с обработкой ошибок
        
        Args:
            func: Функция для выполнения
            *args: Аргументы функции
            **kwargs: Именованные аргументы
            
        Returns:
            Optional[Any]: Результат функции или None при ошибке
        """
        try:
            return func(*args, **kwargs)
        except Exception as e:
            self.handle_error(e, {
                'function': func.__name__,
                'args': args,
                'kwargs': kwargs
            })
            return None
            
    def retry_on_error(self, max_retries: int = 3, delay: float = 1.0):
        """
        Декоратор для повторных попыток при ошибке
        
        Args:
            max_retries: Максимальное количество попыток
            delay: Задержка между попытками в секундах
        """
        def decorator(func: Callable) -> Callable:
            @wraps(func)
            def wrapper(*args, **kwargs):
                last_error = None
                
                for attempt in range(max_retries + 1):
                    try:
                        return func(*args, **kwargs)
                    except Exception as e:
                        last_error = e
                        if attempt < max_retries:
                            self.logger.warning(f"Attempt {attempt + 1} failed for {func.__name__}: {str(e)}")
                            import time
                            time.sleep(delay)
                        else:
                            self.logger.error(f"All {max_retries + 1} attempts failed for {func.__name__}")
                            self.handle_error(e, {
                                'function': func.__name__,
                                'attempts': max_retries + 1
                            })
                            
                return None
            return wrapper
        return decorator
        
    def handle_file_errors(self, error: Exception, context: Dict[str, Any]) -> bool:
        """Обработка ошибок файловых операций"""
        if "Permission denied" in str(error):
            self.logger.warning("Permission denied - trying to elevate privileges")
            return True
        elif "No such file" in str(error):
            self.logger.warning("File not found - skipping")
            return True
        return False
        
    def handle_memory_errors(self, error: Exception, context: Dict[str, Any]) -> bool:
        """Обработка ошибок работы с памятью"""
        if "Access denied" in str(error):
            self.logger.warning("Memory access denied - skipping process")
            return True
        elif "No such process" in str(error):
            self.logger.warning("Process not found - skipping")
            return True
        return False
        
    def handle_network_errors(self, error: Exception, context: Dict[str, Any]) -> bool:
        """Обработка сетевых ошибок"""
        if "Connection refused" in str(error):
            self.logger.warning("Connection refused - retrying later")
            return True
        elif "Timeout" in str(error):
            self.logger.warning("Network timeout - retrying later")
            return True
        return False

# Глобальный экземпляр обработчика ошибок
error_handler = ErrorHandler()

# Регистрируем стандартные обработчики
error_handler.register_error_callback("PermissionError", error_handler.handle_file_errors)
error_handler.register_error_callback("FileNotFoundError", error_handler.handle_file_errors)
error_handler.register_error_callback("AccessDenied", error_handler.handle_memory_errors)
error_handler.register_error_callback("NoSuchProcess", error_handler.handle_memory_errors)
error_handler.register_error_callback("ConnectionRefusedError", error_handler.handle_network_errors)
error_handler.register_error_callback("TimeoutError", error_handler.handle_network_errors) 