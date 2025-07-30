"""
Отслеживание изменений в реестре для инкрементального сканирования
"""

import os
import winreg
import logging
from typing import Dict, List, Any, Optional, Set
from pathlib import Path
from datetime import datetime
import json
import sqlite3
import threading

class RegistryChangeTracker:
    """
    Отслеживание изменений в реестре для инкрементального сканирования
    """
    
    def __init__(self, db_path: str = "state/registry_changes.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.Lock()
        self._init_db()
        
    def _init_db(self) -> None:
        """Инициализация базы данных"""
        with self.lock:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Таблица для хранения состояния ключей
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS registry_state (
                    path TEXT PRIMARY KEY,
                    last_modified INTEGER,
                    values_hash TEXT,
                    subkeys_hash TEXT,
                    last_checked INTEGER
                )
                """)
                
                # Таблица для хранения изменений
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS registry_changes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    path TEXT,
                    change_type TEXT,
                    old_value TEXT,
                    new_value TEXT,
                    timestamp INTEGER,
                    FOREIGN KEY (path) REFERENCES registry_state(path)
                )
                """)
                
                conn.commit()
                
    def _calculate_hash(self, data: Any) -> str:
        """Вычисление хэша данных"""
        import hashlib
        return hashlib.md5(str(data).encode()).hexdigest()
        
    def get_state(self, path: str) -> Optional[Dict[str, Any]]:
        """
        Получение сохраненного состояния ключа
        
        Args:
            path: Путь к ключу реестра
            
        Returns:
            Optional[Dict]: Сохраненное состояние или None
        """
        with self.lock:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT last_modified, values_hash, subkeys_hash FROM registry_state WHERE path = ?",
                    (path,)
                )
                row = cursor.fetchone()
                
                if row:
                    return {
                        'last_modified': row[0],
                        'values_hash': row[1],
                        'subkeys_hash': row[2]
                    }
                    
        return None
        
    def update_state(self, path: str, key_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Обновление состояния ключа и получение списка изменений
        
        Args:
            path: Путь к ключу реестра
            key_info: Текущая информация о ключе
            
        Returns:
            List[Dict]: Список изменений
        """
        changes = []
        current_time = int(datetime.now().timestamp())
        
        # Вычисляем хэши текущего состояния
        values_hash = self._calculate_hash(key_info.get('values', {}))
        subkeys_hash = self._calculate_hash(key_info.get('subkeys', []))
        
        with self.lock:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Получаем предыдущее состояние
                cursor.execute(
                    "SELECT last_modified, values_hash, subkeys_hash FROM registry_state WHERE path = ?",
                    (path,)
                )
                row = cursor.fetchone()
                
                if row:
                    # Проверяем изменения
                    if values_hash != row[1]:
                        changes.append({
                            'path': path,
                            'type': 'values_modified',
                            'old_hash': row[1],
                            'new_hash': values_hash,
                            'timestamp': current_time
                        })
                        
                    if subkeys_hash != row[2]:
                        changes.append({
                            'path': path,
                            'type': 'subkeys_modified',
                            'old_hash': row[2],
                            'new_hash': subkeys_hash,
                            'timestamp': current_time
                        })
                        
                    # Обновляем состояние
                    cursor.execute("""
                    UPDATE registry_state 
                    SET last_modified = ?, values_hash = ?, subkeys_hash = ?, last_checked = ?
                    WHERE path = ?
                    """, (
                        key_info.get('last_modified', current_time),
                        values_hash,
                        subkeys_hash,
                        current_time,
                        path
                    ))
                else:
                    # Добавляем новое состояние
                    cursor.execute("""
                    INSERT INTO registry_state (path, last_modified, values_hash, subkeys_hash, last_checked)
                    VALUES (?, ?, ?, ?, ?)
                    """, (
                        path,
                        key_info.get('last_modified', current_time),
                        values_hash,
                        subkeys_hash,
                        current_time
                    ))
                    
                    changes.append({
                        'path': path,
                        'type': 'new_key',
                        'timestamp': current_time
                    })
                    
                # Сохраняем изменения
                for change in changes:
                    cursor.execute("""
                    INSERT INTO registry_changes (path, change_type, old_value, new_value, timestamp)
                    VALUES (?, ?, ?, ?, ?)
                    """, (
                        change['path'],
                        change['type'],
                        change.get('old_hash', ''),
                        change.get('new_hash', ''),
                        change['timestamp']
                    ))
                    
                conn.commit()
                
        return changes
        
    def get_changes_since(self, timestamp: int) -> List[Dict[str, Any]]:
        """
        Получение списка изменений с указанного времени
        
        Args:
            timestamp: Временная метка (Unix timestamp)
            
        Returns:
            List[Dict]: Список изменений
        """
        changes = []
        
        with self.lock:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                SELECT path, change_type, old_value, new_value, timestamp
                FROM registry_changes
                WHERE timestamp > ?
                ORDER BY timestamp ASC
                """, (timestamp,))
                
                for row in cursor.fetchall():
                    changes.append({
                        'path': row[0],
                        'type': row[1],
                        'old_value': row[2],
                        'new_value': row[3],
                        'timestamp': row[4]
                    })
                    
        return changes
        
    def cleanup_old_changes(self, max_age: int = 604800) -> None:
        """
        Очистка старых записей об изменениях
        
        Args:
            max_age: Максимальный возраст записей в секундах (по умолчанию 7 дней)
        """
        current_time = int(datetime.now().timestamp())
        cutoff_time = current_time - max_age
        
        with self.lock:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Удаляем старые изменения
                cursor.execute(
                    "DELETE FROM registry_changes WHERE timestamp < ?",
                    (cutoff_time,)
                )
                
                # Удаляем записи о состоянии для несуществующих ключей
                cursor.execute(
                    "DELETE FROM registry_state WHERE last_checked < ?",
                    (cutoff_time,)
                )
                
                conn.commit() 