"""
Менеджер восстановления для сохранения состояния и обработки ошибок
"""

import os
import json
import logging
from typing import Dict, Any, Optional, List
from pathlib import Path
from datetime import datetime
import sqlite3
import pickle

class RecoveryManager:
    """
    Менеджер восстановления для:
    - Сохранения состояния сканирования
    - Восстановления после сбоев
    - Отслеживания прогресса
    - Управления повторными попытками
    """
    
    def __init__(self, state_dir: str = "state"):
        self.logger = logging.getLogger("RecoveryManager")
        self.state_dir = Path(state_dir)
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.state_dir / "recovery.db"
        self._init_db()
        
    def _init_db(self) -> None:
        """
        Инициализация базы данных для хранения состояния
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Таблица сессий сканирования
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS scan_sessions (
                    id TEXT PRIMARY KEY,
                    start_time TIMESTAMP,
                    end_time TIMESTAMP,
                    status TEXT,
                    config BLOB
                )
                """)
                
                # Таблица состояний сканеров
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS scanner_states (
                    session_id TEXT,
                    scanner_name TEXT,
                    state BLOB,
                    status TEXT,
                    error TEXT,
                    retry_count INTEGER DEFAULT 0,
                    last_update TIMESTAMP,
                    FOREIGN KEY (session_id) REFERENCES scan_sessions(id)
                )
                """)
                
                # Таблица результатов
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS scan_results (
                    session_id TEXT,
                    scanner_name TEXT,
                    results BLOB,
                    artifacts BLOB,
                    FOREIGN KEY (session_id) REFERENCES scan_sessions(id)
                )
                """)
                
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Error initializing database: {str(e)}")
            raise
            
    def create_session(self, config: Dict[str, Any]) -> str:
        """
        Создание новой сессии сканирования
        
        Args:
            config: Конфигурация сканирования
            
        Returns:
            str: ID сессии
        """
        session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO scan_sessions (id, start_time, status, config) VALUES (?, ?, ?, ?)",
                    (session_id, datetime.now(), "started", pickle.dumps(config))
                )
                conn.commit()
                
            return session_id
            
        except Exception as e:
            self.logger.error(f"Error creating session: {str(e)}")
            raise
            
    def save_scanner_state(self, session_id: str, scanner_name: str, state: Dict[str, Any], status: str, error: Optional[str] = None) -> None:
        """
        Сохранение состояния сканера
        
        Args:
            session_id: ID сессии
            scanner_name: Имя сканера
            state: Состояние сканера
            status: Статус выполнения
            error: Описание ошибки
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Проверяем существующее состояние
                cursor.execute(
                    "SELECT retry_count FROM scanner_states WHERE session_id = ? AND scanner_name = ?",
                    (session_id, scanner_name)
                )
                row = cursor.fetchone()
                
                if row:
                    # Обновляем существующее состояние
                    retry_count = row[0] + (1 if error else 0)
                    cursor.execute("""
                    UPDATE scanner_states 
                    SET state = ?, status = ?, error = ?, retry_count = ?, last_update = ?
                    WHERE session_id = ? AND scanner_name = ?
                    """, (
                        pickle.dumps(state), status, error, retry_count, datetime.now(),
                        session_id, scanner_name
                    ))
                else:
                    # Создаем новое состояние
                    cursor.execute("""
                    INSERT INTO scanner_states 
                    (session_id, scanner_name, state, status, error, retry_count, last_update)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """, (
                        session_id, scanner_name, pickle.dumps(state), status,
                        error, 1 if error else 0, datetime.now()
                    ))
                    
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Error saving scanner state: {str(e)}")
            raise
            
    def save_results(self, session_id: str, scanner_name: str, results: Dict[str, Any], artifacts: Dict[str, Path]) -> None:
        """
        Сохранение результатов сканера
        
        Args:
            session_id: ID сессии
            scanner_name: Имя сканера
            results: Результаты сканирования
            artifacts: Собранные артефакты
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT OR REPLACE INTO scan_results (session_id, scanner_name, results, artifacts) VALUES (?, ?, ?, ?)",
                    (session_id, scanner_name, pickle.dumps(results), pickle.dumps(artifacts))
                )
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Error saving results: {str(e)}")
            raise
            
    def get_scanner_state(self, session_id: str, scanner_name: str) -> Optional[Dict[str, Any]]:
        """
        Получение состояния сканера
        
        Args:
            session_id: ID сессии
            scanner_name: Имя сканера
            
        Returns:
            Optional[Dict]: Состояние сканера
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT state, status, error, retry_count FROM scanner_states WHERE session_id = ? AND scanner_name = ?",
                    (session_id, scanner_name)
                )
                row = cursor.fetchone()
                
                if row:
                    return {
                        'state': pickle.loads(row[0]),
                        'status': row[1],
                        'error': row[2],
                        'retry_count': row[3]
                    }
                    
                return None
                
        except Exception as e:
            self.logger.error(f"Error getting scanner state: {str(e)}")
            return None
            
    def get_session_results(self, session_id: str) -> Dict[str, Any]:
        """
        Получение результатов сессии
        
        Args:
            session_id: ID сессии
            
        Returns:
            Dict: Результаты сканирования
        """
        results = {}
        artifacts = {}
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT scanner_name, results, artifacts FROM scan_results WHERE session_id = ?",
                    (session_id,)
                )
                
                for row in cursor.fetchall():
                    scanner_name = row[0]
                    results[scanner_name] = pickle.loads(row[1])
                    artifacts[scanner_name] = pickle.loads(row[2])
                    
            return {
                'results': results,
                'artifacts': artifacts
            }
            
        except Exception as e:
            self.logger.error(f"Error getting session results: {str(e)}")
            return {'results': {}, 'artifacts': {}}
            
    def can_retry(self, session_id: str, scanner_name: str, max_retries: int = 3) -> bool:
        """
        Проверка возможности повторной попытки
        
        Args:
            session_id: ID сессии
            scanner_name: Имя сканера
            max_retries: Максимальное количество попыток
            
        Returns:
            bool: Можно ли повторить попытку
        """
        state = self.get_scanner_state(session_id, scanner_name)
        if state:
            return state['retry_count'] < max_retries
        return True
        
    def cleanup_old_sessions(self, days: int = 7) -> None:
        """
        Очистка старых сессий
        
        Args:
            days: Количество дней для хранения
        """
        try:
            cutoff_date = datetime.now().timestamp() - (days * 24 * 60 * 60)
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Получаем список старых сессий
                cursor.execute("SELECT id FROM scan_sessions WHERE start_time < ?", (cutoff_date,))
                old_sessions = [row[0] for row in cursor.fetchall()]
                
                # Удаляем данные старых сессий
                for session_id in old_sessions:
                    cursor.execute("DELETE FROM scan_results WHERE session_id = ?", (session_id,))
                    cursor.execute("DELETE FROM scanner_states WHERE session_id = ?", (session_id,))
                    cursor.execute("DELETE FROM scan_sessions WHERE id = ?", (session_id,))
                    
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Error cleaning up old sessions: {str(e)}")
            
    def get_incomplete_scanners(self, session_id: str) -> List[str]:
        """
        Получение списка незавершенных сканеров
        
        Args:
            session_id: ID сессии
            
        Returns:
            List[str]: Список имен сканеров
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT scanner_name FROM scanner_states WHERE session_id = ? AND status != 'completed'",
                    (session_id,)
                )
                return [row[0] for row in cursor.fetchall()]
                
        except Exception as e:
            self.logger.error(f"Error getting incomplete scanners: {str(e)}")
            return [] 