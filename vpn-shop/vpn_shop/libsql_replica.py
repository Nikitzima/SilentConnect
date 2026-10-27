from __future__ import annotations

import logging
import os
import sqlite3
import threading
import time
from typing import Any, Iterable, Iterator

LOGGER = logging.getLogger(__name__)

try:
    import libsql
    HAS_LIBSQL = True
except ImportError:
    libsql = None
    HAS_LIBSQL = False


class LibsqlRow:
    """Полный аналог sqlite3.Row для кортежей из libsql."""
    __slots__ = ("_cols", "_vals", "_map")

    def __init__(self, cols: list[str], vals: tuple[Any, ...]) -> None:
        self._cols = cols
        self._vals = vals
        self._map = dict(zip(cols, vals))

    def __getitem__(self, key: int | str | slice) -> Any:
        if isinstance(key, str):
            return self._map[key]
        return self._vals[key]

    def keys(self) -> list[str]:
        return list(self._cols)

    def values(self) -> tuple[Any, ...]:
        return self._vals

    def items(self) -> list[tuple[str, Any]]:
        return list(self._map.items())

    def get(self, key: str, default: Any = None) -> Any:
        return self._map.get(key, default)

    def __contains__(self, key: str) -> bool:
        return key in self._map

    def __iter__(self) -> Iterator[str]:
        return iter(self._cols)

    def __len__(self) -> int:
        return len(self._cols)

    def __repr__(self) -> str:
        return f"<LibsqlRow {self._map}>"


class LibsqlCursorWrapper:
    """Обёртка курсора libsql, возвращающая LibsqlRow вместо сырых кортежей."""
    def __init__(self, raw_cursor: Any) -> None:
        self._cur = raw_cursor
        self._cols = [col[0] for col in (getattr(raw_cursor, "description", None) or [])]

    @property
    def description(self) -> Any:
        return getattr(self._cur, "description", None)

    @property
    def rowcount(self) -> int:
        return int(getattr(self._cur, "rowcount", -1))

    @property
    def lastrowid(self) -> int | None:
        val = getattr(self._cur, "lastrowid", None)
        return int(val) if val is not None else None

    def fetchone(self) -> LibsqlRow | None:
        row = self._cur.fetchone()
        if row is None:
            return None
        return LibsqlRow(self._cols, tuple(row))

    def fetchall(self) -> list[LibsqlRow]:
        rows = self._cur.fetchall() or []
        return [LibsqlRow(self._cols, tuple(r)) for r in rows]

    def __iter__(self) -> Iterator[LibsqlRow]:
        return iter(self.fetchall())


class LibsqlReplicaManager:
    """
    Потокобезопасный менеджер Embedded Replica для store.py.
    Чтение — 0.02 мс с локального NVMe.
    Сетевой синк с Turso изолирован в _sync_lock и не блокирует параллельное чтение.
    """
    def __init__(
        self,
        local_replica_path: str,
        sync_url: str,
        auth_token: str,
        auto_sync_interval: float = 60.0,
    ) -> None:
        if not HAS_LIBSQL:
            raise RuntimeError("Package 'libsql' is required for LibsqlReplicaManager")

        self._path = local_replica_path
        self._sync_url = sync_url
        self._auth_token = auth_token
        self._sync_interval = auto_sync_interval
        self._sync_lock = threading.Lock()
        self._exec_lock = threading.RLock()
        self._lock = self._exec_lock
        self._last_sync_at = 0.0
        self._ro_local = threading.local()
        try:
            self._conn = libsql.connect(
                self._path,
                sync_url=self._sync_url,
                auth_token=self._auth_token,
            )
        except Exception as e:
            if "invalid local state" in str(e).lower():
                import glob
                LOGGER.warning("Corrupted or stale local replica detected for %s: %s. Re-bootstrapping clean replica...", self._path, e)
                for f in glob.glob(f"{self._path}*"):
                    try:
                        os.remove(f)
                    except OSError:
                        pass
                self._conn = libsql.connect(
                    self._path,
                    sync_url=self._sync_url,
                    auth_token=self._auth_token,
                )
            else:
                raise
        self.force_sync()

    def _get_ro_conn(self) -> sqlite3.Connection | None:
        if not self._path or not os.path.exists(self._path):
            return None
        conn = getattr(self._ro_local, "conn", None)
        if conn is not None:
            return conn
        try:
            uri = f"file:{self._path}?mode=ro"
            conn = sqlite3.connect(uri, uri=True, timeout=15.0, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA query_only = ON;")
            self._ro_local.conn = conn
            return conn
        except Exception:
            return None

    def force_sync(self, min_interval: float = 0.0) -> None:
        """Синхронизация локальной реплики с облаком Turso под выделенным _sync_lock."""
        now = time.monotonic()
        if min_interval > 0.0 and (now - self._last_sync_at) < min_interval:
            return
        with self._sync_lock:
            now = time.monotonic()
            if min_interval > 0.0 and (now - self._last_sync_at) < min_interval:
                return
            try:
                with self._exec_lock:
                    self._conn.sync()
                self._last_sync_at = time.monotonic()
            except Exception as exc:
                LOGGER.warning("Turso force_sync failed: %s", exc)
                self._last_sync_at = time.monotonic() - max(self._sync_interval - 300.0, 0.0)

    def sync_if_stale(self) -> None:
        """Неблокирующая фоновая проверка устаревания реплики."""
        now = time.monotonic()
        if now - self._last_sync_at >= self._sync_interval:
            # Неблокирующий захват: если фоновый синк уже запущен, читаем локальную реплику сразу
            if self._sync_lock.acquire(blocking=False):
                def _bg_sync():
                    try:
                        if time.monotonic() - self._last_sync_at >= self._sync_interval:
                            with self._exec_lock:
                                self._conn.sync()
                            self._last_sync_at = time.monotonic()
                    except Exception as exc:
                        LOGGER.warning("Turso sync_if_stale background sync failed: %s", exc)
                        self._last_sync_at = time.monotonic() - max(self._sync_interval - 300.0, 0.0)
                    finally:
                        self._sync_lock.release()

                threading.Thread(target=_bg_sync, daemon=True, name="turso-stale-syncer").start()

    def connect(self) -> LibsqlConnectionProxy:
        return LibsqlConnectionProxy(self)


class LibsqlConnectionProxy:
    """
    Прокси соединения для store.py и subjson-service:
    1. Потокобезопасен (локальный _exec_lock только на время выполнения запросов).
    2. Поддерживает свойство in_transaction.
    3. Перехватывает BEGIN / COMMIT / ROLLBACK.
    4. Преобразует ошибки в sqlite3.IntegrityError.
    5. Игнорирует несовместимые PRAGMA.
    """
    def __init__(self, manager: LibsqlReplicaManager) -> None:
        self._mgr = manager
        self._wrote = False
        self._in_transaction = False
        self._tx_lock_held = False
        self._closed = False
        self.row_factory: Any = LibsqlRow

    def _get_lock(self) -> Any:
        return getattr(self._mgr, "_lock", None) or getattr(self._mgr, "_exec_lock", None)

    def _acquire_tx_lock(self) -> None:
        if not self._tx_lock_held:
            lock = self._get_lock()
            if lock is not None:
                lock.acquire()
            self._tx_lock_held = True

    def _release_tx_lock(self) -> None:
        if self._tx_lock_held:
            self._tx_lock_held = False
            lock = self._get_lock()
            if lock is not None:
                try:
                    lock.release()
                except RuntimeError:
                    pass

    @property
    def in_transaction(self) -> bool:
        return self._in_transaction

    @staticmethod
    def _wrap_error(exc: Exception) -> Exception:
        msg = str(exc)
        if any(k in msg.upper() for k in ("UNIQUE", "CONSTRAINT", "PRIMARY KEY", "FOREIGN KEY")):
            return sqlite3.IntegrityError(msg)
        return sqlite3.OperationalError(msg)

    def execute(self, sql: str, parameters: Iterable[Any] = ()) -> LibsqlCursorWrapper:
        if self._closed:
            raise sqlite3.ProgrammingError("Cannot operate on a closed database connection")

        stmt_upper = sql.strip().upper()

        # Пропускаем информационные PRAGMA в локальную RO-реплику,
        # игнорируя только конфигурационные PRAGMA (busy_timeout, journal_mode и т.д.)
        if stmt_upper.startswith("PRAGMA"):
            if any(k in stmt_upper for k in ("TABLE_INFO", "INDEX_LIST", "INTEGRITY_CHECK", "FOREIGN_KEY_CHECK")):
                ro_conn = self._mgr._get_ro_conn()
                if ro_conn is not None:
                    cur = ro_conn.execute(sql, tuple(parameters))
                    return LibsqlCursorWrapper(cur)
            empty_cur = type(
                "EmptyCur",
                (),
                {
                    "description": None,
                    "rowcount": 0,
                    "lastrowid": None,
                    "fetchone": lambda: None,
                    "fetchall": lambda: [],
                },
            )()
            return LibsqlCursorWrapper(empty_cur)

        # Обработка BEGIN транзакций
        if stmt_upper.startswith("BEGIN"):
            self._acquire_tx_lock()
            self._in_transaction = True
            try:
                cur = self._mgr._conn.execute(sql)
                return LibsqlCursorWrapper(cur)
            except Exception:
                return LibsqlCursorWrapper(type("EmptyCur", (), {"description": None, "rowcount": 0, "lastrowid": None, "fetchone": lambda: None, "fetchall": lambda: []})())

        # Обработка явного COMMIT
        if stmt_upper.startswith("COMMIT"):
            self.commit()
            return LibsqlCursorWrapper(type("EmptyCur", (), {"description": None, "rowcount": 0, "lastrowid": None, "fetchone": lambda: None, "fetchall": lambda: []})())

        # Обработка явного ROLLBACK
        if stmt_upper.startswith("ROLLBACK"):
            self.rollback()
            return LibsqlCursorWrapper(type("EmptyCur", (), {"description": None, "rowcount": 0, "lastrowid": None, "fetchone": lambda: None, "fetchall": lambda: []})())

        # Отслеживаем модифицирующие операции
        if any(stmt_upper.startswith(w) for w in ("INSERT", "UPDATE", "DELETE", "REPLACE", "CREATE", "ALTER", "DROP")):
            self._wrote = True

        lock = self._get_lock()
        try:
            if lock is not None and not self._tx_lock_held:
                with lock:
                    cur = self._mgr._conn.execute(sql, tuple(parameters))
                    return LibsqlCursorWrapper(cur)
            else:
                cur = self._mgr._conn.execute(sql, tuple(parameters))
                return LibsqlCursorWrapper(cur)
        except Exception as exc:
            raise self._wrap_error(exc) from exc

    def executescript(self, sql_script: str) -> None:
        if self._closed:
            raise sqlite3.ProgrammingError("Cannot operate on a closed database connection")

        lock = self._get_lock()
        ctx = lock if (lock is not None and not self._tx_lock_held) else threading.Lock()
        with ctx:
            for stmt in sql_script.split(";"):
                s = stmt.strip()
                if s and not s.upper().startswith("PRAGMA"):
                    try:
                        self._mgr._conn.execute(s)
                        self._wrote = True
                    except Exception as exc:
                        raise self._wrap_error(exc) from exc
        self.commit()

    def commit(self) -> None:
        if self._closed:
            return
        lock = self._get_lock()
        try:
            if lock is not None and not self._tx_lock_held:
                with lock:
                    self._mgr._conn.commit()
            else:
                self._mgr._conn.commit()
            self._in_transaction = False
        except Exception as exc:
            raise self._wrap_error(exc) from exc
        finally:
            self._release_tx_lock()

        if self._wrote:
            self._mgr.force_sync()
            self._wrote = False

    def rollback(self) -> None:
        if self._closed:
            return
        lock = self._get_lock()
        try:
            if lock is not None and not self._tx_lock_held:
                with lock:
                    try:
                        self._mgr._conn.rollback()
                    except Exception:
                        pass
            else:
                try:
                    self._mgr._conn.rollback()
                except Exception:
                    pass
        finally:
            self._in_transaction = False
            self._wrote = False
            self._release_tx_lock()

    def close(self) -> None:
        if not self._closed:
            try:
                if self._in_transaction or self._tx_lock_held:
                    self.rollback()
                elif self._wrote:
                    self.commit()
            finally:
                self._closed = True

    def __enter__(self) -> LibsqlConnectionProxy:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        try:
            if exc_type is not None:
                self.rollback()
            else:
                self.commit()
        finally:
            self.close()
