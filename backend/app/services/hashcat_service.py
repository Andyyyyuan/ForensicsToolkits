import os
import subprocess
import threading
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4


class HashcatService:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._process: subprocess.Popen[str] | None = None
        self._task_id: str | None = None
        self._command: list[str] = []
        self._started_at: str | None = None
        self._finished_at: str | None = None
        self._exit_code: int | None = None
        self._hash_file: str | None = None
        self._output_tail: deque[str] = deque(maxlen=200)
        self._reader_thread: threading.Thread | None = None

    def is_configured(self) -> bool:
        binary_path = self.get_binary_path()
        return bool(binary_path and Path(binary_path).exists())

    def get_binary_path(self) -> str | None:
        binary_path = self._normalize_env_path(os.getenv("HASHCAT_BINARY_PATH", ""))
        return binary_path or None

    def start_task(self, hash_file_path: str, params: dict) -> dict:
        with self._lock:
            self._refresh_state()
            if self._process and self._process.poll() is None:
                raise ValueError("当前已有 Hashcat 任务在运行，请等待完成或先手动停止。")

            binary_path = self.get_binary_path()
            if not binary_path or not Path(binary_path).exists():
                raise ValueError("未配置有效的 HASHCAT_BINARY_PATH。")

            hash_mode = params.get("hash_mode")
            attack_mode = params.get("attack_mode")
            wordlist_path = params.get("wordlist_path")
            mask = params.get("mask")
            extra_args = params.get("extra_args") or []
            session_name = params.get("session_name") or f"hashcat_{uuid4().hex[:8]}"

            if hash_mode is None:
                raise ValueError("hash_mode 是必填项。")
            if attack_mode not in (0, 3):
                raise ValueError("当前仅支持 attack_mode 0（字典）和 3（掩码）。")

            command = [binary_path, "-m", str(hash_mode), "-a", str(attack_mode), str(hash_file_path)]
            if attack_mode == 0:
                if not wordlist_path:
                    raise ValueError("字典模式下必须提供 wordlist_path。")
                if not Path(wordlist_path).exists():
                    raise ValueError("wordlist_path 不存在。")
                command.append(str(wordlist_path))
            else:
                if not mask:
                    raise ValueError("掩码模式下必须提供 mask。")
                command.append(str(mask))

            command.extend(["--session", session_name, "--status", "--status-timer", "5"])
            if extra_args:
                command.extend([str(item) for item in extra_args])

            self._output_tail.clear()
            self._task_id = uuid4().hex
            self._command = command
            self._started_at = self._now()
            self._finished_at = None
            self._exit_code = None
            self._hash_file = str(hash_file_path)

            self._process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
            )
            self._reader_thread = threading.Thread(target=self._read_output, daemon=True)
            self._reader_thread.start()
            return self.get_status()

    def stop_task(self) -> dict:
        with self._lock:
            self._refresh_state()
            if not self._process or self._process.poll() is not None:
                return self.get_status()

            self._process.terminate()
            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._process.kill()
                self._process.wait(timeout=5)

            self._refresh_state()
            return self.get_status()

    def get_status(self) -> dict:
        with self._lock:
            self._refresh_state()
            running = bool(self._process and self._process.poll() is None)
            return {
                "configured": self.is_configured(),
                "binary_path": self.get_binary_path(),
                "running": running,
                "task_id": self._task_id,
                "pid": self._process.pid if self._process and running else None,
                "command": list(self._command),
                "started_at": self._started_at,
                "finished_at": self._finished_at,
                "exit_code": self._exit_code,
                "hash_file": self._hash_file,
                "output_tail": list(self._output_tail),
            }

    def _read_output(self) -> None:
        process = self._process
        if not process or not process.stdout:
            return

        for line in process.stdout:
            cleaned = line.rstrip()
            if cleaned:
                with self._lock:
                    self._output_tail.append(cleaned)

        process.stdout.close()
        with self._lock:
            self._refresh_state()

    def _refresh_state(self) -> None:
        if self._process and self._process.poll() is not None and self._finished_at is None:
            self._exit_code = self._process.returncode
            self._finished_at = self._now()

    def _now(self) -> str:
        return datetime.now(timezone.utc).isoformat(timespec="seconds")

    def _normalize_env_path(self, value: str) -> str:
        normalized = value.strip()
        if len(normalized) >= 2 and normalized[0] == normalized[-1] and normalized[0] in {'"', "'"}:
            normalized = normalized[1:-1]
        normalized = os.path.expandvars(normalized).strip()
        return normalized


hashcat_service = HashcatService()
