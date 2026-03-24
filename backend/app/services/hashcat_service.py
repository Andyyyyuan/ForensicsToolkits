import json
import os
import platform
import shutil
import subprocess
import threading
from collections import deque
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from uuid import uuid4

from app.core.paths import (
    BASE_DIR,
    get_hashcat_bundle_dir,
    get_hashcat_hash_modes_path,
    get_hashcat_runtime_dir,
    get_hashcat_wordlists_dir,
)
from app.services.db_service import db_service


PLATFORM_BINARY_CANDIDATES: dict[str, tuple[str, ...]] = {
    "windows": ("hashcat.exe",),
    "linux": ("hashcat.bin", "hashcat"),
    "darwin": ("hashcat.bin", "hashcat"),
}
SUPPORTED_ATTACK_MODES = {0, 1, 3, 6, 7}


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
        self._hash_mode: int | None = None
        self._binary_path: str | None = None
        self._potfile_path: str | None = None
        self._result_file: str | None = None
        self._show_results_checked = True
        self._output_tail: deque[str] = deque(maxlen=200)
        self._reader_thread: threading.Thread | None = None

    def is_configured(self) -> bool:
        return bool(self.get_runtime_info()["configured"])

    def get_binary_path(self) -> str | None:
        binary_path = self.get_runtime_info()["binary_path"]
        return str(binary_path) if binary_path else None

    def get_runtime_info(self) -> dict:
        platform_key = self._platform_key()
        bundle_dir = get_hashcat_bundle_dir()
        wordlists_dir = get_hashcat_wordlists_dir()
        runtime_dir = get_hashcat_runtime_dir()
        default_wordlist = self.get_default_wordlist()

        env_binary = self._resolve_explicit_binary(platform_key)
        if env_binary:
            return self._build_runtime_info(
                configured=True,
                binary_path=env_binary,
                binary_source="env",
                detected_platform=platform_key,
                bundle_dir=bundle_dir,
                wordlists_dir=wordlists_dir,
                runtime_dir=runtime_dir,
                default_wordlist=default_wordlist,
            )

        bundled_binary = self._find_bundled_binary(bundle_dir, platform_key)
        if bundled_binary:
            return self._build_runtime_info(
                configured=True,
                binary_path=bundled_binary,
                binary_source="bundled",
                detected_platform=platform_key,
                bundle_dir=bundle_dir,
                wordlists_dir=wordlists_dir,
                runtime_dir=runtime_dir,
                default_wordlist=default_wordlist,
            )

        system_binary = shutil.which("hashcat")
        if system_binary:
            return self._build_runtime_info(
                configured=True,
                binary_path=Path(system_binary),
                binary_source="system_path",
                detected_platform=platform_key,
                bundle_dir=bundle_dir,
                wordlists_dir=wordlists_dir,
                runtime_dir=runtime_dir,
                default_wordlist=default_wordlist,
            )

        return self._build_runtime_info(
            configured=False,
            binary_path=None,
            binary_source=None,
            detected_platform=platform_key,
            bundle_dir=bundle_dir,
            wordlists_dir=wordlists_dir,
            runtime_dir=runtime_dir,
            default_wordlist=default_wordlist,
        )

    def start_task(self, hash_file_path: str, params: dict) -> dict:
        with self._lock:
            self._refresh_state()
            if self._process and self._process.poll() is None:
                raise ValueError("当前已有 Hashcat 任务在运行，请等待完成或先手动停止。")

            runtime_info = self.get_runtime_info()
            binary_path = runtime_info["binary_path"]
            if not binary_path:
                expected_path = runtime_info["bundled_binary_path"]
                raise ValueError(
                    "未发现可用的 Hashcat 可执行文件。"
                    f"请优先配置 HASHCAT_BINARY_PATH，或把对应平台二进制放到 {expected_path}。"
                )
            runtime_dir = Path(runtime_info["runtime_dir"])
            runtime_dir.mkdir(parents=True, exist_ok=True)
            binary_dir = Path(binary_path).resolve().parent

            hash_mode = params.get("hash_mode")
            attack_mode = params.get("attack_mode")
            wordlist_path = params.get("wordlist_path")
            wordlist_file_id = self._optional_text(params.get("wordlist_file_id"))
            secondary_wordlist_path = params.get("secondary_wordlist_path")
            secondary_wordlist_file_id = self._optional_text(params.get("secondary_wordlist_file_id"))
            mask = params.get("mask")
            extra_args = params.get("extra_args") or []
            session_name = params.get("session_name") or f"hashcat_{uuid4().hex[:8]}"
            restore_file_path = runtime_dir / f"{session_name}.restore"
            potfile_path = runtime_dir / "hashcat.potfile"
            result_file_path = runtime_dir / f"{session_name}.result"
            self._remove_runtime_artifact(restore_file_path)
            self._remove_runtime_artifact(result_file_path)

            if hash_mode is None:
                raise ValueError("hash_mode 是必填项。")
            if attack_mode not in SUPPORTED_ATTACK_MODES:
                raise ValueError("当前仅支持 attack_mode 0、1、3、6、7。")

            command = [binary_path, "-m", str(hash_mode), "-a", str(attack_mode), str(Path(hash_file_path).resolve())]
            if attack_mode == 0:
                command.append(self._resolve_primary_wordlist(wordlist_path, wordlist_file_id))
            elif attack_mode == 1:
                resolved_wordlist_path = self._resolve_primary_wordlist(wordlist_path, wordlist_file_id)
                resolved_secondary_wordlist_path = self._resolve_wordlist_source(
                    secondary_wordlist_path,
                    secondary_wordlist_file_id,
                )
                if not resolved_secondary_wordlist_path:
                    raise ValueError("组合模式下必须提供第二个字典。")
                command.extend([resolved_wordlist_path, resolved_secondary_wordlist_path])
            elif attack_mode == 3:
                if not mask:
                    raise ValueError("掩码模式下必须提供 mask。")
                command.append(str(mask))
            elif attack_mode == 6:
                resolved_wordlist_path = self._resolve_primary_wordlist(wordlist_path, wordlist_file_id)
                if not mask:
                    raise ValueError("混合模式 6 下必须提供 mask。")
                command.extend([resolved_wordlist_path, str(mask)])
            elif attack_mode == 7:
                resolved_wordlist_path = self._resolve_primary_wordlist(wordlist_path, wordlist_file_id)
                if not mask:
                    raise ValueError("混合模式 7 下必须提供 mask。")
                command.extend([str(mask), resolved_wordlist_path])

            command.extend(
                [
                    "--session",
                    session_name,
                    "-o",
                    str(result_file_path),
                    "--outfile-format",
                    "1,2",
                    "--restore-file-path",
                    str(restore_file_path),
                    "--potfile-path",
                    str(potfile_path),
                    "--logfile-disable",
                    "--status",
                    "--status-timer",
                    "5",
                ]
            )
            if extra_args:
                command.extend([str(item) for item in extra_args])

            self._output_tail.clear()
            self._task_id = uuid4().hex
            self._command = command
            self._started_at = self._now()
            self._finished_at = None
            self._exit_code = None
            self._hash_file = str(hash_file_path)
            self._hash_mode = int(hash_mode)
            self._binary_path = str(binary_path)
            self._potfile_path = str(potfile_path)
            self._result_file = str(result_file_path)
            self._show_results_checked = False
            self._ensure_binary_ready(binary_path)

            self._process = subprocess.Popen(
                command,
                cwd=str(binary_dir),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
            )
            self._reader_thread = threading.Thread(target=self._read_output, daemon=True)
            self._reader_thread.start()
            return self._build_status_snapshot()

    def stop_task(self) -> dict:
        with self._lock:
            self._refresh_state()
            if not self._process or self._process.poll() is not None:
                return self._build_status_snapshot()

            self._process.terminate()
            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._process.kill()
                self._process.wait(timeout=5)

            self._refresh_state()
            return self._build_status_snapshot()

    def get_status(self) -> dict:
        with self._lock:
            return self._build_status_snapshot()

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
        if self._finished_at and not self._show_results_checked:
            self._backfill_results_from_show()

    def _build_status_snapshot(self) -> dict:
        self._refresh_state()
        runtime_info = self.get_runtime_info()
        running = bool(self._process and self._process.poll() is None)
        return {
            **runtime_info,
            "running": running,
            "task_id": self._task_id,
            "pid": self._process.pid if self._process and running else None,
            "command": list(self._command),
            "started_at": self._started_at,
            "finished_at": self._finished_at,
            "exit_code": self._exit_code,
            "hash_file": self._hash_file,
            "result_file": self._result_file,
            "result_lines": self._read_result_lines(),
            "output_tail": list(self._output_tail),
        }

    def _now(self) -> str:
        return datetime.now(timezone.utc).isoformat(timespec="seconds")

    def _normalize_env_path(self, value: str) -> str:
        normalized = value.strip()
        if len(normalized) >= 2 and normalized[0] == normalized[-1] and normalized[0] in {'"', "'"}:
            normalized = normalized[1:-1]
        normalized = os.path.expandvars(normalized).strip()
        return normalized

    def _platform_key(self) -> str:
        platform_name = platform.system().lower()
        if platform_name.startswith("win"):
            return "windows"
        if platform_name.startswith("darwin"):
            return "darwin"
        return "linux"

    def _build_runtime_info(
        self,
        *,
        configured: bool,
        binary_path: Path | None,
        binary_source: str | None,
        detected_platform: str,
        bundle_dir: Path,
        wordlists_dir: Path,
        runtime_dir: Path,
        default_wordlist: Path | None,
    ) -> dict:
        bundled_binary_path = self._preferred_bundled_binary_path(bundle_dir, detected_platform)
        return {
            "configured": configured,
            "binary_path": str(binary_path.resolve()) if binary_path and binary_path.exists() else None,
            "binary_source": binary_source,
            "detected_platform": detected_platform,
            "bundle_dir": str(bundle_dir),
            "bundled_binary_path": str(bundled_binary_path),
            "wordlists_dir": str(wordlists_dir),
            "runtime_dir": str(runtime_dir),
            "default_wordlist_path": str(default_wordlist.resolve()) if default_wordlist else None,
            "default_wordlist_name": default_wordlist.name if default_wordlist else None,
        }

    @lru_cache(maxsize=1)
    def get_hash_modes(self) -> list[dict[str, object]]:
        hash_modes_path = get_hashcat_hash_modes_path()
        if not hash_modes_path.exists():
            return []
        with hash_modes_path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
        if not isinstance(data, list):
            return []
        return [item for item in data if isinstance(item, dict)]

    def get_default_wordlist(self) -> Path | None:
        wordlists_dir = get_hashcat_wordlists_dir()
        preferred = wordlists_dir / "rockyou.txt"
        if preferred.is_file():
            return preferred.resolve()
        fallback = next((path for path in wordlists_dir.glob("rockyou*") if path.is_file()), None)
        if fallback:
            return fallback.resolve()
        return None

    def _resolve_explicit_binary(self, platform_key: str) -> Path | None:
        binary_path = self._normalize_env_path(os.getenv("HASHCAT_BINARY_PATH", ""))
        if not binary_path:
            return None

        candidate = self._resolve_local_path(binary_path)
        if candidate.is_file():
            return candidate.resolve()
        if candidate.is_dir():
            return self._find_binary_in_roots((candidate,), platform_key)
        return None

    def _find_bundled_binary(self, bundle_dir: Path, platform_key: str) -> Path | None:
        return self._find_binary_in_roots(self._bundle_search_roots(bundle_dir, platform_key), platform_key)

    def _bundle_search_roots(self, bundle_dir: Path, platform_key: str) -> tuple[Path, ...]:
        candidates: list[Path] = [bundle_dir, bundle_dir / platform_key]
        if bundle_dir.name.lower() in {"bundle", "current"}:
            parent_dir = bundle_dir.parent
            candidates.extend([parent_dir / platform_key, parent_dir])

        unique_candidates: list[Path] = []
        seen: set[Path] = set()
        for candidate in candidates:
            normalized_candidate = candidate.resolve(strict=False)
            if normalized_candidate in seen:
                continue
            seen.add(normalized_candidate)
            unique_candidates.append(candidate)
        return tuple(unique_candidates)

    def _find_binary_in_roots(self, roots: tuple[Path, ...], platform_key: str) -> Path | None:
        for root in roots:
            if not root.exists():
                continue
            for candidate_name in PLATFORM_BINARY_CANDIDATES.get(platform_key, ("hashcat", "hashcat.bin", "hashcat.exe")):
                direct_path = root / candidate_name
                if direct_path.is_file():
                    return direct_path.resolve()
                nested_path = next((path for path in root.rglob(candidate_name) if path.is_file()), None)
                if nested_path:
                    return nested_path.resolve()
        return None

    def _preferred_bundled_binary_path(self, bundle_dir: Path, platform_key: str) -> Path:
        candidate_name = PLATFORM_BINARY_CANDIDATES.get(platform_key, ("hashcat",))[0]
        return bundle_dir / candidate_name

    def _resolve_wordlist_source(self, value: str | None, file_id: str | None) -> str | None:
        if file_id:
            file_record = db_service.get_file(file_id)
            if file_record:
                file_path = Path(str(file_record.get("file_path") or ""))
                if file_path.is_file():
                    return str(file_path.resolve())
        if value:
            return self._resolve_wordlist_path(str(value))
        return None

    def _resolve_primary_wordlist(self, value: str | None, file_id: str | None) -> str:
        resolved_wordlist_path = self._resolve_wordlist_source(value, file_id)
        if not resolved_wordlist_path:
            default_wordlist = self.get_default_wordlist()
            if default_wordlist:
                resolved_wordlist_path = str(default_wordlist.resolve())
        if not resolved_wordlist_path:
            raise ValueError(
                "当前攻击模式需要可用字典。"
                "请填写 wordlist_path、上传自定义字典，或确保内置目录存在 rockyou.txt。"
            )
        return resolved_wordlist_path

    def _resolve_wordlist_path(self, value: str) -> str | None:
        normalized = self._normalize_env_path(value)
        if not normalized:
            return None

        candidate = self._resolve_local_path(normalized)
        if candidate.is_file():
            return str(candidate.resolve())

        file_name = Path(normalized).name
        search_roots = (
            get_hashcat_wordlists_dir(),
            BASE_DIR,
            Path.cwd(),
        )
        for root in search_roots:
            if not root.exists():
                continue
            direct_path = root / normalized
            if direct_path.is_file():
                return str(direct_path.resolve())
            nested_path = next((path for path in root.rglob(file_name) if path.is_file()), None)
            if nested_path:
                return str(nested_path.resolve())
        return None

    def _resolve_local_path(self, value: str) -> Path:
        expanded = Path(os.path.expanduser(value))
        if expanded.is_absolute():
            return expanded
        base_dir_candidate = (BASE_DIR / expanded).resolve()
        if base_dir_candidate.exists():
            return base_dir_candidate
        cwd_candidate = (Path.cwd() / expanded).resolve()
        if cwd_candidate.exists():
            return cwd_candidate
        return base_dir_candidate

    def _read_result_lines(self) -> list[str]:
        if not self._result_file:
            return []
        result_path = Path(self._result_file)
        if not result_path.is_file():
            return []
        try:
            lines = [line.strip() for line in result_path.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip()]
        except OSError:
            return []
        return lines[-50:]

    def _optional_text(self, value: object) -> str | None:
        text = str(value).strip() if value is not None else ""
        return text or None

    def _remove_runtime_artifact(self, path: Path) -> None:
        try:
            if path.is_file():
                path.unlink()
        except OSError:
            return

    def _backfill_results_from_show(self) -> None:
        self._show_results_checked = True
        if self._read_result_lines():
            return
        if self._exit_code != 0 and not any("Use --show to display them." in line for line in self._output_tail):
            return
        if not self._binary_path or not self._hash_file or self._hash_mode is None or not self._result_file or not self._potfile_path:
            return

        binary_path = Path(self._binary_path)
        hash_file_path = Path(self._hash_file)
        result_file_path = Path(self._result_file)
        potfile_path = Path(self._potfile_path)
        if not binary_path.is_file() or not hash_file_path.is_file() or not potfile_path.is_file():
            return

        show_command = [
            str(binary_path),
            "-m",
            str(self._hash_mode),
            str(hash_file_path.resolve()),
            "--show",
            "-o",
            str(result_file_path.resolve()),
            "--outfile-format",
            "1,2",
            "--potfile-path",
            str(potfile_path.resolve()),
            "--logfile-disable",
        ]

        self._append_output_line("[show] 检测到结果可能已存在于 potfile，正在自动补跑 --show。")
        try:
            self._ensure_binary_ready(str(binary_path))
            completed = subprocess.run(
                show_command,
                cwd=str(binary_path.resolve().parent),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=60,
            )
            for line in completed.stdout.splitlines():
                cleaned = line.strip()
                if cleaned:
                    self._append_output_line(f"[show] {cleaned}")
        except (OSError, subprocess.SubprocessError) as exc:
            self._append_output_line(f"[show] 自动执行 --show 失败：{exc}")

    def _append_output_line(self, line: str) -> None:
        cleaned = line.strip()
        if cleaned:
            self._output_tail.append(cleaned)

    def _ensure_binary_ready(self, binary_path: str) -> None:
        if self._platform_key() == "windows":
            return
        path = Path(binary_path)
        current_mode = path.stat().st_mode
        executable_mode = current_mode | 0o111
        if executable_mode != current_mode:
            path.chmod(executable_mode)


hashcat_service = HashcatService()
