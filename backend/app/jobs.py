"""进程内任务管理器：采集/研判/单域判定等长任务，带进度行缓冲与 SSE 推送。"""

from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass, field

MAX_PROGRESS_LINES = 800


@dataclass
class Job:
    id: str
    type: str
    params: dict
    status: str = "pending"          # pending / running / success / failed
    created_at: float = field(default_factory=time.time)
    started_at: float | None = None
    finished_at: float | None = None
    progress: list = field(default_factory=list)   # 进度行（环形上限）
    _progress_offset: int = 0        # 已被 SSE 消费到的下标（per-subscriber 用 dict）
    result: dict | None = None
    error: str = ""

    def to_dict(self, tail: int = 0) -> dict:
        return {
            "id": self.id,
            "type": self.type,
            "params": self.params,
            "status": self.status,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "progress_lines": len(self.progress),
            "progress_tail": self.progress[-tail:],
            "result": self.result,
            "error": self.error,
        }


class JobManager:
    def __init__(self) -> None:
        self._jobs: dict[str, Job] = {}
        self._order: list[str] = []
        self._lock = threading.Lock()

    def create(self, type_: str, params: dict) -> Job:
        job = Job(id=uuid.uuid4().hex[:12], type=type_, params=params)
        with self._lock:
            self._jobs[job.id] = job
            self._order.append(job.id)
            self._order = self._order[-200:]  # 保留最近200个任务
        return job

    def get(self, job_id: str) -> Job | None:
        return self._jobs.get(job_id)

    def list(self) -> list[Job]:
        with self._lock:
            return [self._jobs[j] for j in reversed(self._order) if j in self._jobs]

    def log(self, job: Job, line: str) -> None:
        with self._lock:
            job.progress.append(line[:500])
            if len(job.progress) > MAX_PROGRESS_LINES:
                job.progress = job.progress[-MAX_PROGRESS_LINES // 2:]

    def since(self, job: Job, offset: int) -> tuple[int, list[str]]:
        """返回 (新offset, 增量行)。"""
        with self._lock:
            lines = job.progress[offset:offset + 200]
            return offset + len(lines), lines


manager = JobManager()
