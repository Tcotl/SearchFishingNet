"""任务与上传 API。"""

from __future__ import annotations

import asyncio
import json
import shutil
import time
from pathlib import Path

from fastapi import APIRouter, HTTPException, UploadFile, File
from fastapi.responses import StreamingResponse

from fishingnet import config as core_config

from .jobs import manager
from .tasks import TASK_REGISTRY, execute, resolve_upload, latest_crawl_output

router = APIRouter(prefix="/api/jobs", tags=["jobs"])

EXECUTOR = None  # ThreadPoolExecutor，启动时注入


def set_executor(ex) -> None:
    global EXECUTOR
    EXECUTOR = ex


@router.get("")
def list_jobs():
    return [j.to_dict(tail=5) for j in manager.list()]


@router.get("/{job_id}")
def get_job(job_id: str):
    job = manager.get(job_id)
    if not job:
        raise HTTPException(404, "任务不存在")
    return job.to_dict(tail=30)


@router.get("/{job_id}/events")
async def job_events(job_id: str):
    """SSE 实时进度流。"""
    job = manager.get(job_id)
    if not job:
        raise HTTPException(404, "任务不存在")

    async def gen():
        offset = 0
        idle = 0.0
        while True:
            offset, lines = manager.since(job, offset)
            for line in lines:
                yield f"data: {json.dumps({'line': line}, ensure_ascii=False)}\n\n"
            if job.status in ("success", "failed") and offset >= len(job.progress):
                yield f"data: {json.dumps({'done': True, 'status': job.status, 'error': job.error}, ensure_ascii=False)}\n\n"
                return
            await asyncio.sleep(0.5)
            idle += 0.5
            if idle > 7200:  # 2小时兜底断开
                return

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@router.post("")
async def create_job(body: dict):
    type_ = body.get("type", "")
    if type_ not in TASK_REGISTRY:
        raise HTTPException(400, f"未知任务类型: {type_}")

    params = dict(body.get("params") or {})
    if type_ == "ingest":
        name = params.get("file") or ""
        if name == "latest":
            latest = latest_crawl_output()
            if not latest:
                raise HTTPException(400, "没有可用的爬虫输出文件，请先采集或上传")
            params["file"] = latest
        else:
            params["file"] = str(resolve_upload(name))

    job = manager.create(type_, params)
    loop = asyncio.get_running_loop()
    loop.run_in_executor(EXECUTOR, execute, job)
    return job.to_dict(tail=0)


@router.post("/uploads")
async def upload(file: UploadFile = File(...)):
    updir = core_config.DATA_DIR / "uploads"
    updir.mkdir(parents=True, exist_ok=True)
    if not file.filename or not file.filename.endswith(".json"):
        raise HTTPException(400, "仅支持 .json 爬虫结果文件")
    dest = updir / f"{int(time.time())}_{Path(file.filename).name}"
    with open(dest, "wb") as f:
        shutil.copyfileobj(file.file, f)
    return {"filename": dest.name, "size": dest.stat().st_size}


@router.get("/uploads/list")
def list_uploads():
    updir = core_config.DATA_DIR / "uploads"
    if not updir.exists():
        return []
    return [{"filename": p.name, "size": p.stat().st_size, "mtime": p.stat().st_mtime}
            for p in sorted(updir.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)]
