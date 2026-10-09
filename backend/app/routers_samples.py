"""样本分析 API：列表/详情/样本文件下载/人工上传。猎取通过任务 API（type=sample_hunt）。"""

from __future__ import annotations

import json
import re

from fastapi import APIRouter, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse

from fishingnet import intel
from fishingnet.sample_hunter import QUARANTINE_DIR, _safe_filename
from fishingnet.static_analysis import MAX_SAMPLE_SIZE, analyze_bytes

router = APIRouter(prefix="/api/samples", tags=["samples"])


@router.get("")
def list_samples():
    return {"items": intel.list_samples()}


@router.get("/{sha256}")
def get_sample(sha256: str):
    if not re.fullmatch(r"[0-9a-f]{64}", sha256):
        raise HTTPException(400, "非法哈希")
    sample = intel.get_sample(sha256)
    if not sample:
        raise HTTPException(404, "样本不存在")
    return sample


@router.get("/{sha256}/download")
def download_sample(sha256: str):
    """分析师取回隔离区样本（需自行妥善处置）。"""
    path = intel.sample_path(sha256)
    if not path:
        raise HTTPException(404, "隔离区无样本文件")
    return FileResponse(path, filename=path.name,
                        headers={"Content-Disposition": f"attachment; filename={path.name}"})


@router.post("/upload")
async def upload_sample(file: UploadFile = File(...), note: str = Form("")):
    """人工上传样本：哈希落盘隔离 + 静态分析，绝不在本机执行。

    AI 行为分析由前端紧接着创建 sample_analyze 任务（可在任务进度里观察）。
    note 可记录样本来源线索（如"XX 群流传"/"某站点下载"）。
    """
    name = _safe_filename(file.filename or "upload.bin")
    data = await file.read(MAX_SAMPLE_SIZE + 1)
    if len(data) > MAX_SAMPLE_SIZE:
        raise HTTPException(413, f"样本超过大小上限 {MAX_SAMPLE_SIZE // 1024 // 1024}MB")
    if len(data) < 10:
        raise HTTPException(400, "文件过小，非有效样本")

    report = analyze_bytes(name, data)
    sha = report["file"]["sha256"]
    sample_dir = QUARANTINE_DIR / sha
    sample_dir.mkdir(parents=True, exist_ok=True)
    (sample_dir / name).write_bytes(data)
    (sample_dir / "static_report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    duplicate = intel.get_sample(sha) is not None
    intel.upsert_sample({
        "sha256": sha,
        "md5": report["file"]["md5"],
        "sha1": report["file"]["sha1"],
        "source_domain": "manual",
        "source_url": (note or "").strip()[:300] or "(人工上传)",
        "file_name": name,
        "size": len(data),
        "ftype": report["file"]["type"],
        "status": "downloaded",
    }, report)

    return {
        "sha256": sha,
        "sha1": report["file"]["sha1"],
        "md5": report["file"]["md5"],
        "file_name": name,
        "size": len(data),
        "ftype": report["file"]["type"],
        "duplicate": duplicate,
        "static_report": report,
    }
