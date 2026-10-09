"""平台一键启动：python backend/run.py （生产模式，托管前端构建产物）"""

import uvicorn

if __name__ == "__main__":
    uvicorn.run("app.main:app", host="0.0.0.0", port=8765, app_dir=".")
