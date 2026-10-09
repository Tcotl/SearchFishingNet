"""SearchFishingNet 平台后端包。引导项目根目录进 sys.path 以导入 fishingnet 核心包。"""

import sys
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))
