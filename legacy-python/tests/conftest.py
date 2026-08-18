"""legacy-python/ 独立于仓库根目录后，tests/test_cve_replay.py 仍需 import 根目录 evals 包
（cve_replay.py 未随 gloscope/ 一起归档，继续留在 evals/ 供回归验证用，见迁移计划 §1/§6）。
"""

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
