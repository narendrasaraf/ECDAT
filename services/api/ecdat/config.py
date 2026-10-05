from pathlib import Path
import os
import shutil

ROOT = Path(__file__).resolve().parents[3]
STATE = Path(os.getenv("ECDAT_STATE", str(ROOT / ".ecdat"))).resolve()
DATABASE_URL = os.getenv("ECDAT_DATABASE_URL", f"sqlite:///{STATE / 'ecdat.db'}")
PROFILE = os.getenv("ECDAT_PROFILE", "native-fixtures")
_bundled_node = Path.home() / '.cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin/node.exe'
NODE = os.getenv("ECDAT_NODE", str(_bundled_node) if os.name == 'nt' and _bundled_node.exists() else shutil.which('node') or 'node')
AI_PROVIDER = os.getenv("ECDAT_AI_PROVIDER", "ollama")
AI_MODEL = os.getenv("ECDAT_AI_MODEL", "qwen3:1.7b")
COOKIE_SECURE = os.getenv("ECDAT_COOKIE_SECURE", "0") == "1"
DEMO = os.getenv("ECDAT_DEMO", "0") == "1"
WORKER = os.getenv("ECDAT_WORKER", "0") == "1"
MEMORY_RESERVE_MB = int(os.getenv("ECDAT_MEMORY_RESERVE_MB", "350"))
STATE.mkdir(parents=True, exist_ok=True)
