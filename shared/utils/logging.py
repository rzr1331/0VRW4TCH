import logging
from pathlib import Path

from shared.utils.env import env_value

_ROOT_DIR = Path(__file__).resolve().parents[2]
_DEFAULT_LOG_DIR = _ROOT_DIR / "data" / "logs"


def setup_logging(level: int = logging.INFO) -> None:
    """Configure logging to stdout + optional rotating file."""
    log_format = "%(asctime)s %(levelname)s [%(name)s] %(message)s"

    root = logging.getLogger()
    root.setLevel(level)

    # Avoid adding duplicate handlers on repeated calls
    if root.handlers:
        return

    # stdout
    console = logging.StreamHandler()
    console.setFormatter(logging.Formatter(log_format))
    root.addHandler(console)

    # file (opt-out via LOG_FILE=false)
    log_file_flag = (env_value("LOG_FILE", "true") or "true").lower()
    if log_file_flag in ("1", "true", "yes"):
        log_dir = Path(env_value("LOG_DIR", str(_DEFAULT_LOG_DIR)) or str(_DEFAULT_LOG_DIR))
        if not log_dir.is_absolute():
            log_dir = _ROOT_DIR / log_dir
        log_dir.mkdir(parents=True, exist_ok=True)

        log_path = log_dir / "overwatch.log"
        file_handler = logging.handlers.RotatingFileHandler(
            log_path, maxBytes=50 * 1024 * 1024, backupCount=5,
        )
        file_handler.setFormatter(logging.Formatter(log_format))
        root.addHandler(file_handler)


# RotatingFileHandler lives in logging.handlers
import logging.handlers  # noqa: E402
