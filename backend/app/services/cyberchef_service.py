import os
from pathlib import Path


class CyberChefService:
    def __init__(self) -> None:
        self.default_dir = Path(__file__).resolve().parents[3] / "frontend" / "public" / "cyberchef"

    def get_directory(self) -> Path:
        configured = os.getenv("CYBERCHEF_DIR", "").strip()
        if configured:
            return Path(configured)
        return self.default_dir

    def is_available(self) -> bool:
        directory = self.get_directory()
        return directory.is_dir() and (directory / "CyberChef.html").is_file()

    def get_public_url(self) -> str:
        return "/cyberchef/CyberChef.html"


cyberchef_service = CyberChefService()
