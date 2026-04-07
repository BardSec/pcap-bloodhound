"""Application settings — industry pack toggles and persistence."""

import json
import logging
import os
import sys
from pathlib import Path

logger = logging.getLogger(__name__)

INDUSTRY_PACKS = {
    "k12": {
        "label": "K-12 Education",
        "description": "CIPA compliance, content filter bypass detection",
        "analyzers": ["content_filter_bypass", "cipa_compliance"],
    },
    "financial": {
        "label": "Financial Services",
        "description": "PCI DSS compliance, FIX/Bloomberg/SWIFT protocol detection",
        "analyzers": ["pci_compliance", "financial_protocols"],
    },
    "healthcare": {
        "label": "Healthcare",
        "description": "HIPAA compliance, medical device and protocol detection",
        "analyzers": ["hipaa_compliance", "medical_devices"],
    },
    "energy": {
        "label": "Energy / Utilities",
        "description": "ICS/SCADA protocol detection, IT/OT segmentation analysis",
        "analyzers": ["ics_scada", "it_ot_segmentation"],
    },
}

DEFAULT_SETTINGS = {
    "enabled_packs": ["k12"],
}


def _settings_path() -> Path:
    if sys.platform == "win32":
        base = Path(os.environ.get("APPDATA", Path.home()))
    else:
        base = Path.home() / ".config"
    return base / "pcap-detective" / "settings.json"


def load_settings() -> dict:
    path = _settings_path()
    try:
        if path.exists():
            with open(path) as f:
                data = json.load(f)
            merged = {**DEFAULT_SETTINGS, **data}
            merged["enabled_packs"] = [
                p for p in merged.get("enabled_packs", []) if p in INDUSTRY_PACKS
            ]
            return merged
    except Exception as e:
        logger.warning(f"Failed to load settings: {e}")
    return dict(DEFAULT_SETTINGS)


def save_settings(settings: dict) -> None:
    path = _settings_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json.dump(settings, f, indent=2)
    except Exception as e:
        logger.warning(f"Failed to save settings: {e}")


def get_enabled_analyzers() -> set[str]:
    settings = load_settings()
    enabled = set()
    for pack_id in settings.get("enabled_packs", []):
        pack = INDUSTRY_PACKS.get(pack_id)
        if pack:
            enabled.update(pack["analyzers"])
    return enabled


def is_pack_enabled(pack_id: str) -> bool:
    settings = load_settings()
    return pack_id in settings.get("enabled_packs", [])
