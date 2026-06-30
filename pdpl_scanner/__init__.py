"""
pdpl-scanner — entity-aware Saudi PDPL compliance scanner.

Public API:
    from pdpl_scanner import scan, EntityProfile
    from pdpl_scanner.report import to_json, to_markdown, to_sarif, to_html
"""
from .entity_profiles import EntityProfile
from .scanner import scan, ScanResult, Finding

__version__ = "1.1.0"
__all__ = ["scan", "ScanResult", "Finding", "EntityProfile", "__version__"]
