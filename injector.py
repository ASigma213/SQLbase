"""
Security pattern injector: applies intercepting filters and injects filter calls.
Cross-platform: uses pathlib for Linux, Windows, macOS.
"""
from pathlib import Path
from typing import Dict, Optional

from sqlbase.filters import (
    BaseFilter,
    SQLInjectionFilter,
    XSSFilter,
    CommandInjectionFilter,
)


class FilterManager:
    def __init__(self, filters: Dict[str, BaseFilter]) -> None:
        self.filters = filters

    def apply_all(self, data):
        for _name, f in self.filters.items():
            data = f.apply(data)
        return data


class SecurityPatternInjector:
    def __init__(self) -> None:
        self.filter_manager: Optional[FilterManager] = None

    def apply_intercepting_filter(self, project_path: str | Path) -> None:
        filters: Dict[str, BaseFilter] = {
            "SQLi": SQLInjectionFilter(),
            "XSS": XSSFilter(),
            "CommandInjection": CommandInjectionFilter(),
        }
        self.filter_manager = self.generate_filter_manager(filters)
        self.inject_filter_calls(Path(project_path))

    def generate_filter_manager(self, filters: Dict[str, BaseFilter]) -> FilterManager:
        return FilterManager(filters)

    def inject_filter_calls(self, project_path: Path) -> None:
        project_path = Path(project_path).resolve()
        if not project_path.exists():
            return
        # Write a small bootstrap module that projects can import to get FilterManager
        bootstrap_dir = project_path / ".security_filters"
        bootstrap_dir.mkdir(exist_ok=True)
        bootstrap_file = bootstrap_dir / "filter_manager.py"
        content = '''"""
Auto-generated security filter bootstrap. Cross-platform.
Import: from .security_filters.filter_manager import get_filter_manager
"""
from pathlib import Path

_filters = None

def get_filter_manager():
    global _filters
    if _filters is None:
        from sqlbase.filters import SQLInjectionFilter, XSSFilter, CommandInjectionFilter
        from sqlbase.injector import FilterManager
        _filters = FilterManager({
            "SQLi": SQLInjectionFilter(),
            "XSS": XSSFilter(),
            "CommandInjection": CommandInjectionFilter(),
        })
    return _filters

def apply_security_filters(data):
    return get_filter_manager().apply_all(data)
'''
        bootstrap_file.write_text(content, encoding="utf-8")
        init_file = bootstrap_dir / "__init__.py"
        init_file.write_text(
            "from .filter_manager import get_filter_manager, apply_security_filters\n",
            encoding="utf-8",
        )
