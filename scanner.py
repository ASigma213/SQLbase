"""
SQL injection static scanner. Cross-platform: Linux, Windows, macOS.
Uses pathlib for portable paths.
"""
import re
from pathlib import Path
from typing import List, Dict, Any, Optional


class SQLInjectionScanner:
    def __init__(self) -> None:
        self.patterns = [
            (r"execute\s*\([^)]*\+[^)]*\)", "String concatenation in execute"),
            (r"\.(execute|executemany)\s*\([^)]*%\s*s", "%-format in query"),
            (r"\.(execute|executemany)\s*\([^)]*\.format\s*\(", "str.format in query"),
            (r'"(?:SELECT|INSERT|UPDATE|DELETE)\s+[^"]*\{[^}]*\}', "F-string in SQL"),
            (r"'(?:SELECT|INSERT|UPDATE|DELETE)\s+[^']*\{[^}]*\}", "F-string in SQL"),
            (r"query\s*=\s*[^;]+;\s*query\s*\+=", "Query built with +="),
            (r"Statement\.execute\s*\([^)]*\+", "Java statement concatenation"),
            (r"createStatement\s*\(\s*\)\s*\.\s*execute\s*\([^)]*\+", "Statement + string"),
            (r"raw\s*\(\s*[^)]*\+", "Raw query concatenation"),
            (r"\.format\s*\([^)]*\)\s*\)\s*\.(execute|query)", "Format then execute"),
        ]

    def scan_file(self, file_path: str | Path) -> List[Dict[str, Any]]:
        vulnerabilities: List[Dict[str, Any]] = []
        path = Path(file_path)
        if not path.exists():
            return vulnerabilities
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except (OSError, PermissionError):
            return vulnerabilities
        lines = text.splitlines()
        for i, line in enumerate(lines):
            for pattern, desc in self.patterns:
                if re.search(pattern, line, re.IGNORECASE | re.DOTALL):
                    vulnerabilities.append({
                        "line": i + 1,
                        "code": line.strip(),
                        "type": "SQL_INJECTION",
                        "description": desc,
                    })
                    break
        return vulnerabilities

    def scan_path(self, path: str | Path, extensions: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        path = Path(path).resolve()
        extensions = extensions or [".py", ".java", ".js", ".ts", ".php", ".rb", ".go", ".cs"]
        results: List[Dict[str, Any]] = []
        if path.is_file():
            for v in self.scan_file(path):
                v["file"] = str(path)
                results.append(v)
            return results
        for ext in extensions:
            for f in path.rglob(f"*{ext}"):
                try:
                    for v in self.scan_file(f):
                        v["file"] = str(f)
                        results.append(v)
                except (OSError, PermissionError):
                    continue
        return results
