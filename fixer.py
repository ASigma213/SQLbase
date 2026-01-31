"""
SQL injection code fixer. Supports Java and Python. Cross-platform.
"""
import re
from typing import Optional


class SqliCodeFixer:
    def fix_concatenation(self, code_snippet: str, language: str) -> str:
        language = (language or "").strip().lower()
        if language == "java":
            return self.fix_java_sqli(code_snippet)
        if language in ("python", "py"):
            return self.fix_python_sqli(code_snippet)
        return code_snippet

    def fix_java_sqli(self, code: str) -> str:
        # Pattern: String sql = "SELECT ..." + userInput;
        pattern = r'(\w+)\s*=\s*["\'](SELECT\s+.*?)["\']\s*\+\s*(\w+)'
        replacement = (
            r'String \1 = "\2 ?";\n'
            r'PreparedStatement stmt = conn.prepareStatement(\1);\n'
            r'stmt.setString(1, \3);'
        )
        result = re.sub(pattern, replacement, code, flags=re.IGNORECASE)
        # Also: "SELECT ..." + var + " ..."
        pattern2 = r'["\'](SELECT\s+.*?)\s*\+\s*(\w+)\s*\+\s*["\'](.*?)["\']'
        if not re.search(pattern2, result, re.IGNORECASE):
            return result
        result = re.sub(
            pattern2,
            r'"\1 ? \3"; PreparedStatement stmt = conn.prepareStatement(sql); stmt.setString(1, \2);',
            result,
            flags=re.IGNORECASE,
        )
        return result

    def fix_python_sqli(self, code: str) -> str:
        # cursor.execute("SELECT ... " + user_id)
        pattern = r'\.(execute|executemany)\s*\(\s*["\']([^"\']*?)["\']\s*\+\s*(\w+)'
        replacement = r'.\1("\2 %s", (\3,))'
        result = re.sub(pattern, replacement, code)
        # cursor.execute("SELECT ... %s" % user_id) -> parameterized
        pattern2 = r'\.(execute|executemany)\s*\(\s*["\']([^"\']*?)["\']\s*%\s*(\w+)'
        replacement2 = r'.\1("\2", (\3,))'
        result = re.sub(pattern2, replacement2, result)
        # f"SELECT ... {var}"
        pattern3 = r'\.(execute|executemany)\s*\(\s*f["\']([^"\']*)\{(\w+)\}([^"\']*)["\']\s*\)'
        replacement3 = r'.\1("\2%s\3", (\4,))'
        result = re.sub(pattern3, replacement3, result)
        return result
