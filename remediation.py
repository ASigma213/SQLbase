"""
Remediation knowledge base for SQL injection and related fixes. Cross-platform.
"""
from typing import Dict, Any, List


class RemediationKnowledgeBase:
    def __init__(self) -> None:
        self.patterns: Dict[str, Dict[str, Dict[str, Any]]] = {
            "SQL_INJECTION": {
                "java": {
                    "solution": "Use PreparedStatement",
                    "example": 'String sql = "SELECT * FROM users WHERE id = ?";',
                    "libraries": ["java.sql.PreparedStatement"],
                    "extra": "stmt.setString(1, userInput);",
                },
                "python": {
                    "solution": "Use parameterized queries",
                    "example": 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
                    "libraries": ["psycopg2", "sqlite3", "SQLAlchemy", "mysql.connector"],
                    "extra": "Never use % or .format() on the query string; pass params as second argument.",
                },
                "php": {
                    "solution": "Use PDO prepared statements",
                    "example": '$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?"); $stmt->execute([$id]);',
                    "libraries": ["PDO", "mysqli"],
                },
                "csharp": {
                    "solution": "Use parameterized SqlCommand",
                    "example": 'cmd.CommandText = "SELECT * FROM users WHERE id = @id"; cmd.Parameters.AddWithValue("@id", id);',
                    "libraries": ["System.Data.SqlClient"],
                },
            },
            "XSS": {
                "python": {
                    "solution": "Escape output and use CSP",
                    "example": "from markupsafe import escape; escape(user_input)",
                    "libraries": ["markupsafe", "bleach"],
                },
                "java": {
                    "solution": "Use OWASP Java Encoder",
                    "example": "Encoder.forHtml(userInput)",
                    "libraries": ["org.owasp.encoder"],
                },
            },
            "COMMAND_INJECTION": {
                "python": {
                    "solution": "Use subprocess with list args, never shell=True with user input",
                    "example": "subprocess.run([\"ls\", \"-la\"], capture_output=True)",
                    "libraries": ["subprocess"],
                },
            },
        }

    def get_remediation(
        self, vulnerability_type: str, language: str
    ) -> Dict[str, Any]:
        return (
            self.patterns.get(vulnerability_type, {})
            .get(language, {})
            .copy()
            or {}
        )

    def get_languages_for_type(self, vulnerability_type: str) -> List[str]:
        return list(self.patterns.get(vulnerability_type, {}).keys())
