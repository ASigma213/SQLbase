"""
Security filter stubs for intercepting filter pattern. Cross-platform.
"""
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional


class BaseFilter(ABC):
    @abstractmethod
    def apply(self, data: Any) -> Any:
        pass

    @abstractmethod
    def name(self) -> str:
        pass


class SQLInjectionFilter(BaseFilter):
    def name(self) -> str:
        return "SQLi"

    def apply(self, data: Any) -> Any:
        if isinstance(data, str):
            return data.replace("'", "''").replace("\\", "\\\\")
        if isinstance(data, dict):
            return {k: self.apply(v) for k, v in data.items()}
        if isinstance(data, (list, tuple)):
            return type(data)(self.apply(x) for x in data)
        return data


class XSSFilter(BaseFilter):
    def name(self) -> str:
        return "XSS"

    def apply(self, data: Any) -> Any:
        if isinstance(data, str):
            return (
                data.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace('"', "&quot;")
                .replace("'", "&#x27;")
            )
        if isinstance(data, dict):
            return {k: self.apply(v) for k, v in data.items()}
        if isinstance(data, (list, tuple)):
            return type(data)(self.apply(x) for x in data)
        return data


class CommandInjectionFilter(BaseFilter):
    def name(self) -> str:
        return "CommandInjection"

    def apply(self, data: Any) -> Any:
        if isinstance(data, str):
            for char in [";", "|", "&", "$", "`", "\n", "\r"]:
                data = data.replace(char, "")
            return data
        if isinstance(data, dict):
            return {k: self.apply(v) for k, v in data.items()}
        if isinstance(data, (list, tuple)):
            return type(data)(self.apply(x) for x in data)
        return data
