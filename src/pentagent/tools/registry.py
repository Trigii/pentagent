"""Tool registry — discovery for tools and future plugins."""
from __future__ import annotations

from typing import Type

from .base import Tool


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, Type[Tool]] = {}

    def register(self, cls: Type[Tool]) -> Type[Tool]:
        inst = cls()  # instantiating now so spec is present
        if not getattr(inst, "spec", None):
            raise ValueError(f"{cls.__name__} has no `spec` attribute")
        name = inst.spec.name
        if name in self._tools:
            raise ValueError(f"tool {name!r} already registered")
        self._tools[name] = cls
        return cls

    def get(self, name: str) -> Tool:
        if name not in self._tools:
            raise KeyError(f"unknown tool {name!r}; registered: {sorted(self._tools)}")
        return self._tools[name]()

    def names(self) -> list[str]:
        return sorted(self._tools)

    def all(self) -> list[Tool]:
        return [cls() for cls in self._tools.values()]


default_registry = ToolRegistry()


def register_tool(cls: Type[Tool]) -> Type[Tool]:
    return default_registry.register(cls)
