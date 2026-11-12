"""
Base definition, registry, and schema helpers for SentryIP intelligence tools.
"""

from __future__ import annotations

import asyncio
from typing import Any, Callable, Coroutine, Dict, List, Optional
from pydantic import BaseModel
from sentryip.logging import logger


class ToolDefinition(BaseModel):
    name: str
    description: str
    input_schema: Dict[str, Any]
    required_api_key: Optional[str] = None
    timeout_seconds: float = 12.0


class ToolRegistry:
    """Registry holding all registered SentryIP tools and their execution handlers."""

    def __init__(self):
        self._tools: Dict[str, ToolDefinition] = {}
        self._handlers: Dict[str, Callable[[Dict[str, Any]], Coroutine[Any, Any, Dict[str, Any]]]] = {}

    def register(
        self,
        name: str,
        description: str,
        input_schema: Dict[str, Any],
        required_api_key: Optional[str] = None,
        timeout_seconds: float = 12.0,
    ):
        def decorator(func: Callable[[Dict[str, Any]], Coroutine[Any, Any, Dict[str, Any]]]):
            self._tools[name] = ToolDefinition(
                name=name,
                description=description,
                input_schema=input_schema,
                required_api_key=required_api_key,
                timeout_seconds=timeout_seconds,
            )
            self._handlers[name] = func
            return func
        return decorator

    def get_anthropic_tools(self) -> List[Dict[str, Any]]:
        """Return tool definitions in Anthropic Claude API format."""
        anthropic_tools = []
        for tool in self._tools.values():
            anthropic_tools.append({
                "name": tool.name,
                "description": tool.description,
                "input_schema": tool.input_schema,
            })
        return anthropic_tools

    async def execute(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        if name not in self._tools or name not in self._handlers:
            return {"error": f"Tool '{name}' is not registered."}

        tool_def = self._tools[name]
        handler = self._handlers[name]

        try:
            return await asyncio.wait_for(handler(arguments), timeout=tool_def.timeout_seconds)
        except asyncio.TimeoutError:
            logger.warning(f"Tool {name} timed out after {tool_def.timeout_seconds}s")
            return {"error": f"Tool '{name}' timed out after {tool_def.timeout_seconds} seconds."}
        except Exception as e:
            logger.error(f"Error executing tool {name}: {e}", exc_info=True)
            return {"error": f"Tool '{name}' failed: {str(e)}"}

    def get_definition(self, name: str) -> Optional[ToolDefinition]:
        return self._tools.get(name)


registry = ToolRegistry()

