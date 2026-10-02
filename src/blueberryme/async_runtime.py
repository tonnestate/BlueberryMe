from __future__ import annotations

import asyncio
from copy import deepcopy
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Protocol

from .models import DataClass
from .runtime import BlueberryRuntime


class AsyncEnricher(Protocol):
    async def enrich(self, protected_payload: dict[str, Any]) -> Any: ...


Factory = Callable[[], AsyncEnricher | Awaitable[AsyncEnricher]]


class AsyncProviderRegistry:
    """Lazy-load optional providers. They receive protected payloads only."""

    def __init__(self) -> None:
        self._factories: dict[str, Factory] = {}
        self._instances: dict[str, AsyncEnricher] = {}
        self._locks: dict[str, asyncio.Lock] = {}

    def register(self, name: str, factory: Factory) -> None:
        if not name:
            raise ValueError("provider name is required")
        self._factories[name] = factory

    def loaded(self, name: str) -> bool:
        return name in self._instances

    async def get(self, name: str) -> AsyncEnricher:
        if name in self._instances:
            return self._instances[name]
        if name not in self._factories:
            raise KeyError("Unknown async provider")
        lock = self._locks.setdefault(name, asyncio.Lock())
        async with lock:
            if name in self._instances:
                return self._instances[name]
            instance = self._factories[name]()
            if hasattr(instance, "__await__"):
                instance = await instance  # type: ignore[assignment]
            self._instances[name] = instance  # type: ignore[assignment]
            return self._instances[name]

    def schedule(self, name: str, protected_payload: dict[str, Any]) -> asyncio.Task[Any]:
        async def runner() -> Any:
            provider = await self.get(name)
            return await provider.enrich(deepcopy(protected_payload))

        return asyncio.create_task(runner(), name=f"bbm:{name}")

    async def warm(self, *names: str) -> None:
        await asyncio.gather(*(self.get(name) for name in names))


@dataclass(frozen=True)
class AsyncProtection:
    protected: dict[str, Any]
    enrichment_tasks: tuple[asyncio.Task[Any], ...]


class AsyncPrivacyPipeline:
    """Enforce synchronously, enrich asynchronously."""

    def __init__(self, runtime: BlueberryRuntime, registry: AsyncProviderRegistry | None = None) -> None:
        self.runtime = runtime
        self.registry = registry or AsyncProviderRegistry()

    def protect_record(
        self,
        record: dict[str, Any],
        schema: dict[str, DataClass | str],
        lease_id: str,
        *,
        enrichers: tuple[str, ...] = (),
    ) -> AsyncProtection:
        protected = self.runtime.protect_record(record, schema, lease_id)
        tasks = tuple(self.registry.schedule(name, protected) for name in enrichers)
        return AsyncProtection(protected=protected, enrichment_tasks=tasks)
