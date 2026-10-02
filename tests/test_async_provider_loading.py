import asyncio

from blueberryme.async_runtime import AsyncPrivacyPipeline, AsyncProviderRegistry
from blueberryme.models import DataClass


def test_provider_is_loaded_only_when_requested(runtime, lease):
    created = []

    class Provider:
        async def enrich(self, protected_payload):
            assert protected_payload["name"].startswith("BBM1H.PERSON.")
            return {"done": True}

    def factory():
        created.append(True)
        return Provider()

    async def run():
        registry = AsyncProviderRegistry()
        registry.register("risk", factory)
        pipeline = AsyncPrivacyPipeline(runtime, registry)
        assert registry.loaded("risk") is False
        result = pipeline.protect_record(
            {"name": "Max Mustermann"},
            {"name": DataClass.PERSON},
            lease,
            enrichers=("risk",),
        )
        assert result.protected["name"].startswith("BBM1H.PERSON.")
        await asyncio.gather(*result.enrichment_tasks)
        assert registry.loaded("risk") is True

    asyncio.run(run())
    assert created == [True]
