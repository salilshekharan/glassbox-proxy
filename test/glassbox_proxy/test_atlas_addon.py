from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import pytest

from glassbox_proxy.atlas_addon import AtlasClientError
from glassbox_proxy.atlas_addon import AtlasDecision
from glassbox_proxy.atlas_addon import GlassBoxAtlasAddon
from mitmproxy.test import taddons
from mitmproxy.test import tflow


class StubClient:
    def __init__(self, outcome: AtlasDecision | Exception) -> None:
        self.outcome = outcome
        self.payload: Mapping[str, Any] | None = None

    async def inspect(self, payload: Mapping[str, Any]) -> AtlasDecision:
        self.payload = payload
        if isinstance(self.outcome, Exception):
            raise self.outcome
        return self.outcome


@pytest.mark.asyncio
async def test_allows_when_atlas_allows() -> None:
    client = StubClient(AtlasDecision(action="allow", request_id="atlas-allow"))
    addon = GlassBoxAtlasAddon(client)
    with taddons.context(addon) as tctx:
        tctx.configure(addon, glassbox_atlas_enabled=True, glassbox_atlas_endpoint="https://atlas.test/inspect")
        flow = tflow.tflow()
        flow.request.url = "https://agent.example/download?token=not-forwarded"
        flow.request.headers["Authorization"] = "Bearer not-forwarded"
        flow.request.headers["Content-Type"] = "application/json"

        await addon.request(flow)

    assert flow.response is None
    assert client.payload is not None
    assert client.payload["destination"] == "https://agent.example/download"
    assert client.payload["headers"]["content-type"] == "application/json"
    assert "authorization" not in client.payload["headers"]


@pytest.mark.asyncio
async def test_blocks_with_atlas_correlation_id() -> None:
    addon = GlassBoxAtlasAddon(StubClient(AtlasDecision(action="block", request_id="atlas-block-42")))
    with taddons.context(addon) as tctx:
        tctx.configure(addon, glassbox_atlas_enabled=True, glassbox_atlas_endpoint="https://atlas.test/inspect")
        flow = tflow.tflow()

        await addon.request(flow)

    assert flow.response.status_code == 403
    assert flow.response.headers["X-GlassBox-Request-Id"] == "atlas-block-42"
    assert "Blocked by GlassBox Atlas" in flow.response.text
    assert flow.metadata["glassbox_atlas_blocked"] is True


@pytest.mark.asyncio
async def test_fails_closed_when_atlas_is_unavailable() -> None:
    addon = GlassBoxAtlasAddon(StubClient(RuntimeError("unavailable")))
    with taddons.context(addon) as tctx:
        tctx.configure(addon, glassbox_atlas_enabled=True, glassbox_atlas_endpoint="https://atlas.test/inspect")
        flow = tflow.tflow()

        await addon.request(flow)

    assert flow.response.status_code == 503
    assert "Blocked by GlassBox Atlas" in flow.response.text


@pytest.mark.asyncio
async def test_fails_open_when_configured() -> None:
    addon = GlassBoxAtlasAddon(StubClient(AtlasClientError("unavailable")))
    with taddons.context(addon) as tctx:
        tctx.configure(
            addon,
            glassbox_atlas_enabled=True,
            glassbox_atlas_endpoint="https://atlas.test/inspect",
            glassbox_atlas_fail_mode="open",
        )
        flow = tflow.tflow()

        await addon.request(flow)

    assert flow.response is None
