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

    async def inspect(self, payload: Mapping[str, Any], api_key: str) -> AtlasDecision:
        self.payload = payload
        if isinstance(self.outcome, Exception):
            raise self.outcome
        return self.outcome


@pytest.mark.asyncio
async def test_allows_when_atlas_allows() -> None:
    client = StubClient(AtlasDecision(action="allow", request_id="atlas-allow"))
    addon = GlassBoxAtlasAddon(client)
    with taddons.context(addon) as tctx:
        tctx.configure(
            addon,
            glassbox_atlas_enabled=True,
            glassbox_atlas_endpoint="https://atlas.test/inspect",
            glassbox_atlas_inspection_mode="tls_inspection",
        )
        flow = tflow.tflow()
        flow.request.url = "https://agent.example/download?token=not-forwarded"
        flow.request.headers["Authorization"] = "Bearer not-forwarded"
        flow.request.headers["Content-Type"] = "application/json"
        flow.request.headers["X-GlassBox-API-Key"] = "gb_live_test"

        await addon.request(flow)

    assert flow.response is None
    assert client.payload is not None
    assert client.payload["destination"] == "https://agent.example/download"
    assert client.payload["headers"]["content-type"] == "application/json"
    assert "authorization" not in client.payload["headers"]
    assert "X-GlassBox-API-Key" not in flow.request.headers


@pytest.mark.asyncio
async def test_blocks_with_atlas_correlation_id() -> None:
    addon = GlassBoxAtlasAddon(
        StubClient(AtlasDecision(action="block", request_id="atlas-block-42"))
    )
    with taddons.context(addon) as tctx:
        tctx.configure(
            addon,
            glassbox_atlas_enabled=True,
            glassbox_atlas_endpoint="https://atlas.test/inspect",
            glassbox_atlas_inspection_mode="tls_inspection",
        )
        flow = tflow.tflow()
        flow.request.headers["X-GlassBox-API-Key"] = "gb_live_test"

        await addon.request(flow)

    assert flow.response.status_code == 403
    assert flow.response.headers["X-GlassBox-Request-Id"] == "atlas-block-42"
    assert "Blocked by GlassBox Atlas" in flow.response.text
    assert flow.metadata["glassbox_atlas_blocked"] is True


@pytest.mark.asyncio
async def test_fails_closed_when_atlas_is_unavailable() -> None:
    addon = GlassBoxAtlasAddon(StubClient(RuntimeError("unavailable")))
    with taddons.context(addon) as tctx:
        tctx.configure(
            addon,
            glassbox_atlas_enabled=True,
            glassbox_atlas_endpoint="https://atlas.test/inspect",
            glassbox_atlas_inspection_mode="tls_inspection",
        )
        flow = tflow.tflow()
        flow.request.headers["X-GlassBox-API-Key"] = "gb_live_test"

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
            glassbox_atlas_inspection_mode="tls_inspection",
        )
        flow = tflow.tflow()
        flow.request.headers["X-GlassBox-API-Key"] = "gb_live_test"

        await addon.request(flow)

    assert flow.response is None


@pytest.mark.asyncio
async def test_metadata_only_blocks_https_at_connect_without_a_path() -> None:
    addon = GlassBoxAtlasAddon(
        StubClient(AtlasDecision(action="block", request_id="connect-block"))
    )
    with taddons.context(addon) as tctx:
        tctx.configure(
            addon,
            glassbox_atlas_enabled=True,
            glassbox_atlas_endpoint="https://atlas.test/inspect",
        )
        flow = tflow.tflow()
        flow.request.method = "CONNECT"
        flow.request.host = "agent.example"
        flow.request.port = 443
        flow.request.path = "agent.example:443"
        flow.request.headers["Proxy-Authorization"] = "Bearer gb_live_test"

        await addon.http_connect(flow)

    assert flow.response.status_code == 403
    assert addon._client.payload["destination"] == "https://agent.example/"  # type: ignore[union-attr]
    assert addon._client.payload["method"] == "CONNECT"  # type: ignore[union-attr]


@pytest.mark.asyncio
async def test_metadata_only_does_not_inspect_decrypted_https_request() -> None:
    client = StubClient(AtlasDecision(action="allow", request_id="unused"))
    addon = GlassBoxAtlasAddon(client)
    with taddons.context(addon) as tctx:
        tctx.configure(
            addon,
            glassbox_atlas_enabled=True,
            glassbox_atlas_endpoint="https://atlas.test/inspect",
        )
        flow = tflow.tflow()
        flow.request.url = "https://agent.example/private/path?credential=not-inspected"

        await addon.request(flow)

    assert client.payload is None


def test_telemetry_payload_contains_only_cumulative_enforcement_metrics() -> None:
    addon = GlassBoxAtlasAddon()
    addon._forwarded = 7
    addon._blocked = 2
    addon._would_block = 3
    addon._policy_errors = 1
    addon._latencies_ms.extend([1.0, 5.0, 10.0, 40.0])

    assert addon._telemetry_payload() == {
        "version": 0,
        "mode": "per_key",
        "forwarded": 7,
        "blocked": 2,
        "would_block": 3,
        "policy_errors": 1,
        "p95_latency_ms": 40.0,
    }


@pytest.mark.asyncio
async def test_monitor_mode_forwards_a_denied_request_and_records_would_block() -> None:
    addon = GlassBoxAtlasAddon(StubClient(AtlasDecision(action="block", request_id="monitor-block", enforcement_mode="monitor")))
    with taddons.context(addon) as tctx:
        tctx.configure(addon, glassbox_atlas_enabled=True, glassbox_atlas_endpoint="https://atlas.test/inspect", glassbox_atlas_inspection_mode="tls_inspection")
        flow = tflow.tflow()
        flow.request.headers["X-GlassBox-API-Key"] = "gb_live_test"
        await addon.request(flow)

    assert flow.response is None
    assert addon._would_block == 1
    assert addon._forwarded == 1
    assert len(addon._latencies_ms) == 1


@pytest.mark.asyncio
async def test_missing_integration_key_is_blocked_before_atlas_is_called() -> None:
    client = StubClient(AtlasDecision(action="allow", request_id="unused"))
    addon = GlassBoxAtlasAddon(client)
    with taddons.context(addon) as tctx:
        tctx.configure(addon, glassbox_atlas_enabled=True, glassbox_atlas_endpoint="https://atlas.test/inspect", glassbox_atlas_inspection_mode="tls_inspection")
        flow = tflow.tflow()
        await addon.request(flow)

    assert flow.response.status_code == 401
    assert client.payload is None
