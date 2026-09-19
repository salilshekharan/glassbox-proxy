"""Bounded request-policy bridge from GlassBox Proxy to GlassBox Atlas.

This addon intentionally starts with metadata-only enforcement. It never sends
request bodies, query strings, cookies, authorization headers, or the Atlas API
key to Atlas audit payloads. TLS interception remains a deployment decision;
the addon only sees HTTPS request paths after an administrator has explicitly
enabled the relevant mitmproxy mode and client trust configuration.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import time
import uuid
from collections import deque
from collections.abc import Mapping
from typing import Any
from typing import NamedTuple
from typing import Protocol
from urllib import error
from urllib import request
from urllib.parse import urlsplit
from urllib.parse import urlunsplit

from mitmproxy import ctx
from mitmproxy import http
from mitmproxy.exceptions import OptionsError

_SAFE_REQUEST_HEADERS = frozenset(
    {"accept", "content-length", "content-type", "user-agent"}
)
_BLOCKING_ACTIONS = frozenset({"block", "require_review"})


class AtlasClientError(RuntimeError):
    """Atlas cannot provide a valid policy decision for this request."""


class AtlasDecision(NamedTuple):
    """The subset of an Atlas decision needed at the proxy enforcement point."""

    action: str
    request_id: str


class AtlasInspectionClient(Protocol):
    """Transport boundary that keeps mitmproxy hooks testable and replaceable."""

    async def inspect(self, payload: Mapping[str, Any]) -> AtlasDecision: ...


class UrllibAtlasInspectionClient:
    """Small standard-library client with certificate verification left enabled."""

    def __init__(self, *, endpoint: str, api_key: str, timeout_seconds: float) -> None:
        self._endpoint = endpoint
        self._api_key = api_key
        self._timeout_seconds = timeout_seconds

    async def inspect(self, payload: Mapping[str, Any]) -> AtlasDecision:
        return await asyncio.to_thread(self._inspect_blocking, payload)

    def _inspect_blocking(self, payload: Mapping[str, Any]) -> AtlasDecision:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        api_request = request.Request(
            self._endpoint,
            data=body,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "X-API-Key": self._api_key,
            },
            method="POST",
        )
        try:
            with request.urlopen(
                api_request, timeout=self._timeout_seconds
            ) as response:
                if response.status != 200:
                    raise AtlasClientError(f"Atlas returned HTTP {response.status}")
                decoded = json.loads(response.read().decode("utf-8"))
        except error.URLError as exc:
            raise AtlasClientError("Atlas policy service is unavailable") from exc
        except json.JSONDecodeError as exc:
            raise AtlasClientError("Atlas returned an invalid policy response") from exc

        action = decoded.get("action")
        request_id = decoded.get("id")
        if not isinstance(action, str) or not isinstance(request_id, str):
            raise AtlasClientError("Atlas returned an incomplete policy response")
        return AtlasDecision(action=action, request_id=request_id)


class GlassBoxAtlasAddon:
    """Apply Atlas allow/block decisions before a proxied request is sent upstream."""

    def __init__(self, client: AtlasInspectionClient | None = None) -> None:
        self._client = client
        self._enforcement_mode = "enforce"
        self._control_version = 0
        self._control_checked_at = 0.0
        self._telemetry_checked_at = 0.0
        self._telemetry_task: asyncio.Task[None] | None = None
        self._forwarded = 0
        self._blocked = 0
        self._would_block = 0
        self._policy_errors = 0
        self._latencies_ms: deque[float] = deque(maxlen=256)

    def load(self, loader: Any) -> None:
        loader.add_option(
            name="glassbox_atlas_enabled",
            typespec=bool,
            default=False,
            help="Enable GlassBox Atlas request-policy enforcement.",
        )
        loader.add_option(
            name="glassbox_atlas_endpoint",
            typespec=str,
            default="",
            help="HTTPS Atlas /api/v1/atlas/gateway/inspect endpoint.",
        )
        loader.add_option(
            name="glassbox_atlas_api_key_env",
            typespec=str,
            default="GLASSBOX_ATLAS_API_KEY",
            help="Environment variable containing the Atlas API key; its value is never logged.",
        )
        loader.add_option(
            name="glassbox_atlas_timeout_seconds",
            # mitmproxy's script option parser supports scalar strings across
            # both the v12 pin and current development sources. Convert at the
            # boundary below instead of depending on its float parser.
            typespec=str,
            default="0.5",
            help="Bounded Atlas policy-decision timeout in seconds.",
        )
        loader.add_option(
            name="glassbox_atlas_fail_mode",
            typespec=str,
            default="closed",
            help="Policy service failure behavior: closed or open.",
        )
        loader.add_option(
            name="glassbox_atlas_source",
            typespec=str,
            default="glassbox-proxy",
            help="Non-secret source identity sent to Atlas.",
        )
        loader.add_option(
            name="glassbox_atlas_profile",
            typespec=str,
            default="quick",
            help="Atlas policy profile for metadata-only proxy enforcement.",
        )
        loader.add_option(
            name="glassbox_atlas_inspection_mode",
            typespec=str,
            default="metadata_only",
            help="HTTPS enforcement mode: metadata_only or tls_inspection.",
        )
        loader.add_option(name="glassbox_control_config_url", typespec=str, default="", help="Atlas signed proxy-control configuration endpoint.")
        loader.add_option(name="glassbox_control_token_env", typespec=str, default="GLASSBOX_PROXY_CONTROL_TOKEN", help="Environment variable containing the per-proxy control token.")
        loader.add_option(name="glassbox_control_poll_seconds", typespec=str, default="5", help="Signed control configuration polling interval in seconds.")
        loader.add_option(name="glassbox_control_telemetry_url", typespec=str, default="", help="Atlas authenticated proxy telemetry endpoint.")
        loader.add_option(name="glassbox_control_telemetry_seconds", typespec=str, default="5", help="Minimum telemetry publish interval in seconds.")

    def configure(self, updates: set[str]) -> None:
        if not {
            "glassbox_atlas_enabled",
            "glassbox_atlas_endpoint",
            "glassbox_atlas_timeout_seconds",
            "glassbox_atlas_fail_mode",
            "glassbox_atlas_inspection_mode",
        }.intersection(updates):
            return
        if (
            ctx.options.glassbox_atlas_enabled
            and not ctx.options.glassbox_atlas_endpoint
        ):
            raise OptionsError(
                "glassbox_atlas_endpoint is required when GlassBox Atlas is enabled"
            )
        try:
            timeout_seconds = float(ctx.options.glassbox_atlas_timeout_seconds)
        except (TypeError, ValueError) as exc:
            raise OptionsError(
                "glassbox_atlas_timeout_seconds must be a number"
            ) from exc
        if timeout_seconds <= 0:
            raise OptionsError(
                "glassbox_atlas_timeout_seconds must be greater than zero"
            )
        if ctx.options.glassbox_atlas_fail_mode not in {"closed", "open"}:
            raise OptionsError("glassbox_atlas_fail_mode must be closed or open")
        if ctx.options.glassbox_atlas_inspection_mode not in {
            "metadata_only",
            "tls_inspection",
        }:
            raise OptionsError(
                "glassbox_atlas_inspection_mode must be metadata_only or tls_inspection"
            )

    async def http_connect(self, flow: http.HTTPFlow) -> None:
        """Check an HTTPS tunnel before a client TLS session is established.

        ``metadata_only`` is the managed-image default. It provides hostname,
        port, method and source to Atlas, but neither requires client CA trust
        nor exposes the encrypted request path, headers, or body to the proxy.
        """
        if (
            not ctx.options.glassbox_atlas_enabled
            or ctx.options.glassbox_atlas_inspection_mode != "metadata_only"
            or flow.response is not None
        ):
            return
        await self._enforce(flow, self._connect_payload(flow))

    async def request(self, flow: http.HTTPFlow) -> None:
        if not ctx.options.glassbox_atlas_enabled or flow.response is not None:
            return
        # HTTPS is handled at CONNECT in metadata-only mode. The managed image
        # also configures mitmproxy passthrough for that mode, so this hook
        # never receives decrypted application traffic.
        if (
            flow.request.scheme == "https"
            and ctx.options.glassbox_atlas_inspection_mode == "metadata_only"
        ):
            return
        await self._enforce(flow, self._payload(flow))

    async def _enforce(self, flow: http.HTTPFlow, payload: Mapping[str, Any]) -> None:
        started_at = time.monotonic()
        await self._refresh_control_mode()
        if self._enforcement_mode == "bypass":
            flow.metadata["glassbox_atlas_mode"] = "bypass"
            self._record_telemetry("forwarded", started_at)
            return
        local_request_id = str(uuid.uuid4())
        try:
            decision = await self._inspection_client().inspect(payload)
        # The enforcement point must not leak an unexpected client/transport
        # exception into the proxy runtime. The configured fail mode owns every
        # inability to obtain a decision, including future transport adapters.
        except Exception:
            self._record_telemetry("policy_error", started_at)
            if ctx.options.glassbox_atlas_fail_mode == "closed":
                self._block(flow, request_id=local_request_id, service_unavailable=True)
                self._record_telemetry("blocked", started_at)
            else:
                self._record_telemetry("forwarded", started_at)
            return

        if decision.action in _BLOCKING_ACTIONS and self._enforcement_mode == "enforce":
            self._block(flow, request_id=decision.request_id, service_unavailable=False)
            self._record_telemetry("blocked", started_at)
        elif decision.action in _BLOCKING_ACTIONS:
            flow.metadata["glassbox_atlas_would_block"] = True
            self._record_telemetry("would_block", started_at)
            self._record_telemetry("forwarded", started_at)
        else:
            self._record_telemetry("forwarded", started_at)

    def _record_telemetry(self, outcome: str, started_at: float) -> None:
        """Record real enforcement outcomes without retaining request content."""
        if outcome == "forwarded":
            self._forwarded += 1
        elif outcome == "blocked":
            self._blocked += 1
        elif outcome == "would_block":
            self._would_block += 1
        elif outcome == "policy_error":
            self._policy_errors += 1
        self._latencies_ms.append((time.monotonic() - started_at) * 1_000)
        self._schedule_telemetry_publish()

    def _schedule_telemetry_publish(self) -> None:
        url = ctx.options.glassbox_control_telemetry_url
        if not url or self._telemetry_task is not None and not self._telemetry_task.done():
            return
        try:
            interval = float(ctx.options.glassbox_control_telemetry_seconds)
        except (TypeError, ValueError):
            return
        if interval <= 0 or time.monotonic() - self._telemetry_checked_at < interval:
            return
        self._telemetry_task = asyncio.create_task(self._publish_telemetry(url))

    async def _publish_telemetry(self, url: str) -> None:
        """Best-effort, authenticated telemetry; it can never delay egress."""
        self._telemetry_checked_at = time.monotonic()
        token = os.getenv(ctx.options.glassbox_control_token_env)
        if not token:
            return
        try:
            await asyncio.to_thread(self._post_telemetry, url, token, self._telemetry_payload())
        except Exception:
            # Retain counters in memory. The next bounded publish carries the
            # latest cumulative values when Atlas becomes reachable again.
            return

    def _telemetry_payload(self) -> dict[str, Any]:
        samples = sorted(self._latencies_ms)
        # Nearest-rank percentile: with four observed requests, p95 is the
        # slowest sample rather than the third sample.
        p95 = samples[max(0, (len(samples) * 95 + 99) // 100 - 1)] if samples else None
        return {
            "version": self._control_version,
            "mode": self._enforcement_mode,
            "forwarded": self._forwarded,
            "blocked": self._blocked,
            "would_block": self._would_block,
            "policy_errors": self._policy_errors,
            "p95_latency_ms": p95,
        }

    @staticmethod
    def _post_telemetry(url: str, token: str, payload: Mapping[str, Any]) -> None:
        telemetry_request = request.Request(
            url,
            data=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "X-GlassBox-Proxy-Token": token,
            },
            method="POST",
        )
        with request.urlopen(telemetry_request, timeout=2.0) as response:
            if response.status != 204:
                raise AtlasClientError(f"Atlas telemetry returned HTTP {response.status}")

    async def _refresh_control_mode(self) -> None:
        """Accept only an HMAC-authenticated, monotonically-versioned Atlas mode."""
        url = ctx.options.glassbox_control_config_url
        if not url or time.monotonic() - self._control_checked_at < float(ctx.options.glassbox_control_poll_seconds):
            return
        self._control_checked_at = time.monotonic()
        token = os.getenv(ctx.options.glassbox_control_token_env)
        if not token:
            return
        try:
            envelope = await asyncio.to_thread(self._fetch_control_config, url, token)
            config = envelope["config"]
            canonical = json.dumps(config, sort_keys=True, separators=(",", ":")).encode()
            expected = hmac.new(token.encode(), canonical, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expected, envelope["signature"]):
                raise AtlasClientError("Atlas control signature did not verify")
            mode = config.get("mode")
            version = config.get("version")
            if mode not in {"enforce", "monitor", "bypass"} or not isinstance(version, int):
                raise AtlasClientError("Atlas control configuration is invalid")
            if version >= self._control_version:
                self._enforcement_mode, self._control_version = mode, version
        except Exception:
            # Retain the last verified mode. A control-plane outage must never
            # turn an enforcing proxy into bypass mode.
            return

    @staticmethod
    def _fetch_control_config(url: str, token: str) -> dict[str, Any]:
        control_request = request.Request(url, headers={"Accept": "application/json", "X-GlassBox-Proxy-Token": token})
        with request.urlopen(control_request, timeout=2.0) as response:
            return json.loads(response.read().decode("utf-8"))

    @staticmethod
    def _connect_payload(flow: http.HTTPFlow) -> dict[str, Any]:
        host = flow.request.host
        port = flow.request.port or 443
        authority = host if port == 443 else f"{host}:{port}"
        return {
            "protocol": "https",
            "direction": "outbound",
            "source": ctx.options.glassbox_atlas_source,
            "destination": f"https://{authority}/",
            "method": "CONNECT",
            "headers": {},
            "profile": ctx.options.glassbox_atlas_profile,
            "tags": ["glassbox_proxy", "metadata_only", "connect"],
        }

    def _inspection_client(self) -> AtlasInspectionClient:
        if self._client is not None:
            return self._client
        api_key = os.getenv(ctx.options.glassbox_atlas_api_key_env)
        if not api_key:
            raise AtlasClientError("Atlas API key is unavailable")
        return UrllibAtlasInspectionClient(
            endpoint=ctx.options.glassbox_atlas_endpoint,
            api_key=api_key,
            timeout_seconds=float(ctx.options.glassbox_atlas_timeout_seconds),
        )

    @staticmethod
    def _payload(flow: http.HTTPFlow) -> dict[str, Any]:
        return {
            "protocol": "https" if flow.request.scheme == "https" else "http",
            "direction": "outbound",
            "source": ctx.options.glassbox_atlas_source,
            "destination": _destination_without_query(flow.request.pretty_url),
            "method": flow.request.method,
            "headers": {
                name.lower(): value
                for name, value in flow.request.headers.items(multi=True)
                if name.lower() in _SAFE_REQUEST_HEADERS
            },
            "profile": ctx.options.glassbox_atlas_profile,
            "tags": ["glassbox_proxy", "metadata_only"],
        }

    @staticmethod
    def _block(
        flow: http.HTTPFlow, *, request_id: str, service_unavailable: bool
    ) -> None:
        message = (
            "Blocked by GlassBox Atlas: policy service unavailable."
            if service_unavailable
            else "Blocked by GlassBox Atlas: egress policy denied this request."
        )
        body = json.dumps({"message": message, "request_id": request_id}).encode(
            "utf-8"
        )
        flow.response = http.Response.make(
            503 if service_unavailable else 403,
            body,
            {
                "Content-Type": "application/json; charset=utf-8",
                "Cache-Control": "no-store",
                "X-GlassBox-Request-Id": request_id,
            },
        )
        flow.metadata["glassbox_atlas_blocked"] = True
        flow.metadata["glassbox_atlas_request_id"] = request_id


def _destination_without_query(value: str) -> str:
    """Keep path-level policy useful without leaking query credentials or tokens."""

    parts = urlsplit(value)
    return urlunsplit((parts.scheme, parts.netloc, parts.path or "/", "", ""))


addons = [GlassBoxAtlasAddon()]
