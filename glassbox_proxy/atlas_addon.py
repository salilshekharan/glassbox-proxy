"""Bounded request-policy bridge from GlassBox Proxy to GlassBox Atlas.

This addon intentionally starts with metadata-only enforcement. It never sends
request bodies, query strings, cookies, authorization headers, or the Atlas API
key to Atlas audit payloads. TLS interception remains a deployment decision;
the addon only sees HTTPS request paths after an administrator has explicitly
enabled the relevant mitmproxy mode and client trust configuration.
"""

from __future__ import annotations

import asyncio
import json
import os
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
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


@dataclass(frozen=True)
class AtlasDecision:
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
            typespec=float,
            default=0.5,
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
        if ctx.options.glassbox_atlas_timeout_seconds <= 0:
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
        local_request_id = str(uuid.uuid4())
        try:
            decision = await self._inspection_client().inspect(payload)
        # The enforcement point must not leak an unexpected client/transport
        # exception into the proxy runtime. The configured fail mode owns every
        # inability to obtain a decision, including future transport adapters.
        except Exception:
            if ctx.options.glassbox_atlas_fail_mode == "closed":
                self._block(flow, request_id=local_request_id, service_unavailable=True)
            return

        if decision.action in _BLOCKING_ACTIONS:
            self._block(flow, request_id=decision.request_id, service_unavailable=False)

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
            timeout_seconds=ctx.options.glassbox_atlas_timeout_seconds,
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
