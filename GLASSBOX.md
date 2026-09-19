# GlassBox Proxy distribution boundary

## Purpose

This repository is the source repository for **GlassBox Proxy**, the
GlassBox-maintained proxy data-plane distribution used by GlassBox Atlas.
It is forked from [mitmproxy](https://github.com/mitmproxy/mitmproxy). Atlas
itself remains a separate control-plane repository.

## Initial source pin

| Field | Value |
|---|---|
| Upstream repository | `https://github.com/mitmproxy/mitmproxy` |
| Upstream release | `v12.2.3` |
| Upstream commit | `6c09d56e4c29a92f5ad01b03199977584b8ea14f` |
| Upstream license | MIT |

The existing `LICENSE` file and all upstream copyright and permission notices
must remain present in every source and binary distribution.

## Product ownership boundary

GlassBox owns the fork's changes, release process, signed artifacts, Atlas
integration, policy behavior, operational configuration, support lifecycle,
and enterprise documentation. mitmproxy remains third-party upstream software;
this repository must retain clear provenance and must not represent upstream
code as wholly GlassBox-authored.

## Release controls

No commit becomes a GlassBox Proxy release until it has:

1. an immutable source commit and container-image digest;
2. a software bill of materials and third-party notices;
3. a recorded upstream comparison and security-advisory review;
4. passing proxy protocol, Atlas contract, TLS, resource-isolation, load, and
   recovery tests; and
5. an approved rollback and supported-upgrade path.

## Current status

This fork is **not yet a production release**. Upstream characterizes
mitmproxy as an interactive inspection tool and does not treat denial-of-service
resilience as a security-vulnerability commitment. GlassBox Proxy must prove
its own concurrency, backpressure, high-availability, observability, and
incident-response requirements before it can be offered as the enterprise
default.

## Open release blocker

The current fork source reports `mitmproxy 13.0.0.dev0` when packaged, which
does not match the recorded v12.2.3 source pin above. Do not publish a
GlassBox Proxy release until the branch is reset to an independently verified
upstream commit or this provenance record is intentionally revised through the
release approval process.
