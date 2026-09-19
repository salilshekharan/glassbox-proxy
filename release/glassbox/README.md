# GlassBox Proxy managed image

Build from the root of this pinned GlassBox-owned fork:

```sh
docker build -f release/glassbox/Dockerfile -t glassbox-proxy:dev .
```

Run it as an explicit forward proxy. The Atlas API credential is injected at
runtime, never baked into an image or passed as a command-line value.

```sh
docker run --rm -p 8080:8080 \
  -e GLASSBOX_ATLAS_ENDPOINT=https://atlas.example/api/v1/atlas/gateway/inspect \
  -e GLASSBOX_ATLAS_API_KEY=replace-with-a-managed-atlas-api-key \
  glassbox-proxy:dev
```

The container starts fail-closed in `metadata_only` mode by default: HTTPS is
checked at `CONNECT`, then passed through without TLS decryption or client CA
trust. Plain HTTP is checked from its normal proxy request metadata. Mount
`/var/lib/glassbox-proxy` only when TLS inspection is explicitly enabled in a
later deployment phase. The image is not yet an
enterprise release: SBOM, image signing, HA, performance, recovery, and
security gates remain required by `GLASSBOX.md`.
