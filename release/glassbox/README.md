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

The container starts fail-closed by default and exits before binding if its
endpoint or API-key environment variable is absent. Mount
`/var/lib/glassbox-proxy` to retain the generated CA only when TLS inspection
is explicitly enabled in a later deployment phase. The image is not yet an
enterprise release: SBOM, image signing, HA, performance, recovery, and
security gates remain required by `GLASSBOX.md`.
