# GlassBox Atlas addon

The `atlas_addon.py` module makes GlassBox Proxy ask Atlas for a synchronous
policy decision before forwarding an HTTP request. It is metadata-only by
design: request bodies, query strings, cookies, authorization headers, and the
Atlas API key are not forwarded as inspection payloads.

## Local development run

Set the API key in the process environment, then load the addon with an
explicit HTTPS Atlas endpoint:

```powershell
$env:GLASSBOX_ATLAS_API_KEY = "replace-with-a-managed-atlas-api-key"
mitmdump -s glassbox_proxy/atlas_addon.py `
  --set glassbox_atlas_enabled=true `
  --set glassbox_atlas_endpoint=https://atlas.example/api/v1/atlas/gateway/inspect `
  --set glassbox_atlas_fail_mode=closed
```

The API key is resolved only from `GLASSBOX_ATLAS_API_KEY` by default. Do not
place it on the command line, in addon source, or in a versioned configuration
file. A deployment may select a different environment-variable *name* with
`glassbox_atlas_api_key_env`.

## Enforcement behavior

- `allow` and `warn`: the request continues.
- `block` and `require_review`: the proxy returns `403` with a JSON `Blocked by
  GlassBox Atlas` message and an `X-GlassBox-Request-Id` correlation header.
- Atlas unavailable with `closed`: the proxy returns `503` and a locally
  generated correlation ID.
- Atlas unavailable with `open`: the request continues. This must be an
  explicit enterprise policy decision, not a default.

TLS decryption, request/response body scanning, mTLS to Atlas, certificate
lifecycle management, and high-availability deployment are separate production
work items. This addon does not enable TLS interception by itself.
