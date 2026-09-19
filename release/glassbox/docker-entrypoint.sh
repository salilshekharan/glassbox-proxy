#!/bin/sh
set -eu

if [ "$#" -eq 0 ]; then
  set -- mitmdump
fi

if [ "$1" != "mitmdump" ]; then
  exec "$@"
fi

: "${GLASSBOX_ATLAS_ENABLED:=true}"
: "${GLASSBOX_ATLAS_FAIL_MODE:=closed}"
: "${GLASSBOX_ATLAS_TIMEOUT_SECONDS:=0.5}"
: "${GLASSBOX_ATLAS_INSPECTION_MODE:=metadata_only}"
: "${GLASSBOX_ATLAS_PROFILE:=quick}"
: "${GLASSBOX_ATLAS_SOURCE:=glassbox-proxy}"
: "${GLASSBOX_ATLAS_API_KEY_ENV:=GLASSBOX_ATLAS_API_KEY}"
: "${GLASSBOX_CONTROL_TOKEN_ENV:=GLASSBOX_PROXY_CONTROL_TOKEN}"
: "${GLASSBOX_CONTROL_POLL_SECONDS:=5}"
: "${GLASSBOX_PROXY_LISTEN_HOST:=0.0.0.0}"
: "${GLASSBOX_PROXY_LISTEN_PORT:=8080}"

if [ "$GLASSBOX_ATLAS_ENABLED" = "true" ]; then
  if [ -z "${GLASSBOX_ATLAS_ENDPOINT:-}" ]; then
    echo "GLASSBOX_ATLAS_ENDPOINT is required when GlassBox Atlas enforcement is enabled" >&2
    exit 64
  fi
  if ! printf '%s' "$GLASSBOX_ATLAS_API_KEY_ENV" | grep -Eq '^[A-Za-z_][A-Za-z0-9_]*$'; then
    echo "GLASSBOX_ATLAS_API_KEY_ENV must be a valid environment variable name" >&2
    exit 64
  fi
  atlas_key="$(printenv "$GLASSBOX_ATLAS_API_KEY_ENV" || true)"
  if [ -z "${atlas_key:-}" ]; then
    echo "Atlas API key environment variable is not set: $GLASSBOX_ATLAS_API_KEY_ENV" >&2
    exit 64
  fi
fi

mkdir -p "$HOME/.mitmproxy"
chown -R glassbox:glassbox "$HOME"

if [ "$GLASSBOX_ATLAS_INSPECTION_MODE" = "metadata_only" ]; then
  # CONNECT is evaluated by the add-on before mitmproxy selects this
  # passthrough layer. No client CA is needed and TLS is never decrypted.
  passthrough_args="--set ignore_hosts=.+"
else
  passthrough_args=""
fi

# shellcheck disable=SC2086
set -- "$@" $passthrough_args

exec gosu glassbox "$@" \
  --listen-host "$GLASSBOX_PROXY_LISTEN_HOST" \
  --listen-port "$GLASSBOX_PROXY_LISTEN_PORT" \
  --set "confdir=$HOME/.mitmproxy" \
  --set "block_global=false" \
  -s /opt/glassbox/atlas_addon.py \
  --set "glassbox_atlas_enabled=$GLASSBOX_ATLAS_ENABLED" \
  --set "glassbox_atlas_endpoint=${GLASSBOX_ATLAS_ENDPOINT:-}" \
  --set "glassbox_atlas_api_key_env=$GLASSBOX_ATLAS_API_KEY_ENV" \
  --set "glassbox_atlas_timeout_seconds=$GLASSBOX_ATLAS_TIMEOUT_SECONDS" \
  --set "glassbox_atlas_inspection_mode=$GLASSBOX_ATLAS_INSPECTION_MODE" \
  --set "glassbox_atlas_fail_mode=$GLASSBOX_ATLAS_FAIL_MODE" \
  --set "glassbox_atlas_source=$GLASSBOX_ATLAS_SOURCE" \
  --set "glassbox_atlas_profile=$GLASSBOX_ATLAS_PROFILE"
  --set "glassbox_control_config_url=${GLASSBOX_CONTROL_CONFIG_URL:-}" \
  --set "glassbox_control_token_env=$GLASSBOX_CONTROL_TOKEN_ENV" \
  --set "glassbox_control_poll_seconds=$GLASSBOX_CONTROL_POLL_SECONDS"
