# GlassBox Proxy managed data-plane image.
# Build from the repository root:
#   docker build -f release/glassbox/Dockerfile -t glassbox-proxy:dev .
FROM python:3.14-slim-trixie AS builder

WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY mitmproxy ./mitmproxy
COPY glassbox_proxy ./glassbox_proxy

# Build a wheel from the pinned fork. Runtime installation is then offline and
# contains exactly the dependency set resolved during this image build.
RUN pip wheel --wheel-dir /wheels .

FROM python:3.14-slim-trixie

LABEL org.opencontainers.image.title="GlassBox Proxy" \
      org.opencontainers.image.description="GlassBox Atlas managed egress data plane" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.source="https://github.com/salilshekharan/glassbox-proxy"

RUN apt-get update \
    && apt-get install -y --no-install-recommends gosu \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 glassbox \
    && useradd --uid 10001 --gid glassbox --home-dir /var/lib/glassbox-proxy --create-home --shell /usr/sbin/nologin glassbox

COPY --from=builder /wheels /wheels
RUN pip install --no-index --find-links=/wheels mitmproxy \
    && rm -rf /wheels

COPY glassbox_proxy/atlas_addon.py /opt/glassbox/atlas_addon.py
COPY release/glassbox/docker-entrypoint.sh /usr/local/bin/glassbox-entrypoint
# Keep the image runnable when the source tree was checked out on Windows.
RUN sed -i 's/\r$//' /usr/local/bin/glassbox-entrypoint \
    && chmod 0555 /usr/local/bin/glassbox-entrypoint \
    && chown -R glassbox:glassbox /opt/glassbox /var/lib/glassbox-proxy

ENV HOME=/var/lib/glassbox-proxy \
    GLASSBOX_PROXY_LISTEN_HOST=0.0.0.0 \
    GLASSBOX_PROXY_LISTEN_PORT=8080 \
    GLASSBOX_ATLAS_ENABLED=true \
    GLASSBOX_ATLAS_FAIL_MODE=closed \
    GLASSBOX_ATLAS_TIMEOUT_SECONDS=0.5 \
    GLASSBOX_ATLAS_INSPECTION_MODE=metadata_only \
    GLASSBOX_ATLAS_PROFILE=quick \
    GLASSBOX_ATLAS_SOURCE=glassbox-proxy

VOLUME ["/var/lib/glassbox-proxy"]
EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/glassbox-entrypoint"]
CMD ["mitmdump"]
