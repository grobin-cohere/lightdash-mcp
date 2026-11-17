# Base images pinned by digest. To update one, take the new digest from `docker buildx imagetools inspect <image>`.
FROM ghcr.io/astral-sh/uv:python3.15-trixie-slim@sha256:053efa9652f89ac056731b55b4912131fca1dd644d472b6a40340a62f183a5db AS build
WORKDIR /app
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=0
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --locked --no-dev --no-install-project
COPY src ./src
RUN uv sync --locked --no-dev --no-editable

FROM python:3.15-slim-trixie@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928
COPY --from=build /app/.venv /app/.venv
# 0.0.0.0 is right with -p port mapping. With network_mode host, set HOST=127.0.0.1 (docs/configuration.md).
ENV PATH=/app/.venv/bin:$PATH HOST=0.0.0.0
USER nobody
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s CMD ["python", "-c", "import os, urllib.request; urllib.request.urlopen(f'http://127.0.0.1:{os.environ.get(\"PORT\", \"8000\")}/health', timeout=4)"]
CMD ["lightdash-mcp"]
