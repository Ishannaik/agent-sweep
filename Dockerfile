# syntax=docker/dockerfile:1

# --- Build stage: produce a wheel from source -------------------------------
FROM python:3.13-slim AS build

WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY src ./src

RUN pip install --no-cache-dir --upgrade pip build \
    && python -m build --wheel --outdir /dist

# --- Runtime stage: install the wheel into a slim, non-root image ----------
FROM python:3.13-slim AS runtime

# ps is required for the process-running preflight check
# (agentsweep.preflight._list_process_cmdlines shells out to `ps`).
RUN apt-get update \
    && apt-get install -y --no-install-recommends procps \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm -rf /tmp/*.whl

# Run as a non-root user. agentsweep only ever reads/writes files under
# whatever directory you mount at runtime (e.g. your real $HOME's agent
# history) -- it never needs root inside the container.
RUN useradd --create-home --uid 1000 sweeper
USER sweeper
WORKDIR /home/sweeper

ENTRYPOINT ["agentsweep"]
CMD ["--help"]
