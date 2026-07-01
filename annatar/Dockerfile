FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml .
COPY annatar/ annatar/
COPY scripts/ scripts/
COPY technique_catalog.yaml .

# The campaign planner/synthesizer reads the shared technique catalog at repo root.

RUN pip install --no-cache-dir -e ".[annatar]"

# Run as the host operator's UID/GID (injected by `make build` via `id -u`/`id -g`) so
# state written to the bind-mounted ~/.annatar is owned by the operator, not root. HOME
# stays /root (chowned) so mount targets and shell init-files keep working unchanged.
# Building as root (UID=0) falls back to the historical root image.
ARG UID=1001
ARG GID=1001
RUN groupadd -o -g "$GID" app && \
    useradd -o -u "$UID" -g "$GID" -d /root -s /bin/bash app && \
    chown -R "$UID:$GID" /root /app
ENV HOME=/root
USER app

CMD ["annatar"]
