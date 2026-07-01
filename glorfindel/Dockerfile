FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml .
COPY annatar/ annatar/
COPY glorfindel/ glorfindel/
# Shared technique catalog (Annatar↔Glorfindel contract) — root-level, consumed by
# detection_authoring.load_catalog(). Baked in so the image is self-contained; the
# compose mount overrides it for live edits.
COPY technique_catalog.yaml .

RUN pip install --no-cache-dir -e ".[glorfindel,war-room]"

# `gf` alias for interactive shells — works for `docker exec -it <c> bash` and the
# compose container, independent of any host-mounted ~/.glorfindel/.bashrc.
RUN echo "alias gf='glorfindel'" >> /etc/bash.bashrc

# Run as the host operator's UID/GID (injected by `make build` via `id -u`/`id -g`) so
# state written to the bind-mounted ~/.glorfindel / ~/.cache/chroma / ./runs is owned by
# the operator, not root — otherwise the local `glorfindel` CLI can't mutate files the
# container wrote (PermissionError on reset/unblock). The user's HOME stays /root
# (chowned to it) so every mount target, shell init-file and HOME-writing lib keeps
# working unchanged. Building as root (UID=0) falls back to the historical root image.
ARG UID=1001
ARG GID=1001
RUN groupadd -o -g "$GID" app && \
    useradd -o -u "$UID" -g "$GID" -d /root -s /bin/bash app && \
    chown -R "$UID:$GID" /root /app
ENV HOME=/root
USER app

CMD ["glorfindel"]
