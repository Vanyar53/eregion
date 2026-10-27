FROM python:3.12-slim

WORKDIR /app

# M-3 (#183): the dependencies come from the lock, every file checked against its hash
# (pip refuses any unpinned or unhashed requirement); the build backend too, so the project
# installs without fetching anything else. Before the code: a code change keeps this layer.
# Regenerate with `make lock` (docs/operations.md, « Verrou des dépendances »).
COPY requirements/glorfindel.txt requirements/glorfindel.txt
RUN pip install --no-cache-dir --require-hashes -r requirements/glorfindel.txt

COPY pyproject.toml .
COPY annatar/ annatar/
COPY eregion_core/ eregion_core/
COPY glorfindel/ glorfindel/
# The Eregion console (`eregion console`): its API and pages, served from this image.
COPY eregion_console/ eregion_console/
# The analysis AI (IA0): the watch on H0 writes the report of the campaigns Orodruin
# publishes (#167, analysis/hosted_report.py) — chromadb and litellm come with [glorfindel].
COPY analysis/ analysis/
# Shared technique catalog (Annatar↔Glorfindel contract) — root-level, consumed by
# detection_authoring.load_catalog(). Baked in so the image is self-contained; the
# compose mount overrides it for live edits.
COPY technique_catalog.yaml .

# The project alone: its dependencies are all above (--no-deps), nothing resolved here.
RUN pip install --no-cache-dir --no-deps --no-build-isolation -e .

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

# The reference deploy.sh built this image from (M-3), shown in the console's header. Last, so
# a new reference rebuilds no earlier layer; empty for a local `make build`.
ARG EREGION_REF=
ARG EREGION_REVISION=
ENV EREGION_REF=$EREGION_REF EREGION_REVISION=$EREGION_REVISION

CMD ["glorfindel"]
