FROM python:3.12-slim

WORKDIR /app

# M-3 (#183), HY1: the dependencies come from the lock, every file checked against its hash
# (pip refuses any unpinned or unhashed requirement); the build backend too, so the project
# installs without fetching anything else. litellm is in it: the campaign planner
# (`annatar campaign plan --llm`) needs it. Before the code: a code change keeps this layer.
# Regenerate with `make lock` (docs/operations.md, « Verrou des dépendances »).
COPY requirements/annatar.txt requirements/annatar.txt
RUN pip install --no-cache-dir --require-hashes -r requirements/annatar.txt

COPY pyproject.toml .
COPY annatar/ annatar/
# Gothmog (G0) shares this image: it is the injectors' image on Orodruin (make orodruin-push).
COPY gothmog/ gothmog/
COPY eregion_core/ eregion_core/
COPY analysis/ analysis/
COPY scripts/ scripts/
COPY technique_catalog.yaml .

# The campaign planner/synthesizer reads the shared technique catalog at repo root.

# The project alone: its dependencies are all above (--no-deps), nothing resolved here.
RUN pip install --no-cache-dir --no-deps --no-build-isolation -e .

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
