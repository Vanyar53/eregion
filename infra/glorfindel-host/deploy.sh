#!/bin/bash
# deploy.sh — on Glorfindel's VM (H0), in ~/eregion: deploy a named reference (M-3, #183).
#
#   make glorfindel-host-start [REF=v0.3.1|<commit>]    # sends this script over ssh
#
#   deploy.sh [REF]                  fetch, check out REF detached, build the image, start
#   deploy.sh --checkout-only [REF]  fetch and check out, nothing built or started
#   deploy.sh --show                 the reference the running watch was built from
#   deploy.sh --build-only REF [TAG] build eregion-glorfindel:REF (or :TAG) from the current
#                                    directory, which must be checked out at REF (the CD's own
#                                    worktree, H1): the running image and the checkout of
#                                    ~/eregion are not touched
#   deploy.sh --activate REF         check out REF, make eregion-glorfindel:REF the running
#                                    image and restart the services — no build: the image must
#                                    be there (a candidate the CD built, or the one before:
#                                    the rollback, H1). No pruning: until the health is green,
#                                    the image to go back to must stay. A failed git fetch is
#                                    tolerated: the reference is resolved locally (the rollback
#                                    must not depend on the network)
#   deploy.sh --prune REF...         remove the old images, keeping REF... and the three newest
#                                    (the CD calls it once the health is green: the new and the
#                                    one before)
#
# REF is a tag or a commit, never a branch: a branch moves, and H0 ran whatever had just
# been merged into main. Without REF, the latest `v*` tag (version order). The image carries
# the reference (labels org.opencontainers.image.version / .revision) — `--show`, and so
# `make glorfindel-host-status`, read it back from the running container. Each image is also
# tagged by its reference, and the three newest are kept, with the one running and the one
# before it: going back is a retag, not a build.
#
# The script comes from the operator's checkout, not the VM's: deploying an old tag (one
# from before this script) works the same. The CD (H1) runs its own installed copy, and
# holds ~/.eregion-deploy.lock for its whole pass: a deployment by hand meanwhile is refused.
set -euo pipefail
shopt -s inherit_errexit   # a failure inside $(…) stops the script, not only the subshell

IMAGE="${EREGION_IMAGE:-eregion-glorfindel}"
LABEL_REF="org.opencontainers.image.version"
LABEL_REV="org.opencontainers.image.revision"
KEEP_IMAGES=3

die() { echo "✗ $*" >&2; exit 1; }

# One deployment at a time: the CD (H1) takes the lock for its pass and tells this script
# so (EREGION_DEPLOY_LOCKED=1); by hand, the lock is taken here, or refused.
lock() {
  [ -n "${EREGION_DEPLOY_LOCKED:-}" ] && return 0
  exec 9>"$HOME/.eregion-deploy.lock"
  flock -n 9 || die "un déploiement est en cours (le CD de H0, H1) : rien n'est fait. Réessayer après, ou make glorfindel-host-cd-status."
}

# The ref to deploy → "<ref> <full commit>", or die. A tag (refs/tags/REF) or a hexadecimal
# commit id (7 to 40 digits) that the commit it names starts with. Anything else — main,
# origin/main, HEAD, HEAD~1, a name that is both — is refused.
resolve() {
  local ref="$1" commit
  case "$ref" in
    "" | -* | .* | *[!A-Za-z0-9._-]*) die "référence invalide : « $ref » (un tag ou un commit)" ;;
  esac
  if commit=$(git rev-parse -q --verify "refs/tags/$ref^{commit}" 2>/dev/null); then
    echo "$ref $commit"
    return
  fi
  if [[ "$ref" =~ ^[0-9a-f]{7,40}$ ]] \
      && commit=$(git rev-parse -q --verify "$ref^{commit}" 2>/dev/null) \
      && [[ "$commit" == "$ref"* ]]; then
    echo "$ref $commit"
    return
  fi
  if git show-ref -q --verify "refs/heads/$ref" || git show-ref -q --verify "refs/remotes/origin/$ref"; then
    die "« $ref » est une branche : elle bouge. Déployer un tag (v*) ou un commit."
  fi
  die "« $ref » n'est ni un tag ni un commit connu (après git fetch)."
}

latest_tag() {
  git tag -l 'v*' --sort=-v:refname | head -1
}

checkout() {
  local want="${1:-}" tolerant="${2:-}" expect="${3:-}" pair dirty rules
  if ! git fetch -q --tags --force origin; then
    [ -n "$tolerant" ] || die "git fetch a échoué : rien n'est déployé"
    echo "⚠ git fetch a échoué : la référence est résolue sur la VM" >&2
  fi
  if [ -z "$want" ]; then
    want=$(latest_tag)
    [ -n "$want" ] || die "aucun tag v* : préciser REF=<commit>"
  fi
  pair=$(resolve "$want")
  # The image was built from one commit (H1): a tag rewritten since names another — its compose,
  # its rules, its catalogue beside the old image. The image's own commit is checked out
  # instead, said; refused if the VM does not have it.
  if [ -n "$expect" ] && [ "${pair#* }" != "$expect" ]; then
    git cat-file -e "$expect^{commit}" 2>/dev/null || die "« $want » désigne maintenant ${pair#* }, son image a été construite depuis $expect, absent de la VM (tag réécrit) : rien n'a bougé"
    echo "⚠ « $want » désigne maintenant ${pair#* } (tag réécrit) : le commit de son image, $expect, est extrait" >&2
    pair="${pair% *} $expect"
  fi
  # A tracked file changed on the VM would ride along into the image: refused. The detection
  # rules too (P1): the containers no longer write them (mounted read-only) — approved rules
  # live in the client's layer, ~/.glorfindel/client_rules.yaml, which no checkout touches.
  # A rules file modified on the VM holds rules approved before P1: to migrate first, said
  # with what to do, before anything moves.
  dirty=$(git status --porcelain --untracked-files=no | awk '{print $NF}')
  rules=$(echo "$dirty" | grep '^glorfindel/rules/' || true)
  [ -z "$rules" ] || die "$(echo "$rules" | tr '\n' ' ')— modifié sur la VM (règles approuvées avant P1) : rien n'est déployé. Les migrer vers la couche du client (~/.glorfindel/client_rules.yaml) : infra/glorfindel-host/README.md, « Migrer les règles approuvées vers la couche du client ». Jamais git checkout -- glorfindel/rules : il les efface."
  [ -z "$dirty" ] || die "fichiers suivis modifiés sur la VM (rien n'est déployé) : $(echo "$dirty" | tr '\n' ' ')"
  git -c advice.detachedHead=false checkout -q --detach "${pair#* }"
  echo "$pair"
}

# Build from the current directory, tagged by its reference (or by NAME); `latest` also makes
# it the image compose runs (the deployment by hand), never for the CD's candidate.
build() {
  local ref="$1" commit="$2" latest="${3:-}" name="${4:-$1}"
  local tags=(-t "$IMAGE:$name")
  [ -n "$latest" ] && tags+=(-t "$IMAGE")
  # The labels for `--show`; the build-args so the console can say what it runs (its header).
  docker build --build-arg UID="$(id -u)" --build-arg GID="$(id -g)" \
    --build-arg "EREGION_REF=$ref" --build-arg "EREGION_REVISION=$commit" \
    --label "$LABEL_REF=$ref" --label "$LABEL_REV=$commit" \
    -f glorfindel/Dockerfile "${tags[@]}" .
}

start() {
  docker compose --profile bot up -d watch war-room bot
}

# The three newest images by reference stay, and every one named (the running one, the one
# before): going back is a retag. Older ones go, then the dangling layers.
prune() {
  local n=0 tag k kept
  while read -r tag; do
    [ -z "$tag" ] || [ "$tag" = "latest" ] || [ "$tag" = "<none>" ] && continue
    n=$((n + 1))
    kept=""
    for k in "$@"; do [ "$tag" = "$k" ] && kept=1; done
    [ -n "$kept" ] && continue
    [ "$n" -le "$KEEP_IMAGES" ] && continue
    docker image rm "$IMAGE:$tag" >/dev/null 2>&1 || true
  done < <(docker image ls "$IMAGE" --format '{{.CreatedAt}}\t{{.Tag}}' | sort -r | cut -f2)
  docker image prune -f >/dev/null
}

running_ref() {
  docker inspect -f "{{index .Config.Labels \"$LABEL_REF\"}}" eregion-watch 2>/dev/null || true
}

show() {
  local ref rev head notes="" mark="✓"
  ref=$(docker inspect -f "{{index .Config.Labels \"$LABEL_REF\"}}" eregion-watch 2>/dev/null || true)
  rev=$(docker inspect -f "{{index .Config.Labels \"$LABEL_REV\"}}" eregion-watch 2>/dev/null || true)
  head=$(git rev-parse HEAD 2>/dev/null || true)
  if [ -z "$ref" ] || [ "$ref" = "<no value>" ]; then
    echo "  ⚠ référence déployée : inconnue (image sans référence) — checkout ${head:0:12}"
    return 0
  fi
  if [ "$rev" != "$head" ]; then
    mark="⚠"; notes=" — le checkout est ailleurs (${head:0:12}) : redéployer"
  fi
  if git symbolic-ref -q HEAD >/dev/null; then
    mark="⚠"; notes="$notes — checkout sur une branche"
  fi
  echo "  $mark référence déployée : $ref (${rev:0:12})$notes"
}

case "${1:-}" in
  --show)
    show ;;
  --checkout-only)
    lock
    checkout "${2:-}" ;;
  --build-only)
    [ -n "${2:-}" ] || die "--build-only REF : la référence manque"
    name="${3:-$2}"
    case "$name" in -* | .* | *[!A-Za-z0-9._-]*) die "nom d'image invalide : « $name »" ;; esac
    pair=$(resolve "$2")
    [ "$(git rev-parse HEAD)" = "${pair#* }" ] || die "le répertoire n'est pas au commit de « $2 » : rien n'est construit"
    build "${pair% *}" "${pair#* }" "" "$name"
    echo "✓ construite : $IMAGE:$name (${pair#* }) — rien n'a basculé" ;;
  --activate)
    [ -n "${2:-}" ] || die "--activate REF : la référence manque"
    lock
    docker image inspect "$IMAGE:$2" >/dev/null 2>&1 || die "pas d'image $IMAGE:$2 sur la VM : rien n'a bougé"
    rev=$(docker image inspect -f "{{index .Config.Labels \"$LABEL_REV\"}}" "$IMAGE:$2" 2>/dev/null || true)
    [ "$rev" = "<no value>" ] && rev=""
    pair=$(checkout "$2" tolerant "$rev")
    docker tag "$IMAGE:${pair% *}" "$IMAGE"
    start
    echo "✓ activé : ${pair% *} (${pair#* })" ;;
  --prune)
    shift
    lock
    prune "$@"
    echo "✓ images gardées : les trois plus récentes et $*" ;;
  *)
    lock
    pair=$(checkout "${1:-}")
    before=$(running_ref)                  # the containers have not moved yet
    commit="${pair#* }"
    build "${pair% *}" "$commit" latest
    start
    prune "${pair% *}" "$before"
    echo "✓ déployé : ${pair% *} (${commit:0:12})" ;;
esac
