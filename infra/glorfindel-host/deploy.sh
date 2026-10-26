#!/bin/bash
# deploy.sh — on Glorfindel's VM (H0), in ~/eregion: deploy a named reference (M-3, #183).
#
#   make glorfindel-host-start [REF=v0.3.1|<commit>]    # sends this script over ssh
#
#   deploy.sh [REF]                  fetch, check out REF detached, build the image, start
#   deploy.sh --checkout-only [REF]  fetch and check out, nothing built or started
#   deploy.sh --show                 the reference the running watch was built from
#
# REF is a tag or a commit, never a branch: a branch moves, and H0 ran whatever had just
# been merged into main. Without REF, the latest `v*` tag (version order). The image carries
# the reference (labels org.opencontainers.image.version / .revision) — `--show`, and so
# `make glorfindel-host-status`, read it back from the running container.
#
# The script comes from the operator's checkout, not the VM's: deploying an old tag (one
# from before this script) works the same.
set -euo pipefail
shopt -s inherit_errexit   # a failure inside $(…) stops the script, not only the subshell

IMAGE="${EREGION_IMAGE:-eregion-glorfindel}"
LABEL_REF="org.opencontainers.image.version"
LABEL_REV="org.opencontainers.image.revision"

die() { echo "✗ $*" >&2; exit 1; }

# The ref to deploy → "<ref> <full commit>", or die. A tag (refs/tags/REF) or a hexadecimal
# commit id (7 to 40 digits) that the commit it names starts with. Anything else — main,
# origin/main, HEAD, HEAD~1, a name that is both — is refused.
resolve() {
  local ref="$1" commit
  case "$ref" in
    "" | -* | *[!A-Za-z0-9._-]*) die "référence invalide : « $ref » (un tag ou un commit)" ;;
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
  local want="${1:-}" pair dirty
  git fetch -q --tags --force origin
  if [ -z "$want" ]; then
    want=$(latest_tag)
    [ -n "$want" ] || die "aucun tag v* : préciser REF=<commit>"
  fi
  pair=$(resolve "$want")
  # A tracked file changed on the VM would ride along into the image: refused, except the
  # detection rules, which the containers write (approved rules, mounted read-write).
  dirty=$(git status --porcelain --untracked-files=no | awk '{print $NF}' | grep -v '^glorfindel/rules/' || true)
  [ -z "$dirty" ] || die "fichiers suivis modifiés sur la VM (rien n'est déployé) : $(echo "$dirty" | tr '\n' ' ')"
  if git status --porcelain --untracked-files=no | grep -q 'glorfindel/rules/'; then
    echo "  · glorfindel/rules modifié sur la VM (règles approuvées) : gardé" >&2
  fi
  git -c advice.detachedHead=false checkout -q --detach "${pair#* }"
  echo "$pair"
}

build_and_start() {
  local ref="$1" commit="$2"
  docker build --build-arg UID="$(id -u)" --build-arg GID="$(id -g)" \
    --label "$LABEL_REF=$ref" --label "$LABEL_REV=$commit" \
    -f glorfindel/Dockerfile -t "$IMAGE" .
  docker compose --profile bot up -d watch war-room bot
  docker image prune -f >/dev/null
  echo "✓ déployé : $ref (${commit:0:12})"
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
    checkout "${2:-}" ;;
  *)
    pair=$(checkout "${1:-}")
    build_and_start "${pair% *}" "${pair#* }" ;;
esac
