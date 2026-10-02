#!/usr/bin/env bash
set -euo pipefail

rust=false
deps=false
python=false
docs=false
catalog=false
host=false
image=false
workflows=false
case "${GITHUB_EVENT_NAME:?event is required}" in
  workflow_dispatch|schedule) full=true ;;
  push|pull_request)
    full=false
    if [[ "$GITHUB_EVENT_NAME" == push && "${GITHUB_REF:-}" == refs/tags/* ]]; then full=true; fi
    ;;
  *) echo 'Unsupported CI event' >&2; exit 1 ;;
esac
if [[ "$full" == true ]]; then
  rust=true; deps=true; python=true; docs=true; catalog=true; host=true; image=true; workflows=true
else
  [[ "${BASE_SHA:-}" =~ ^[0-9a-f]{40}$ ]] || { echo 'A full base commit is required' >&2; exit 1; }
  changed_files="$(mktemp)"
  trap 'rm -f "$changed_files"' EXIT
  if [[ "$GITHUB_EVENT_NAME" == pull_request ]]; then
    git diff --name-only --no-renames -z "$BASE_SHA...HEAD" >"$changed_files"
  else
    git diff --name-only --no-renames -z "$BASE_SHA" HEAD >"$changed_files"
  fi
  while IFS= read -r -d '' path; do
    case "$path" in
      scripts/ci-scope.sh) rust=true; deps=true; python=true; docs=true; catalog=true; host=true; image=true; workflows=true ;;

      .github/workflows/*) rust=true; deps=true; python=true; docs=true; catalog=true; host=true; image=true; workflows=true ;;
      Cargo.toml|Cargo.lock|rust-toolchain.toml|rust-toolchain|crates/*/Cargo.toml) rust=true; deps=true; catalog=true; host=true; image=true ;;
      .cargo/*) rust=true ;;
      rustfmt.toml|.rustfmt.toml|clippy.toml|.clippy.toml) rust=true ;;
      crates/*/tests/*|crates/*/benches/*|crates/*/test-fixtures/*|testdata/*) rust=true ;;
      crates/*/*.md) docs=true ;;
      crates/*) rust=true; catalog=true; host=true; image=true ;;
      Dockerfile|.dockerignore|scripts/qualify_image.py|scripts/prepare_release.py|scripts/check_image_security.py|LICENSE|THIRD_PARTY_NOTICES.md)
        image=true ;;
      host-client/*|scripts/generate_host_client.py) host=true ;;
      api-coverage/*) catalog=true ;;
      security/*|scripts/check_advisories.py) deps=true ;;
      docs/generated-catalog.md|docs/workflows.json|scripts/catalog_summary.py) catalog=true ;;
      docs/tool-surface.md|gateway-manifest.yaml) rust=true ;;
    esac
    case "$path" in
      *.md) docs=true ;;
      scripts/check_docs.py) docs=true; python=true ;;
      scripts/*) python=true ;;
    esac

    case "$path" in
      scripts/check_api_coverage.py|docs/api-coverage.md) catalog=true ;;
    esac
    if [[ ! -e "$path" ]]; then docs=true; fi
  done <"$changed_files"
fi
printf 'rust=%s\ndeps=%s\npython=%s\ndocs=%s\ncatalog=%s\nhost=%s\nimage=%s\nworkflows=%s\n' \
  "$rust" "$deps" "$python" "$docs" "$catalog" "$host" "$image" "$workflows" >>"${GITHUB_OUTPUT:?output file is required}"
