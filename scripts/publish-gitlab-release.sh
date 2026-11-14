#!/usr/bin/env bash
set -euo pipefail

: "${CI_API_V4_URL:?CI_API_V4_URL is required}"
: "${CI_PROJECT_ID:?CI_PROJECT_ID is required}"
: "${CI_JOB_TOKEN:?CI_JOB_TOKEN is required}"
: "${CI_COMMIT_TAG:?CI_COMMIT_TAG is required}"

if [[ ! "$CI_COMMIT_TAG" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
  echo "Expected a release tag such as v1.2.0." >&2
  exit 1
fi

version="${CI_COMMIT_TAG#v}"
project_api="${CI_API_V4_URL}/projects/${CI_PROJECT_ID}"
package_url="${project_api}/packages/generic/frp-ban/${version}"
release_url="${project_api}/releases/${CI_COMMIT_TAG}"
notes="packaging/RELEASE_NOTES.md"

if [[ "$(head -n 1 "$notes")" != "# $CI_COMMIT_TAG" ]]; then
  echo "Release notes must describe $CI_COMMIT_TAG." >&2
  exit 1
fi

files=()
for package in frp-ban frp-ban-client; do
  for rid in win-x64 win-arm64 osx-x64 osx-arm64 linux-x64 linux-arm64 linux-musl-x64 linux-musl-arm64; do
    extension=tar.gz
    if [[ "$rid" == win-* ]]; then
      extension=zip
    fi
    file="$package-$version-$rid.$extension"
    if [[ ! -s "dist/$file" || -L "dist/$file" ]]; then
      echo "Missing or invalid release archive: $file" >&2
      exit 1
    fi
    files+=("$file")
  done
done

# Reject unexpected files instead of attaching an incomplete or mixed release.
entry_count=$(find dist -mindepth 1 -maxdepth 1 ! -name SHA256SUMS | wc -l)
if [[ "$entry_count" -ne "${#files[@]}" ]]; then
  echo "Expected exactly ${#files[@]} release archives." >&2
  exit 1
fi

(cd dist && sha256sum "${files[@]}" > SHA256SUMS && sha256sum --check SHA256SUMS)
files+=(SHA256SUMS)

temporary_dir=$(mktemp -d)
trap 'rm -rf "$temporary_dir"' EXIT

# Use the numeric project ID: encoded namespace paths can be rejected by proxies.
for file in "${files[@]}"; do
  echo "Publishing $file to the GitLab package registry"
  curl --fail-with-body --silent --show-error --retry 3 --connect-timeout 30 --max-time 600 \
    --header "JOB-TOKEN: $CI_JOB_TOKEN" --upload-file "dist/$file" \
    "$package_url/$file"
done

printf '%s\n' "${files[@]}" | jq -Rn --arg base "$package_url" \
  '[inputs | {name: ., url: ($base + "/" + .), direct_asset_path: ("/" + .), link_type: "package"}]' \
  > "$temporary_dir/links.json"
jq -n --arg tag "$CI_COMMIT_TAG" --rawfile notes "$notes" \
  --slurpfile links "$temporary_dir/links.json" \
  '{name: $tag, tag_name: $tag, description: $notes, assets: {links: $links[0]}}' \
  > "$temporary_dir/release.json"

status=$(curl --silent --show-error --connect-timeout 30 --max-time 120 \
  --header "JOB-TOKEN: $CI_JOB_TOKEN" --output "$temporary_dir/existing.json" \
  --write-out '%{http_code}' "$release_url")

case "$status" in
  404)
    curl --fail-with-body --silent --show-error --connect-timeout 30 --max-time 120 \
      --header "JOB-TOKEN: $CI_JOB_TOKEN" --header 'Content-Type: application/json' \
      --request POST --data-binary "@$temporary_dir/release.json" "$project_api/releases"
    ;;
  200)
    # Re-running a failed publish job repairs links without creating duplicates.
    jq '{name, description}' "$temporary_dir/release.json" > "$temporary_dir/update.json"
    curl --fail-with-body --silent --show-error --connect-timeout 30 --max-time 120 \
      --header "JOB-TOKEN: $CI_JOB_TOKEN" --header 'Content-Type: application/json' \
      --request PUT --data-binary "@$temporary_dir/update.json" "$release_url"
    for file in "${files[@]}"; do
      jq --arg name "$file" '.[] | select(.name == $name)' "$temporary_dir/links.json" > "$temporary_dir/link.json"
      link_id=$(jq -r --arg name "$file" '.assets.links[]? | select(.name == $name) | .id' "$temporary_dir/existing.json")
      method=POST
      link_url="$release_url/assets/links"
      if [[ -n "$link_id" ]]; then
        method=PUT
        link_url="$link_url/$link_id"
      fi
      curl --fail-with-body --silent --show-error --connect-timeout 30 --max-time 120 \
        --header "JOB-TOKEN: $CI_JOB_TOKEN" --header 'Content-Type: application/json' \
        --request "$method" --data-binary "@$temporary_dir/link.json" "$link_url"
    done
    ;;
  *)
    echo "Unable to read the existing GitLab release (HTTP $status)." >&2
    exit 1
    ;;
esac

echo "Published $CI_COMMIT_TAG with ${#files[@]} assets."
