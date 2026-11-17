#!/bin/sh
set -eu

: "${MCP_CI_IMAGE_ROOT:?Set the CI tools image root}"
: "${MCP_CONTAINER_IMAGE:?Set the MCP image repository}"
: "${HARBOR_USER:?Set the registry username}"
: "${HARBOR_PWD:?Set the registry password}"

version=${CI_COMMIT_TAG:-$CI_COMMIT_SHORT_SHA}
tag=${CI_COMMIT_TAG:-$MCP_RELEASE_CHANNEL-$CI_PIPELINE_ID}
image="$MCP_CONTAINER_IMAGE:$tag"
registry=${MCP_CONTAINER_IMAGE%%/*}

attempt=0
until docker info >/dev/null 2>&1; do
    attempt=$((attempt + 1))
    if [ "$attempt" -ge 12 ]; then
        echo "Docker daemon is unavailable" >&2
        exit 1
    fi
    sleep 5
done
printf '%s\n' "$HARBOR_PWD" | docker login "$registry" -u "$HARBOR_USER" --password-stdin
docker build -f ci/mcp/Dockerfile \
    --build-arg "BUILD_IMAGE=$MCP_CI_IMAGE_ROOT/golang:1.25" \
    --build-arg "RUNTIME_IMAGE=$MCP_CI_IMAGE_ROOT/alpine:3.19" \
    --build-arg "GOPROXY=${GOPROXY:-https://goproxy.cn,direct}" \
    --build-arg "VERSION=$version" --tag "$image" .
docker push "$image"

digest_ref=$(docker inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "$image" |
    awk -v prefix="$MCP_CONTAINER_IMAGE@sha256:" 'index($0, prefix) == 1 { print; exit }')
if [ -z "$digest_ref" ]; then
    echo "No registry digest found for the pushed MCP image" >&2
    exit 1
fi
printf 'MCP_DEPLOY_IMAGE=%s\n' "$digest_ref" > mcp-image.env
