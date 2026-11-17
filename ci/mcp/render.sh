#!/bin/sh
set -eu

: "${MCP_DEPLOY_IMAGE:?Use the image digest from package_image}"
: "${CI_PIPELINE_ID:?Set the GitLab pipeline ID}"
: "${MCP_NAMESPACE:?Set the deployment namespace}"
: "${MCP_OCTO_GATEWAY_URL:?Set the Octo API gateway origin}"
: "${MCP_PUBLIC_HOST:?Set the MCP ingress hostname}"
: "${MCP_GATEWAY_NAME:?Set the existing HTTPS Gateway name}"
: "${MCP_GATEWAY_NAMESPACE:?Set the HTTPS Gateway namespace}"

gateway_listener=${MCP_GATEWAY_LISTENER:-https}
image_pull_secret=${MCP_IMAGE_PULL_SECRET:-tcr-image-xtiao}
cpu_request=${MCP_CPU_REQUEST:-250m}
memory_request=${MCP_MEMORY_REQUEST:-256Mi}
cpu_limit=${MCP_CPU_LIMIT:-1}
memory_limit=${MCP_MEMORY_LIMIT:-512Mi}
min_replicas=${MCP_MIN_REPLICAS:-2}
max_replicas=${MCP_MAX_REPLICAS:-10}
target_cpu=${MCP_TARGET_CPU_PERCENT:-70}
target_inflight=${MCP_TARGET_INFLIGHT:-12}
drain_delay=${MCP_DRAIN_DELAY_SECONDS:-5}
shutdown_timeout=${MCP_SHUTDOWN_TIMEOUT_SECONDS:-150}

for value in "$MCP_DEPLOY_IMAGE" "$MCP_NAMESPACE" "$MCP_OCTO_GATEWAY_URL" \
    "$MCP_PUBLIC_HOST" "$MCP_GATEWAY_NAME" "$MCP_GATEWAY_NAMESPACE" \
    "$gateway_listener" "$image_pull_secret" "$cpu_request" "$memory_request" "$cpu_limit" "$memory_limit"; do
    case "$value" in
        ''|*[!a-zA-Z0-9._/+:@-]*)
            echo "CI deployment values must be plain image references, origins, names or resource quantities" >&2
            exit 1 ;;
    esac
done
case "$MCP_OCTO_GATEWAY_URL" in
    http://*|https://*) ;;
    *) echo "MCP_OCTO_GATEWAY_URL requires an HTTP or HTTPS origin" >&2; exit 1 ;;
esac
case "$MCP_DEPLOY_IMAGE" in
    */*@sha256:*) ;;
    *) echo "MCP_DEPLOY_IMAGE must be pinned to a registry digest" >&2; exit 1 ;;
esac
digest=${MCP_DEPLOY_IMAGE##*@sha256:}
case "$digest" in
    *[!a-f0-9]*) echo "MCP_DEPLOY_IMAGE contains an invalid digest" >&2; exit 1 ;;
esac
if [ "${#digest}" -ne 64 ]; then
    echo "MCP_DEPLOY_IMAGE contains an invalid digest" >&2
    exit 1
fi

for number in "$CI_PIPELINE_ID" "$min_replicas" "$max_replicas" "$target_cpu" \
    "$target_inflight" "$drain_delay" "$shutdown_timeout"; do
    case "$number" in
        ''|*[!0-9]*|0[0-9]*)
            echo "MCP replica, autoscaling and shutdown settings require decimal integers" >&2
            exit 1 ;;
    esac
done
if [ "$min_replicas" -lt 1 ] || [ "$max_replicas" -lt "$min_replicas" ] ||
    [ "$target_cpu" -lt 1 ] || [ "$target_inflight" -lt 1 ] || [ "$shutdown_timeout" -lt 1 ]; then
    echo "Invalid MCP replica, autoscaling or shutdown setting" >&2
    exit 1
fi
termination_grace=$((drain_delay + shutdown_timeout + 10))

sed -e "s|{{PIPELINE_ID}}|$CI_PIPELINE_ID|g" \
    -e "s|{{NAMESPACE}}|$MCP_NAMESPACE|g" \
    -e "s|{{IMAGE}}|$MCP_DEPLOY_IMAGE|g" \
    -e "s|{{IMAGE_PULL_SECRET}}|$image_pull_secret|g" \
    -e "s|{{OCTO_GATEWAY_URL}}|$MCP_OCTO_GATEWAY_URL|g" \
    -e "s|{{PUBLIC_HOST}}|$MCP_PUBLIC_HOST|g" \
    -e "s|{{GATEWAY_NAME}}|$MCP_GATEWAY_NAME|g" \
    -e "s|{{GATEWAY_NAMESPACE}}|$MCP_GATEWAY_NAMESPACE|g" \
    -e "s|{{GATEWAY_LISTENER}}|$gateway_listener|g" \
    -e "s|{{CPU_REQUEST}}|$cpu_request|g" \
    -e "s|{{MEMORY_REQUEST}}|$memory_request|g" \
    -e "s|{{CPU_LIMIT}}|$cpu_limit|g" \
    -e "s|{{MEMORY_LIMIT}}|$memory_limit|g" \
    -e "s|{{MIN_REPLICAS}}|$min_replicas|g" \
    -e "s|{{MAX_REPLICAS}}|$max_replicas|g" \
    -e "s|{{TARGET_CPU}}|$target_cpu|g" \
    -e "s|{{TARGET_INFLIGHT}}|$target_inflight|g" \
    -e "s|{{DRAIN_DELAY}}|$drain_delay|g" \
    -e "s|{{SHUTDOWN_TIMEOUT}}|$shutdown_timeout|g" \
    -e "s|{{TERMINATION_GRACE}}|$termination_grace|g" \
    "$(dirname "$0")/deploy.yaml"
