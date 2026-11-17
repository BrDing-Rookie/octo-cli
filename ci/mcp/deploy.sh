#!/bin/sh
set -eu

: "${MCP_DEPLOY_FILES_URL:?Set the deploy-files git URL}"
: "${CODE_TOKEN:?Set the GitOps repository write token}"
: "${MCP_ARGOCD_URL:?Set the Argo CD API origin}"
: "${MCP_ARGOCD_APP:?Set the MCP Argo CD application name}"
: "${ARGOCD_TOKEN:?Set the Argo CD token}"

case "${MCP_DEPLOY_ENV:-}" in
    develop|prod) branch="octo-cli-mcp-$MCP_DEPLOY_ENV" ;;
    *) echo "Unexpected MCP deployment environment" >&2; exit 1 ;;
esac
case "$MCP_ARGOCD_APP" in
    *[!a-zA-Z0-9._-]*) echo "Invalid MCP Argo CD application name" >&2; exit 1 ;;
esac

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
sh "$(dirname "$0")/render.sh" > "$work/deploy.yaml"

# Keep credentials out of remote URLs, Git config and artifacts.
cat > "$work/askpass" <<'EOF'
#!/bin/sh
case "$1" in
    Username*) printf '%s\n' '__token__' ;;
    Password*) printf '%s\n' "$CODE_TOKEN" ;;
    *) exit 1 ;;
esac
EOF
chmod 700 "$work/askpass"
export GIT_ASKPASS="$work/askpass" GIT_TERMINAL_PROMPT=0 LC_ALL=C
git init --quiet "$work/repo"
cd "$work/repo"
git remote add origin "$MCP_DEPLOY_FILES_URL"
status=0
git ls-remote --exit-code --heads origin "refs/heads/$branch" >/dev/null || status=$?
case "$status" in
    0)
        git fetch --quiet --depth 1 origin "refs/heads/$branch"
        git checkout --quiet --detach FETCH_HEAD ;;
    2) ;; # A new MCP branch starts with its own manifest.
    *) exit "$status" ;;
esac

manifest=manifests/deploy.yaml
if [ "$status" -eq 0 ] && [ -f "$manifest" ]; then
    current_pipeline=$(sed -n '1s/^# GitLab pipeline \([0-9][0-9]*\)$/\1/p' "$manifest")
    if [ "${current_pipeline:-0}" -gt "$CI_PIPELINE_ID" ]; then
        echo "The GitOps branch already contains a newer MCP pipeline" >&2
        exit 1
    fi
fi
mkdir -p manifests
cp "$work/deploy.yaml" "$manifest"
git add "$manifest"
if ! git diff --cached --quiet; then
    git -c user.name='GitLab CI' -c "user.email=gitlab-ci@$CI_SERVER_HOST" \
        commit --quiet -m "Deploy octo-cli-mcp from pipeline $CI_PIPELINE_ID"
fi
revision=$(git rev-parse HEAD)
git push origin "$revision:refs/heads/$branch"

sync_status=$(curl --silent --show-error --fail --max-time 30 --output /dev/null --write-out '%{http_code}' \
    --request POST "${MCP_ARGOCD_URL%/}/api/v1/applications/$MCP_ARGOCD_APP/sync" \
    --header "Authorization: Bearer $ARGOCD_TOKEN" --header "Content-Type: application/json" \
    --data "{\"revision\":\"$revision\",\"prune\":false,\"dryRun\":false}")
case "$sync_status" in
    2??) printf 'Argo CD accepted MCP revision %s for %s\n' "$revision" "$MCP_ARGOCD_APP" ;;
    *) printf 'Argo CD sync returned HTTP %s\n' "$sync_status" >&2; exit 1 ;;
esac
