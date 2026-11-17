# Enterprise MCP deployment

GitLab CI builds the container, publishes it to the registry and releases the
deployment through the existing Argo CD setup. The release job renders
`deploy.yaml`, pushes it to the environment's `deploy-files` branch and requests
an Argo CD sync for the resulting Git revision. Kubernetes pulls the exact
image digest recorded by the package job.

| Trigger | Pipeline result |
| --- | --- |
| Merge request | Build, vet and race tests |
| Push to `develop` | Publish `dev-<pipeline-id>` |
| Push to `test` | Publish `test-<pipeline-id>` and sync `octo-cli-mcp-develop` |
| Push a release tag | Publish the tagged image, then run `deploy_mcp` in GitLab to release `octo-cli-mcp-prod` |

## GitLab CI variables

Set `MCP_CI_IMAGE_ROOT` to the registry path that supplies the Octo CI
`golang:1.25`, `docker:20.10.17`, and `alpine:3.19` images. The runner tagged
`tke-deepmining-runner` provides the Docker daemon at `docker:2375`. The Go
image needs Git and curl for the deploy job. Set `MCP_CONTAINER_IMAGE` to the
dedicated container repository. Use masked `HARBOR_USER` and `HARBOR_PWD` for
registry authentication. Use Docker-compatible release tags.

Scope the following variables to the `develop` and `prod` GitLab environments.
Set `CODE_TOKEN` and `ARGOCD_TOKEN` as masked variables available to the
release refs. The GitOps token needs write access to the two MCP branches.
The Argo CD token needs sync access to the corresponding MCP applications.

| Variable | Value |
| --- | --- |
| `MCP_DEPLOY_FILES_URL` | GitOps repository HTTPS URL |
| `MCP_ARGOCD_URL` | Argo CD API origin |
| `MCP_ARGOCD_APP` | Application tracking `manifests/` on the matching release branch |
| `MCP_NAMESPACE` | Application namespace |
| `MCP_OCTO_GATEWAY_URL` | Octo API origin used for business calls |
| `MCP_PUBLIC_HOST` | External MCP hostname |
| `MCP_GATEWAY_NAME`, `MCP_GATEWAY_NAMESPACE` | Platform HTTPS Gateway serving that hostname |
| `MCP_GATEWAY_LISTENER` | Listener name, default `https` |
| `MCP_IMAGE_PULL_SECRET` | Registry read secret in the target namespace, default `tcr-image-xtiao` |

Configure the platform Gateway to accept the route from the MCP namespace,
authenticate `/mcp` requests and preserve their Octo Bearer header. The route
publishes exactly `/mcp`. Kubernetes uses `/readyz` and Prometheus scrapes
`/metrics` through the Pod network. Size the gateway request timeout to
cover the two-minute execution deadline plus HTTP body and response handling.
[Gateway API HTTP routing](https://gateway-api.sigs.k8s.io/guides/user-guides/http-routing/)

## Scaling and shutdown

Set capacity from load tests against the target environment. These CI
variables provide initial values for the rendered resources.

| Variable | Initial value |
| --- | --- |
| `MCP_MIN_REPLICAS`, `MCP_MAX_REPLICAS` | `2`, `10` |
| `MCP_CPU_REQUEST`, `MCP_CPU_LIMIT` | `250m`, `1` |
| `MCP_MEMORY_REQUEST`, `MCP_MEMORY_LIMIT` | `256Mi`, `512Mi` |
| `MCP_TARGET_CPU_PERCENT`, `MCP_TARGET_INFLIGHT` | `70`, `12` executing calls per Pod |
| `MCP_DRAIN_DELAY_SECONDS`, `MCP_SHUTDOWN_TIMEOUT_SECONDS` | `5`, `150` |

The cluster supplies the Gateway API, Prometheus Operator, resource metrics
API and Prometheus Adapter. Prometheus selects the MCP PodMonitor and retains
the `namespace` and `pod` target labels. Add this rule to the adapter's shared
configuration through its CI or GitOps release, so the HPA can find the
per-Pod gauge in `custom.metrics.k8s.io`.

```yaml
rules:
  - seriesQuery: 'octo_mcp_exec_inflight{namespace!="",pod!=""}'
    resources:
      overrides:
        namespace: {resource: namespace}
        pod: {resource: pod}
    name:
      matches: '^octo_mcp_exec_inflight$'
      as: octo_mcp_exec_inflight
    metricsQuery: 'max(<<.Series>>{<<.LabelMatchers>>}) by (<<.GroupBy>>)'
```

The gauge counts executing HTTP `exec` calls and feeds the HPA alongside CPU.
Upon SIGTERM, `/readyz` returns 503 while endpoint changes propagate. The
listener then closes and accepted requests drain within the shutdown timeout.
The manifest sets the Pod grace period to drain delay plus shutdown timeout
plus ten seconds.
[Kubernetes HPA](https://kubernetes.io/docs/concepts/workloads/autoscaling/horizontal-pod-autoscale/#scaling-on-custom-metrics)
[Prometheus Adapter configuration](https://github.com/kubernetes-sigs/prometheus-adapter/blob/master/docs/config.md)
