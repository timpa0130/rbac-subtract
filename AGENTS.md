# rbac-subtract

Kubernetes controller that subtracts permissions from an existing ClusterRole. Fills a gap where a ClusterRole is almost perfect except for a few rules you want to remove — Kubernetes has no native way to do this.

Built with [Kubebuilder](https://github.com/kubernetes-sigs/kubebuilder) v4 and [controller-runtime](https://github.com/kubernetes-sigs/controller-runtime).

## Architecture

```
api/v1/modifyclusterrole_types.go     — CRD types with kubebuilder markers
cmd/main.go                           — Manager entry point
internal/controller/*.go              — Reconciler + integration tests
pkg/subtract/subtract.go              — Core subtraction logic (pure Go, no K8s deps)
pkg/subtract/subtract_test.go         — Unit tests (31 cases)
pkg/wildcard/wildcard.go              — Wildcard expansion via discovery API
config/crd/bases/                     — Generated CRD (from markers)
config/rbac/                          — Generated ClusterRole + bindings
config/manager/                       — Deployment manifest
examples/                             — Sample ModifyClusterRole manifests
```

### Core algorithm

1. **Flatten** source rules into `Set[(apiGroup, resource, verb)]` tuples
2. **Flatten** remove rules the same way
3. **Subtract** uses wildcard-aware matching (`*` matches any value present in source)
4. **Regroup** remaining tuples into K8s PolicyRule structs, grouped by `(apiGroup, resource)`

### Design decisions

- **Wildcard expansion** — Source ClusterRole wildcards (`*`) are expanded in `pkg/wildcard/` before `Subtract()` is called via the K8s discovery API:
  - `resources: ["*"]` expanded via discovery to all resource names in the rule's apiGroups
  - `verbs: ["*"]` expanded per resource by querying discovery for each resource's actual verb list. Errors if a resource is not found (stale role).
  - `apiGroups: ["*"]` rejected with permanent error (too broad to expand meaningfully)
  - Rules with `resourceNames` pass through unchanged regardless of wildcards
- **Owner reference GC** — Target ClusterRoles are owned by their ModifyClusterRole CR via `ownerReferences`. No delete handler needed — K8s garbage collection cleans up the ClusterRole when the CR is deleted.
- **Label/annotation propagation** — CR labels (with `app.kubernetes.io/managed-by: rbac-subtract` always present) and annotations (excluding `kubectl.kubernetes.io/*`) propagate to the target ClusterRole.

## Commands

```bash
make test             # Run unit tests (pkg/subtract)
make test-integration # Run integration tests (envtest)
make build            # Build manager binary to bin/manager
make run              # Run controller locally against current kubeconfig
make docker-build     # Build Docker image
make deploy           # Deploy CRD + controller to cluster
make manifests        # Regenerate CRD and RBAC manifests from code markers
make generate         # Regenerate deepcopy code
```

## Conventions

- Go >= 1.25, kubebuilder v4, controller-runtime v0.24
- Use descriptive variable names — no single-letter names (`gv`, `r`, `v`, `ag`). Loop variables should reflect what they iterate over (`resource`, `group`, `version`, `apiGroup`).
- `pkg/subtract/` has no K8s client imports — pure logic, testable in isolation
- New features add unit tests for `pkg/subtract/` first, then wire into the controller
- K8s manifests are generated from kubebuilder markers — edit markers, not YAML
- CRD validation uses kubebuilder CEL markers on the Go types

## Limitations

- Source ClusterRole must not contain `*` in `apiGroups` (rejected with error)
- Rules with `resourceNames` pass through unchanged (safe default)
- `nonResourceURLs` not supported (dropped from output)
