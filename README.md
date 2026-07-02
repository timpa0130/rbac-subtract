# RBAC Subtract

A Kubernetes controller that fills a gap when a ClusterRole is almost perfect except for a few rules you'd like to remove. Kubernetes has no native way to subtract permissions from an existing ClusterRole — this does it for you.

Built in Go with [Kubebuilder](https://github.com/kubernetes-sigs/kubebuilder) v4 and [controller-runtime](https://github.com/kubernetes-sigs/controller-runtime).

## How to use

Create a `ModifyClusterRole` custom resource referencing a source ClusterRole and specifying the rules to remove. The controller creates a new ClusterRole (named after the custom resource) with those permissions subtracted.

```yaml
apiVersion: kim.karolinska.se/v1
kind: ModifyClusterRole
metadata:
  name: kim-edit
spec:
  clusterRole: edit
  removeRules:
  - apiGroups:
    - networking.k8s.io
    resources:
    - ingresses
    verbs:
    - list
```

This reads the existing `edit` ClusterRole, removes `list` on `networking.k8s.io/ingresses`, and creates a new ClusterRole named `kim-edit`.

## How it works

The source ClusterRole's rules are flattened into a set of `(apiGroup, resource, verb)` tuples. The `removeRules` are flattened the same way. The two sets are subtracted, and the remaining tuples are regrouped into output rules.

### Example: Remove an entire block

**Source ClusterRole `my-role`:**
```yaml
rules:
- apiGroups:
  - postgresql.cnpg.io
  resources:
  - imagecatalogs
  verbs:
  - get
  - list
  - watch
- apiGroups:
  - networking.k8s.io
  resources:
  - ingresses
  verbs:
  - list
```

**ModifyClusterRole:**
```yaml
apiVersion: kim.karolinska.se/v1
kind: ModifyClusterRole
metadata:
  name: kim-role
spec:
  clusterRole: my-role
  removeRules:
  - apiGroups:
    - networking.k8s.io
    resources:
    - ingresses
    verbs:
    - list
```

The entire `networking.k8s.io` rule is removed. If the rule contained additional verbs, only `list` would be removed.

### Example: Remove a single resource from a multi-resource rule

**Source ClusterRole `my-role`:**
```yaml
rules:
- apiGroups:
  - networking.k8s.io
  resources:
  - ingresses
  - networkpolicies
  verbs:
  - list
```

**ModifyClusterRole:**
```yaml
apiVersion: kim.karolinska.se/v1
kind: ModifyClusterRole
metadata:
  name: kim-role
spec:
  clusterRole: my-role
  removeRules:
  - apiGroups:
    - networking.k8s.io
    resources:
    - ingresses
    verbs:
    - list
```

`ingresses` is removed from the rule; `networkpolicies` remains with `list`.

### Example: The tricky split case

**Source ClusterRole `my-role`:**
```yaml
rules:
- apiGroups:
  - networking.k8s.io
  resources:
  - ingresses
  - networkpolicies
  verbs:
  - list
  - patch
```

**ModifyClusterRole:**
```yaml
apiVersion: kim.karolinska.se/v1
kind: ModifyClusterRole
metadata:
  name: kim-role
spec:
  clusterRole: my-role
  removeRules:
  - apiGroups:
    - networking.k8s.io
    resources:
    - ingresses
    verbs:
    - patch
```

Removing `patch` on `ingresses` means the original rule can't stay as-is — it must be split. The output becomes:

```yaml
rules:
- apiGroups:
  - networking.k8s.io
  resources:
  - ingresses
  verbs:
  - list
- apiGroups:
  - networking.k8s.io
  resources:
  - networkpolicies
  verbs:
  - list
  - patch
```

One rule becomes two: `ingresses` keeps only `list`, while `networkpolicies` retains both verbs.

## Wildcard support in removeRules

`removeRules` supports `"*"` as a wildcard in `resources` and `verbs`. `"*"` matches any value present in the source ClusterRole — no expansion or enumeration needed.

```yaml
# Remove all verbs on apps/deployments
removeRules:
- apiGroups:
  - apps
  resources:
  - deployments
  verbs:
  - "*"

# Remove all resources in networking.k8s.io
removeRules:
- apiGroups:
  - networking.k8s.io
  resources:
  - "*"
  verbs:
  - get

# Remove everything in the apps API group
removeRules:
- apiGroups:
  - apps
  resources:
  - "*"
  verbs:
  - "*"
```

## Owner references and cleanup

The target ClusterRole is owned by the `ModifyClusterRole` custom resource via an `ownerReference`. When the `ModifyClusterRole` is deleted, Kubernetes garbage collection automatically removes the target ClusterRole. No manual cleanup or delete handler is needed.

## Label and annotation propagation

Labels from the `ModifyClusterRole` custom resource propagate to the target ClusterRole. The label `app.kubernetes.io/managed-by: rbac-subtract` is always present.

Annotations also propagate, excluding system annotations from kubectl (`kubectl.kubernetes.io/*`).

## Deployment prerequisites

The controller's service account (`rbac-subtract-controller-manager`) needs additional RBAC permissions beyond what kubebuilder auto-scaffolds:

- **`escalate` on `clusterroles`** — Required to create ClusterRoles whose rules include permissions the service account does not hold. Without it, Kubernetes RBAC escalation prevention rejects the request.
- **Leases in `coordination.k8s.io`** — Required for leader election when `--leader-elect` is enabled (default). Needs `get;list;watch;create;update;patch;delete`.
- **Events** — Recommended for recording reconcile and leader election events. Needs `create;patch` on `events` in the core API group.

All RBAC rules are managed via kubebuilder markers (`// +kubebuilder:rbac:...`) in Go source files and regenerated with `make manifests`.

## Development

```bash
make lint-fix      # Run golangci-lint linter and perform fixes
make docker-build  # Build container image
make manifests     # Regenerate CRD and RBAC manifests from markers
make deploy        # Deploy CRD + controller to cluster
make test          # Run all tests (unit + envtest integration)
make help          # For more commands
```

Requires Go >= 1.25.

## Limitations

### Source ClusterRole wildcard expansion

The source ClusterRole may contain `"*"` in `resources` and `verbs`. These are expanded to concrete values at reconciliation time using the Kubernetes discovery API:

- `resources: ["*"]` → expanded to all known resource names in the rule's API groups.
- `verbs: ["*"]` → expanded to the actual verbs each resource supports (e.g., `get`, `list`, `create`, `delete`). If a resource is not found in the discovery API (e.g., a stale role referencing a removed CRD), the controller raises a permanent error.

Expansion snapshots the currently-known resources. CRDs installed after reconciliation are not picked up until the next reconciliation (the controller re-reconciles periodically via `REQUEUE_INTERVAL`, default 4h).

`apiGroups: ["*"]` — rules with a wildcard API group are passed through unchanged. The controller adds the annotation `rbac-subtract.kim.karolinska.se/api-group-wildcard` to the target ClusterRole instead of rejecting.

Rules with `resourceNames` pass through unchanged regardless of wildcards.

### `resourceNames` rules pass through unchanged

Rules containing `resourceNames` (restricting access to specific named resources) are preserved as-is in the output. Subtraction is skipped for these rules because flattening loses the name restriction, which would accidentally expand permissions.

### `nonResourceURLs` not supported

ClusterRole rules with `nonResourceURLs` (e.g. access to `/healthz`, `/version`) are dropped from the output. The subtraction logic only operates on `apiGroups` + `resources` + `verbs` tuples. Using `nonResourceURLs` in `removeRules` is also unsupported.
