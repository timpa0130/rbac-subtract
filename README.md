# RBAC Subtract

A Kubernetes controller that fills a gap when a ClusterRole is almost perfect except for a few rules you'd like to remove. Kubernetes has no native way to subtract permissions from an existing ClusterRole — this does it for you.

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

## Limitations

### Source ClusterRole wildcards rejected

The source ClusterRole must not contain `"*"` in `apiGroups`, `resources`, or `verbs`. A source rule with `resources: ["*"]` is forward-looking (grants access to CRDs installed in the future), and snapshotting it to currently-known resources would silently change behavior. The controller rejects such roles with a permanent error.

### `resourceNames` rules pass through unchanged

Rules containing `resourceNames` (restricting access to specific named resources) are preserved as-is in the output. Subtraction is skipped for these rules because flattening loses the name restriction, which would accidentally expand permissions.

### `nonResourceURLs` not supported

ClusterRole rules with `nonResourceURLs` (e.g. access to `/healthz`, `/version`) are dropped from the output. The subtraction logic only operates on `apiGroups` + `resources` + `verbs` tuples. Using `nonResourceURLs` in `removeRules` is also unsupported.
