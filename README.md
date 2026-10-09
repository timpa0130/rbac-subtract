# RBAC Subtract

A Kubernetes controller that fills a gap when a ClusterRole is almost perfect except for a few rules you'd like to remove. Kubernetes has no native way to subtract permissions from an existing ClusterRole — this does it for you.

Built in Go with [Kubebuilder](https://github.com/kubernetes-sigs/kubebuilder) v4 and [controller-runtime](https://github.com/kubernetes-sigs/controller-runtime).

## How to use

Create a `ModifyClusterRole` custom resource referencing a source ClusterRole and specifying the rules to remove. The controller creates a new ClusterRole (named after the custom resource) with those permissions subtracted.

```yaml
apiVersion: rbac.kim.karolinska.se/v1
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

The controller reconciles in two phases:

**Phase 1: Wildcard expansion** — Before subtraction, `*` in the source ClusterRole's `resources` and `verbs`, and RBAC's `*/subresource` form (e.g. `*/scale`), are expanded to concrete values by querying the Kubernetes discovery API. Rules with `apiGroups: ["*"]` pass through unchanged. This produces a fully concrete set of rules to subtract from.

**Phase 2: Rule subtraction** — The expanded source rules and the `removeRules` are both flattened into `(apiGroup, resource, resourceName, verb)` tuples, where an empty resource name means the grant is not restricted to named objects. Matching tuples are removed. The remaining tuples are regrouped into efficient PolicyRule dicts (merging resources that share identical API groups and verbs, and resource names that share identical resources and verbs). The output is deterministically sorted. Access that remains on targeted resources through subresources or resource names is reported in `status.remainingGrants` (see [Exact matching](#exact-matching-subresources-and-resourcenames)).

After subtraction, the controller creates or updates a target ClusterRole named after the `ModifyClusterRole` CR using `CreateOrUpdate` (idempotent), sets an owner reference so Kubernetes garbage-collects the target when the CR is deleted, and propagates labels and annotations from the CR. The CR status is updated with `rulesCount` — the number of rules in the generated ClusterRole. Reconciliation re-queues periodically (default every 4h, configurable via `REQUEUE_INTERVAL`).

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
apiVersion: rbac.kim.karolinska.se/v1
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
apiVersion: rbac.kim.karolinska.se/v1
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
apiVersion: rbac.kim.karolinska.se/v1
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

## Exact matching: subresources and resourceNames

`removeRules` remove exactly what they name, like RBAC grants exactly what a rule names. Two things are therefore never removed implicitly:

- **Subresources.** In RBAC, `pods/exec` is a separate resource from `pods`. Removing `pods` does not remove `pods/exec`, `pods/attach` or `pods/portforward`. The built-in `edit` role grants all of these, so name them if you want them gone.
- **Grants restricted to `resourceNames`.** A `removeRule` without `resourceNames` only removes grants that are not restricted to names. To remove a named grant, list the same names:

```yaml
removeRules:
- apiGroups: [""]
  resources: [configmaps]
  resourceNames: [my-config]
  verbs: [get]
```

Names match exactly; there are no name wildcards. `"*"` in `resources` and `verbs` still matches subresources and every verb, with or without `resourceNames`.

When a `removeRule` targets a resource and no unrestricted access to it is left, but access remains through a subresource or a named grant, the controller lists it in `status.remainingGrants`:

```yaml
status:
  remainingGrants:
  - apiGroup: ""
    resource: configmaps
    resourceNames: [my-config]
    verbs: [get]
    reason: ResourceNames
  - apiGroup: ""
    resource: pods/exec
    verbs: [create]
    reason: Subresource
```

The list is recomputed on every reconciliation and is empty once the `removeRules` name everything. It is informational: the `ModifyClusterRole` stays `Available`.

## Owner references and cleanup

The target ClusterRole is owned by the `ModifyClusterRole` custom resource via an `ownerReference`. When the `ModifyClusterRole` is deleted, Kubernetes garbage collection automatically removes the target ClusterRole. No manual cleanup or delete handler is needed.

rbac-subtract never adopts a ClusterRole it did not create. If a ClusterRole with the target name already exists and is not owned by the `ModifyClusterRole`, rbac-subtract leaves it unchanged and marks the `ModifyClusterRole` as degraded with reason `TargetNotOwned`. Choose a different name for the `ModifyClusterRole`.

## Label and annotation propagation

Labels from the `ModifyClusterRole` custom resource propagate to the target ClusterRole. The label `app.kubernetes.io/managed-by: rbac-subtract` is always present.

Annotations also propagate, excluding system annotations from kubectl (`kubectl.kubernetes.io/*`).

## Deployment prerequisites

The controller's service account (`rbac-subtract-controller-manager`) needs additional RBAC permissions beyond what kubebuilder auto-scaffolds:

- **`escalate` on `clusterroles`** — Required to create ClusterRoles whose rules include permissions the service account does not hold. Without it, Kubernetes RBAC escalation prevention rejects the request.
- **Leases in `coordination.k8s.io`** — Required for leader election when `--leader-elect` is enabled (default). Needs `get;list;watch;create;update;patch;delete`.
- **Events** — Recommended for recording reconcile and leader election events. Needs `create;patch` on `events` in the core API group.

All RBAC rules are managed via kubebuilder markers (`// +kubebuilder:rbac:...`) in Go source files and regenerated with `make manifests`.

## Packages

### `pkg/subtract` — Rule subtraction engine

The core logic that removes permissions from a set of RBAC rules.

**`Type Permission`** — `{APIGroup, Resource, ResourceName, Verb string}` tuple. The granular unit of RBAC that the engine operates on. An empty `ResourceName` means the grant is not restricted to named objects.

**`Flatten(rules) → set[Permission]`** — Expands `PolicyRule` dicts into individual `(apiGroup, resource, resourceName, verb)` tuples. One rule with 2 resources × 3 verbs = 6 tuples.

**`Matches(source, pattern) → bool`** — Checks whether a source tuple matches a removal pattern. `"*"` in the pattern's API group, resource or verb acts as wildcard (matches any value). Resource names always match exactly.

**`Regroup(permissions) → []PolicyRule`** — Reverse of flatten. Groups tuples back into efficient PolicyRule dicts by merging resources that share identical API groups and verbs, then resource names that share identical resources and verbs. Output is deterministically sorted for idempotency.

**`Subtract(source, remove) → []PolicyRule`** — The main entry point. Separates pass-through rules (those with wildcard `apiGroups`), flattens the rest, subtracts matching tuples, regroups the remainder, and appends pass-through rules.

**`RemainingGrants(result, remove) → []RemainingGrant`** — Reports access left on resources the `removeRules` targeted: subresources whose parent has no unrestricted verbs left (`Subresource`), and named grants on a resource with no unrestricted verbs left (`ResourceNames`). Sorted for idempotency; the controller writes it to `status.remainingGrants`.

**How the 5-step regroup works:**

| Step | Input | Output |
|------|-------|--------|
| 1. Collect verbs | `{(apps,deployments,get), (apps,deployments,list), (apps,statefulsets,get), (apps,statefulsets,list)}` | `{apps/deployments: {get,list}, apps/statefulsets: {get,list}}` |
| 2. Merge by verbs | (above) | `{(apps,"get,list"): {deployments, statefulsets}}` |
| 3. Merge names | Named tuples only, e.g. `{(,configmaps,a,get), (,configmaps,b,get)}` | `{(,"get","configmaps"): {a, b}}`; unrestricted entries stay apart |
| 4. Build rules | (above) | `PolicyRule{APIGroups: ["apps"], Resources: ["deployments","statefulsets"], Verbs: ["get","list"]}` |
| 5. Sort | (rules from step 4) | Deterministically ordered rules (by apiGroup, unrestricted before named, then verbs, resources and names) |

### `pkg/wildcard` — Wildcard expansion from discovery API

Expands `"*"` in source ClusterRole rules to concrete values by querying the Kubernetes discovery API.

**`ExpandWildcards(discoveryClient, rules) → ([]PolicyRule, hasWildcardAPI bool, error)`** — The main entry point. Handles three cases for each rule:

- **`apiGroups: ["*"]`** — passes through unchanged, sets `hasWildcardAPI=true` (controller adds an annotation to warn).
- **`resources: ["*"]` and/or `verbs: ["*"]`** — expands to all known resources/verbs in the rule's API groups using the discovery API.
- **`resources: ["*/scale"]`** — RBAC's `*/subresource` form expands to every resource in the rule's API groups with that subresource (e.g. `deployments/scale`, `statefulsets/scale`).

Rules with `resourceNames` are expanded the same way and keep their names.

**Internal flow:**
1. `collectApiGroups` — gathers unique API groups from rules, excluding pass-through rules.
2. `fetchApiGroupVersions` — resolves API group names to their available versions.
3. `discoverResources` — fetches all resources and their verbs for each group version. Builds a cache: `apiGroup → resourceName → []verbs`.
4. `expandResourceNames` — replaces `"*"` with all resource names from the cache. `expandSubresources` replaces `"*/subresource"` with the matching resource names.
5. `expandVerbs` — replaces `"*"` with the actual verbs each resource supports. Errors if a resource is not found (e.g. stale role referencing a removed CRD).

**Caching note:** Expansion snapshots the currently-known resources at reconciliation time. CRDs installed later are picked up on the next reconciliation (re-queued via `REQUEUE_INTERVAL`, default 4h).

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
- `resources: ["*/scale"]` → expanded to every known resource in the rule's API groups with that subresource.
- `verbs: ["*"]` → expanded to the actual verbs each resource supports (e.g., `get`, `list`, `create`, `delete`). If a resource is not found in the discovery API (e.g., a stale role referencing a removed CRD), the controller raises a permanent error.

Expansion snapshots the currently-known resources. CRDs installed after reconciliation are not picked up until the next reconciliation (the controller re-reconciles periodically via `REQUEUE_INTERVAL`, default 4h).

`apiGroups: ["*"]` — rules with a wildcard API group are passed through unchanged. The controller adds the annotation `subtract.rbac.kim.karolinska.se/api-group-wildcard` to the target ClusterRole instead of rejecting.

Rules with `resourceNames` are expanded the same way and keep their names. Note that `verbs: ["*"]` expands to the verbs discovery reports, so verbs it does not list (such as `use`, `bind` or `escalate`) are not carried over.

### Aggregated ClusterRoles (`aggregationRule`)

For an aggregated source, give the `ModifyClusterRole` a different name. rbac-subtract reads the source's current rules and writes the result to a separate target, leaving the source under Kubernetes RBAC aggregation. Source changes are picked up on a later reconciliation (default interval: 4h).

If the target already has an `.aggregationRule`, rbac-subtract leaves it unchanged and marks the `ModifyClusterRole` as degraded with reason `TargetAggregated`. Choose a different target name to preserve the aggregated role.

When the source and `ModifyClusterRole` have the same name, the source is the target. rbac-subtract did not create it, so it leaves it unchanged and reports `TargetNotOwned` (or `TargetAggregated` for an aggregated source).

### `nonResourceURLs` not supported

ClusterRole rules with `nonResourceURLs` (e.g. access to `/healthz`, `/version`) are dropped from the output. The subtraction logic only operates on `apiGroups` + `resources` + `verbs` tuples. Using `nonResourceURLs` in `removeRules` is also unsupported.
