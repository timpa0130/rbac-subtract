# rbac-subtract

Kubernetes controller that subtracts permissions from an existing ClusterRole. Fills a gap where a ClusterRole is almost perfect except for a few rules you want to remove — Kubernetes has no native way to do this.

## Architecture

```
subtract.py   → Core subtraction logic (pure functions, no K8s deps)
main.py       → Kopf controller (watches ModifyClusterRole CRD, calls subtract)
tests/         → Unit tests for subtract.py (26 tests)
manifests/     → CRD definition + deployment YAML
examples/      → Sample ModifyClusterRole manifests
```

### Core algorithm

1. **Flatten** source rules into `Set[(apiGroup, resource, verb)]` tuples
2. **Flatten** remove rules the same way
3. **Subtract** uses wildcard-aware matching (`*` matches any value present in source)
4. **Regroup** remaining tuples into K8s PolicyRule dicts, grouped by `(apiGroup, resource)`

## Commands

```bash
make test         # Run unit tests
make dev-up       # Create kind cluster, apply CRD, run controller locally
make dev-down     # Tear down kind cluster
make build        # Build Docker image
```

Or directly:

```bash
.venv/bin/python -m pytest tests/ -v
.venv/bin/kopf run main.py --verbose
```

## Conventions

- Python >= 3.11, venv-managed dependencies
- `subtract.py` has no K8s client imports — pure logic, testable in isolation
- Tests go in `tests/`, one file per module, pytest style
- New features add unit tests for `subtract.py` first, then wire into the controller
- K8s manifests go in `manifests/`
- Avoid guard clauses based on unverified assumptions. Always check framework documentation to confirm whether a given scenario actually occurs before coding defenses against it.

## Limitations

- Source ClusterRole must not contain `*` wildcards (rejected with error)
- Rules with `resourceNames` pass through unchanged (safe default)
- `nonResourceURLs` not supported (dropped from output)
