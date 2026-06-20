from collections import defaultdict
from logging import Logger, getLogger
from typing import List, Dict, Set, Optional, NamedTuple


class Permission(NamedTuple):
    api_group: str
    resource: str
    verb: str


def matches(source: Permission, pattern: Permission) -> bool:
    """Check if a source permission matches a removal pattern. '*' acts as wildcard."""
    return (pattern.api_group == source.api_group or pattern.api_group == '*') and \
           (pattern.resource == source.resource or pattern.resource == '*') and \
           (pattern.verb == source.verb or pattern.verb == '*')


def flatten(rules: List[Dict]) -> Set[Permission]:
    """Flatten K8s PolicyRule dicts into a set of (apiGroup, resource, verb) tuples."""
    result: Set[Permission] = set()
    for rule in rules:
        for ag in rule.get('apiGroups', []):
            for r in rule.get('resources', []):
                for v in rule.get('verbs', []):
                    result.add(Permission(ag, r, v))
    return result


def regroup(permissions: Set[Permission]) -> List[Dict]:
    """Regroup (apiGroup, resource, verb) tuples back into PolicyRule dicts.

    Groups by (apiGroup, resource) and collects verbs.
    """
    groups: dict[tuple[str, str], set[str]] = defaultdict(set)
    for p in permissions:
        groups[(p.api_group, p.resource)].add(p.verb)

    result: List[Dict] = []
    for (ag, r), verbs in sorted(groups.items()):
        result.append({
            'apiGroups': [ag],
            'resources': [r],
            'verbs': sorted(verbs),
        })
    return result


def _has_wildcard(rules: List[Dict]) -> bool:
    for rule in rules:
        for field in ('apiGroups', 'resources', 'verbs'):
            if '*' in rule.get(field, []):
                return True
    return False


def subtract(
    source_rules: List[Dict],
    remove_rules: List[Dict],
    logger: Optional[Logger] = None,
) -> List[Dict]:
    """Subtract remove_rules from source_rules, returning the resulting rules."""
    if _has_wildcard(source_rules):
        raise ValueError(
            "source ClusterRole contains '*' wildcard in apiGroups, resources, or verbs — not supported"
        )

    log = logger or getLogger(__name__)

    pass_through = [r for r in source_rules if r.get('resourceNames')]
    concrete = [r for r in source_rules if not r.get('resourceNames')]

    if pass_through:
        log.debug(
            "Skipping %d rule(s) with resourceNames (pass through unchanged)",
            len(pass_through),
        )
        for rule in pass_through:
            log.debug(
                "  Pass-through: apiGroups=%s resources=%s resourceNames=%s verbs=%s",
                rule.get('apiGroups'), rule.get('resources'),
                rule.get('resourceNames'), rule.get('verbs'),
            )

    if not concrete:
        log.debug("No concrete source rules to subtract from, returning %d pass-through rule(s)", len(pass_through))
        return pass_through

    log.debug(
        "Flattening %d source rule(s) and %d remove rule(s)",
        len(concrete), len(remove_rules),
    )

    source = flatten(concrete)
    remove_flat = flatten(remove_rules)

    log.debug(
        "Flattened to %d source tuple(s) and %d remove pattern(s)",
        len(source), len(remove_flat),
    )

    remaining: Set[Permission] = set()
    removed: list[tuple[Permission, Permission]] = []

    for perm in source:
        matching_pat = None
        for pat in remove_flat:
            if matches(perm, pat):
                matching_pat = pat
                break
        if matching_pat:
            removed.append((perm, matching_pat))
        else:
            remaining.add(perm)

    if removed:
        log.debug("Removed %d tuple(s):", len(removed))
        for src, pat in removed:
            log.debug(
                "  (%s, %s, %s) matched by (%s, %s, %s)",
                src.api_group, src.resource, src.verb,
                pat.api_group, pat.resource, pat.verb,
            )

    log.debug("Remaining tuples: %d", len(remaining))

    result = regroup(remaining)

    total = len(result) + len(pass_through)
    log.debug(
        "Regrouped into %d rule(s) (%d from subtraction + %d pass-through)",
        total, len(result), len(pass_through),
    )

    return result + pass_through
