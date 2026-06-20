import pytest
from subtract import Permission, flatten, regroup, subtract

# --- flatten ---

def test_flatten_single_rule():
    rules = [{
        'apiGroups': ['apps'],
        'resources': ['deployments'],
        'verbs': ['get', 'list'],
    }]
    result = flatten(rules)
    assert result == {('apps', 'deployments', 'get'), ('apps', 'deployments', 'list')}


def test_flatten_multiple_api_groups():
    rules = [{
        'apiGroups': ['apps', 'extensions'],
        'resources': ['deployments'],
        'verbs': ['get'],
    }]
    result = flatten(rules)
    assert result == {
        ('apps', 'deployments', 'get'),
        ('extensions', 'deployments', 'get'),
    }


def test_flatten_multiple_resources():
    rules = [{
        'apiGroups': ['networking.k8s.io'],
        'resources': ['ingresses', 'networkpolicies'],
        'verbs': ['get', 'list'],
    }]
    result = flatten(rules)
    assert result == {
        ('networking.k8s.io', 'ingresses', 'get'),
        ('networking.k8s.io', 'ingresses', 'list'),
        ('networking.k8s.io', 'networkpolicies', 'get'),
        ('networking.k8s.io', 'networkpolicies', 'list'),
    }


def test_flatten_empty_rule():
    result = flatten([])
    assert result == set()


# --- regroup ---

def test_regroup_single_permission():
    result = regroup({Permission('apps', 'deployments', 'get')})
    assert result == [{
        'apiGroups': ['apps'],
        'resources': ['deployments'],
        'verbs': ['get'],
    }]


def test_regroup_merges_verbs():
    result = regroup({
        Permission('apps', 'deployments', 'get'),
        Permission('apps', 'deployments', 'list'),
    })
    assert result == [{
        'apiGroups': ['apps'],
        'resources': ['deployments'],
        'verbs': ['get', 'list'],
    }]


def test_regroup_separate_resources():
    result = regroup({
        Permission('apps', 'deployments', 'get'),
        Permission('apps', 'statefulsets', 'get'),
    })
    assert len(result) == 2
    verbs_sets = {frozenset(r['verbs']) for r in result}
    assert verbs_sets == {frozenset({'get'})}


def test_regroup_empty():
    result = regroup(set())
    assert result == []


# --- subtract (integration) ---

def test_subtract_remove_entire_rule():
    source = [{
        'apiGroups': ['postgresql.cnpg.io'],
        'resources': ['imagecatalogs'],
        'verbs': ['get', 'list', 'watch'],
    }, {
        'apiGroups': ['networking.k8s.io'],
        'resources': ['ingresses'],
        'verbs': ['list'],
    }]
    remove = [{
        'apiGroups': ['networking.k8s.io'],
        'resources': ['ingresses'],
        'verbs': ['list'],
    }]
    result = subtract(source, remove)
    assert result == [{
        'apiGroups': ['postgresql.cnpg.io'],
        'resources': ['imagecatalogs'],
        'verbs': ['get', 'list', 'watch'],
    }]


def test_subtract_remove_single_verb():
    source = [{
        'apiGroups': ['networking.k8s.io'],
        'resources': ['ingresses'],
        'verbs': ['get', 'list', 'watch'],
    }]
    remove = [{
        'apiGroups': ['networking.k8s.io'],
        'resources': ['ingresses'],
        'verbs': ['list'],
    }]
    result = subtract(source, remove)
    assert result == [{
        'apiGroups': ['networking.k8s.io'],
        'resources': ['ingresses'],
        'verbs': ['get', 'watch'],
    }]


def test_subtract_remove_single_resource_from_multi():
    source = [{
        'apiGroups': ['networking.k8s.io'],
        'resources': ['ingresses', 'networkpolicies'],
        'verbs': ['list'],
    }]
    remove = [{
        'apiGroups': ['networking.k8s.io'],
        'resources': ['ingresses'],
        'verbs': ['list'],
    }]
    result = subtract(source, remove)
    assert result == [{
        'apiGroups': ['networking.k8s.io'],
        'resources': ['networkpolicies'],
        'verbs': ['list'],
    }]


def test_subtract_tricky_split_case():
    """Removing (networking.k8s.io, ingresses, patch) from a rule with multiple resources and verbs."""
    source = [{
        'apiGroups': ['networking.k8s.io'],
        'resources': ['ingresses', 'networkpolicies'],
        'verbs': ['list', 'patch'],
    }]
    remove = [{
        'apiGroups': ['networking.k8s.io'],
        'resources': ['ingresses'],
        'verbs': ['patch'],
    }]
    result = subtract(source, remove)
    assert len(result) == 2
    assert {
        'apiGroups': ['networking.k8s.io'],
        'resources': ['ingresses'],
        'verbs': ['list'],
    } in result
    assert {
        'apiGroups': ['networking.k8s.io'],
        'resources': ['networkpolicies'],
        'verbs': ['list', 'patch'],
    } in result


def test_subtract_noop_when_remove_empty():
    source = [{
        'apiGroups': ['apps'],
        'resources': ['deployments'],
        'verbs': ['get'],
    }]
    result = subtract(source, [])
    assert result == source


def test_subtract_noop_when_no_match():
    source = [{
        'apiGroups': ['apps'],
        'resources': ['deployments'],
        'verbs': ['get'],
    }]
    remove = [{
        'apiGroups': ['networking.k8s.io'],
        'resources': ['ingresses'],
        'verbs': ['list'],
    }]
    result = subtract(source, remove)
    assert result == source


def test_subtract_removes_all_results_in_empty():
    source = [{
        'apiGroups': ['apps'],
        'resources': ['deployments'],
        'verbs': ['get'],
    }]
    remove = [{
        'apiGroups': ['apps'],
        'resources': ['deployments'],
        'verbs': ['get'],
    }]
    result = subtract(source, remove)
    assert result == []


def test_subtract_multiple_remove_rules():
    source = [{
        'apiGroups': ['apps'],
        'resources': ['deployments', 'statefulsets'],
        'verbs': ['get', 'list'],
    }]
    remove = [
        {
            'apiGroups': ['apps'],
            'resources': ['deployments'],
            'verbs': ['get'],
        },
        {
            'apiGroups': ['apps'],
            'resources': ['statefulsets'],
            'verbs': ['list'],
        },
    ]
    result = subtract(source, remove)
    assert len(result) == 2
    assert {
        'apiGroups': ['apps'],
        'resources': ['deployments'],
        'verbs': ['list'],
    } in result
    assert {
        'apiGroups': ['apps'],
        'resources': ['statefulsets'],
        'verbs': ['get'],
    } in result


def test_subtract_partial_api_group_match():
    """Remove only matches the specific apiGroup, not all apiGroups."""
    source = [{
        'apiGroups': ['apps', 'extensions'],
        'resources': ['deployments'],
        'verbs': ['get'],
    }]
    remove = [{
        'apiGroups': ['apps'],
        'resources': ['deployments'],
        'verbs': ['get'],
    }]
    result = subtract(source, remove)
    assert result == [{
        'apiGroups': ['extensions'],
        'resources': ['deployments'],
        'verbs': ['get'],
    }]


# --- wildcard removal ---

def test_remove_verb_wildcard():
    source = [{
        'apiGroups': ['apps'],
        'resources': ['deployments'],
        'verbs': ['get', 'list', 'watch'],
    }]
    remove = [{
        'apiGroups': ['apps'],
        'resources': ['deployments'],
        'verbs': ['*'],
    }]
    result = subtract(source, remove)
    assert result == []


def test_remove_resource_wildcard():
    source = [{
        'apiGroups': ['networking.k8s.io'],
        'resources': ['ingresses', 'networkpolicies'],
        'verbs': ['get'],
    }]
    remove = [{
        'apiGroups': ['networking.k8s.io'],
        'resources': ['*'],
        'verbs': ['get'],
    }]
    result = subtract(source, remove)
    assert result == []


def test_remove_both_wildcards():
    source = [{
        'apiGroups': ['apps'],
        'resources': ['deployments', 'statefulsets'],
        'verbs': ['get', 'list'],
    }]
    remove = [{
        'apiGroups': ['apps'],
        'resources': ['*'],
        'verbs': ['*'],
    }]
    result = subtract(source, remove)
    assert result == []


def test_remove_wildcard_partial():
    """Resource wildcard removes only matching verbs, other resources survive."""
    source = [{
        'apiGroups': ['apps'],
        'resources': ['deployments', 'statefulsets'],
        'verbs': ['get', 'list'],
    }]
    remove = [{
        'apiGroups': ['apps'],
        'resources': ['deployments'],
        'verbs': ['*'],
    }]
    result = subtract(source, remove)
    assert result == [{
        'apiGroups': ['apps'],
        'resources': ['statefulsets'],
        'verbs': ['get', 'list'],
    }]


def test_remove_wildcard_verb_partial():
    """Verb wildcard on one resource, other resource in rule intact."""
    source = [{
        'apiGroups': ['apps'],
        'resources': ['deployments', 'statefulsets'],
        'verbs': ['get', 'list'],
    }]
    remove = [{
        'apiGroups': ['apps'],
        'resources': ['deployments'],
        'verbs': ['*'],
    }]
    result = subtract(source, remove)
    assert result == [{
        'apiGroups': ['apps'],
        'resources': ['statefulsets'],
        'verbs': ['get', 'list'],
    }]


# --- source wildcard handling ---

def test_source_apigroup_wildcard_rejected():
    source = [{
        'apiGroups': ['*'],
        'resources': ['deployments'],
        'verbs': ['get'],
    }]
    remove = [{
        'apiGroups': ['apps'],
        'resources': ['deployments'],
        'verbs': ['get'],
    }]
    with pytest.raises(ValueError, match="apiGroups"):
        subtract(source, remove)


def test_source_resource_wildcard_accepted():
    source = [{
        'apiGroups': ['apps'],
        'resources': ['*'],
        'verbs': ['get'],
    }]
    remove = [{
        'apiGroups': ['apps'],
        'resources': ['deployments'],
        'verbs': ['get'],
    }]
    subtract(source, remove)


def test_source_verb_wildcard_accepted():
    source = [{
        'apiGroups': ['apps'],
        'resources': ['deployments'],
        'verbs': ['*'],
    }]
    remove = [{
        'apiGroups': ['apps'],
        'resources': ['deployments'],
        'verbs': ['get'],
    }]
    subtract(source, remove)


# --- resourceNames preservation ---

def test_resource_names_preserved():
    source = [{
        'apiGroups': ['apps'],
        'resources': ['deployments'],
        'resourceNames': ['my-deploy'],
        'verbs': ['get'],
    }]
    remove = [{
        'apiGroups': ['apps'],
        'resources': ['deployments'],
        'verbs': ['get'],
    }]
    result = subtract(source, remove)
    assert result == source


def test_resource_names_preserved_with_other_rules():
    source = [
        {
            'apiGroups': ['apps'],
            'resources': ['deployments'],
            'resourceNames': ['my-deploy'],
            'verbs': ['get'],
        },
        {
            'apiGroups': ['apps'],
            'resources': ['statefulsets'],
            'verbs': ['get'],
        },
    ]
    remove = [{
        'apiGroups': ['apps'],
        'resources': ['statefulsets'],
        'verbs': ['get'],
    }]
    result = subtract(source, remove)
    assert len(result) == 1
    assert result[0]['resourceNames'] == ['my-deploy']
