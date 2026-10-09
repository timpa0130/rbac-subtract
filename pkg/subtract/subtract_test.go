package subtract

import (
	"testing"

	"github.com/go-logr/logr"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	rbacv1 "k8s.io/api/rbac/v1"
)

var discardLog = logr.Discard()

// cmpOpts ignores ordering of PolicyRule slices within results.
var cmpOpts = cmp.Options{
	cmpopts.EquateEmpty(),
	cmpopts.SortSlices(func(a, b rbacv1.PolicyRule) bool {
		return a.APIGroups[0] < b.APIGroups[0] ||
			(a.APIGroups[0] == b.APIGroups[0] && a.Resources[0] < b.Resources[0])
	}),
}

// --- flatten ---

func TestFlatten(t *testing.T) {
	tests := []struct {
		name  string
		rules []rbacv1.PolicyRule
		want  map[Permission]struct{}
	}{
		{
			"single rule",
			[]rbacv1.PolicyRule{{APIGroups: []string{"apps"}, Resources: []string{"deployments"}, Verbs: []string{"get", "list"}}},
			map[Permission]struct{}{
				{"apps", "deployments", "", "get"}:  {},
				{"apps", "deployments", "", "list"}: {},
			},
		},
		{
			"multiple apiGroups",
			[]rbacv1.PolicyRule{{APIGroups: []string{"apps", "extensions"}, Resources: []string{"deployments"}, Verbs: []string{"get"}}},
			map[Permission]struct{}{
				{"apps", "deployments", "", "get"}:       {},
				{"extensions", "deployments", "", "get"}: {},
			},
		},
		{
			"multiple resources",
			[]rbacv1.PolicyRule{{APIGroups: []string{"networking.k8s.io"}, Resources: []string{"ingresses", "networkpolicies"}, Verbs: []string{"get", "list"}}},
			map[Permission]struct{}{
				{"networking.k8s.io", "ingresses", "", "get"}:        {},
				{"networking.k8s.io", "ingresses", "", "list"}:       {},
				{"networking.k8s.io", "networkpolicies", "", "get"}:  {},
				{"networking.k8s.io", "networkpolicies", "", "list"}: {},
			},
		},
		{
			"resourceNames",
			[]rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"configmaps"}, ResourceNames: []string{"a", "b"}, Verbs: []string{"get"}}},
			map[Permission]struct{}{
				{"", "configmaps", "a", "get"}: {},
				{"", "configmaps", "b", "get"}: {},
			},
		},
		{"empty", nil, map[Permission]struct{}{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if diff := cmp.Diff(tt.want, flatten(tt.rules)); diff != "" {
				t.Errorf("Flatten() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// --- regroup ---

func TestRegroup(t *testing.T) {
	tests := []struct {
		name        string
		permissions map[Permission]struct{}
		want        []rbacv1.PolicyRule
	}{
		{
			"single permission",
			map[Permission]struct{}{{"apps", "deployments", "", "get"}: {}},
			[]rbacv1.PolicyRule{{APIGroups: []string{"apps"}, Resources: []string{"deployments"}, Verbs: []string{"get"}}},
		},
		{
			"merges verbs",
			map[Permission]struct{}{{"apps", "deployments", "", "get"}: {}, {"apps", "deployments", "", "list"}: {}},
			[]rbacv1.PolicyRule{{APIGroups: []string{"apps"}, Resources: []string{"deployments"}, Verbs: []string{"get", "list"}}},
		},
		{
			"merges resources with same verbs",
			map[Permission]struct{}{
				{"apps", "deployments", "", "get"}:   {},
				{"apps", "deployments", "", "list"}:  {},
				{"apps", "statefulsets", "", "get"}:  {},
				{"apps", "statefulsets", "", "list"}: {},
			},
			[]rbacv1.PolicyRule{{APIGroups: []string{"apps"}, Resources: []string{"deployments", "statefulsets"}, Verbs: []string{"get", "list"}}},
		},
		{
			"splits when verbs differ",
			map[Permission]struct{}{{"apps", "deployments", "", "get"}: {}, {"apps", "statefulsets", "", "get"}: {}, {"apps", "statefulsets", "", "list"}: {}},
			[]rbacv1.PolicyRule{
				{APIGroups: []string{"apps"}, Resources: []string{"deployments"}, Verbs: []string{"get"}},
				{APIGroups: []string{"apps"}, Resources: []string{"statefulsets"}, Verbs: []string{"get", "list"}},
			},
		},
		{"empty", nil, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if diff := cmp.Diff(tt.want, regroup(tt.permissions), cmpOpts); diff != "" {
				t.Errorf("Regroup() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// Regroup output is deterministic, so these compare in order.
func TestRegroupResourceNames(t *testing.T) {
	tests := []struct {
		name        string
		permissions map[Permission]struct{}
		want        []rbacv1.PolicyRule
	}{
		{
			"merges names with the same resources and verbs",
			map[Permission]struct{}{{"", "configmaps", "a", "get"}: {}, {"", "configmaps", "b", "get"}: {}},
			[]rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"configmaps"}, ResourceNames: []string{"a", "b"}, Verbs: []string{"get"}}},
		},
		{
			"keeps unrestricted and named grants apart, unrestricted first",
			map[Permission]struct{}{{"", "configmaps", "a", "get"}: {}, {"", "configmaps", "", "get"}: {}},
			[]rbacv1.PolicyRule{
				{APIGroups: []string{""}, Resources: []string{"configmaps"}, Verbs: []string{"get"}},
				{APIGroups: []string{""}, Resources: []string{"configmaps"}, ResourceNames: []string{"a"}, Verbs: []string{"get"}},
			},
		},
		{
			"does not merge names whose resources differ",
			map[Permission]struct{}{
				{"", "configmaps", "a", "get"}: {},
				{"", "secrets", "a", "get"}:    {},
				{"", "configmaps", "b", "get"}: {},
			},
			[]rbacv1.PolicyRule{
				{APIGroups: []string{""}, Resources: []string{"configmaps"}, ResourceNames: []string{"b"}, Verbs: []string{"get"}},
				{APIGroups: []string{""}, Resources: []string{"configmaps", "secrets"}, ResourceNames: []string{"a"}, Verbs: []string{"get"}},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if diff := cmp.Diff(tt.want, regroup(tt.permissions), cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("Regroup() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// --- subtract ---

func TestSubtract(t *testing.T) {
	tests := []struct {
		name   string
		source []rbacv1.PolicyRule
		remove []rbacv1.PolicyRule
		want   []rbacv1.PolicyRule
		err    bool
	}{
		{
			"remove entire rule",
			[]rbacv1.PolicyRule{
				{APIGroups: []string{"postgresql.cnpg.io"}, Resources: []string{"imagecatalogs"}, Verbs: []string{"get", "list", "watch"}},
				{APIGroups: []string{"networking.k8s.io"}, Resources: []string{"ingresses"}, Verbs: []string{"list"}},
			},
			[]rbacv1.PolicyRule{
				{APIGroups: []string{"networking.k8s.io"}, Resources: []string{"ingresses"}, Verbs: []string{"list"}},
			},
			[]rbacv1.PolicyRule{
				{APIGroups: []string{"postgresql.cnpg.io"}, Resources: []string{"imagecatalogs"}, Verbs: []string{"get", "list", "watch"}},
			},
			false,
		},
		{
			"remove single verb",
			[]rbacv1.PolicyRule{{APIGroups: []string{"networking.k8s.io"}, Resources: []string{"ingresses"}, Verbs: []string{"get", "list", "watch"}}},
			[]rbacv1.PolicyRule{{APIGroups: []string{"networking.k8s.io"}, Resources: []string{"ingresses"}, Verbs: []string{"list"}}},
			[]rbacv1.PolicyRule{{APIGroups: []string{"networking.k8s.io"}, Resources: []string{"ingresses"}, Verbs: []string{"get", "watch"}}},
			false,
		},
		{
			"remove single resource from multi",
			[]rbacv1.PolicyRule{{APIGroups: []string{"networking.k8s.io"}, Resources: []string{"ingresses", "networkpolicies"}, Verbs: []string{"list"}}},
			[]rbacv1.PolicyRule{{APIGroups: []string{"networking.k8s.io"}, Resources: []string{"ingresses"}, Verbs: []string{"list"}}},
			[]rbacv1.PolicyRule{{APIGroups: []string{"networking.k8s.io"}, Resources: []string{"networkpolicies"}, Verbs: []string{"list"}}},
			false,
		},
		{
			"noop when remove empty",
			[]rbacv1.PolicyRule{{APIGroups: []string{"apps"}, Resources: []string{"deployments"}, Verbs: []string{"get"}}},
			nil,
			[]rbacv1.PolicyRule{{APIGroups: []string{"apps"}, Resources: []string{"deployments"}, Verbs: []string{"get"}}},
			false,
		},
		{
			"noop when no match",
			[]rbacv1.PolicyRule{{APIGroups: []string{"apps"}, Resources: []string{"deployments"}, Verbs: []string{"get"}}},
			[]rbacv1.PolicyRule{{APIGroups: []string{"networking.k8s.io"}, Resources: []string{"ingresses"}, Verbs: []string{"list"}}},
			[]rbacv1.PolicyRule{{APIGroups: []string{"apps"}, Resources: []string{"deployments"}, Verbs: []string{"get"}}},
			false,
		},
		{
			"removes all results in empty",
			[]rbacv1.PolicyRule{{APIGroups: []string{"apps"}, Resources: []string{"deployments"}, Verbs: []string{"get"}}},
			[]rbacv1.PolicyRule{{APIGroups: []string{"apps"}, Resources: []string{"deployments"}, Verbs: []string{"get"}}},
			nil,
			false,
		},
		{
			"partial apiGroup match",
			[]rbacv1.PolicyRule{{APIGroups: []string{"apps", "extensions"}, Resources: []string{"deployments"}, Verbs: []string{"get"}}},
			[]rbacv1.PolicyRule{{APIGroups: []string{"apps"}, Resources: []string{"deployments"}, Verbs: []string{"get"}}},
			[]rbacv1.PolicyRule{{APIGroups: []string{"extensions"}, Resources: []string{"deployments"}, Verbs: []string{"get"}}},
			false,
		},
		{
			"verb wildcard removes all verbs",
			[]rbacv1.PolicyRule{{APIGroups: []string{"apps"}, Resources: []string{"deployments"}, Verbs: []string{"get", "list", "watch"}}},
			[]rbacv1.PolicyRule{{APIGroups: []string{"apps"}, Resources: []string{"deployments"}, Verbs: []string{"*"}}},
			nil,
			false,
		},
		{
			"resource wildcard removes all resources",
			[]rbacv1.PolicyRule{{APIGroups: []string{"networking.k8s.io"}, Resources: []string{"ingresses", "networkpolicies"}, Verbs: []string{"get"}}},
			[]rbacv1.PolicyRule{{APIGroups: []string{"networking.k8s.io"}, Resources: []string{"*"}, Verbs: []string{"get"}}},
			nil,
			false,
		},
		{
			"both wildcards remove everything",
			[]rbacv1.PolicyRule{{APIGroups: []string{"apps"}, Resources: []string{"deployments", "statefulsets"}, Verbs: []string{"get", "list"}}},
			[]rbacv1.PolicyRule{{APIGroups: []string{"apps"}, Resources: []string{"*"}, Verbs: []string{"*"}}},
			nil,
			false,
		},
		{
			"wildcard partial — other resource survives",
			[]rbacv1.PolicyRule{{APIGroups: []string{"apps"}, Resources: []string{"deployments", "statefulsets"}, Verbs: []string{"get", "list"}}},
			[]rbacv1.PolicyRule{{APIGroups: []string{"apps"}, Resources: []string{"deployments"}, Verbs: []string{"*"}}},
			[]rbacv1.PolicyRule{{APIGroups: []string{"apps"}, Resources: []string{"statefulsets"}, Verbs: []string{"get", "list"}}},
			false,
		},
		{
			"source '*' in apiGroups passes through",
			[]rbacv1.PolicyRule{{APIGroups: []string{"*"}, Resources: []string{"deployments"}, Verbs: []string{"get"}}},
			[]rbacv1.PolicyRule{{APIGroups: []string{"apps"}, Resources: []string{"deployments"}, Verbs: []string{"get"}}},
			[]rbacv1.PolicyRule{{APIGroups: []string{"*"}, Resources: []string{"deployments"}, Verbs: []string{"get"}}},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := Subtract(tt.source, tt.remove, discardLog)
			if tt.err {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(tt.want, result, cmpOpts); diff != "" {
				t.Errorf("Subtract() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestSubtractTrickySplitCase(t *testing.T) {
	source := []rbacv1.PolicyRule{
		{APIGroups: []string{"networking.k8s.io"}, Resources: []string{"ingresses", "networkpolicies"}, Verbs: []string{"list", "patch"}},
	}
	remove := []rbacv1.PolicyRule{
		{APIGroups: []string{"networking.k8s.io"}, Resources: []string{"ingresses"}, Verbs: []string{"patch"}},
	}
	result, err := Subtract(source, remove, discardLog)
	if err != nil {
		t.Fatal(err)
	}
	want := []rbacv1.PolicyRule{
		{APIGroups: []string{"networking.k8s.io"}, Resources: []string{"ingresses"}, Verbs: []string{"list"}},
		{APIGroups: []string{"networking.k8s.io"}, Resources: []string{"networkpolicies"}, Verbs: []string{"list", "patch"}},
	}
	if diff := cmp.Diff(want, result, cmpOpts); diff != "" {
		t.Errorf("Subtract() mismatch (-want +got):\n%s", diff)
	}
}

func TestSubtractMultipleRemoveRules(t *testing.T) {
	result, err := Subtract(
		[]rbacv1.PolicyRule{{APIGroups: []string{"apps"}, Resources: []string{"deployments", "statefulsets"}, Verbs: []string{"get", "list"}}},
		[]rbacv1.PolicyRule{
			{APIGroups: []string{"apps"}, Resources: []string{"deployments"}, Verbs: []string{"get"}},
			{APIGroups: []string{"apps"}, Resources: []string{"statefulsets"}, Verbs: []string{"list"}},
		},
		discardLog,
	)
	if err != nil {
		t.Fatal(err)
	}
	want := []rbacv1.PolicyRule{
		{APIGroups: []string{"apps"}, Resources: []string{"deployments"}, Verbs: []string{"list"}},
		{APIGroups: []string{"apps"}, Resources: []string{"statefulsets"}, Verbs: []string{"get"}},
	}
	if diff := cmp.Diff(want, result, cmpOpts); diff != "" {
		t.Errorf("Subtract() mismatch (-want +got):\n%s", diff)
	}
}

// --- source wildcard acceptance ---

func TestSourceWildcardsAccepted(t *testing.T) {
	tests := []struct {
		name   string
		source []rbacv1.PolicyRule
	}{
		{"resources '*' accepted", []rbacv1.PolicyRule{{APIGroups: []string{"apps"}, Resources: []string{"*"}, Verbs: []string{"get"}}}},
		{"verbs '*' accepted", []rbacv1.PolicyRule{{APIGroups: []string{"apps"}, Resources: []string{"deployments"}, Verbs: []string{"*"}}}},
	}
	remove := []rbacv1.PolicyRule{{APIGroups: []string{"apps"}, Resources: []string{"deployments"}, Verbs: []string{"get"}}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Subtract(tt.source, remove, discardLog); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// --- resourceNames ---

func TestResourceNamesPreserved(t *testing.T) {
	source := []rbacv1.PolicyRule{
		{APIGroups: []string{"apps"}, Resources: []string{"deployments"}, ResourceNames: []string{"my-deploy"}, Verbs: []string{"get"}},
	}
	remove := []rbacv1.PolicyRule{
		{APIGroups: []string{"apps"}, Resources: []string{"deployments"}, Verbs: []string{"get"}},
	}
	result, err := Subtract(source, remove, discardLog)
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(source, result); diff != "" {
		t.Errorf("a removeRule without names should not remove a named grant (-want +got):\n%s", diff)
	}
}

// Subtract output is deterministic, so these compare in order.
func TestSubtractResourceNames(t *testing.T) {
	tests := []struct {
		name   string
		source []rbacv1.PolicyRule
		remove []rbacv1.PolicyRule
		want   []rbacv1.PolicyRule
	}{
		{
			"named removeRule removes the named grant",
			[]rbacv1.PolicyRule{
				{APIGroups: []string{""}, Resources: []string{"configmaps"}, ResourceNames: []string{"my-config"}, Verbs: []string{"get"}},
				{APIGroups: []string{""}, Resources: []string{"configmaps"}, Verbs: []string{"get", "list"}},
			},
			[]rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"configmaps"}, ResourceNames: []string{"my-config"}, Verbs: []string{"get"}}},
			[]rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"configmaps"}, Verbs: []string{"get", "list"}}},
		},
		{
			"named removeRule does not remove unrestricted access",
			[]rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"configmaps"}, Verbs: []string{"get"}}},
			[]rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"configmaps"}, ResourceNames: []string{"my-config"}, Verbs: []string{"get"}}},
			[]rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"configmaps"}, Verbs: []string{"get"}}},
		},
		{
			"removes one name from several",
			[]rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"configmaps"}, ResourceNames: []string{"a", "b"}, Verbs: []string{"get"}}},
			[]rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"configmaps"}, ResourceNames: []string{"a"}, Verbs: []string{"get"}}},
			[]rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"configmaps"}, ResourceNames: []string{"b"}, Verbs: []string{"get"}}},
		},
		{
			"removes one verb from a named grant",
			[]rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"configmaps"}, ResourceNames: []string{"a"}, Verbs: []string{"get", "update"}}},
			[]rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"configmaps"}, ResourceNames: []string{"a"}, Verbs: []string{"update"}}},
			[]rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"configmaps"}, ResourceNames: []string{"a"}, Verbs: []string{"get"}}},
		},
		{
			"verbs '*' with a name removes every verb on that name only",
			[]rbacv1.PolicyRule{
				{APIGroups: []string{""}, Resources: []string{"configmaps"}, ResourceNames: []string{"a"}, Verbs: []string{"get", "update"}},
				{APIGroups: []string{""}, Resources: []string{"configmaps"}, ResourceNames: []string{"b"}, Verbs: []string{"get"}},
			},
			[]rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"configmaps"}, ResourceNames: []string{"a"}, Verbs: []string{"*"}}},
			[]rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"configmaps"}, ResourceNames: []string{"b"}, Verbs: []string{"get"}}},
		},
		{
			"resources '*' with a name removes that name on every resource",
			[]rbacv1.PolicyRule{
				{APIGroups: []string{""}, Resources: []string{"configmaps", "secrets"}, ResourceNames: []string{"a"}, Verbs: []string{"get"}},
				{APIGroups: []string{""}, Resources: []string{"configmaps"}, ResourceNames: []string{"b"}, Verbs: []string{"get"}},
			},
			[]rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"*"}, ResourceNames: []string{"a"}, Verbs: []string{"get"}}},
			[]rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"configmaps"}, ResourceNames: []string{"b"}, Verbs: []string{"get"}}},
		},
		{
			"named subresource",
			[]rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods/exec"}, ResourceNames: []string{"my-pod"}, Verbs: []string{"create"}}},
			[]rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods/exec"}, ResourceNames: []string{"my-pod"}, Verbs: []string{"create"}}},
			nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := Subtract(tt.source, tt.remove, discardLog)
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(tt.want, result, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("Subtract() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// --- remaining grants ---

func TestRemainingGrants(t *testing.T) {
	tests := []struct {
		name   string
		result []rbacv1.PolicyRule
		remove []rbacv1.PolicyRule
		want   []RemainingGrant
	}{
		{
			"removing pods leaves its subresources",
			[]rbacv1.PolicyRule{
				{APIGroups: []string{""}, Resources: []string{"pods/exec"}, Verbs: []string{"create", "get"}},
				{APIGroups: []string{""}, Resources: []string{"pods/log"}, Verbs: []string{"get"}},
			},
			[]rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"*"}}},
			[]RemainingGrant{
				{APIGroup: "", Resource: "pods/exec", Verbs: []string{"create", "get"}, Reason: ReasonSubresource},
				{APIGroup: "", Resource: "pods/log", Verbs: []string{"get"}, Reason: ReasonSubresource},
			},
		},
		{
			"nothing reported while the parent keeps unrestricted verbs",
			[]rbacv1.PolicyRule{
				{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}},
				{APIGroups: []string{""}, Resources: []string{"pods/exec"}, Verbs: []string{"create"}},
			},
			[]rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"delete"}}},
			nil,
		},
		{
			"nothing reported for a parent no removeRule targets",
			[]rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods/exec"}, Verbs: []string{"create"}}},
			[]rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"configmaps"}, Verbs: []string{"*"}}},
			nil,
		},
		{
			"named grant remains after unrestricted access is removed",
			[]rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"configmaps"}, ResourceNames: []string{"a", "b"}, Verbs: []string{"get"}}},
			[]rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"configmaps"}, Verbs: []string{"*"}}},
			[]RemainingGrant{
				{APIGroup: "", Resource: "configmaps", ResourceNames: []string{"a", "b"}, Verbs: []string{"get"}, Reason: ReasonResourceNames},
			},
		},
		{
			"nothing reported while unrestricted access remains",
			[]rbacv1.PolicyRule{
				{APIGroups: []string{""}, Resources: []string{"configmaps"}, Verbs: []string{"list"}},
				{APIGroups: []string{""}, Resources: []string{"configmaps"}, ResourceNames: []string{"a"}, Verbs: []string{"get"}},
			},
			[]rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"configmaps"}, Verbs: []string{"get"}}},
			nil,
		},
		{
			"named grants with different verbs are reported separately",
			[]rbacv1.PolicyRule{
				{APIGroups: []string{""}, Resources: []string{"configmaps"}, ResourceNames: []string{"a"}, Verbs: []string{"get"}},
				{APIGroups: []string{""}, Resources: []string{"configmaps"}, ResourceNames: []string{"b"}, Verbs: []string{"get", "update"}},
			},
			[]rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"configmaps"}, Verbs: []string{"*"}}},
			[]RemainingGrant{
				{APIGroup: "", Resource: "configmaps", ResourceNames: []string{"a"}, Verbs: []string{"get"}, Reason: ReasonResourceNames},
				{APIGroup: "", Resource: "configmaps", ResourceNames: []string{"b"}, Verbs: []string{"get", "update"}, Reason: ReasonResourceNames},
			},
		},
		{
			"unrestricted and named subresource grants with the same verbs stay apart",
			[]rbacv1.PolicyRule{
				{APIGroups: []string{""}, Resources: []string{"pods/exec"}, Verbs: []string{"create"}},
				{APIGroups: []string{""}, Resources: []string{"pods/exec"}, ResourceNames: []string{"my-pod"}, Verbs: []string{"create"}},
			},
			[]rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"*"}}},
			[]RemainingGrant{
				{APIGroup: "", Resource: "pods/exec", Verbs: []string{"create"}, Reason: ReasonSubresource},
				{APIGroup: "", Resource: "pods/exec", ResourceNames: []string{"my-pod"}, Verbs: []string{"create"}, Reason: ReasonSubresource},
			},
		},
		{
			"named subresource targeted directly is reported as resourceNames",
			[]rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods/exec"}, ResourceNames: []string{"my-pod"}, Verbs: []string{"create"}}},
			[]rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods/exec"}, Verbs: []string{"*"}}},
			[]RemainingGrant{
				{APIGroup: "", Resource: "pods/exec", ResourceNames: []string{"my-pod"}, Verbs: []string{"create"}, Reason: ReasonResourceNames},
			},
		},
		{
			"resources '*' targets every resource in the group",
			[]rbacv1.PolicyRule{{APIGroups: []string{"apps"}, Resources: []string{"deployments"}, ResourceNames: []string{"my-app"}, Verbs: []string{"get"}}},
			[]rbacv1.PolicyRule{{APIGroups: []string{"apps"}, Resources: []string{"*"}, Verbs: []string{"*"}}},
			[]RemainingGrant{
				{APIGroup: "apps", Resource: "deployments", ResourceNames: []string{"my-app"}, Verbs: []string{"get"}, Reason: ReasonResourceNames},
			},
		},
		{
			"rules with '*' in apiGroups are not reported",
			[]rbacv1.PolicyRule{{APIGroups: []string{"*"}, Resources: []string{"pods/exec"}, Verbs: []string{"create"}}},
			[]rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"*"}}},
			nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if diff := cmp.Diff(tt.want, RemainingGrants(tt.result, tt.remove), cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("RemainingGrants() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestResourceNamesPreservedWithOtherRules(t *testing.T) {
	source := []rbacv1.PolicyRule{
		{APIGroups: []string{"apps"}, Resources: []string{"deployments"}, ResourceNames: []string{"my-deploy"}, Verbs: []string{"get"}},
		{APIGroups: []string{"apps"}, Resources: []string{"statefulsets"}, Verbs: []string{"get"}},
	}
	remove := []rbacv1.PolicyRule{
		{APIGroups: []string{"apps"}, Resources: []string{"statefulsets"}, Verbs: []string{"get"}},
	}
	result, err := Subtract(source, remove, discardLog)
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("len(Subtract()) = %d, want 1", len(result))
	}
	want := []rbacv1.PolicyRule{
		{APIGroups: []string{"apps"}, Resources: []string{"deployments"}, ResourceNames: []string{"my-deploy"}, Verbs: []string{"get"}},
	}
	if diff := cmp.Diff(want, result, cmpOpts); diff != "" {
		t.Errorf("Subtract() mismatch (-want +got):\n%s", diff)
	}
}

// --- end-to-end scenario tests ---

func TestSubtractSimpleYAMLScenario(t *testing.T) {
	source := []rbacv1.PolicyRule{
		{APIGroups: []string{"networking.k8s.io"}, Resources: []string{"ingresses", "networkpolicies"}, Verbs: []string{"create", "delete", "deletecollection", "patch", "update"}},
		{APIGroups: []string{"apps"}, Resources: []string{"daemonsets", "deployments", "deployments/rollback", "deployments/scale", "replicasets", "replicasets/scale", "statefulsets", "statefulsets/scale"}, Verbs: []string{"create", "delete", "deletecollection", "patch", "update"}},
	}
	remove := []rbacv1.PolicyRule{
		{APIGroups: []string{"networking.k8s.io"}, Resources: []string{"ingresses"}, Verbs: []string{"*"}},
		{APIGroups: []string{"networking.k8s.io"}, Resources: []string{"networkpolicies"}, Verbs: []string{"delete", "deletecollection", "patch", "update"}},
		{APIGroups: []string{"apps"}, Resources: []string{"daemonsets"}, Verbs: []string{"*"}},
	}
	result, err := Subtract(source, remove, discardLog)
	if err != nil {
		t.Fatal(err)
	}
	want := []rbacv1.PolicyRule{
		{APIGroups: []string{"apps"}, Resources: []string{"deployments", "deployments/rollback", "deployments/scale", "replicasets", "replicasets/scale", "statefulsets", "statefulsets/scale"}, Verbs: []string{"create", "delete", "deletecollection", "patch", "update"}},
		{APIGroups: []string{"networking.k8s.io"}, Resources: []string{"networkpolicies"}, Verbs: []string{"create"}},
	}
	if diff := cmp.Diff(want, result, cmpOpts); diff != "" {
		t.Errorf("Subtract() mismatch (-want +got):\n%s", diff)
	}
}

func TestSubtractEditYAMLScenario(t *testing.T) {
	source := []rbacv1.PolicyRule{
		{APIGroups: []string{"apps"}, Resources: []string{"daemonsets", "deployments", "deployments/rollback", "deployments/scale", "replicasets", "replicasets/scale", "statefulsets", "statefulsets/scale"}, Verbs: []string{"create", "delete", "deletecollection", "patch", "update"}},
		{APIGroups: []string{"extensions"}, Resources: []string{"daemonsets", "deployments", "deployments/rollback", "deployments/scale", "ingresses", "networkpolicies", "replicasets", "replicasets/scale", "replicationcontrollers/scale"}, Verbs: []string{"create", "delete", "deletecollection", "patch", "update"}},
		{APIGroups: []string{"networking.k8s.io"}, Resources: []string{"ingresses", "networkpolicies"}, Verbs: []string{"create", "delete", "deletecollection", "patch", "update"}},
	}
	remove := []rbacv1.PolicyRule{
		{APIGroups: []string{"apps"}, Resources: []string{"daemonsets"}, Verbs: []string{"create"}},
		{APIGroups: []string{"networking.k8s.io"}, Resources: []string{"ingresses"}, Verbs: []string{"create", "delete", "deletecollection", "patch", "update"}},
	}
	result, err := Subtract(source, remove, discardLog)
	if err != nil {
		t.Fatal(err)
	}
	want := []rbacv1.PolicyRule{
		{APIGroups: []string{"apps"}, Resources: []string{"daemonsets"}, Verbs: []string{"delete", "deletecollection", "patch", "update"}},
		{APIGroups: []string{"apps"}, Resources: []string{"deployments", "deployments/rollback", "deployments/scale", "replicasets", "replicasets/scale", "statefulsets", "statefulsets/scale"}, Verbs: []string{"create", "delete", "deletecollection", "patch", "update"}},
		{APIGroups: []string{"extensions"}, Resources: []string{"daemonsets", "deployments", "deployments/rollback", "deployments/scale", "ingresses", "networkpolicies", "replicasets", "replicasets/scale", "replicationcontrollers/scale"}, Verbs: []string{"create", "delete", "deletecollection", "patch", "update"}},
		{APIGroups: []string{"networking.k8s.io"}, Resources: []string{"networkpolicies"}, Verbs: []string{"create", "delete", "deletecollection", "patch", "update"}},
	}
	if diff := cmp.Diff(want, result, cmpOpts); diff != "" {
		t.Errorf("Subtract() mismatch (-want +got):\n%s", diff)
	}
}
