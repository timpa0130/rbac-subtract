package wildcard

import (
	"errors"
	"testing"

	"github.com/go-logr/logr"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	fakediscovery "k8s.io/client-go/discovery/fake"
	clienttesting "k8s.io/client-go/testing"
)

var discardLog = logr.Discard()

var cmpOpts = cmp.Options{cmpopts.EquateEmpty()}

// discoveryResources is what the fake discovery client serves.
// example.com is served in two versions with overlapping resources.
var discoveryResources = []*metav1.APIResourceList{
	{GroupVersion: "v1", APIResources: []metav1.APIResource{
		{Name: "pods", Verbs: metav1.Verbs{"create", "delete", "get", "list", "patch", "update", "watch"}},
		{Name: "pods/log", Verbs: metav1.Verbs{"get"}},
		{Name: "configmaps", Verbs: metav1.Verbs{"get", "list"}},
		{Name: "bindings", Verbs: nil},
	}},
	{GroupVersion: "apps/v1", APIResources: []metav1.APIResource{
		{Name: "deployments", Verbs: metav1.Verbs{"create", "delete", "deletecollection", "get", "list", "patch", "update", "watch"}},
		{Name: "deployments/scale", Verbs: metav1.Verbs{"get", "patch", "update"}},
		{Name: "statefulsets", Verbs: metav1.Verbs{"get", "list", "watch"}},
	}},
	{GroupVersion: "example.com/v1", APIResources: []metav1.APIResource{
		{Name: "widgets", Verbs: metav1.Verbs{"get", "list"}},
	}},
	{GroupVersion: "example.com/v2", APIResources: []metav1.APIResource{
		{Name: "widgets", Verbs: metav1.Verbs{"get", "list", "watch"}},
		{Name: "gadgets", Verbs: metav1.Verbs{"get"}},
	}},
}

func newFakeDiscovery() *fakediscovery.FakeDiscovery {
	return &fakediscovery.FakeDiscovery{Fake: &clienttesting.Fake{Resources: discoveryResources}}
}

// --- ExpandWildcards ---

func TestExpandWildcards(t *testing.T) {
	tests := []struct {
		name            string
		rules           []rbacv1.PolicyRule
		want            []rbacv1.PolicyRule
		wantWildcardAPI bool
	}{
		{
			"concrete rule unchanged",
			[]rbacv1.PolicyRule{{APIGroups: []string{"apps"}, Resources: []string{"deployments"}, Verbs: []string{"get"}}},
			[]rbacv1.PolicyRule{{APIGroups: []string{"apps"}, Resources: []string{"deployments"}, Verbs: []string{"get"}}},
			false,
		},
		{
			"resources '*' expands to every resource in the group",
			[]rbacv1.PolicyRule{{APIGroups: []string{"apps"}, Resources: []string{"*"}, Verbs: []string{"get"}}},
			[]rbacv1.PolicyRule{{APIGroups: []string{"apps"}, Resources: []string{"deployments", "deployments/scale", "statefulsets"}, Verbs: []string{"get"}}},
			false,
		},
		{
			"verbs '*' expands to the verbs discovery reports",
			[]rbacv1.PolicyRule{{APIGroups: []string{"apps"}, Resources: []string{"deployments"}, Verbs: []string{"*"}}},
			[]rbacv1.PolicyRule{{APIGroups: []string{"apps"}, Resources: []string{"deployments"}, Verbs: []string{"create", "delete", "deletecollection", "get", "list", "patch", "update", "watch"}}},
			false,
		},
		{
			"verbs '*' over several resources is the union of their verbs",
			[]rbacv1.PolicyRule{{APIGroups: []string{"apps"}, Resources: []string{"deployments/scale", "statefulsets"}, Verbs: []string{"*"}}},
			[]rbacv1.PolicyRule{{APIGroups: []string{"apps"}, Resources: []string{"deployments/scale", "statefulsets"}, Verbs: []string{"get", "list", "patch", "update", "watch"}}},
			false,
		},
		{
			"resources and verbs '*' both expand",
			[]rbacv1.PolicyRule{{APIGroups: []string{"apps"}, Resources: []string{"*"}, Verbs: []string{"*"}}},
			[]rbacv1.PolicyRule{{APIGroups: []string{"apps"}, Resources: []string{"deployments", "deployments/scale", "statefulsets"}, Verbs: []string{"create", "delete", "deletecollection", "get", "list", "patch", "update", "watch"}}},
			false,
		},
		{
			"core group expands and skips resources without verbs",
			[]rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"*"}, Verbs: []string{"get"}}},
			[]rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"configmaps", "pods", "pods/log"}, Verbs: []string{"get"}}},
			false,
		},
		{
			"resources and verbs are deduplicated across group versions",
			[]rbacv1.PolicyRule{{APIGroups: []string{"example.com"}, Resources: []string{"*"}, Verbs: []string{"*"}}},
			[]rbacv1.PolicyRule{{APIGroups: []string{"example.com"}, Resources: []string{"gadgets", "widgets"}, Verbs: []string{"get", "list", "watch"}}},
			false,
		},
		{
			"unknown group with resources '*' expands to no resources",
			[]rbacv1.PolicyRule{{APIGroups: []string{"example.org"}, Resources: []string{"*"}, Verbs: []string{"get"}}},
			[]rbacv1.PolicyRule{{APIGroups: []string{"example.org"}, Resources: nil, Verbs: []string{"get"}}},
			false,
		},
		{
			"apiGroups '*' passes through and is flagged",
			[]rbacv1.PolicyRule{{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"}}},
			[]rbacv1.PolicyRule{{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"}}},
			true,
		},
		{
			"resourceNames rule is expanded and keeps its names",
			[]rbacv1.PolicyRule{{APIGroups: []string{"apps"}, Resources: []string{"deployments"}, ResourceNames: []string{"my-app"}, Verbs: []string{"*"}}},
			[]rbacv1.PolicyRule{{APIGroups: []string{"apps"}, Resources: []string{"deployments"}, ResourceNames: []string{"my-app"}, Verbs: []string{"create", "delete", "deletecollection", "get", "list", "patch", "update", "watch"}}},
			false,
		},
		{
			"'*/subresource' expands to every resource with that subresource",
			[]rbacv1.PolicyRule{{APIGroups: []string{"apps"}, Resources: []string{"*/scale"}, Verbs: []string{"get"}}},
			[]rbacv1.PolicyRule{{APIGroups: []string{"apps"}, Resources: []string{"deployments/scale"}, Verbs: []string{"get"}}},
			false,
		},
		{
			"'*/subresource' expands across the rule's groups and keeps concrete resources",
			[]rbacv1.PolicyRule{{APIGroups: []string{"", "apps"}, Resources: []string{"*/log", "*/scale", "configmaps"}, Verbs: []string{"get"}}},
			[]rbacv1.PolicyRule{{APIGroups: []string{"", "apps"}, Resources: []string{"configmaps", "deployments/scale", "pods/log"}, Verbs: []string{"get"}}},
			false,
		},
		{
			"'*/subresource' with verbs '*' uses the subresources' verbs",
			[]rbacv1.PolicyRule{{APIGroups: []string{"apps"}, Resources: []string{"*/scale"}, Verbs: []string{"*"}}},
			[]rbacv1.PolicyRule{{APIGroups: []string{"apps"}, Resources: []string{"deployments/scale"}, Verbs: []string{"get", "patch", "update"}}},
			false,
		},
		{
			"'*/subresource' that nothing has expands to no resources",
			[]rbacv1.PolicyRule{{APIGroups: []string{"apps"}, Resources: []string{"*/exec"}, Verbs: []string{"get"}}},
			[]rbacv1.PolicyRule{{APIGroups: []string{"apps"}, Resources: nil, Verbs: []string{"get"}}},
			false,
		},
		{
			"rule order is preserved",
			[]rbacv1.PolicyRule{
				{APIGroups: []string{"apps"}, Resources: []string{"statefulsets"}, Verbs: []string{"*"}},
				{APIGroups: []string{"*"}, Resources: []string{"nodes"}, Verbs: []string{"get"}},
				{APIGroups: []string{""}, Resources: []string{"configmaps"}, Verbs: []string{"get"}},
			},
			[]rbacv1.PolicyRule{
				{APIGroups: []string{"apps"}, Resources: []string{"statefulsets"}, Verbs: []string{"get", "list", "watch"}},
				{APIGroups: []string{"*"}, Resources: []string{"nodes"}, Verbs: []string{"get"}},
				{APIGroups: []string{""}, Resources: []string{"configmaps"}, Verbs: []string{"get"}},
			},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotWildcardAPI, err := ExpandWildcards(newFakeDiscovery(), tt.rules, discardLog)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if diff := cmp.Diff(tt.want, got, cmpOpts); diff != "" {
				t.Errorf("rules mismatch (-want +got):\n%s", diff)
			}
			if gotWildcardAPI != tt.wantWildcardAPI {
				t.Errorf("hadWildcardAPI = %v, want %v", gotWildcardAPI, tt.wantWildcardAPI)
			}
		})
	}
}

func TestExpandWildcardsVerbsOnUnknownResource(t *testing.T) {
	rules := []rbacv1.PolicyRule{{APIGroups: []string{"apps"}, Resources: []string{"cronjobs"}, Verbs: []string{"*"}}}
	if _, _, err := ExpandWildcards(newFakeDiscovery(), rules, discardLog); err == nil {
		t.Fatal("expected an error for verbs '*' on a resource missing from discovery")
	}
}

func TestExpandWildcardsDiscoveryErrors(t *testing.T) {
	tests := []struct {
		name     string
		resource string // fake discovery action resource: "group" for ServerGroups, "resource" for ServerResourcesForGroupVersion
	}{
		{"server groups error is returned", "group"},
		{"group version resources error is returned", "resource"},
	}
	rules := []rbacv1.PolicyRule{{APIGroups: []string{"apps"}, Resources: []string{"deployments"}, Verbs: []string{"get"}}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			discovery := newFakeDiscovery()
			discovery.PrependReactor("get", tt.resource, func(clienttesting.Action) (bool, runtime.Object, error) {
				return true, nil, errors.New("discovery unavailable")
			})
			if _, _, err := ExpandWildcards(discovery, rules, discardLog); err == nil {
				t.Fatal("expected the discovery error to be returned")
			}
		})
	}
}
