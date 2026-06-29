package wildcard

import (
	"context"
	"fmt"
	"sort"
	"slices"

	"github.com/go-logr/logr"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
)

// ExpandWildcards expands wildcards ('*') in source ClusterRole rules
// using the discovery API. Rules with ResourceNames pass through unchanged.
// Errors for '*' in apiGroups or resources not found in discovery.
func ExpandWildcards(ctx context.Context, disco discovery.DiscoveryInterface, rules []rbacv1.PolicyRule, log logr.Logger) ([]rbacv1.PolicyRule, error) {
	logger := log.WithName("wildcard")

	var expanded []rbacv1.PolicyRule
	for _, rule := range rules {
		if len(rule.ResourceNames) > 0 {
			expanded = append(expanded, rule)
			continue
		}

		// Check if the rule contains wildcard in apiGroups if so we return
		if slices.Contains(rule.APIGroups, "*") {
    		return nil, fmt.Errorf("source ClusterRole contains '*' in apiGroups — not supported")
		}

		resources := rule.Resources
		verbs := rule.Verbs
		verbCache := make(map[string][]string)

		if hasWildcard(resources) {
			var resourceNames []string
			for _, apiGroup := range rule.APIGroups {
				names, err := resourcesForGroup(ctx, disco, apiGroup, verbCache)
				if err != nil {
					return nil, fmt.Errorf("discovery API error for apiGroup %q: %w", apiGroup, err)
				}
				logger.V(1).Info("expanding resources", "apiGroup", apiGroup, "count", len(names))
				resourceNames = append(resourceNames, names...)
			}
			resources = uniqueSorted(resourceNames)
		}

		if hasWildcard(verbs) {
			var newVerbs []string
			for _, resourceName := range resources {
				resourceVerbs := verbCache[resourceName]
				if resourceVerbs == nil {
					var err error
					resourceVerbs, err = verbsForResource(ctx, disco, resourceName)
					if err != nil {
						return nil, fmt.Errorf("discovery API error for resource %q: %w", resourceName, err)
					}
				}
				if len(resourceVerbs) == 0 {
					return nil, fmt.Errorf("resource %q not found in discovery API — cannot expand verbs: ['*']", resourceName)
				}
				newVerbs = append(newVerbs, resourceVerbs...)
			}
			verbs = uniqueSorted(newVerbs)
		}

		expanded = append(expanded, rbacv1.PolicyRule{
			APIGroups: rule.APIGroups,
			Resources: resources,
			Verbs:     verbs,
		})
	}
	return expanded, nil
}

func resourcesForGroup(ctx context.Context, disco discovery.DiscoveryInterface, apiGroup string, cache map[string][]string) ([]string, error) {
	apiGroupList, err := disco.ServerGroups()
	if err != nil {
		return nil, err
	}

	var names []string
	seen := make(map[string]bool)
	for _, g := range apiGroupList.Groups {
		if g.Name != apiGroup {
			continue
		}
		for _, v := range g.Versions {
			gv := schema.GroupVersion{Group: apiGroup, Version: v.Version}
			resourceList, err := disco.ServerResourcesForGroupVersion(gv.String())
			if err != nil {
				return nil, err
			}
			for _, r := range resourceList.APIResources {
				if len(r.Verbs) == 0 {
					continue
				}
				if !seen[r.Name] {
					names = append(names, r.Name)
					seen[r.Name] = true
				}
				cache[r.Name] = r.Verbs
			}
		}
	}
	return names, nil
}

func verbsForResource(ctx context.Context, disco discovery.DiscoveryInterface, resourceName string) ([]string, error) {
	apiGroupList, err := disco.ServerGroups()
	if err != nil {
		return nil, err
	}
	for _, g := range apiGroupList.Groups {
		for _, v := range g.Versions {
			resourceList, err := disco.ServerResourcesForGroupVersion(v.GroupVersion)
			if err != nil {
				return nil, err
			}
			for _, r := range resourceList.APIResources {
				if r.Name == resourceName {
					return r.Verbs, nil
				}
			}
		}
	}
	return nil, nil
}

func hasWildcard(items []string) bool {
	for _, item := range items {
		if item == "*" {
			return true
		}
	}
	return false
}

func uniqueSorted(items []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, item := range items {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}
	sort.Strings(result)
	return result
}
