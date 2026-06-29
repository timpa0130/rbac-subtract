package wildcard

import (
	"errors"
	"sort"
	"slices"

	"github.com/go-logr/logr"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
)

func ExpandWildcards(discoveryClient discovery.DiscoveryInterface, rules []rbacv1.PolicyRule, log logr.Logger) ([]rbacv1.PolicyRule, bool, error) {
	log = log.WithName("wildcard")

	// Discover apiGroups, Resources and Verbs for the rules 
	// ----------------------------------------------------- 
	uniqueApiGroups := collectApiGroups(rules)
	apiGroupVersions, err := fetchApiGroupVersions(discoveryClient, uniqueApiGroups)
	if err != nil {
		return nil, false, err
	}

	scopedCache, err := discoverResources(discoveryClient, apiGroupVersions)
	if err != nil {
		return nil, false, err
	}
	// ----------------------------------------------------- 

	hadWildcardAPI := false
	var expanded []rbacv1.PolicyRule

	// Here we need to build a new the expanded single instance of rbacv1.PolicyRule
	for _, rule := range rules {
		// We need to check if the rule can be proccesed, if not pass it through as is.
		if len(rule.ResourceNames) > 0 {
			log.V(1).Info("passing through rule with resourceNames — subtraction skipped",
				"apiGroups", rule.APIGroups,
				"resources", rule.Resources,
				"resourceNames", rule.ResourceNames,
				"verbs", rule.Verbs,
			)
			expanded = append(expanded, rule)
			continue
		}
		if hasWildcard(rule.APIGroups) {
			// If this happens we want a label on the resource we will create.
			// Warning that the subtraction may not work correctly.
			hadWildcardAPI = true
			log.V(0).Info("passing through rule with '*' in apiGroups — subtraction skipped",
				"apiGroups", rule.APIGroups,
				"resources", rule.Resources,
				"verbs", rule.Verbs,
			)
			expanded = append(expanded, rule)
			continue
		}
		
		resources := rule.Resources
		verbs := rule.Verbs

		// The resources is wildcarded, build the rule with the actuall resources
		if hasWildcard(resources) {
			resources = expandResourceNames(scopedCache, rule.APIGroups)
			log.V(1).Info("expanded resources", "count", len(resources))
		}

		// The verbs in this rule has a wildcard expand it to the available verbs
		if hasWildcard(verbs) {
			verbs, err = expandVerbs(scopedCache, rule.APIGroups, resources)
			if err != nil {
				return nil, false, err
			}
		}

		// Append the expanded rule to the 	"var expanded []rbacv1.PolicyRule"
		expanded = append(expanded, rbacv1.PolicyRule{
			APIGroups: rule.APIGroups,
			Resources: resources,
			Verbs:     verbs,
		})
	}
	return expanded, hadWildcardAPI, nil
}


func collectApiGroups(rules []rbacv1.PolicyRule) []string {
	var all []string
	for _, rule := range rules {
		// Exclude pass-through rules as we dont want to process those
		if len(rule.ResourceNames) > 0 || hasWildcard(rule.APIGroups) {
			continue
		}
		all = append(all, rule.APIGroups...)
	}
	return dedupeSorted(nil, all)
}


func fetchApiGroupVersions(discoveryClient discovery.DiscoveryInterface, apiGroups []string) (map[string][]string, error) {
	// fetchApiGroupVersions resolves the apiGroups and its versions returning a list needed for resolving resources
	// The versions isnt used on the rules so we only want to discover resources that may be only present on a newer or older apiVersion
	apiGroupList, err := discoveryClient.ServerGroups()
	if err != nil {
		return nil, err
	}

	result := make(map[string][]string, len(apiGroups))
	for _, apiGroup := range apiGroups {
		for _, group := range apiGroupList.Groups {
			if group.Name == apiGroup {
				for _, version := range group.Versions {
					result[apiGroup] = append(result[apiGroup], version.Version)
				}
			}
		}
	}
	return result, nil
}

// discoverResources fetches all resources for the given groupVersion and
// returns a cache scoped per apiGroup: apiGroup → resourceName → verbs.
// We dont use the versions after this
func discoverResources(discoveryClient discovery.DiscoveryInterface, apiGroupVersions map[string][]string) (map[string]map[string][]string, error) {
	cache := make(map[string]map[string][]string)

	for apiGroup, versions := range apiGroupVersions {
		cache[apiGroup] = make(map[string][]string)
		for _, version := range versions {
			groupVersion := schema.GroupVersion{Group: apiGroup, Version: version}
			resourceList, err := discoveryClient.ServerResourcesForGroupVersion(groupVersion.String())
			if err != nil {
				return nil, err
			}
			for _, resource := range resourceList.APIResources {
				if len(resource.Verbs) == 0 {
					continue
				}
				cache[apiGroup][resource.Name] = dedupeSorted(cache[apiGroup][resource.Name], resource.Verbs)
			}
		}
	}
	return cache, nil
}

// expandResourceNames collects and deduplicates resource names across the
// given apiGroups from the scoped cache.
func expandResourceNames(cache map[string]map[string][]string, apiGroups []string) []string {
	var allNames []string
	for _, apiGroup := range apiGroups {
		for resourceName := range cache[apiGroup] {
			allNames = append(allNames, resourceName)
		}
	}
	return dedupeSorted(nil, allNames)
}

// expandVerbs resolves the verbs for each resource across the rule's apiGroups,
// returning a deduplicated sorted list. A rule with multiple apiGroups applies
// the same verbs to a resource across all groups, so we union the results.
func expandVerbs(cache map[string]map[string][]string, apiGroups, resources []string) ([]string, error) {
	var allVerbs []string
	for _, resourceName := range resources {
		var found bool
		for _, apiGroup := range apiGroups {
			if verbs, exists := cache[apiGroup][resourceName]; exists {
				allVerbs = append(allVerbs, verbs...)
				found = true
			}
		}
		if !found {
			return nil, errors.New("resource not found in discovery API — cannot expand verbs")
		}
	}
	return dedupeSorted(nil, allVerbs), nil
}

func hasWildcard(items []string) bool {
	return slices.Contains(items, "*")
}

func dedupeSorted(existing, new []string) []string {
	combined := append(existing, new...)
	// Creating a map with a bool is a more efficent approach
	// For 100 items: map does ~100 lookups, slice does ~5,000
	seen := make(map[string]bool)
	var result []string
	for _, item := range combined {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}
	sort.Strings(result)
	return result
}
