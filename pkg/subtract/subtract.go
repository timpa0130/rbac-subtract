package subtract

import (
	"cmp"
	"maps"
	"slices"
	"strings"

	"github.com/go-logr/logr"
	rbacv1 "k8s.io/api/rbac/v1"
)

// Reasons a grant remains on a resource targeted by removeRules.
const (
	ReasonSubresource   = "Subresource"
	ReasonResourceNames = "ResourceNames"
)

// matches checks whether a source tuple matches a removal pattern. '*' in the pattern's apiGroup,
// resource or verb matches any value. Resource names always match exactly, so a pattern without a
// name only removes unrestricted grants.
func matches(source, pattern Permission) bool {
	return (pattern.APIGroup == source.APIGroup || pattern.APIGroup == "*") &&
		(pattern.Resource == source.Resource || pattern.Resource == "*") &&
		pattern.ResourceName == source.ResourceName &&
		(pattern.Verb == source.Verb || pattern.Verb == "*")
}

func flatten(rules []rbacv1.PolicyRule) map[Permission]struct{} {
	result := make(map[Permission]struct{})
	for _, rule := range rules {
		// A rule without resourceNames grants unrestricted access, represented by an empty name
		resourceNames := rule.ResourceNames
		if len(resourceNames) == 0 {
			resourceNames = []string{""}
		}
		for _, apiGroup := range rule.APIGroups {
			for _, resource := range rule.Resources {
				for _, resourceName := range resourceNames {
					for _, verb := range rule.Verbs {
						result[Permission{APIGroup: apiGroup, Resource: resource, ResourceName: resourceName, Verb: verb}] = struct{}{}
					}
				}
			}
		}
	}
	return result
}

// A hard part to cognitivly understand here is that the key is a struct
func regroup(permissions map[Permission]struct{}) []rbacv1.PolicyRule {
	//    Step 1: collect verbs per resource (and resource name)
	//   {apiGroup, resource, name, verb} tuples  →  groups[(apiGroup,resource,name)] = {verb, ...}
	//
	//   Example: {(apps,deployments,get), (apps,deployments,list), (apps,statefulsets,get), (apps,statefulsets,list)}
	//         →  {apps/deployments: {get,list}, apps/statefulsets: {get,list}}
	type resourceGroup struct {
		apiGroup     string
		resource     string
		resourceName string
	}
	type verbSet map[string]struct{}

	groups := make(map[resourceGroup]verbSet)
	for permission := range permissions {
		key := resourceGroup{permission.APIGroup, permission.Resource, permission.ResourceName}
		if groups[key] == nil {
			groups[key] = make(verbSet)
		}
		groups[key][permission.Verb] = struct{}{}
	}

	//   Step 2: merge resources that share identical verbs (and resource name)
	//   groups[(apiGroup,resource,name)] = {verb, ...}  →  merged[(apiGroup, "verb1,verb2", name)] = {resource, ...}
	//
	//   Example: {apps/deployments: {get,list}, apps/statefulsets: {get,list}}
	//         →  {(apps,"get,list"): {deployments, statefulsets}}
	type verbGroup struct {
		apiGroup     string
		verbs        string
		resourceName string
	}
	type resourceSet map[string]struct{}

	merged := make(map[verbGroup]resourceSet)
	for key, verbSet := range groups {
		sortedVerbs := slices.Sorted(maps.Keys(verbSet))
		verbKey := strings.Join(sortedVerbs, ",")
		mergedKey := verbGroup{key.apiGroup, verbKey, key.resourceName}
		if merged[mergedKey] == nil {
			merged[mergedKey] = make(resourceSet)
		}
		merged[mergedKey][key.resource] = struct{}{}
	}

	//   Step 3: merge resource names that share identical verbs and resources
	//   merged[(apiGroup, "verb1,verb2", name)] = {resource, ...}  →  named[(apiGroup, "verb1,verb2", "res1,res2")] = {name, ...}
	//   Unrestricted entries (empty name) are kept apart so they never pick up a name restriction.
	//
	//   Example: {(,"get",a): {configmaps}, (,"get",b): {configmaps}}
	//         →  {(,"get","configmaps"): {a, b}}
	type nameGroup struct {
		apiGroup  string
		verbs     string
		resources string
		named     bool
	}
	type nameSet map[string]struct{}

	named := make(map[nameGroup]nameSet)
	for key, resourceSet := range merged {
		resourceKey := strings.Join(slices.Sorted(maps.Keys(resourceSet)), ",")
		namedKey := nameGroup{key.apiGroup, key.verbs, resourceKey, key.resourceName != ""}
		if named[namedKey] == nil {
			named[namedKey] = make(nameSet)
		}
		named[namedKey][key.resourceName] = struct{}{}
	}

	//	 Step 4: convert to sorted PolicyRules
	//   named[(apiGroup, "verb1,verb2", "res1,res2")] = {name, ...}  →  []PolicyRule
	rules := make([]rbacv1.PolicyRule, 0, len(named))
	for key, nameSet := range named {
		var resourceNames []string
		if key.named {
			resourceNames = slices.Sorted(maps.Keys(nameSet))
		}
		rules = append(rules, rbacv1.PolicyRule{
			APIGroups:     []string{key.apiGroup},
			Resources:     strings.Split(key.resources, ","),
			ResourceNames: resourceNames,
			Verbs:         strings.Split(key.verbs, ","),
		})
	}

	//	 Step 5: Sort the rules for idempotency
	// 	 this is important so we dont endlessly update because its not sorted
	//   	return: "is element at a less than element at b?"
	slices.SortFunc(rules, func(a, b rbacv1.PolicyRule) int {
		return cmp.Or(
			cmp.Compare(a.APIGroups[0], b.APIGroups[0]),
			// Unrestricted rules come before rules restricted to resource names
			cmp.Compare(len(a.ResourceNames), 0)-cmp.Compare(len(b.ResourceNames), 0),
			cmp.Compare(strings.Join(a.Verbs, ","), strings.Join(b.Verbs, ",")),
			cmp.Compare(strings.Join(a.Resources, ","), strings.Join(b.Resources, ",")),
			cmp.Compare(strings.Join(a.ResourceNames, ","), strings.Join(b.ResourceNames, ",")),
		)
	})

	return rules
}

// Subtract removes removeRules from sourceRules, returning the resulting rules.
func Subtract(sourceRules, removeRules []rbacv1.PolicyRule, logger logr.Logger) ([]rbacv1.PolicyRule, error) {

	log := logger.WithName("subtract")

	var passThrough []rbacv1.PolicyRule
	var concrete []rbacv1.PolicyRule
	// Source rules with '*' in apiGroups pass through unchanged.
	for _, rule := range sourceRules {
		if hasWildcard(rule.APIGroups) {
			passThrough = append(passThrough, rule)
		} else {
			concrete = append(concrete, rule)
		}
	}

	if len(passThrough) > 0 {
		log.V(1).Info("skipping rules with '*' in apiGroups (pass through unchanged)", "count", len(passThrough))
		for _, rule := range passThrough {
			log.V(1).Info("pass-through",
				"apiGroups", rule.APIGroups,
				"resources", rule.Resources,
				"resourceNames", rule.ResourceNames,
				"verbs", rule.Verbs,
			)
		}
	}

	if len(concrete) == 0 {
		log.V(1).Info("no concrete source rules to subtract from, returning pass-through", "passThroughCount", len(passThrough))
		return passThrough, nil
	}

	log.V(1).Info("flattening rules", "sourceCount", len(concrete), "removeCount", len(removeRules))

	source := flatten(concrete)
	removeFlat := flatten(removeRules)

	log.V(1).Info("flattened", "sourceCount", len(source), "removeCount", len(removeFlat))

	remaining := make(map[Permission]struct{})
	// Removed tracks which tuples were matched (for logging only)
	type removal struct {
		src, pattern Permission
	}

	var removedTuples []removal

	for permission := range source {
		var matching *Permission
		for pattern := range removeFlat {
			if matches(permission, pattern) {
				p := pattern
				matching = &p
				break
			}
		}
		if matching != nil {
			removedTuples = append(removedTuples, removal{permission, *matching})
		} else {
			remaining[permission] = struct{}{}
		}
	}

	if len(removedTuples) > 0 {
		log.V(1).Info("removed tuples", "count", len(removedTuples))
		for _, removal := range removedTuples {
			log.V(1).Info("removed",
				"sourceApiGroup", removal.src.APIGroup,
				"sourceResource", removal.src.Resource,
				"sourceResourceName", removal.src.ResourceName,
				"sourceVerb", removal.src.Verb,
				"patternApiGroup", removal.pattern.APIGroup,
				"patternResource", removal.pattern.Resource,
				"patternResourceName", removal.pattern.ResourceName,
				"patternVerb", removal.pattern.Verb,
			)
		}
	}

	log.V(1).Info("remaining tuples", "count", len(remaining))

	result := regroup(remaining)
	log.V(1).Info("regrouped", "totalRules", len(result)+len(passThrough),
		"subtractionRules", len(result), "passThrough", len(passThrough))

	return append(result, passThrough...), nil
}

// RemainingGrant is access left on a resource that removeRules targeted, because it is granted through a
// subresource or resource names that the removeRules did not name.
type RemainingGrant struct {
	APIGroup      string
	Resource      string
	ResourceNames []string
	Verbs         []string
	Reason        string
}

// RemainingGrants reports access in resultRules on resources that removeRules targeted but that is still
// granted, because the removeRules did not name it:
//   - Subresource: the parent resource has no unrestricted verbs left, but a subresource still does
//     (removing pods leaves pods/exec).
//   - ResourceNames: the resource has no unrestricted verbs left, but a grant restricted to resource
//     names remains (removing configmaps leaves configmaps restricted to my-config).
//
// Rules with '*' in apiGroups are not subtracted, so they are not reported.
func RemainingGrants(resultRules, removeRules []rbacv1.PolicyRule) []RemainingGrant {
	var concrete []rbacv1.PolicyRule
	for _, rule := range resultRules {
		if !hasWildcard(rule.APIGroups) {
			concrete = append(concrete, rule)
		}
	}
	permissions := flatten(concrete)
	targets := flatten(removeRules)

	type resourceKey struct{ apiGroup, resource string }
	unrestricted := make(map[resourceKey]bool)
	for permission := range permissions {
		if permission.ResourceName == "" {
			unrestricted[resourceKey{permission.APIGroup, permission.Resource}] = true
		}
	}

	targeted := func(apiGroup, resource string) bool {
		for target := range targets {
			if (target.APIGroup == apiGroup || target.APIGroup == "*") &&
				(target.Resource == resource || target.Resource == "*") {
				return true
			}
		}
		return false
	}
	// fullyRemoved means removeRules targeted the resource and no unrestricted access to it is left
	fullyRemoved := func(apiGroup, resource string) bool {
		return targeted(apiGroup, resource) && !unrestricted[resourceKey{apiGroup, resource}]
	}

	type grantKey struct{ apiGroup, resource, resourceName, reason string }
	verbsByGrant := make(map[grantKey]map[string]struct{})
	for permission := range permissions {
		var reason string
		parent, _, isSubresource := strings.Cut(permission.Resource, "/")
		switch {
		case permission.ResourceName != "" && fullyRemoved(permission.APIGroup, permission.Resource):
			reason = ReasonResourceNames
		case isSubresource && fullyRemoved(permission.APIGroup, parent):
			reason = ReasonSubresource
		default:
			continue
		}
		key := grantKey{permission.APIGroup, permission.Resource, permission.ResourceName, reason}
		if verbsByGrant[key] == nil {
			verbsByGrant[key] = make(map[string]struct{})
		}
		verbsByGrant[key][permission.Verb] = struct{}{}
	}

	// Merge resource names that share a resource, reason and verbs into one grant. Unrestricted
	// grants are kept apart so they are never reported as restricted to names.
	type mergedKey struct {
		apiGroup, resource, reason, verbs string
		named                             bool
	}
	namesByGrant := make(map[mergedKey][]string)
	for key, verbs := range verbsByGrant {
		merged := mergedKey{key.apiGroup, key.resource, key.reason, strings.Join(slices.Sorted(maps.Keys(verbs)), ","), key.resourceName != ""}
		namesByGrant[merged] = append(namesByGrant[merged], key.resourceName)
	}

	grants := make([]RemainingGrant, 0, len(namesByGrant))
	for key, names := range namesByGrant {
		var resourceNames []string
		if key.named {
			resourceNames = slices.Sorted(slices.Values(names))
		}
		grants = append(grants, RemainingGrant{
			APIGroup:      key.apiGroup,
			Resource:      key.resource,
			ResourceNames: resourceNames,
			Verbs:         strings.Split(key.verbs, ","),
			Reason:        key.reason,
		})
	}
	slices.SortFunc(grants, func(a, b RemainingGrant) int {
		return cmp.Or(
			cmp.Compare(a.APIGroup, b.APIGroup),
			cmp.Compare(a.Resource, b.Resource),
			cmp.Compare(len(a.ResourceNames), 0)-cmp.Compare(len(b.ResourceNames), 0),
			cmp.Compare(strings.Join(a.ResourceNames, ","), strings.Join(b.ResourceNames, ",")),
			cmp.Compare(strings.Join(a.Verbs, ","), strings.Join(b.Verbs, ",")),
		)
	})
	return grants
}

// Permission represents a single (apiGroup, resource, resourceName, verb) tuple. An empty
// ResourceName means the permission is not restricted to named objects.
type Permission struct {
	APIGroup     string
	Resource     string
	ResourceName string
	Verb         string
}

func hasWildcard(apiGroups []string) bool {
	return slices.Contains(apiGroups, "*")
}
