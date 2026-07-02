package subtract

import (
	"maps"
	"slices"
	"cmp"
	"strings"

	"github.com/go-logr/logr"
	rbacv1 "k8s.io/api/rbac/v1"
)

// Matches checks whether a source permission matches a removal pattern.
// '*' in the pattern acts as wildcard matching any value.
func Matches(source, pattern Permission) bool {
	return (pattern.APIGroup == source.APIGroup || pattern.APIGroup == "*") &&
		(pattern.Resource == source.Resource || pattern.Resource == "*") &&
		(pattern.Verb == source.Verb || pattern.Verb == "*")
}

// Flatten expands PolicyRule dicts into a set of Permission tuples.
func Flatten(rules []rbacv1.PolicyRule) map[Permission]struct{} {
	result := make(map[Permission]struct{})
	for _, rule := range rules {
		for _, apiGroup := range rule.APIGroups {
			for _, resource := range rule.Resources {
				for _, verb := range rule.Verbs {
					result[Permission{APIGroup: apiGroup, Resource: resource, Verb: verb}] = struct{}{}
				}
			}
		}
	}
	return result
}

// A hard part to cognitivly understand here is that the key is a struct
func Regroup(permissions map[Permission]struct{}) []rbacv1.PolicyRule {
	//    Step 1: collect verbs per resource
	//   {apiGroup, resource, verb} tuples  →  groups[(apiGroup,resource)] = {verb, ...}
	//
	//   Example: {(apps,deployments,get), (apps,deployments,list), (apps,statefulsets,get), (apps,statefulsets,list)}
	//         →  {apps/deployments: {get,list}, apps/statefulsets: {get,list}}
	type resourceGroup struct {
		apiGroup string
		resource string
	}
	type verbSet map[string]struct{}

	groups := make(map[resourceGroup]verbSet)
	for permission := range permissions {
		key := resourceGroup{permission.APIGroup, permission.Resource}
		if groups[key] == nil {
			groups[key] = make(verbSet)
		}
		groups[key][permission.Verb] = struct{}{}
	}

	//   Step 2: merge resources that share identical verbs
	//   groups[(apiGroup,resource)] = {verb, ...}  →  merged[(apiGroup, "verb1,verb2")] = {resource, ...}
	//
	//   Example: {apps/deployments: {get,list}, apps/statefulsets: {get,list}}
	//         →  {(apps,"get,list"): {deployments, statefulsets}}
	type verbGroup struct {
		apiGroup string
		verbs    string
	}
	type resourceSet map[string]struct{}

	merged := make(map[verbGroup]resourceSet)
	for key, verbSet := range groups {
		sortedVerbs := slices.Sorted(maps.Keys(verbSet))
		verbKey := strings.Join(sortedVerbs, ",")
		mergedKey := verbGroup{key.apiGroup, verbKey}
		if merged[mergedKey] == nil {
			merged[mergedKey] = make(resourceSet)
		}
		merged[mergedKey][key.resource] = struct{}{}
	}

	//	 Step 3: convert to sorted PolicyRules
	//   merged[(apiGroup, "verb1,verb2")] = {resource, ...}  →  []PolicyRule
	var rules []rbacv1.PolicyRule
	for key, resourceSet := range merged {
		verbList := strings.Split(key.verbs, ",")
		if key.verbs == "" {
			verbList = nil
		}
		rules = append(rules, rbacv1.PolicyRule{
			APIGroups: []string{key.apiGroup},
			Resources: slices.Sorted(maps.Keys(resourceSet)),
			Verbs:     verbList,
		})
	}

	//	 Step 4: Sort the rules for idempotency
	// 	 this is important so we dont endlessly update because its not sorted
	//   	return: "is element at a less than element at b?"
	slices.SortFunc(rules, func(a, b rbacv1.PolicyRule) int {
		// if apiGroups are not the same we compare them, it can only return -1 or 1 then.
	    if a.APIGroups[0] != b.APIGroups[0] {
	        return cmp.Compare(a.APIGroups[0], b.APIGroups[0])  // int: -1/0/1
	    }
		// The apiGroup is the same compare the verbs and sort
	    return cmp.Compare(strings.Join(a.Verbs, ","), strings.Join(b.Verbs, ","))
	})

	return rules
}

// Subtract removes removeRules from sourceRules, returning the resulting rules.
func Subtract(sourceRules, removeRules []rbacv1.PolicyRule, logger logr.Logger) ([]rbacv1.PolicyRule, error) {

	log := logger.WithName("subtract")

	var passThrough []rbacv1.PolicyRule
	var concrete []rbacv1.PolicyRule
	// Source rules with ResourceNames or '*' in apiGroups pass through unchanged.
	for _, rule := range sourceRules {
		if len(rule.ResourceNames) > 0 || hasWildcard(rule.APIGroups) {
			passThrough = append(passThrough, rule)
		} else {
			concrete = append(concrete, rule)
		}
	}

	if len(passThrough) > 0 {
		log.V(1).Info("skipping rules with resourceNames (pass through unchanged)", "count", len(passThrough))
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

	source := Flatten(concrete)
	removeFlat := Flatten(removeRules)

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
			if Matches(permission, pattern) {
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
				"sourceVerb", removal.src.Verb,
				"patternApiGroup", removal.pattern.APIGroup,
				"patternResource", removal.pattern.Resource,
				"patternVerb", removal.pattern.Verb,
			)
		}
	}

	log.V(1).Info("remaining tuples", "count", len(remaining))

	result := Regroup(remaining)
	log.V(1).Info("regrouped", "totalRules", len(result)+len(passThrough),
		"subtractionRules", len(result), "passThrough", len(passThrough))

	return append(result, passThrough...), nil
}

func hasWildcard(apiGroups []string) bool {
	return slices.Contains(apiGroups, "*")
}
