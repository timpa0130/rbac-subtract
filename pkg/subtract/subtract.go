package subtract

import (
	"maps"
	"slices"
	"sort"
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

// Regroup converts a set of Permission tuples back into PolicyRule objects.
// Groups by (apiGroup, resource) to collect verbs, then merges rules that
// share the same apiGroup and verbs into a single rule with combined resources.
func Regroup(permissions map[Permission]struct{}) []rbacv1.PolicyRule {
	// Step 1: group by (apiGroup, resource) -> set of verbs
	type agResourceKey struct {
		apiGroup string
		resource string
	}
	groups := make(map[agResourceKey]map[string]struct{})
	for permission := range permissions {
		key := agResourceKey{permission.APIGroup, permission.Resource}
		if groups[key] == nil {
			groups[key] = make(map[string]struct{})
		}
		groups[key][permission.Verb] = struct{}{}
	}

	// Step 2: merge by (apiGroup, sortedVerbTuple) -> set of resources
	type agVerbsKey struct {
		apiGroup string
		verbs    string // comma-joined sorted verbs, used as a stable key
	}
	merged := make(map[agVerbsKey]map[string]struct{})
	for key, verbSet := range groups {
		sortedVerbs := slices.Sorted(maps.Keys(verbSet))
		verbKey := strings.Join(sortedVerbs, ",")
		agv := agVerbsKey{key.apiGroup, verbKey}
		if merged[agv] == nil {
			merged[agv] = make(map[string]struct{})
		}
		merged[agv][key.resource] = struct{}{}
	}

	// Step 3: build sorted result
	type ruleSpec struct {
		apiGroup  string
		resources []string
		verbs     []string
	}

	var specs []ruleSpec
	for key, resourceSet := range merged {
		verbList := strings.Split(key.verbs, ",")
		if key.verbs == "" {
			verbList = nil
		}
		specs = append(specs, ruleSpec{
			apiGroup:  key.apiGroup,
			resources: slices.Sorted(maps.Keys(resourceSet)),
			verbs:     verbList,
		})
	}

	sort.Slice(specs, func(i, j int) bool {
		if specs[i].apiGroup != specs[j].apiGroup {
			return specs[i].apiGroup < specs[j].apiGroup
		}
		return strings.Join(specs[i].verbs, ",") < strings.Join(specs[j].verbs, ",")
	})

	result := make([]rbacv1.PolicyRule, 0, len(specs))
	for _, spec := range specs {
		result = append(result, rbacv1.PolicyRule{
			APIGroups: []string{spec.apiGroup},
			Resources: spec.resources,
			Verbs:     spec.verbs,
		})
	}
	return result
}

// Subtract removes removeRules from sourceRules, returning the resulting rules.
// Source rules with ResourceNames or '*' in apiGroups pass through unchanged.
func Subtract(sourceRules, removeRules []rbacv1.PolicyRule, logger logr.Logger) ([]rbacv1.PolicyRule, error) {

	log := logger.WithName("subtract")

	var passThrough []rbacv1.PolicyRule
	var concrete []rbacv1.PolicyRule
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
	// removed tracks which tuples were matched (for logging only)
	type removal struct {
		src, pattern Permission
	}
	var removedTuples []removal

	for perm := range source {
		var matching *Permission
		for pattern := range removeFlat {
			if Matches(perm, pattern) {
				p := pattern
				matching = &p
				break
			}
		}
		if matching != nil {
			removedTuples = append(removedTuples, removal{perm, *matching})
		} else {
			remaining[perm] = struct{}{}
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
