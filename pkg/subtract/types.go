package subtract

// Permission represents a single (apiGroup, resource, verb) tuple.
type Permission struct {
	APIGroup string
	Resource string
	Verb     string
}
