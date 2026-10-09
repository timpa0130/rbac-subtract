package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// ModifyClusterRoleSpec defines the desired state of ModifyClusterRole
type ModifyClusterRoleSpec struct {
	// +kubebuilder:validation:MinLength=1
	// Name of the source ClusterRole to copy from
	ClusterRole string `json:"clusterRole"`

	// +kubebuilder:validation:MinItems=1
	// Rules to subtract from the source ClusterRole
	RemoveRules []RemoveRule `json:"removeRules"`
}

// RemoveRule defines a rule to remove from the source ClusterRole.
type RemoveRule struct {
	// +kubebuilder:validation:MinItems=1
	APIGroups []string `json:"apiGroups"`

	// +kubebuilder:validation:MinItems=1
	Resources []string `json:"resources"`

	// ResourceNames restricts the rule to the named objects. A rule without resourceNames only
	// removes grants that are not restricted to names, so named grants must be listed explicitly.
	// +optional
	ResourceNames []string `json:"resourceNames,omitempty"`

	// +kubebuilder:validation:MinItems=1
	Verbs []string `json:"verbs"`
}

// RemainingGrant is access that is still granted on a resource targeted by removeRules,
// through a subresource or resourceNames that the removeRules did not name.
type RemainingGrant struct {
	// APIGroup of the resource; empty for the core group
	APIGroup string `json:"apiGroup"`

	// Resource that is still granted, e.g. pods/exec
	Resource string `json:"resource"`

	// ResourceNames the grant is restricted to, if any
	// +optional
	ResourceNames []string `json:"resourceNames,omitempty"`

	// Verbs that are still granted
	Verbs []string `json:"verbs"`

	// Reason the grant remains: Subresource when the parent resource was removed but this
	// subresource was not, ResourceNames when unnamed access was removed but this named grant was not
	// +kubebuilder:validation:Enum=Subresource;ResourceNames
	Reason string `json:"reason"`
}

// ModifyClusterRoleStatus defines the observed state of ModifyClusterRole.
type ModifyClusterRoleStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// For Kubernetes API conventions, see:
	// https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md#typical-status-properties

	// Conditions represent the current state of the ModifyClusterRole resource.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// Number of rules in the generated ClusterRole
	// +optional
	RulesCount int32 `json:"rulesCount,omitempty"`

	// RemainingGrants lists access that is still granted on resources targeted by removeRules,
	// because it comes through subresources or resourceNames that the removeRules did not name
	// +listType=atomic
	// +optional
	RemainingGrants []RemainingGrant `json:"remainingGrants,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster

// ModifyClusterRole is the Schema for the modifyclusterroles API
type ModifyClusterRole struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of ModifyClusterRole
	// +required
	Spec ModifyClusterRoleSpec `json:"spec"`

	// status defines the observed state of ModifyClusterRole
	// +optional
	Status ModifyClusterRoleStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// ModifyClusterRoleList contains a list of ModifyClusterRole
type ModifyClusterRoleList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []ModifyClusterRole `json:"items"`
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &ModifyClusterRole{}, &ModifyClusterRoleList{})
		return nil
	})
}
