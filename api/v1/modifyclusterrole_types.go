package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

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

	// +kubebuilder:validation:MinItems=1
	Verbs []string `json:"verbs"`
}

// ModifyClusterRoleStatus defines the observed state of ModifyClusterRole.
type ModifyClusterRoleStatus struct {
	// Number of rules in the generated ClusterRole
	// +optional
	RulesCount int32 `json:"rulesCount,omitempty"`

	// Conditions represent the current state of the resource
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:validation:XValidation:rule="self.spec.clusterRole != self.metadata.name",message="spec.clusterRole cannot be the same as metadata.name — this would overwrite the source ClusterRole"

// ModifyClusterRole is the Schema for the modifyclusterroles API
type ModifyClusterRole struct {
	metav1.TypeMeta `json:",inline"`

	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// +required
	Spec ModifyClusterRoleSpec `json:"spec"`

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
