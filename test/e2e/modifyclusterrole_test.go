//go:build e2e
// +build e2e

package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	kimv1 "github.com/timpa0130/rbac-subtract/api/v1"
	"github.com/timpa0130/rbac-subtract/test/utils"
)

const wildcardAPIAnnotation = "subtract.rbac.kim.karolinska.se/api-group-wildcard"

// modifyClusterRoleSpecs registers the ModifyClusterRole scenarios. It is called from the
// ordered Manager container in e2e_test.go, which deploys the controller before these run.
func modifyClusterRoleSpecs() {
	Context("subtraction", func() {
		DescribeTable("writes the expected rules to the target ClusterRole",
			func(name string, source []rbacv1.PolicyRule, remove []kimv1.RemoveRule, want []rbacv1.PolicyRule) {
				target := reconcileScenario(name, source, remove)
				Expect(target.Rules).To(Equal(want))
			},
			Entry("removes an entire rule", "e2e-remove-rule",
				[]rbacv1.PolicyRule{
					{APIGroups: []string{"apps"}, Resources: []string{"deployments"}, Verbs: []string{"get", "list", "watch"}},
					{APIGroups: []string{"networking.k8s.io"}, Resources: []string{"ingresses"}, Verbs: []string{"list"}},
				},
				[]kimv1.RemoveRule{{APIGroups: []string{"networking.k8s.io"}, Resources: []string{"ingresses"}, Verbs: []string{"list"}}},
				[]rbacv1.PolicyRule{
					{APIGroups: []string{"apps"}, Resources: []string{"deployments"}, Verbs: []string{"get", "list", "watch"}},
				},
			),
			Entry("removes one resource from a multi-resource rule", "e2e-remove-resource",
				[]rbacv1.PolicyRule{
					{APIGroups: []string{"networking.k8s.io"}, Resources: []string{"ingresses", "networkpolicies"}, Verbs: []string{"list"}},
				},
				[]kimv1.RemoveRule{{APIGroups: []string{"networking.k8s.io"}, Resources: []string{"ingresses"}, Verbs: []string{"list"}}},
				[]rbacv1.PolicyRule{
					{APIGroups: []string{"networking.k8s.io"}, Resources: []string{"networkpolicies"}, Verbs: []string{"list"}},
				},
			),
			Entry("splits a rule when one resource loses a verb", "e2e-split",
				[]rbacv1.PolicyRule{
					{APIGroups: []string{"networking.k8s.io"}, Resources: []string{"ingresses", "networkpolicies"}, Verbs: []string{"list", "patch"}},
				},
				[]kimv1.RemoveRule{{APIGroups: []string{"networking.k8s.io"}, Resources: []string{"ingresses"}, Verbs: []string{"patch"}}},
				[]rbacv1.PolicyRule{
					{APIGroups: []string{"networking.k8s.io"}, Resources: []string{"ingresses"}, Verbs: []string{"list"}},
					{APIGroups: []string{"networking.k8s.io"}, Resources: []string{"networkpolicies"}, Verbs: []string{"list", "patch"}},
				},
			),
			Entry("removes every verb on a resource with verbs '*'", "e2e-remove-all-verbs",
				[]rbacv1.PolicyRule{
					{APIGroups: []string{"apps"}, Resources: []string{"deployments", "statefulsets"}, Verbs: []string{"get", "list"}},
				},
				[]kimv1.RemoveRule{{APIGroups: []string{"apps"}, Resources: []string{"deployments"}, Verbs: []string{"*"}}},
				[]rbacv1.PolicyRule{
					{APIGroups: []string{"apps"}, Resources: []string{"statefulsets"}, Verbs: []string{"get", "list"}},
				},
			),
			Entry("removes a verb across a group with resources '*'", "e2e-remove-all-resources",
				[]rbacv1.PolicyRule{
					{APIGroups: []string{"apps"}, Resources: []string{"deployments", "statefulsets"}, Verbs: []string{"get", "list"}},
					{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}},
				},
				[]kimv1.RemoveRule{{APIGroups: []string{"apps"}, Resources: []string{"*"}, Verbs: []string{"list"}}},
				[]rbacv1.PolicyRule{
					{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}},
					{APIGroups: []string{"apps"}, Resources: []string{"deployments", "statefulsets"}, Verbs: []string{"get"}},
				},
			),
			Entry("keeps a named grant when the removeRule has no names", "e2e-resource-names-kept",
				[]rbacv1.PolicyRule{
					{APIGroups: []string{""}, Resources: []string{"configmaps"}, ResourceNames: []string{"my-config"}, Verbs: []string{"get"}},
					{APIGroups: []string{""}, Resources: []string{"configmaps"}, Verbs: []string{"get", "list"}},
				},
				[]kimv1.RemoveRule{{APIGroups: []string{""}, Resources: []string{"configmaps"}, Verbs: []string{"get"}}},
				[]rbacv1.PolicyRule{
					{APIGroups: []string{""}, Resources: []string{"configmaps"}, Verbs: []string{"list"}},
					{APIGroups: []string{""}, Resources: []string{"configmaps"}, ResourceNames: []string{"my-config"}, Verbs: []string{"get"}},
				},
			),
			Entry("removes a named grant when the removeRule names it", "e2e-resource-names-removed",
				[]rbacv1.PolicyRule{
					{APIGroups: []string{""}, Resources: []string{"configmaps"}, ResourceNames: []string{"my-config", "other-config"}, Verbs: []string{"get", "update"}},
					{APIGroups: []string{""}, Resources: []string{"configmaps"}, Verbs: []string{"list"}},
				},
				[]kimv1.RemoveRule{{APIGroups: []string{""}, Resources: []string{"configmaps"}, ResourceNames: []string{"my-config"}, Verbs: []string{"update"}}},
				[]rbacv1.PolicyRule{
					{APIGroups: []string{""}, Resources: []string{"configmaps"}, Verbs: []string{"list"}},
					{APIGroups: []string{""}, Resources: []string{"configmaps"}, ResourceNames: []string{"my-config"}, Verbs: []string{"get"}},
					{APIGroups: []string{""}, Resources: []string{"configmaps"}, ResourceNames: []string{"other-config"}, Verbs: []string{"get", "update"}},
				},
			),
		)
	})

	Context("wildcard expansion with real discovery", func() {
		It("expands resources '*' to the group's resources before subtracting", func() {
			target := reconcileScenario("e2e-wildcard-resources",
				[]rbacv1.PolicyRule{{APIGroups: []string{"apps"}, Resources: []string{"*"}, Verbs: []string{"get"}}},
				[]kimv1.RemoveRule{{APIGroups: []string{"apps"}, Resources: []string{"deployments"}, Verbs: []string{"get"}}},
			)
			permissions := flatten(target.Rules)
			Expect(permissions).NotTo(ContainElement(ContainSubstring("*")), "no wildcard should survive expansion")
			Expect(permissions).NotTo(ContainElement("apps/deployments/get"))
			Expect(permissions).To(ContainElements(
				"apps/statefulsets/get",
				"apps/daemonsets/get",
				"apps/replicasets/get",
				"apps/controllerrevisions/get",
				// Subresources are separate RBAC resources, so removing deployments keeps deployments/scale
				"apps/deployments/scale/get",
			))
		})

		It("expands verbs '*' to the verbs discovery reports before subtracting", func() {
			target := reconcileScenario("e2e-wildcard-verbs",
				[]rbacv1.PolicyRule{{APIGroups: []string{"apps"}, Resources: []string{"deployments"}, Verbs: []string{"*"}}},
				[]kimv1.RemoveRule{{APIGroups: []string{"apps"}, Resources: []string{"deployments"}, Verbs: []string{"delete", "deletecollection"}}},
			)
			Expect(target.Rules).To(Equal([]rbacv1.PolicyRule{
				{APIGroups: []string{"apps"}, Resources: []string{"deployments"}, Verbs: []string{"create", "get", "list", "patch", "update", "watch"}},
			}))
		})

		It("expands '*/scale' in a source role so one scale subresource can be removed", func() {
			target := reconcileScenario("e2e-wildcard-subresource",
				[]rbacv1.PolicyRule{{APIGroups: []string{"apps"}, Resources: []string{"*/scale"}, Verbs: []string{"get", "update"}}},
				[]kimv1.RemoveRule{{APIGroups: []string{"apps"}, Resources: []string{"deployments/scale"}, Verbs: []string{"*"}}},
			)
			permissions := flatten(target.Rules)
			Expect(permissions).NotTo(ContainElement(ContainSubstring("*")), "no wildcard should survive expansion")
			Expect(permissions).NotTo(ContainElement(HavePrefix("apps/deployments/scale/")))
			Expect(permissions).To(ContainElements(
				"apps/replicasets/scale/get", "apps/replicasets/scale/update",
				"apps/statefulsets/scale/get", "apps/statefulsets/scale/update",
			))
		})

		It("discovers resources served by a CRD", func() {
			target := reconcileScenario("e2e-wildcard-crd",
				[]rbacv1.PolicyRule{{APIGroups: []string{kimv1.GroupVersion.Group}, Resources: []string{"*"}, Verbs: []string{"*"}}},
				[]kimv1.RemoveRule{{APIGroups: []string{kimv1.GroupVersion.Group}, Resources: []string{"modifyclusterroles/status"}, Verbs: []string{"*"}}},
			)
			Expect(target.Rules).To(Equal([]rbacv1.PolicyRule{
				{
					APIGroups: []string{kimv1.GroupVersion.Group},
					Resources: []string{"modifyclusterroles"},
					Verbs:     []string{"create", "delete", "deletecollection", "get", "list", "patch", "update", "watch"},
				},
			}))
		})

		It("passes apiGroups '*' through unchanged and annotates the target", func() {
			source := []rbacv1.PolicyRule{{APIGroups: []string{"*"}, Resources: []string{"pods"}, Verbs: []string{"get"}}}
			target := reconcileScenario("e2e-wildcard-api-group", source,
				[]kimv1.RemoveRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}}},
			)
			Expect(target.Rules).To(Equal(source))
			Expect(target.Annotations).To(HaveKey(wildcardAPIAnnotation))
		})
	})

	Context("remaining grants", func() {
		It("lists access left through subresources and resourceNames until the removeRules name it", func() {
			const name = "e2e-remaining-grants"
			reconcileScenario(name,
				[]rbacv1.PolicyRule{
					{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get", "list"}},
					{APIGroups: []string{""}, Resources: []string{"pods/exec"}, Verbs: []string{"create"}},
					{APIGroups: []string{""}, Resources: []string{"configmaps"}, Verbs: []string{"get"}},
					{APIGroups: []string{""}, Resources: []string{"configmaps"}, ResourceNames: []string{"my-config"}, Verbs: []string{"get"}},
				},
				[]kimv1.RemoveRule{{APIGroups: []string{""}, Resources: []string{"pods", "configmaps"}, Verbs: []string{"*"}}},
			)
			Expect(getModifyClusterRole(name).Status.RemainingGrants).To(Equal([]kimv1.RemainingGrant{
				{APIGroup: "", Resource: "configmaps", ResourceNames: []string{"my-config"}, Verbs: []string{"get"}, Reason: "ResourceNames"},
				{APIGroup: "", Resource: "pods/exec", Verbs: []string{"create"}, Reason: "Subresource"},
			}))

			By("naming the remaining grants in the removeRules")
			applyObject(modifyClusterRole(name, name+"-source", []kimv1.RemoveRule{
				{APIGroups: []string{""}, Resources: []string{"pods", "configmaps", "pods/exec"}, Verbs: []string{"*"}},
				{APIGroups: []string{""}, Resources: []string{"configmaps"}, ResourceNames: []string{"my-config"}, Verbs: []string{"*"}},
			}))
			waitForCondition(name, "Available", "Reconciled")
			Expect(getModifyClusterRole(name).Status.RemainingGrants).To(BeEmpty())
			Expect(getClusterRole(name).Rules).To(BeEmpty())
		})
	})

	Context("lifecycle and ownership", func() {
		It("garbage-collects the target when the ModifyClusterRole is deleted", func() {
			const name = "e2e-gc"
			target := reconcileScenario(name,
				[]rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get", "list"}}},
				[]kimv1.RemoveRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"list"}}},
			)
			Expect(target.OwnerReferences).To(HaveLen(1))
			Expect(target.OwnerReferences[0].Kind).To(Equal("ModifyClusterRole"))

			kubectl("delete", "modifyclusterrole", name, "--wait=true")
			Eventually(func(g Gomega) {
				g.Expect(clusterRoleExists(name)).To(BeFalse())
			}).Should(Succeed())
		})

		It("leaves an existing ClusterRole it does not own unchanged", func() {
			const name = "e2e-not-owned"
			existing := clusterRole(name, []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}}})
			existing.Labels = map[string]string{"owner": "platform-team"}
			applyObject(existing)
			applyObject(clusterRole(name+"-source", []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"configmaps"}, Verbs: []string{"get"}}}))
			applyObject(modifyClusterRole(name, name+"-source",
				[]kimv1.RemoveRule{{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get"}}}))
			DeferCleanup(cleanupScenario, name)

			waitForCondition(name, "Degraded", "TargetNotOwned")
			unchanged := getClusterRole(name)
			Expect(unchanged.Rules).To(Equal(existing.Rules))
			Expect(unchanged.Labels).To(Equal(existing.Labels))
			Expect(unchanged.OwnerReferences).To(BeEmpty())

			kubectl("delete", "modifyclusterrole", name, "--wait=true")
			Consistently(func(g Gomega) {
				g.Expect(clusterRoleExists(name)).To(BeTrue())
			}, 10*time.Second, time.Second).Should(Succeed())
		})

		It("reports a missing source and recovers once the source exists", func() {
			const name = "e2e-missing-source"
			applyObject(modifyClusterRole(name, name+"-source",
				[]kimv1.RemoveRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"list"}}}))
			DeferCleanup(cleanupScenario, name)

			waitForCondition(name, "Degraded", "SourceNotFound")
			Expect(clusterRoleExists(name)).To(BeFalse())

			applyObject(clusterRole(name+"-source", []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get", "list"}}}))
			waitForCondition(name, "Available", "Reconciled")
			Expect(getClusterRole(name).Rules).To(Equal([]rbacv1.PolicyRule{
				{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}},
			}))
		})

		It("copies labels and annotations to the target, except kubectl annotations", func() {
			const name = "e2e-metadata"
			applyObject(clusterRole(name+"-source", []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get", "list"}}}))
			mcr := modifyClusterRole(name, name+"-source",
				[]kimv1.RemoveRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"list"}}})
			mcr.Labels = map[string]string{"team": "platform"}
			mcr.Annotations = map[string]string{"example.com/note": "hello"}
			// kubectl apply also adds kubectl.kubernetes.io/last-applied-configuration to the ModifyClusterRole
			applyObject(mcr)
			DeferCleanup(cleanupScenario, name)

			waitForCondition(name, "Available", "Reconciled")
			target := getClusterRole(name)
			Expect(target.Labels).To(HaveKeyWithValue("team", "platform"))
			Expect(target.Labels).To(HaveKeyWithValue("app.kubernetes.io/managed-by", "rbac-subtract"))
			Expect(target.Annotations).To(HaveKeyWithValue("example.com/note", "hello"))
			Expect(target.Annotations).NotTo(HaveKey("kubectl.kubernetes.io/last-applied-configuration"))
		})
	})
}

// reconcileScenario creates a source ClusterRole and a ModifyClusterRole named name, waits for the
// ModifyClusterRole to become Available, and returns the target ClusterRole.
func reconcileScenario(name string, source []rbacv1.PolicyRule, remove []kimv1.RemoveRule) *rbacv1.ClusterRole {
	applyObject(clusterRole(name+"-source", source))
	applyObject(modifyClusterRole(name, name+"-source", remove))
	DeferCleanup(cleanupScenario, name)

	waitForCondition(name, "Available", "Reconciled")
	return getClusterRole(name)
}

func cleanupScenario(name string) {
	_, _ = utils.Run(exec.Command("kubectl", "delete", "modifyclusterrole", name, "--ignore-not-found", "--wait=true"))
	_, _ = utils.Run(exec.Command("kubectl", "delete", "clusterrole", name, name+"-source", "--ignore-not-found"))
}

func clusterRole(name string, rules []rbacv1.PolicyRule) *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		TypeMeta:   metav1.TypeMeta{APIVersion: rbacv1.SchemeGroupVersion.String(), Kind: "ClusterRole"},
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Rules:      rules,
	}
}

func modifyClusterRole(name, source string, remove []kimv1.RemoveRule) *kimv1.ModifyClusterRole {
	return &kimv1.ModifyClusterRole{
		TypeMeta:   metav1.TypeMeta{APIVersion: kimv1.GroupVersion.String(), Kind: "ModifyClusterRole"},
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       kimv1.ModifyClusterRoleSpec{ClusterRole: source, RemoveRules: remove},
	}
}

// applyObject applies obj with kubectl, using its JSON form as the manifest.
func applyObject(obj any) {
	manifest, err := json.Marshal(obj)
	Expect(err).NotTo(HaveOccurred())
	cmd := exec.Command("kubectl", "apply", "-f", "-")
	cmd.Stdin = bytes.NewReader(manifest)
	_, err = utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred(), "Failed to apply %s", manifest)
}

func kubectl(args ...string) {
	_, err := utils.Run(exec.Command("kubectl", args...))
	Expect(err).NotTo(HaveOccurred())
}

// getJSON reads one object with kubectl get -o json. Only stdout is parsed, so warnings on stderr
// don't break decoding.
func getJSON(into any, resource, name string) error {
	cmd := exec.Command("kubectl", "get", resource, name, "-o", "json")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("kubectl get %s %s: %w: %s", resource, name, err, stderr.String())
	}
	return json.Unmarshal(output, into)
}

func getClusterRole(name string) *rbacv1.ClusterRole {
	var role rbacv1.ClusterRole
	Expect(getJSON(&role, "clusterrole", name)).To(Succeed())
	return &role
}

func getModifyClusterRole(name string) *kimv1.ModifyClusterRole {
	var mcr kimv1.ModifyClusterRole
	Expect(getJSON(&mcr, "modifyclusterrole", name)).To(Succeed())
	return &mcr
}

func clusterRoleExists(name string) bool {
	output, err := utils.Run(exec.Command("kubectl", "get", "clusterrole", name, "--ignore-not-found", "-o", "name"))
	Expect(err).NotTo(HaveOccurred())
	return strings.TrimSpace(output) != ""
}

// waitForCondition waits until the ModifyClusterRole reports the condition as True with the given reason
// for its current generation.
func waitForCondition(name, conditionType, reason string) {
	Eventually(func(g Gomega) {
		var mcr kimv1.ModifyClusterRole
		g.Expect(getJSON(&mcr, "modifyclusterrole", name)).To(Succeed())
		condition := meta.FindStatusCondition(mcr.Status.Conditions, conditionType)
		g.Expect(condition).NotTo(BeNil(), "condition %s not set yet", conditionType)
		g.Expect(condition.Status).To(Equal(metav1.ConditionTrue))
		g.Expect(condition.Reason).To(Equal(reason))
		g.Expect(condition.ObservedGeneration).To(Equal(mcr.Generation))
	}).Should(Succeed())
}

// flatten turns rules into "apiGroup/resource/verb" strings for membership checks.
func flatten(rules []rbacv1.PolicyRule) []string {
	var permissions []string
	for _, rule := range rules {
		for _, apiGroup := range rule.APIGroups {
			for _, resource := range rule.Resources {
				for _, verb := range rule.Verbs {
					permissions = append(permissions, apiGroup+"/"+resource+"/"+verb)
				}
			}
		}
	}
	return permissions
}
