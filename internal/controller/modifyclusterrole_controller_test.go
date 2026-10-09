package controller

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	fakediscovery "k8s.io/client-go/discovery/fake"
	"k8s.io/client-go/testing"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	kimv1 "github.com/timpa0130/rbac-subtract/api/v1"
)

var _ = Describe("ModifyClusterRole Controller", func() {
	Context("with source ClusterRole and remove rules", func() {
		const targetName = "test-target"
		const sourceName = "test-source"

		ctx := context.Background()
		namespacedName := types.NamespacedName{Name: targetName}

		BeforeEach(func() {
			source := &rbacv1.ClusterRole{
				ObjectMeta: metav1.ObjectMeta{Name: sourceName},
				Rules: []rbacv1.PolicyRule{
					{APIGroups: []string{"apps"}, Resources: []string{"deployments", "statefulsets"}, Verbs: []string{"get", "list"}},
				},
			}
			err := k8sClient.Get(ctx, types.NamespacedName{Name: sourceName}, &rbacv1.ClusterRole{})
			if errors.IsNotFound(err) {
				Expect(k8sClient.Create(ctx, source)).To(Succeed())
			}

			cr := &kimv1.ModifyClusterRole{
				ObjectMeta: metav1.ObjectMeta{Name: targetName},
				Spec: kimv1.ModifyClusterRoleSpec{
					ClusterRole: sourceName,
					RemoveRules: []kimv1.RemoveRule{
						{APIGroups: []string{"apps"}, Resources: []string{"deployments"}, Verbs: []string{"list"}},
					},
				},
			}
			err = k8sClient.Get(ctx, namespacedName, &kimv1.ModifyClusterRole{})
			if errors.IsNotFound(err) {
				Expect(k8sClient.Create(ctx, cr)).To(Succeed())
			}
		})

		AfterEach(func() {
			_ = k8sClient.Delete(ctx, &kimv1.ModifyClusterRole{ObjectMeta: metav1.ObjectMeta{Name: targetName}})
			_ = k8sClient.Delete(ctx, &rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: targetName}})
			_ = k8sClient.Delete(ctx, &rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: sourceName}})
		})

		It("creates target ClusterRole with subtracted rules", func() {
			reconciler := &ModifyClusterRoleReconciler{
				Client:    k8sClient,
				Discovery: &fakediscovery.FakeDiscovery{Fake: &testing.Fake{}},
				Scheme:    k8sClient.Scheme(),
			}

			_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: namespacedName})
			Expect(err).NotTo(HaveOccurred())

			var target rbacv1.ClusterRole
			err = k8sClient.Get(ctx, types.NamespacedName{Name: targetName}, &target)
			Expect(err).NotTo(HaveOccurred())

			Expect(target.Labels).To(HaveKeyWithValue("app.kubernetes.io/managed-by", "rbac-subtract"))
			Expect(target.OwnerReferences).To(HaveLen(1))
			Expect(target.OwnerReferences[0].Name).To(Equal(targetName))

			Expect(target.Rules).To(ContainElement(rbacv1.PolicyRule{
				APIGroups: []string{"apps"},
				Resources: []string{"deployments"},
				Verbs:     []string{"get"},
			}))
			Expect(target.Rules).To(ContainElement(rbacv1.PolicyRule{
				APIGroups: []string{"apps"},
				Resources: []string{"statefulsets"},
				Verbs:     []string{"get", "list"},
			}))
		})

		It("leaves an aggregated target unchanged and reports the conflict", func() {
			const aggTargetName = "test-agg-target"

			aggregationRule := &rbacv1.AggregationRule{
				ClusterRoleSelectors: []metav1.LabelSelector{
					{MatchLabels: map[string]string{"rbac.example.com/aggregate-to-view": "true"}},
				},
			}
			targetRules := []rbacv1.PolicyRule{{
				APIGroups: []string{"apps"},
				Resources: []string{"deployments"},
				Verbs:     []string{"get", "list"},
			}}
			target := &rbacv1.ClusterRole{
				ObjectMeta:      metav1.ObjectMeta{Name: aggTargetName},
				AggregationRule: aggregationRule,
				Rules:           targetRules,
			}
			Expect(k8sClient.Create(ctx, target)).To(Succeed())

			cr := &kimv1.ModifyClusterRole{
				ObjectMeta: metav1.ObjectMeta{Name: aggTargetName},
				Spec: kimv1.ModifyClusterRoleSpec{
					ClusterRole: aggTargetName,
					RemoveRules: []kimv1.RemoveRule{
						{APIGroups: []string{"apps"}, Resources: []string{"deployments"}, Verbs: []string{"list"}},
					},
				},
			}
			Expect(k8sClient.Create(ctx, cr)).To(Succeed())

			reconciler := &ModifyClusterRoleReconciler{
				Client:    k8sClient,
				Discovery: &fakediscovery.FakeDiscovery{Fake: &testing.Fake{}},
				Scheme:    k8sClient.Scheme(),
			}
			_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: aggTargetName}})
			Expect(err).NotTo(HaveOccurred())

			var updated rbacv1.ClusterRole
			err = k8sClient.Get(ctx, types.NamespacedName{Name: aggTargetName}, &updated)
			Expect(err).NotTo(HaveOccurred())
			Expect(updated.AggregationRule).To(Equal(aggregationRule))
			Expect(updated.Rules).To(Equal(targetRules))
			Expect(updated.OwnerReferences).To(BeEmpty())
			Expect(updated.Labels).To(BeEmpty())

			var updatedCR kimv1.ModifyClusterRole
			err = k8sClient.Get(ctx, types.NamespacedName{Name: aggTargetName}, &updatedCR)
			Expect(err).NotTo(HaveOccurred())
			available := meta.FindStatusCondition(updatedCR.Status.Conditions, "Available")
			Expect(available).NotTo(BeNil())
			Expect(available.Status).To(Equal(metav1.ConditionFalse))
			Expect(available.Reason).To(Equal("TargetAggregated"))
			degraded := meta.FindStatusCondition(updatedCR.Status.Conditions, "Degraded")
			Expect(degraded).NotTo(BeNil())
			Expect(degraded.Status).To(Equal(metav1.ConditionTrue))
			Expect(degraded.Reason).To(Equal("TargetAggregated"))
			Expect(degraded.Message).To(ContainSubstring("choose a different target name"))

			_ = k8sClient.Delete(ctx, &kimv1.ModifyClusterRole{ObjectMeta: metav1.ObjectMeta{Name: aggTargetName}})
			_ = k8sClient.Delete(ctx, &rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: aggTargetName}})
		})

		It("leaves an existing ClusterRole it does not own unchanged and reports the conflict", func() {
			const existingName = "test-existing-target"

			existingLabels := map[string]string{"owner": "platform-team"}
			existingRules := []rbacv1.PolicyRule{{
				APIGroups: []string{""},
				Resources: []string{"pods"},
				Verbs:     []string{"get"},
			}}
			existing := &rbacv1.ClusterRole{
				ObjectMeta: metav1.ObjectMeta{Name: existingName, Labels: existingLabels},
				Rules:      existingRules,
			}
			Expect(k8sClient.Create(ctx, existing)).To(Succeed())

			cr := &kimv1.ModifyClusterRole{
				ObjectMeta: metav1.ObjectMeta{Name: existingName},
				Spec: kimv1.ModifyClusterRoleSpec{
					ClusterRole: sourceName,
					RemoveRules: []kimv1.RemoveRule{
						{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get"}},
					},
				},
			}
			Expect(k8sClient.Create(ctx, cr)).To(Succeed())

			reconciler := &ModifyClusterRoleReconciler{
				Client:    k8sClient,
				Discovery: &fakediscovery.FakeDiscovery{Fake: &testing.Fake{}},
				Scheme:    k8sClient.Scheme(),
			}
			_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: existingName}})
			Expect(err).NotTo(HaveOccurred())

			var updated rbacv1.ClusterRole
			err = k8sClient.Get(ctx, types.NamespacedName{Name: existingName}, &updated)
			Expect(err).NotTo(HaveOccurred())
			Expect(updated.Rules).To(Equal(existingRules))
			Expect(updated.OwnerReferences).To(BeEmpty())
			Expect(updated.Labels).To(Equal(existingLabels))

			var updatedCR kimv1.ModifyClusterRole
			err = k8sClient.Get(ctx, types.NamespacedName{Name: existingName}, &updatedCR)
			Expect(err).NotTo(HaveOccurred())
			available := meta.FindStatusCondition(updatedCR.Status.Conditions, "Available")
			Expect(available).NotTo(BeNil())
			Expect(available.Status).To(Equal(metav1.ConditionFalse))
			Expect(available.Reason).To(Equal("TargetNotOwned"))
			degraded := meta.FindStatusCondition(updatedCR.Status.Conditions, "Degraded")
			Expect(degraded).NotTo(BeNil())
			Expect(degraded.Status).To(Equal(metav1.ConditionTrue))
			Expect(degraded.Reason).To(Equal("TargetNotOwned"))

			_ = k8sClient.Delete(ctx, &kimv1.ModifyClusterRole{ObjectMeta: metav1.ObjectMeta{Name: existingName}})
			_ = k8sClient.Delete(ctx, &rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: existingName}})
		})

		It("keeps updating a target ClusterRole it owns", func() {
			reconciler := &ModifyClusterRoleReconciler{
				Client:    k8sClient,
				Discovery: &fakediscovery.FakeDiscovery{Fake: &testing.Fake{}},
				Scheme:    k8sClient.Scheme(),
			}
			_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: namespacedName})
			Expect(err).NotTo(HaveOccurred())

			var cr kimv1.ModifyClusterRole
			Expect(k8sClient.Get(ctx, namespacedName, &cr)).To(Succeed())
			cr.Spec.RemoveRules = []kimv1.RemoveRule{
				{APIGroups: []string{"apps"}, Resources: []string{"statefulsets"}, Verbs: []string{"*"}},
			}
			Expect(k8sClient.Update(ctx, &cr)).To(Succeed())

			_, err = reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: namespacedName})
			Expect(err).NotTo(HaveOccurred())

			var target rbacv1.ClusterRole
			Expect(k8sClient.Get(ctx, types.NamespacedName{Name: targetName}, &target)).To(Succeed())
			Expect(target.Rules).To(Equal([]rbacv1.PolicyRule{{
				APIGroups: []string{"apps"},
				Resources: []string{"deployments"},
				Verbs:     []string{"get", "list"},
			}}))

			var updatedCR kimv1.ModifyClusterRole
			Expect(k8sClient.Get(ctx, namespacedName, &updatedCR)).To(Succeed())
			available := meta.FindStatusCondition(updatedCR.Status.Conditions, "Available")
			Expect(available).NotTo(BeNil())
			Expect(available.Status).To(Equal(metav1.ConditionTrue))
		})

		It("reports missing source ClusterRole", func() {
			cr := &kimv1.ModifyClusterRole{
				ObjectMeta: metav1.ObjectMeta{Name: "no-source"},
				Spec: kimv1.ModifyClusterRoleSpec{
					ClusterRole: "nonexistent",
					RemoveRules: []kimv1.RemoveRule{
						{APIGroups: []string{"apps"}, Resources: []string{"deployments"}, Verbs: []string{"get"}},
					},
				},
			}
			err := k8sClient.Get(ctx, types.NamespacedName{Name: "no-source"}, &kimv1.ModifyClusterRole{})
			if errors.IsNotFound(err) {
				Expect(k8sClient.Create(ctx, cr)).To(Succeed())
			}

			reconciler := &ModifyClusterRoleReconciler{
				Client:    k8sClient,
				Discovery: &fakediscovery.FakeDiscovery{Fake: &testing.Fake{}},
				Scheme:    k8sClient.Scheme(),
			}

			_, err = reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Name: "no-source"}})
			Expect(err).To(HaveOccurred())

			// Cleanup
			_ = k8sClient.Delete(ctx, &kimv1.ModifyClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "no-source"}})
		})
	})
})
