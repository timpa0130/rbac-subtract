package controller

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/errors"
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

		It("handles missing source ClusterRole gracefully", func() {
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
			Expect(err).NotTo(HaveOccurred())

			// Cleanup
			_ = k8sClient.Delete(ctx, &kimv1.ModifyClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "no-source"}})
		})
	})
})
