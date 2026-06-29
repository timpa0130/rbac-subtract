package controller

import (
	"context"
	"os"
	"strconv"
	"strings"
	"time"

	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/discovery"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	kimv1 "github.com/timpa0130/rbac-subtract/api/v1"
	"github.com/timpa0130/rbac-subtract/pkg/subtract"
	"github.com/timpa0130/rbac-subtract/pkg/wildcard"
)

var reconcileInterval = defaultReconcileInterval()

func defaultReconcileInterval() time.Duration {
	if s := os.Getenv("REQUEUE_INTERVAL"); s != "" {
		if d, err := strconv.Atoi(s); err == nil && d > 0 {
			return time.Duration(d) * time.Second
		}
	}
	return 60 * time.Second
}

// ModifyClusterRoleReconciler reconciles a ModifyClusterRole object
type ModifyClusterRoleReconciler struct {
	client.Client
	Discovery discovery.DiscoveryInterface
	Scheme    *runtime.Scheme
}

// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=clusterroles,verbs=get;list;watch;create;update;patch;delete;escalate
// +kubebuilder:rbac:groups=kim.karolinska.se,resources=modifyclusterroles,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=kim.karolinska.se,resources=modifyclusterroles/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=apiextensions.k8s.io,resources=customresourcedefinitions,verbs=get;list;watch
// +kubebuilder:rbac:groups=coordination.k8s.io,resources=leases,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=events,verbs=create;patch


// Reconcile processes a ModifyClusterRole and maintains the target ClusterRole.
func (r *ModifyClusterRoleReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	// Check if the ModifyClusterRole doesn't exist, if it doesn't do nothing
	var cr kimv1.ModifyClusterRole
	if err := r.Get(ctx, req.NamespacedName, &cr); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	sourceName := cr.Spec.ClusterRole
	log.Info("Reading source ClusterRole", "sourceName", sourceName)
	var sourceRole rbacv1.ClusterRole
	if err := r.Get(ctx, client.ObjectKey{Name: sourceName}, &sourceRole); err != nil {
		if errors.IsNotFound(err) {
			log.Error(err, "Source ClusterRole not found")
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	sourceRules := sourceRole.Rules
	log.Info("Expanding wildcards from the source ClusterRole")
	expandedRules, hadWildcardAPI, err := wildcard.ExpandWildcards(r.Discovery, sourceRules, log)
	if err != nil {
		log.Error(err, "Failed to expand wildcards")
		return ctrl.Result{}, nil
	}

	// Because we created a custom type we need to convert it to a rbacv1.PolicyRule
	removeRules := make([]rbacv1.PolicyRule, len(cr.Spec.RemoveRules))
	for i, rr := range cr.Spec.RemoveRules {
		removeRules[i] = rbacv1.PolicyRule{
			APIGroups: rr.APIGroups,
			Resources: rr.Resources,
			Verbs:     rr.Verbs,
		}
	}

	log.Info("subtracting rules",
		"sourceCount", len(expandedRules),
		"removeCount", len(removeRules),
	)

	resultRules, err := subtract.Subtract(expandedRules, removeRules, log)
	if err != nil {
		log.Error(err, "subtraction failed")
		return ctrl.Result{}, nil
	}

	labels := cr.Labels
	if labels == nil {
		labels = make(map[string]string)
	}
	labels["app.kubernetes.io/managed-by"] = "rbac-subtract"

	annotations := make(map[string]string)
	for k, v := range cr.Annotations {
		if !strings.HasPrefix(k, "kubectl.kubernetes.io/") {
			annotations[k] = v
		}
	}
	if hadWildcardAPI {
		annotations["rbac-subtract.kim.karolinska.se/api-group-wildcard"] = "source ClusterRole contains '*' in apiGroups — subtraction skipped for those rules"
	}

	ownerRef := metav1.OwnerReference{
		APIVersion:         "kim.karolinska.se/v1",
		Kind:               "ModifyClusterRole",
		Name:               cr.Name,
		UID:                cr.UID,
		Controller:         ptr(true),
		BlockOwnerDeletion: ptr(true),
	}

	target := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name:            cr.Name,
			Labels:          labels,
			Annotations:     annotations,
			OwnerReferences: []metav1.OwnerReference{ownerRef},
		},
		Rules: resultRules,
	}

	var existing rbacv1.ClusterRole
	if err := r.Get(ctx, client.ObjectKey{Name: cr.Name}, &existing); err != nil {
		if errors.IsNotFound(err) {
			if err := r.Create(ctx, target); err != nil {
				log.Error(err, "failed to create target ClusterRole")
				return ctrl.Result{}, err
			}
			log.Info("created target ClusterRole", "rulesCount", len(resultRules))
		} else {
			log.Error(err, "failed to get existing target ClusterRole")
			return ctrl.Result{}, err
		}
	} else {
		target.ResourceVersion = existing.ResourceVersion
		if err := r.Update(ctx, target); err != nil {
			log.Error(err, "failed to update target ClusterRole")
			return ctrl.Result{}, err
		}
		log.Info("updated target ClusterRole", "rulesCount", len(resultRules))
	}

	cr.Status.RulesCount = int32(len(resultRules))
	if err := r.Status().Update(ctx, &cr); err != nil {
		log.Error(err, "failed to update status")
		return ctrl.Result{}, err
	}

	return ctrl.Result{RequeueAfter: reconcileInterval}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *ModifyClusterRoleReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&kimv1.ModifyClusterRole{}).
		Named("modifyclusterrole").
		Owns(&rbacv1.ClusterRole{}).
		Complete(r)
}

func ptr[T any](v T) *T {
	return &v
}
