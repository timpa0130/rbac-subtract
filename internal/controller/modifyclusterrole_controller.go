package controller

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/discovery"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
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
	return 4 * time.Hour
}

// ModifyClusterRoleReconciler reconciles a ModifyClusterRole object
type ModifyClusterRoleReconciler struct {
	client.Client
	Discovery discovery.DiscoveryInterface
	Scheme    *runtime.Scheme
}

// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=clusterroles,verbs=get;list;watch;create;update;patch;delete;escalate
// +kubebuilder:rbac:groups=rbac.kim.karolinska.se,resources=modifyclusterroles,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=rbac.kim.karolinska.se,resources=modifyclusterroles/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=rbac.kim.karolinska.se,resources=modifyclusterroles/finalizers,verbs=update
// +kubebuilder:rbac:groups=apiextensions.k8s.io,resources=customresourcedefinitions,verbs=get;list;watch
// +kubebuilder:rbac:groups=coordination.k8s.io,resources=leases,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=events,verbs=create;patch

// Reconcile processes.
func (r *ModifyClusterRoleReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// Check if the ModifyClusterRole doesn't exist, if it doesn't do nothing
	var cr kimv1.ModifyClusterRole
	if err := r.Get(ctx, req.NamespacedName, &cr); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	// Santitize rules
	// ---------------
	logger.Info("Reading source ClusterRole", "sourceName", cr.Spec.ClusterRole)
	var sourceRole rbacv1.ClusterRole
	if err := r.Get(ctx, client.ObjectKey{Name: cr.Spec.ClusterRole}, &sourceRole); err != nil {
		if errors.IsNotFound(err) {
			logger.Error(err, "Source ClusterRole not found")
			meta.SetStatusCondition(&cr.Status.Conditions, metav1.Condition{
				Type:               "Degraded",
				Status:             metav1.ConditionTrue,
				Reason:             "SourceNotFound",
				Message:            fmt.Sprintf("Source ClusterRole %q was not found", cr.Spec.ClusterRole),
				ObservedGeneration: cr.Generation,
			})
			if updateErr := r.Status().Update(ctx, &cr); updateErr != nil {
				logger.Error(updateErr, "Failed to update status condition")
			}
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, err
	}

	logger.Info("Expanding wildcards from the source ClusterRole")
	expandedRules, hadWildcardAPI, err := wildcard.ExpandWildcards(r.Discovery, sourceRole.Rules, logger)
	if err != nil {
		logger.Error(err, "Failed to expand wildcards")
		meta.SetStatusCondition(&cr.Status.Conditions, metav1.Condition{
			Type:               "Degraded",
			Status:             metav1.ConditionTrue,
			Reason:             "WildcardExpansionFailed",
			Message:            "Failed to expand wildcards in the source ClusterRole",
			ObservedGeneration: cr.Generation,
		})
		if updateErr := r.Status().Update(ctx, &cr); updateErr != nil {
			logger.Error(updateErr, "Failed to update status condition")
		}
		return ctrl.Result{}, err
	}

	// Because we created a custom type we need to make it to a rbacv1.PolicyRule
	removeRules := make([]rbacv1.PolicyRule, len(cr.Spec.RemoveRules))
	for i, rr := range cr.Spec.RemoveRules {
		removeRules[i] = rbacv1.PolicyRule{
			APIGroups: rr.APIGroups,
			Resources: rr.Resources,
			Verbs:     rr.Verbs,
		}
	}

	logger.Info("subtracting rules", "sourceCount", len(expandedRules), "removeCount", len(removeRules))
	resultingRules, err := subtract.Subtract(expandedRules, removeRules, logger)
	if err != nil {
		logger.Error(err, "subtraction failed")
		meta.SetStatusCondition(&cr.Status.Conditions, metav1.Condition{
			Type:               "Degraded",
			Status:             metav1.ConditionTrue,
			Reason:             "SubtractionFailed",
			Message:            "Failed to subtract rules from the source ClusterRole",
			ObservedGeneration: cr.Generation,
		})
		if updateErr := r.Status().Update(ctx, &cr); updateErr != nil {
			logger.Error(updateErr, "Failed to update status condition")
		}
		return ctrl.Result{}, err
	}
	// ---------------

	// Labels and annotations
	// ----------------------
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
		annotations["subtract.rbac.kim.karolinska.se/api-group-wildcard"] = "source ClusterRole contains '*' in apiGroups — subtraction may not work as expected"
	}
	// ----------------------

	target := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: cr.Name,
		},
	}

	targetIsAggregated := false
	result, err := controllerutil.CreateOrUpdate(ctx, r.Client, target, func() error {
		if target.AggregationRule != nil {
			targetIsAggregated = true
			return nil
		}
		if err := controllerutil.SetControllerReference(&cr, target, r.Scheme); err != nil {
			return err
		}
		target.Labels = labels
		target.Annotations = annotations
		target.Rules = resultingRules
		return nil
	})
	if err != nil {
		logger.Error(err, "Failed to reconcile target ClusterRole")
		meta.SetStatusCondition(&cr.Status.Conditions, metav1.Condition{
			Type:               "Degraded",
			Status:             metav1.ConditionTrue,
			Reason:             "CreateOrUpdateFailed",
			Message:            "Failed to create or update the target ClusterRole",
			ObservedGeneration: cr.Generation,
		})
		if updateErr := r.Status().Update(ctx, &cr); updateErr != nil {
			logger.Error(updateErr, "Failed to update status condition")
		}
		return ctrl.Result{}, err
	}
	if targetIsAggregated {
		message := fmt.Sprintf("Target ClusterRole %q has an aggregationRule; choose a different target name", cr.Name)
		logger.Info("Leaving aggregated target ClusterRole unchanged", "targetName", cr.Name)
		meta.SetStatusCondition(&cr.Status.Conditions, metav1.Condition{
			Type:               "Available",
			Status:             metav1.ConditionFalse,
			Reason:             "TargetAggregated",
			Message:            message,
			ObservedGeneration: cr.Generation,
		})
		meta.SetStatusCondition(&cr.Status.Conditions, metav1.Condition{
			Type:               "Degraded",
			Status:             metav1.ConditionTrue,
			Reason:             "TargetAggregated",
			Message:            message,
			ObservedGeneration: cr.Generation,
		})
		if updateErr := r.Status().Update(ctx, &cr); updateErr != nil {
			logger.Error(updateErr, "Failed to update status condition")
			return ctrl.Result{}, updateErr
		}
		return ctrl.Result{RequeueAfter: reconcileInterval}, nil
	}
	logger.Info("Reconciled target ClusterRole", "operation", result, "rulesCount", len(resultingRules))

	meta.SetStatusCondition(&cr.Status.Conditions, metav1.Condition{
		Type:               "Available",
		Status:             metav1.ConditionTrue,
		Reason:             "Reconciled",
		Message:            fmt.Sprintf("Target ClusterRole %q updated with %d rules", cr.Name, len(resultingRules)),
		ObservedGeneration: cr.Generation,
	})
	meta.SetStatusCondition(&cr.Status.Conditions, metav1.Condition{
		Type:               "Degraded",
		Status:             metav1.ConditionFalse,
		Reason:             "Reconciled",
		Message:            "",
		ObservedGeneration: cr.Generation,
	})
	cr.Status.RulesCount = int32(len(resultingRules))
	if err := r.Status().Update(ctx, &cr); err != nil {
		logger.Error(err, "Failed to update status")
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
