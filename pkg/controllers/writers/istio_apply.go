package writers

import (
	"context"
	"errors"

	"google.golang.org/protobuf/proto"
	istiosecurityv1 "istio.io/client-go/pkg/apis/security/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

// createOrUpdatePolicy is controllerutil.CreateOrUpdate for an AuthorizationPolicy, comparing the
// spec by content. CreateOrUpdate compares with DeepEqual, and the spec is a protobuf message whose
// internal fields differ even between a copy and its original, so it sent an Update for every
// policy on every reconcile, also when nothing had changed.
func createOrUpdatePolicy(ctx context.Context, c client.Client, policy *istiosecurityv1.AuthorizationPolicy, mutate func() error) (controllerutil.OperationResult, error) {
	key := client.ObjectKeyFromObject(policy)
	if err := c.Get(ctx, key, policy); err != nil {
		if !apierrors.IsNotFound(err) {
			return controllerutil.OperationResultNone, err
		}
		if err := mutateKeepingKey(policy, key, mutate); err != nil {
			return controllerutil.OperationResultNone, err
		}
		if err := c.Create(ctx, policy); err != nil {
			return controllerutil.OperationResultNone, err
		}
		return controllerutil.OperationResultCreated, nil
	}

	existing := policy.DeepCopy()
	if err := mutateKeepingKey(policy, key, mutate); err != nil {
		return controllerutil.OperationResultNone, err
	}
	if proto.Equal(&existing.Spec, &policy.Spec) && equality.Semantic.DeepEqual(existing.ObjectMeta, policy.ObjectMeta) {
		return controllerutil.OperationResultNone, nil
	}
	if err := c.Update(ctx, policy); err != nil {
		return controllerutil.OperationResultNone, err
	}
	return controllerutil.OperationResultUpdated, nil
}

// mutateKeepingKey runs mutate and refuses a change of name or namespace, like CreateOrUpdate.
func mutateKeepingKey(policy *istiosecurityv1.AuthorizationPolicy, key client.ObjectKey, mutate func() error) error {
	if err := mutate(); err != nil {
		return err
	}
	if client.ObjectKeyFromObject(policy) != key {
		return errors.New("MutateFn cannot mutate object name and/or object namespace")
	}
	return nil
}
