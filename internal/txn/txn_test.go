package txn

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/sftp-jailer-dev/sftp-jailer/internal/sysops"
	"github.com/stretchr/testify/require"
)

// recordingStep is the test-only helper Step. It appends "Apply <name>" /
// "Compensate <name>" to a shared []string under the *calls pointer, so
// individual tests can compose multi-step batches and assert the exact
// invocation sequence.
type recordingStep struct {
	name       string
	applyErr   error
	compErr    error
	calls      *[]string
	applyCheck func(ctx context.Context) error // optional; for ctx-cancellation test
}

func (s *recordingStep) Name() string { return s.name }

func (s *recordingStep) Apply(ctx context.Context, _ sysops.SystemOps) error {
	if s.applyCheck != nil {
		if err := s.applyCheck(ctx); err != nil {
			return err
		}
	}
	*s.calls = append(*s.calls, "Apply "+s.name)
	return s.applyErr
}

func (s *recordingStep) Compensate(_ context.Context, _ sysops.SystemOps) error {
	*s.calls = append(*s.calls, "Compensate "+s.name)
	return s.compErr
}

func TestApply_runs_steps_in_order_on_success(t *testing.T) {
	t.Parallel()

	var calls []string
	steps := []Step{
		&recordingStep{name: "A", calls: &calls},
		&recordingStep{name: "B", calls: &calls},
		&recordingStep{name: "C", calls: &calls},
	}

	tx := New(sysops.NewFake())
	err := tx.Apply(context.Background(), steps)

	require.NoError(t, err)
	require.Equal(t, []string{"Apply A", "Apply B", "Apply C"}, calls)
	for _, c := range calls {
		require.False(t, strings.HasPrefix(c, "Compensate"), "unexpected compensator on success path: %q", c)
	}
}

func TestApply_runs_compensators_in_reverse_on_mid_batch_failure(t *testing.T) {
	t.Parallel()

	var calls []string
	stepErr := errors.New("step C boom")
	steps := []Step{
		&recordingStep{name: "A", calls: &calls},
		&recordingStep{name: "B", calls: &calls},
		&recordingStep{name: "C", calls: &calls, applyErr: stepErr},
		&recordingStep{name: "D", calls: &calls},
		&recordingStep{name: "E", calls: &calls},
	}

	tx := New(sysops.NewFake())
	err := tx.Apply(context.Background(), steps)

	require.Error(t, err)
	require.True(t, errors.Is(err, stepErr), "returned error must wrap the original step error")
	require.Contains(t, err.Error(), "C", "wrapped error must include the failing Step's Name()")
	// Step C's Apply ran (it failed), Steps D and E never ran. Compensators run for B then A.
	require.Equal(t, []string{
		"Apply A",
		"Apply B",
		"Apply C",
		"Compensate B",
		"Compensate A",
	}, calls)
}

func TestApply_returns_original_error_when_compensator_succeeds(t *testing.T) {
	t.Parallel()

	var calls []string
	stepFailure := errors.New("step failure")
	steps := []Step{
		&recordingStep{name: "A", calls: &calls},
		&recordingStep{name: "B", calls: &calls, applyErr: stepFailure},
	}

	tx := New(sysops.NewFake())
	err := tx.Apply(context.Background(), steps)

	require.Error(t, err)
	require.True(t, errors.Is(err, stepFailure))
	// No compensator-error noise — only the original step failure.
	require.NotContains(t, err.Error(), "compensate")
}

func TestApply_joins_compensator_errors_when_rollback_partially_fails(t *testing.T) {
	t.Parallel()

	var calls []string
	stepFailure := errors.New("step failure")
	compFailure := errors.New("compensator failure")
	steps := []Step{
		&recordingStep{name: "A", calls: &calls},
		&recordingStep{name: "B", calls: &calls, compErr: compFailure},
		&recordingStep{name: "C", calls: &calls, applyErr: stepFailure},
	}

	tx := New(sysops.NewFake())
	err := tx.Apply(context.Background(), steps)

	require.Error(t, err)
	require.True(t, errors.Is(err, stepFailure), "returned error must wrap original step failure")
	require.True(t, errors.Is(err, compFailure), "returned error must also wrap compensator failure")
}

func TestApply_zero_steps_is_noop(t *testing.T) {
	t.Parallel()

	tx := New(sysops.NewFake())
	require.NoError(t, tx.Apply(context.Background(), nil))
	require.NoError(t, tx.Apply(context.Background(), []Step{}))
}

func TestApply_single_step_failure_no_compensators_run(t *testing.T) {
	t.Parallel()

	var calls []string
	stepErr := errors.New("only step boom")
	steps := []Step{
		&recordingStep{name: "Only", calls: &calls, applyErr: stepErr},
	}

	tx := New(sysops.NewFake())
	err := tx.Apply(context.Background(), steps)

	require.Error(t, err)
	require.True(t, errors.Is(err, stepErr))
	// The failing step's own Apply ran but Compensate did NOT (its mutation
	// is presumed not to have taken effect — Apply is "atomic or no-op").
	require.Equal(t, []string{"Apply Only"}, calls)
}

func TestApply_ctx_cancelled_before_first_step_returns_ctx_err(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var calls []string
	steps := []Step{
		&recordingStep{name: "A", calls: &calls},
		&recordingStep{name: "B", calls: &calls},
	}

	tx := New(sysops.NewFake())
	err := tx.Apply(ctx, steps)

	require.Error(t, err)
	require.True(t, errors.Is(err, context.Canceled))
	require.Empty(t, calls, "no Step.Apply should have run before cancellation gate")
}

func TestApply_ctx_cancelled_mid_batch_aborts_and_rolls_back(t *testing.T) {
	t.Parallel()

	var calls []string
	ctx, cancel := context.WithCancel(context.Background())

	// Step 1 cancels ctx after recording its Apply. Tx's loop-top ctx.Err()
	// check then aborts before invoking Step 2's Apply.
	steps := []Step{
		&recordingStep{
			name:  "1",
			calls: &calls,
			applyCheck: func(_ context.Context) error {
				// noop pre-check; cancellation happens AFTER the record below
				return nil
			},
		},
		&recordingStep{name: "2", calls: &calls},
	}

	// Wrap step 1 so it cancels ctx after its body runs.
	steps[0] = &recordingStep{
		name:  "1",
		calls: &calls,
		applyCheck: func(_ context.Context) error {
			cancel()
			return nil
		},
	}

	tx := New(sysops.NewFake())
	err := tx.Apply(ctx, steps)

	require.Error(t, err)
	require.True(t, errors.Is(err, context.Canceled))
	// Step 1's Apply ran; Step 2 did NOT (loop-top ctx.Err() bailed); Step 1's
	// Compensate ran during rollback.
	require.Equal(t, []string{"Apply 1", "Compensate 1"}, calls)
}
