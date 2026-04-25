// Package nav (msgs.go): shared cross-screen message types.
//
// These types are owned by the nav package so any screen can emit or
// consume them without creating an import cycle between the emitter and
// receiver. This file was introduced by plan 02-08 (M-OBSERVE) — both
// M-OBSERVE (emitter) and S-LOGS (receiver) import the types here. The
// pattern replaces the local statusRefreshMsg placeholder that S-LOGS
// shipped in plan 02-06.
//
// New cross-package message types belong in this file when:
//   - Both an emitter and a receiver live in different screen packages.
//   - The message carries no behaviour, just data flowing across the stack.
//
// Single-screen messages should remain unexported in their own package.
package nav

// StatusRefreshMsg signals S-LOGS to re-query the status row. Emitted by
// M-OBSERVE on phase=done so the parent log screen's status row rebuilds
// (D-08 refresh contract). Cross-package message routing is owned by plan
// 02-08 — both M-OBSERVE (emitter) and S-LOGS (receiver) import this type
// from internal/tui/nav so neither package needs to import the other.
type StatusRefreshMsg struct{}

// ObserveRunCompleteToast carries the completion summary back to S-LOGS,
// which renders it as a transient toast (UI-SPEC line 305:
// "observe-run done — N events, M counters, K dropped").
type ObserveRunCompleteToast struct {
	Events   int
	Counters int
	Dropped  int
}

// ObserveRunCancelledToast carries the partial-work count after Esc cancel
// (UI-SPEC line 306: "observe-run cancelled — N events ingested").
type ObserveRunCancelledToast struct {
	Count int
}
