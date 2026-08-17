//go:build linux

package main

import (
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/ghostpsy/agent-linux/internal/agentconfig"
	"github.com/ghostpsy/agent-linux/internal/schedule"
	"github.com/ghostpsy/agent-linux/internal/solve"
	"github.com/ghostpsy/agent-linux/internal/state"
	"github.com/ghostpsy/agent-linux/internal/version"
)

// retryDelay is how long the loop leaves a failed scan or heartbeat alone.
//
// A failure is deliberately not recorded as a success, so the next pass still
// finds the work due. Without something holding it back that is a hot loop: on a
// host with no network the agent spawned a scan every two seconds, forever.
// Found on a real machine, not by a unit test.
//
// It is a time to wait until, not a sleep. Sleeping for it blocked the whole
// loop, so a scan failing for its own reasons — a rate limit, a broken
// collector — also stopped the agent asking whether a person had approved any
// work. Somebody would have clicked approve and waited fifteen minutes for
// something entirely unrelated. Also found on a real machine.
const retryDelay = 15 * time.Minute

// serveDeps is everything the loop touches, gathered in one place so the rules
// about when we act on a customer's server can be tested without acting on one.
type serveDeps struct {
	machineID string
	startedAt time.Time

	lastScan      time.Time
	lastHeartbeat time.Time

	now       func() time.Time
	scan      func(context.Context) error
	heartbeat func(context.Context) error
	sleep     func(context.Context, time.Duration) error

	// pollSolve asks the service whether a person has approved any work for this
	// machine. It runs on every pass, which is why the loop sleeps in minutes.
	pollSolve func(context.Context) error

	// When a failed scan or heartbeat may be tried again. Zero means now.
	scanRetryAfter      time.Time
	heartbeatRetryAfter time.Time
}

// servePass runs one pass of the service loop.
//
// It never returns an error for a failed scan or heartbeat. A machine that goes
// silent because one scan could not reach the network is exactly the failure
// this work exists to remove — the loop logs it and carries on.
func servePass(ctx context.Context, d *serveDeps) error {
	now := d.now()
	act := schedule.Decide(d.machineID, d.lastScan, d.lastHeartbeat, d.startedAt, now)

	// First, and never fatal. Solve is the newest part of the agent and the
	// least essential: a machine whose channel is broken must go on scanning and
	// go on saying it is alive, or a new feature could take out an old one.
	if d.pollSolve != nil {
		if err := d.pollSolve(ctx); err != nil {
			slog.Warn("could not ask the service for work", "error", err)
		}
	}

	if act.Heartbeat && !now.Before(d.heartbeatRetryAfter) {
		if err := d.heartbeat(ctx); err != nil {
			// Same trap as the scan below: a failure leaves lastHeartbeat unset,
			// so every following pass asks for another one. The retry time is
			// what stops that becoming a hot loop.
			//
			// Warn, not Debug. This is the line that explains why a machine has
			// gone quiet in the dashboard, and at Debug nobody could ever see
			// it: the agent set no log level, so Debug went nowhere.
			slog.Warn("heartbeat failed, will try again", "error", err, "retry_in", retryDelay)
			d.heartbeatRetryAfter = now.Add(retryDelay)
		} else {
			d.lastHeartbeat = now
			d.heartbeatRetryAfter = time.Time{}
		}
	}

	if act.Scan && !now.Before(d.scanRetryAfter) {
		if err := d.scan(ctx); err != nil {
			// Deliberately not recorded as a scan: recording it would make the
			// machine wait a full day before trying again. The retry time holds
			// it back instead, without holding back everything else.
			slog.Warn("scan failed, will try again", "error", err, "retry_in", retryDelay)
			d.scanRetryAfter = now.Add(retryDelay)
		} else {
			d.lastScan = now
			d.scanRetryAfter = time.Time{}
		}
	}

	// One sleep, at the end, capped at the poll interval. Nothing that fails
	// earlier in the pass can make the loop stop asking for work.
	wait := act.Wait
	if wait <= 0 {
		wait = schedule.SolvePollInterval
	}
	return d.sleep(ctx, wait)
}

func newServeCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "serve",
		Short: "Run the agent in the background (used by the service, not by people)",
		Long: "Runs the scan schedule and the heartbeat until stopped.\n\n" +
			"This is what the service manager starts. To see what it is doing, use\n" +
			"`ghostpsy status`. To scan right now without waiting, use `ghostpsy scan`.",
		Args:   cobra.NoArgs,
		Hidden: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runServe(cmd.Context())
		},
	}
}

func runServe(ctx context.Context) error {
	st, err := state.Load()
	if err != nil {
		return fmt.Errorf("this machine is not registered yet. Run `ghostpsy register` first: %w", err)
	}

	now := time.Now().UTC()
	d := &serveDeps{
		machineID:     st.MachineUUID,
		startedAt:     now,
		lastScan:      time.Unix(st.LastScanAt, 0).UTC(),
		lastHeartbeat: time.Time{},
		now:           func() time.Time { return time.Now().UTC() },
		scan:          runScanSubprocess,
		heartbeat:     heartbeatSender(st.MachineUUID),
		pollSolve:     solvePoller(st.MachineUUID),
		sleep:         sleepUntilCancelled,
	}
	if st.LastScanAt == 0 {
		d.lastScan = time.Time{}
	}

	slog.Info("ghostpsy agent started",
		"machine", st.MachineUUID,
		"next_scan", schedule.Next(d.machineID, d.lastScan, d.startedAt, now).Format(time.RFC3339))

	for ctx.Err() == nil {
		if err := servePass(ctx, d); err != nil {
			return err
		}
		if d.lastScan.After(time.Unix(st.LastScanAt, 0).UTC()) {
			st.LastScanAt = d.lastScan.Unix()
			if err := state.Save(st); err != nil {
				slog.Warn("could not record the last scan time", "error", err)
			}
		}
	}
	return nil
}

// runScanSubprocess runs a scan as a child process rather than in this one.
//
// `ghostpsy scan` calls os.Exit on any failure — it was written as a one-shot
// command, and that is correct for a person at a terminal. Calling it inline
// would take the whole service down the first time a scan could not reach the
// network, which is precisely the silent-machine failure this service exists to
// prevent. Running it as a child also means a panic in a collector costs one
// scan rather than the agent.
func runScanSubprocess(ctx context.Context) error {
	self, err := resolveSelfPath()
	if err != nil {
		return fmt.Errorf("could not find the agent binary: %w", err)
	}
	cmd := exec.CommandContext(ctx, self, "scan", "--yes")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("scan failed: %w: %s", err, lastLine(out))
	}
	return nil
}

func lastLine(b []byte) string {
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	return lines[len(lines)-1]
}

func sleepUntilCancelled(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return nil
	case <-t.C:
		return nil
	}
}

// heartbeatSender reports that this agent is alive, and whether its sudo rule
// still matches what this version needs.
//
// Drift is included because the person who can fix it is not reading this
// server's logs. If we cannot tell — no rule installed, or the check failed —
// nothing is sent for it: absent and false are different answers.
func heartbeatSender(machineUUID string) func(context.Context) error {
	return func(ctx context.Context) error {
		token, err := agentconfig.Load()
		if err != nil {
			return fmt.Errorf("no agent token yet: %w", err)
		}

		body := heartbeatBody{
			MachineUUID:  machineUUID,
			AgentVersion: version.Version,
		}
		if drifted, err := sudoersHasDrifted(installedGrantPath); err == nil {
			current := !drifted
			body.SudoRuleCurrent = &current
		}

		return postHeartbeat(ctx, envOr("GHOSTPSY_API_URL", defaultAPIBaseURL), token, body)
	}
}

// solvePoller asks the service for work and writes down what it was given.
//
// It does not run anything. Carrying out an action is #182's job, and an agent
// that pretended to would report a preview it never computed — the one thing this
// design exists to make impossible. So for now the work is logged, which is
// enough to prove the road reaches the machine.
func solvePoller(machineUUID string) func(context.Context) error {
	return func(ctx context.Context) error {
		token, err := agentconfig.Load()
		if err != nil {
			return fmt.Errorf("no agent token yet: %w", err)
		}

		work, err := solve.NextWork(ctx, envOr("GHOSTPSY_API_URL", defaultAPIBaseURL), token, machineUUID)
		if err != nil {
			return err
		}
		if !work.HasWork() {
			// The usual answer, and not worth a line in anyone's log every minute.
			slog.Debug("no solve work for this machine")
			return nil
		}

		slog.Info("the service has work for this machine",
			"mode", work.Mode,
			"job", work.JobID,
			"actions", len(work.Actions),
			"note", "not run: the action runtime is not built yet (#182)")
		return nil
	}
}
