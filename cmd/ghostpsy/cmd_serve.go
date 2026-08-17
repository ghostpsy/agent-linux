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
	"github.com/ghostpsy/agent-linux/internal/state"
	"github.com/ghostpsy/agent-linux/internal/version"
)

// retryDelay is how long the loop waits after a scan fails.
//
// A failed scan is deliberately not recorded, so the next pass still finds one
// due. Without a wait that is a hot loop: on a host with no network the agent
// spawned a scan every two seconds, forever. Found on a real machine, not by a
// unit test.
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
}

// servePass runs one pass of the service loop.
//
// It never returns an error for a failed scan or heartbeat. A machine that goes
// silent because one scan could not reach the network is exactly the failure
// this work exists to remove — the loop logs it and carries on.
func servePass(ctx context.Context, d *serveDeps) error {
	now := d.now()
	act := schedule.Decide(d.machineID, d.lastScan, d.lastHeartbeat, d.startedAt, now)

	if act.Heartbeat {
		if err := d.heartbeat(ctx); err != nil {
			// Same trap as the scan path: a failure leaves lastHeartbeat unset,
			// so the next pass asks for another one and Wait stays zero. Without
			// this sleep the loop spins as fast as the CPU allows, forever.
			//
			// Warn, not Debug. This is the line that explains why a machine has
			// gone quiet in the dashboard, and at Debug nobody could ever see
			// it: the agent set no log level, so Debug went nowhere.
			slog.Warn("heartbeat failed, will try again", "error", err, "retry_in", retryDelay)
			if !act.Scan {
				return d.sleep(ctx, retryDelay)
			}
		} else {
			d.lastHeartbeat = now
		}
	}

	if act.Scan {
		if err := d.scan(ctx); err != nil {
			// Deliberately not recorded as a scan. Recording it would make the
			// machine wait a full day before trying again — but that is exactly
			// why the retry has to wait here instead.
			slog.Warn("scan failed, will try again", "error", err, "retry_in", retryDelay)
			return d.sleep(ctx, retryDelay)
		}
		d.lastScan = now
	}

	if act.Wait > 0 {
		return d.sleep(ctx, act.Wait)
	}
	return nil
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
