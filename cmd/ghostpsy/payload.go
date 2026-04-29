//go:build linux

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/neilotoole/jsoncolor"

	"github.com/ghostpsy/agent-linux/internal/actionlog"
	"github.com/ghostpsy/agent-linux/internal/collect"
	"github.com/ghostpsy/agent-linux/internal/payload"
	"github.com/ghostpsy/agent-linux/internal/state"
)

func writePayloadPreview(w io.Writer, p payload.V1) error {
	enc := jsoncolor.NewEncoder(w)
	enc.SetIndent("", "  ")
	if jsoncolor.IsColorTerminal(w) {
		enc.SetColors(jsoncolor.DefaultColors())
	}
	return enc.Encode(p)
}

func buildScanPayload(ctx context.Context, logger *actionlog.Logger) (*state.AgentState, int, payload.V1, []byte, error) {
	logger.Step("local-read-only", state.Path(), "Reading local agent state from "+state.Path(), nil)
	st := ensureState(logger)
	nextSeq := st.ScanSeq + 1
	logger.Step("local-compute", "payload.v1", "Building allowlisted inventory payload from local system data", map[string]string{"scan_seq": fmt.Sprintf("%d", nextSeq)})
	p, err := collect.StubWithObserver(ctx, st.MachineUUID, nextSeq, func(event collect.ActionEvent) {
		if event.Phase == "start" {
			logger.Step("local-read-only", event.Action, humanMessageForCollectionAction(event.Action), nil)
			return
		}
		if event.Error != "" {
			logger.Note(humanDoneWarningMessage(event.Action, event.Items, event.Error), nil)
			return
		}
		logger.Note(humanDoneMessage(event.Action, event.Items), nil)
	})
	if err != nil {
		return nil, 0, payload.V1{}, nil, err
	}
	logger.Step("local-compute", "payload.v1", "Preparing JSON payload preview before any network send", nil)
	body, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return nil, 0, payload.V1{}, nil, err
	}
	logger.Note("Payload prepared successfully", map[string]string{"payload_bytes": fmt.Sprintf("%d", len(body))})
	return st, nextSeq, p, body, nil
}
