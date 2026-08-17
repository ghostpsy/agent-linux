//go:build linux

package solve

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const (
	testToken   = "agent-token"
	testMachine = "8f8ef0e3-829a-432d-83f0-11e106e8ace1"
)

func serving(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return server
}

// The usual answer. Nothing to do is not a failure, and a loop that treated it
// as one would log a warning every minute on every quiet machine.
func TestNothingToDoIsNotAnError(t *testing.T) {
	server := serving(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"mode":null,"job_id":null,"actions":null}`))
	})

	work, err := NextWork(context.Background(), server.URL, testToken, testMachine)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if work.HasWork() {
		t.Errorf("expected no work, got %+v", work)
	}
}

func TestWorkToPreviewIsReported(t *testing.T) {
	server := serving(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"mode":"dry_run","job_id":"job-1",
			"actions":[{"type":"restart_service"}]}`))
	})

	work, err := NextWork(context.Background(), server.URL, testToken, testMachine)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !work.HasWork() || work.Mode != ModeDryRun {
		t.Fatalf("expected a dry run, got %+v", work)
	}
	if work.JobID != "job-1" || len(work.Actions) != 1 {
		t.Errorf("the job did not survive the round trip: %+v", work)
	}
}

// The agent must send its token and say which machine it is. Without the machine
// the service cannot answer, and without the token it must not.
func TestTheRequestIdentifiesTheAgentAndTheMachine(t *testing.T) {
	var gotAuth, gotQuery string
	server := serving(t, func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotQuery = r.URL.RawQuery
		_, _ = w.Write([]byte(`{"mode":null}`))
	})

	if _, err := NextWork(context.Background(), server.URL, testToken, testMachine); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if gotAuth != "Bearer "+testToken {
		t.Errorf("token not sent as a bearer credential, got %q", gotAuth)
	}
	if !strings.Contains(gotQuery, testMachine) {
		t.Errorf("machine not named in the request, got %q", gotQuery)
	}
}

// A revoked token, a token for another machine, a machine we do not know: all of
// them mean stop asking, and none of them mean "no work". Reporting them as no
// work would hide a broken agent for good.
func TestARefusalIsAnErrorAndNotSilence(t *testing.T) {
	for _, status := range []int{401, 403, 404, 500} {
		server := serving(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(status)
		})

		_, err := NextWork(context.Background(), server.URL, testToken, testMachine)

		if err == nil {
			t.Errorf("status %d was reported as success", status)
		}
	}
}

func TestAPreviewIsSentBackWithItsJob(t *testing.T) {
	var body map[string]any
	var path string
	server := serving(t, func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&body)
		_, _ = w.Write([]byte(`{"job_id":"job-1","state":"dry_run_done"}`))
	})

	err := ReportDryRun(context.Background(), server.URL, testToken, DryRunReport{
		MachineUUID: testMachine,
		JobID:       "job-1",
		PreviewID:   "preview-1",
		Detail:      map[string]any{"would_change": []string{"nginx"}},
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(path, "job-1") || !strings.HasSuffix(path, "/dry-run") {
		t.Errorf("preview sent to the wrong place: %q", path)
	}
	if body["preview_id"] != "preview-1" {
		t.Errorf("the preview was not named: %+v", body)
	}
}

func TestAResultIsSentBackWithItsJob(t *testing.T) {
	var body map[string]any
	var path string
	server := serving(t, func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&body)
		_, _ = w.Write([]byte(`{"job_id":"job-1","state":"done"}`))
	})

	err := ReportResult(context.Background(), server.URL, testToken, ResultReport{
		MachineUUID: testMachine,
		JobID:       "job-1",
		OK:          false,
		Detail:      map[string]any{"exit_code": 1},
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasSuffix(path, "/result") {
		t.Errorf("result sent to the wrong place: %q", path)
	}
	if body["ok"] != false {
		t.Errorf("a failed run must be reported as failed: %+v", body)
	}
}

// The service refusing a report is not something to swallow: it means the job is
// not in the state we thought, and the loop needs to know.
func TestARefusedReportIsAnError(t *testing.T) {
	server := serving(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(409)
		_, _ = w.Write([]byte(`{"detail":"this job was not running"}`))
	})

	err := ReportResult(context.Background(), server.URL, testToken, ResultReport{
		MachineUUID: testMachine,
		JobID:       "job-1",
		OK:          true,
	})

	if err == nil {
		t.Fatal("a refused report was reported as success")
	}
	if !strings.Contains(err.Error(), "not running") {
		t.Errorf("the service's own words should survive: %v", err)
	}
}
