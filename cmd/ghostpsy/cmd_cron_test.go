//go:build linux

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLookupSchedule_KnownNames(t *testing.T) {
	for _, name := range []string{"hourly", "daily", "weekly", "monthly"} {
		spec, err := lookupSchedule(name)
		if err != nil {
			t.Errorf("%s: unexpected error %v", name, err)
			continue
		}
		if spec.name != name {
			t.Errorf("%s: spec.name=%q", name, spec.name)
		}
		if spec.cronExpr == "" || spec.onCalendar == "" {
			t.Errorf("%s: empty cron or onCalendar", name)
		}
	}
}

func TestLookupSchedule_Unknown(t *testing.T) {
	if _, err := lookupSchedule("yearly"); err == nil {
		t.Fatal("expected error for unknown schedule")
	}
}

func TestRenderSystemdService_ContainsExecStart(t *testing.T) {
	out := renderSystemdService("/usr/local/bin/ghostpsy")
	if !strings.Contains(out, "ExecStart=/usr/local/bin/ghostpsy scan --yes") {
		t.Fatalf("missing ExecStart: %s", out)
	}
	if !strings.Contains(out, "Type=oneshot") {
		t.Fatalf("missing Type=oneshot: %s", out)
	}
}

func TestRenderSystemdTimer_ContainsOnCalendar(t *testing.T) {
	spec, _ := lookupSchedule("weekly")
	out := renderSystemdTimer(spec)
	if !strings.Contains(out, "OnCalendar=Sun *-*-* 03:00:00") {
		t.Fatalf("missing OnCalendar: %s", out)
	}
	if !strings.Contains(out, "Unit=ghostpsy.service") {
		t.Fatalf("missing Unit=: %s", out)
	}
}

func TestRenderCronEntry_ContainsScheduleAndUser(t *testing.T) {
	spec, _ := lookupSchedule("daily")
	out := renderCronEntry(spec, "/usr/local/bin/ghostpsy")
	if !strings.Contains(out, "0 3 * * * root /usr/local/bin/ghostpsy scan --yes") {
		t.Fatalf("unexpected cron line: %s", out)
	}
}

func TestInstallSystemdUnits_WritesBothFiles(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GHOSTPSY_SYSTEMD_DIR", dir)
	spec, _ := lookupSchedule("weekly")
	if err := installSystemdUnits(spec, "/usr/local/bin/ghostpsy"); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"ghostpsy.service", "ghostpsy.timer"} {
		p := filepath.Join(dir, name)
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("%s not written: %v", p, err)
		}
	}
}

func TestRemoveSystemdUnits_DeletesBothFiles(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GHOSTPSY_SYSTEMD_DIR", dir)
	spec, _ := lookupSchedule("weekly")
	if err := installSystemdUnits(spec, "/usr/local/bin/ghostpsy"); err != nil {
		t.Fatal(err)
	}
	if err := removeSystemdUnits(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"ghostpsy.service", "ghostpsy.timer"} {
		p := filepath.Join(dir, name)
		if _, err := os.Stat(p); err == nil {
			t.Fatalf("%s should be removed", p)
		}
	}
}

func TestInstallCronEntry_WritesFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "ghostpsy")
	t.Setenv("GHOSTPSY_CRON_FILE", p)
	spec, _ := lookupSchedule("daily")
	if err := installCronEntry(spec, "/usr/local/bin/ghostpsy"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "0 3 * * *") {
		t.Fatalf("missing schedule: %s", data)
	}
}
