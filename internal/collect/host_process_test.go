//go:build linux

package collect

import "testing"

func TestIsJavaInterpreter(t *testing.T) {
	t.Parallel()
	if !isJavaInterpreter("java", "java -jar app.jar") {
		t.Fatal("expected java process name match")
	}
	if isJavaInterpreter("node", "node server.js") {
		t.Fatal("node should not match java")
	}
}

func TestMergeProcessTopOrderAndCap(t *testing.T) {
	t.Parallel()
	samples := []procSample{
		{pid: 1, name: "a", user: "root", cpu: 1, rss: 100, cmdline: "a"},
		{pid: 2, name: "b", user: "root", cpu: 50, rss: 200, cmdline: "b"},
		{pid: 3, name: "c", user: "root", cpu: 10, rss: 9000, cmdline: "c"},
		{pid: 4, name: "d", user: "root", cpu: 5, rss: 8000, cmdline: "d"},
	}
	out := mergeProcessTop(samples)
	if len(out) > processTopMax {
		t.Fatalf("len %d > max %d", len(out), processTopMax)
	}
	ids := map[int32]struct{}{}
	for _, e := range out {
		ids[e.Pid] = struct{}{}
	}
	if _, ok := ids[2]; !ok {
		t.Fatal("expected top CPU process 2 in output")
	}
	if _, ok := ids[3]; !ok {
		t.Fatal("expected top RSS process 3 in output")
	}
}

func TestCountProcessSignals(t *testing.T) {
	t.Parallel()
	samples := []procSample{
		{pid: 1, name: "python3", user: "u", cpu: 0, rss: 0, cmdline: "/usr/bin/python3"},
		{pid: 2, name: "node", user: "u", cpu: 0, rss: 0, cmdline: "node index.js"},
		{pid: 3, name: "java", user: "u", cpu: 0, rss: 0, cmdline: "java -jar x.jar"},
		{pid: 4, name: "sh", user: "u", cpu: 0, rss: 0, cmdline: "/tmp/xmrig -o stratum"},
	}
	sig := countProcessSignals(samples)
	if sig.InterpreterPython < 1 || sig.InterpreterNode < 1 || sig.InterpreterJava < 1 {
		t.Fatalf("interpreter counts: %+v", sig)
	}
	if sig.UnknownHashWorkers < 1 {
		t.Fatal("expected miner keyword hit")
	}
}

func TestProcSampleToEntryTruncatesCmdline(t *testing.T) {
	t.Parallel()
	long := make([]rune, 400)
	for i := range long {
		long[i] = 'a'
	}
	s := procSample{pid: 1, name: "n", user: "u", cpu: 1.2, rss: 1048576, cmdline: string(long)}
	e := procSampleToEntry(s)
	if len([]rune(e.CmdlineTruncated)) > maxCmdlineRunes {
		t.Fatalf("cmdline not truncated: len=%d", len([]rune(e.CmdlineTruncated)))
	}
}
