// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package compliance

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

const (
	// hangTimeout is the wait for an answer in the cases where the fake
	// oscap-io hangs. It exceeds the start time of the test binary.
	hangTimeout = 10 * time.Second

	// slowEvaluation is the time the fake oscap-io takes on a slow rule.
	slowEvaluation = 500 * time.Millisecond
)

// TestMain runs the test binary as a fake oscap-io when the evaluator tests
// start it with GO_WANT_HELPER_OSCAP_IO set to 1, and as a child of the fake
// that holds its stdout when it is set to sleep.
func TestMain(m *testing.M) {
	switch os.Getenv("GO_WANT_HELPER_OSCAP_IO") {
	case "1":
		fakeOSCAPIO()
		os.Exit(0)
	case "sleep":
		holdStdout()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// holdStdout writes an empty line on stdout twice a second, until a write
// fails once the reader has closed the pipe, or 3*hangTimeout has passed.
func holdStdout() {
	for end := time.Now().Add(3 * hangTimeout); time.Now().Before(end); time.Sleep(500 * time.Millisecond) {
		if _, err := os.Stdout.Write([]byte("\n")); err != nil {
			return
		}
	}
}

// fakeOSCAPIO speaks the oscap-io protocol on its standard input and output.
// It answers each request after the suffix of the rule id.
func fakeOSCAPIO() {
	codes := map[string]int{
		"pass":        xccdfPass,
		"fail":        xccdfFail,
		"error":       xccdfError,
		"unknown":     xccdfUnknown,
		"skip":        xccdfNotApplicable,
		"notchecked":  xccdfNotChecked,
		"notselected": xccdfNotSelected,
		"unscored":    xccdfInformational,
		"fixed":       xccdfFixed,
	}
	s := bufio.NewScanner(os.Stdin)
	for s.Scan() {
		_, id, _ := strings.Cut(s.Text(), " ")
		switch suffix := id[strings.LastIndexByte(id, '_')+1:]; suffix {
		case "silent":
			fmt.Fprintf(os.Stderr, "error: xccdf_session_evaluate: %s\n", id)
		case "garbage":
			fmt.Printf("garbage\nunrequested_pass 1\n%s 42\n%s 1\n%s 2\n", id, id, id)
		case "stderr":
			fmt.Fprint(os.Stderr, strings.Repeat("W: oscap: probe warning\n", 5000))
			fmt.Printf("%s %d\n", id, xccdfPass)
		case "crash":
			os.Exit(1)
		case "slow":
			time.Sleep(slowEvaluation)
			fmt.Printf("%s %d\n", id, xccdfPass)
		case "abort":
			fmt.Printf("%s %d\n", id, xccdfPass)
			os.Exit(1)
		case "hang":
			// A select {} would end the process as a deadlock.
			time.Sleep(time.Hour)
		case "orphan":
			// The child holds stdout open once the watchdog kills the fake.
			child := exec.Command(os.Args[0])
			child.Env = append(os.Environ(), "GO_WANT_HELPER_OSCAP_IO=sleep")
			child.Stdout = os.Stdout
			if err := child.Start(); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			time.Sleep(time.Hour)
		default:
			fmt.Printf("%s %d\n", id, codes[suffix])
		}
	}
	if err := s.Err(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// fakeOSCAPIOCommand returns a command running the test binary as fakeOSCAPIO.
func fakeOSCAPIOCommand(ctx context.Context, _ string) (*exec.Cmd, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, exe)
	cmd.Env = append(os.Environ(), "GO_WANT_HELPER_OSCAP_IO=1")
	return cmd, nil
}

// fakeBenchmark returns a benchmark with a rule for each XCCDF rule id, of
// the same id.
func fakeBenchmark(ids []string) *Benchmark {
	benchmark := &Benchmark{FrameworkID: "test"}
	for _, id := range ids {
		spec := &InputSpecXCCDF{Name: "ds.xml", Profile: "profile", Rule: id}
		benchmark.Rules = append(benchmark.Rules, &Rule{ID: id, InputSpecs: []*InputSpec{{XCCDF: spec}}})
	}
	return benchmark
}

// evaluateFake evaluates the XCCDF rule ids of fakeBenchmark with
// fakeOSCAPIO, and returns "rule result" for each event.
func evaluateFake(ctx context.Context, ids []string, interval, timeout time.Duration) ([]string, error) {
	var got []string
	err := evaluateXCCDF(ctx, "host", fakeBenchmark(ids), fakeOSCAPIOCommand, interval, timeout, func(e *CheckEvent, _ time.Duration) {
		got = append(got, e.RuleID+" "+string(e.Result))
	})
	return got, err
}

func TestOSCAPIOEvaluate(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		ids      []string
		interval time.Duration
		timeout  time.Duration
		want     []string
		wantErr  bool
		atMost   time.Duration // longest run, zero for any
	}{
		{
			name:    "codes",
			ids:     []string{"a_pass", "b_fail", "c_error", "d_unknown", "e_skip", "f_notchecked", "g_notselected", "h_unscored", "i_fixed"},
			timeout: time.Minute,
			want:    []string{"a_pass passed", "b_fail failed", "c_error error", "d_unknown error", "e_skip skipped"},
		},
		{
			name:     "paced",
			ids:      []string{"a_pass", "b_fail", "c_pass"},
			interval: 10 * time.Millisecond,
			timeout:  time.Minute,
			want:     []string{"a_pass passed", "b_fail failed", "c_pass passed"},
		},
		{
			name:     "paced silent",
			ids:      []string{"a_silent", "b_pass"},
			interval: 10 * time.Millisecond,
			timeout:  hangTimeout,
			want:     []string{"b_pass passed"},
		},
		{
			name:    "silent",
			ids:     []string{"a_silent", "b_pass", "c_silent", "d_silent"},
			timeout: time.Minute,
			want:    []string{"b_pass passed"},
		},
		{
			name:    "only silent",
			ids:     []string{"a_silent", "b_silent"},
			timeout: time.Minute,
			wantErr: true,
		},
		{
			name:    "only notchecked",
			ids:     []string{"a_notchecked"},
			timeout: time.Minute,
			wantErr: true,
		},
		{
			name:    "garbage",
			ids:     []string{"a_garbage", "b_fail"},
			timeout: time.Minute,
			want:    []string{"a_garbage passed", "b_fail failed"},
		},
		{
			name:    "stderr",
			ids:     []string{"a_stderr", "b_fail"},
			timeout: time.Minute,
			want:    []string{"a_stderr passed", "b_fail failed"},
		},
		{
			name:    "crash",
			ids:     []string{"a_pass", "b_crash", "c_fail"},
			timeout: time.Minute,
			want:    []string{"a_pass passed", "c_fail failed"},
		},
		{
			name:    "one crash",
			ids:     []string{"a_crash"},
			timeout: time.Minute,
			wantErr: true,
		},
		{
			name:    "no answer",
			ids:     []string{"a_crash", "b_crash", "c_pass"},
			timeout: time.Minute,
			wantErr: true,
		},
		{
			name:    "abort after each answer",
			ids:     []string{"a_abort", "b_abort", "c_fail"},
			timeout: time.Minute,
			want:    []string{"a_abort passed", "b_abort passed", "c_fail failed"},
		},
		{
			name:    "abort on the last rule",
			ids:     []string{"a_pass", "b_abort"},
			timeout: time.Minute,
			want:    []string{"a_pass passed", "b_abort passed"},
		},
		{
			name:    "hang",
			ids:     []string{"a_pass", "b_hang", "c_fail"},
			timeout: hangTimeout,
			want:    []string{"a_pass passed", "c_fail failed"},
			atMost:  2 * hangTimeout,
		},
		{
			name:    "hang first",
			ids:     []string{"a_hang", "b_pass"},
			timeout: hangTimeout,
			want:    []string{"b_pass passed"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			start := time.Now()
			got, err := evaluateFake(t.Context(), tt.ids, tt.interval, tt.timeout)
			if (err != nil) != tt.wantErr {
				t.Errorf("evaluate(%q) error = %v, want error %t", tt.ids, err, tt.wantErr)
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("evaluate(%q) = %q, want %q", tt.ids, got, tt.want)
			}
			if d := time.Since(start); tt.atMost > 0 && d > tt.atMost {
				t.Errorf("evaluate(%q) took %v, want at most %v", tt.ids, d, tt.atMost)
			}
		})
	}
}

func TestOSCAPIOEvaluateDeadline(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), hangTimeout)
	defer cancel()
	ids := []string{"a_pass", "b_hang", "c_fail"}
	got, err := evaluateFake(ctx, ids, 0, time.Minute)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("evaluate(%q) error = %v, want %v", ids, err, context.DeadlineExceeded)
	}
	if want := []string{"a_pass passed"}; !slices.Equal(got, want) {
		t.Errorf("evaluate(%q) = %q, want %q", ids, got, want)
	}
}

// TestOSCAPIOEvaluateTook checks that the time of a rule queued behind a slow
// one starts at the answer to the slow one.
func TestOSCAPIOEvaluateTook(t *testing.T) {
	t.Parallel()
	ids := []string{"a_slow", "b_pass"}
	var took []time.Duration
	err := evaluateXCCDF(t.Context(), "host", fakeBenchmark(ids), fakeOSCAPIOCommand, 0, time.Minute, func(_ *CheckEvent, d time.Duration) {
		took = append(took, d)
	})
	if err != nil || len(took) != len(ids) {
		t.Fatalf("evaluate(%q) = %d events, %v, want %d events", ids, len(took), err, len(ids))
	}
	if took[0] < slowEvaluation || took[1] >= slowEvaluation {
		t.Errorf("evaluate(%q) took %v, want at least %v on the first rule and less on the second", ids, took, slowEvaluation)
	}
}

// TestOSCAPIOEvaluateSlowReport checks that a run outlives a report that
// takes longer than the timeout.
func TestOSCAPIOEvaluateSlowReport(t *testing.T) {
	t.Parallel()
	ids := []string{"a_pass", "b_fail"}
	var got []string
	err := evaluateXCCDF(t.Context(), "host", fakeBenchmark(ids), fakeOSCAPIOCommand, 0, hangTimeout, func(e *CheckEvent, _ time.Duration) {
		if len(got) == 0 {
			time.Sleep(hangTimeout + slowEvaluation)
		}
		got = append(got, e.RuleID+" "+string(e.Result))
	})
	if err != nil {
		t.Errorf("evaluate(%q) error = %v", ids, err)
	}
	if want := []string{"a_pass passed", "b_fail failed"}; !slices.Equal(got, want) {
		t.Errorf("evaluate(%q) = %q, want %q", ids, got, want)
	}
}

// TestOSCAPIOEvaluateStartFailure checks that an oscap-io command that
// cannot start ends the evaluation at once.
func TestOSCAPIOEvaluateStartFailure(t *testing.T) {
	calls := 0
	newCmd := func(ctx context.Context, _ string) (*exec.Cmd, error) {
		calls++
		return exec.CommandContext(ctx, filepath.Join(t.TempDir(), "oscap-io")), nil
	}
	ids := []string{"a_pass", "b_pass"}
	err := evaluateXCCDF(t.Context(), "host", fakeBenchmark(ids), newCmd, 0, time.Minute, func(*CheckEvent, time.Duration) {})
	if !errors.Is(err, errStart) || calls != 1 {
		t.Errorf("evaluate(%q) = %v after %d starts, want %v after 1", ids, err, calls, errStart)
	}
}

// TestOSCAPIOEvaluateOrphan checks that a run ends when the watchdog kills
// oscap-io while a child of oscap-io still holds its stdout.
func TestOSCAPIOEvaluateOrphan(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), 2*hangTimeout)
	defer cancel()
	ids := []string{"a_pass", "b_orphan", "c_fail"}
	got, err := evaluateFake(ctx, ids, 0, hangTimeout)
	if err != nil {
		t.Errorf("evaluate(%q) error = %v, want nil", ids, err)
	}
	if want := []string{"a_pass passed", "c_fail failed"}; !slices.Equal(got, want) {
		t.Errorf("evaluate(%q) = %q, want %q", ids, got, want)
	}
}

// TestOSCAPIOWrite checks that a paced writer holds a request until oscap-io
// answers the previous one, and that an unpaced one sends them all at once.
func TestOSCAPIOWrite(t *testing.T) {
	reqs := []xccdfRequest{{profile: "p", id: "a"}, {profile: "p", id: "b"}}
	tests := []struct {
		name     string
		interval time.Duration
		early    int // requests sent before the first answer
	}{
		{name: "all at once", early: 2},
		{name: "paced", interval: 2 * time.Second, early: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				o := &oscapIO{interval: tt.interval}
				r, w := io.Pipe()
				defer r.Close()
				sent := make(chan time.Time, len(reqs))
				answered := make(chan struct{}, len(reqs))
				done := make(chan struct{})
				defer close(done)
				go o.write(w, reqs, sent, answered, done)

				lines := bufio.NewScanner(r)
				if !lines.Scan() || lines.Text() != "p a" {
					t.Fatalf("write sent %q first, want %q", lines.Text(), "p a")
				}
				synctest.Wait()
				if len(sent) != tt.early {
					t.Fatalf("write sent %d requests before the first answer, want %d", len(sent), tt.early)
				}
				start := time.Now()
				answered <- struct{}{}
				if !lines.Scan() || lines.Text() != "p b" {
					t.Fatalf("write sent %q second, want %q", lines.Text(), "p b")
				}
				if d := time.Since(start); d < tt.interval {
					t.Errorf("write sent the second request %v after the first answer, want at least %v", d, tt.interval)
				}
				if lines.Scan() {
					t.Errorf("write sent %q after the last request", lines.Text())
				}
			})
		})
	}
}

func TestXCCDFRequests(t *testing.T) {
	xccdf := func(name, rule string, rules ...string) []*InputSpec {
		return []*InputSpec{{XCCDF: &InputSpecXCCDF{Name: name, Profile: "profile", Rule: rule, Rules: rules}}}
	}
	benchmark := &Benchmark{
		dirname:     "compliance.d",
		FrameworkID: "test",
		Rules: []*Rule{
			{ID: "a", InputSpecs: xccdf("ds.xml", "a_pass")},
			{ID: "rego", InputSpecs: []*InputSpec{{File: &InputSpecFile{Path: "/etc/passwd"}}}},
			{ID: "b", InputSpecs: xccdf("other.xml", "", "b_pass", "b fail", "b_fail")},
			{ID: "c", InputSpecs: xccdf("ds.xml", "c_pass")},
			{ID: "d", InputSpecs: xccdf("ds.xml", "")},
		},
	}
	groups, err := xccdfRequests(benchmark)
	if err != nil {
		t.Fatalf("xccdfRequests() error = %v", err)
	}
	dir, err := filepath.Abs("compliance.d")
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, g := range groups {
		for _, r := range g.reqs {
			got = append(got, g.file+" "+r.rule.ID+" "+r.profile+" "+r.id)
		}
	}
	ds, other := filepath.Join(dir, "ds.xml"), filepath.Join(dir, "other.xml")
	want := []string{
		ds + " a profile a_pass",
		ds + " c profile c_pass",
		other + " b profile b_pass",
		other + " b profile b_fail",
	}
	if !slices.Equal(got, want) {
		t.Errorf("xccdfRequests() = %q, want %q", got, want)
	}
}
