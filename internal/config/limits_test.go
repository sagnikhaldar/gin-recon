package config

import "testing"

func TestResolveNilLimitsConfigReturnsDefaults(t *testing.T) {
	var l *LimitsConfig
	got := l.Resolve()
	want := DefaultResolvedLimits()
	if got != want {
		t.Errorf("Resolve() on a nil *LimitsConfig = %+v, want defaults %+v", got, want)
	}
}

func TestResolveEmptyLimitsConfigReturnsDefaults(t *testing.T) {
	got := (&LimitsConfig{}).Resolve()
	want := DefaultResolvedLimits()
	if got != want {
		t.Errorf("Resolve() on an empty LimitsConfig = %+v, want defaults %+v", got, want)
	}
}

func TestResolveOverridesOnlySetFields(t *testing.T) {
	maxOutputBytes := 12345
	got := (&LimitsConfig{MaxOutputBytes: &maxOutputBytes}).Resolve()
	if got.MaxOutputBytes != 12345 {
		t.Errorf("MaxOutputBytes = %d, want 12345", got.MaxOutputBytes)
	}
	// Every other field must still be at its default — Resolve merges,
	// it does not reset the rest to zero.
	def := DefaultResolvedLimits()
	if got.MaxFiles != def.MaxFiles || got.MaxPackages != def.MaxPackages ||
		got.MaxFileBytes != def.MaxFileBytes || got.MaxDiagnostics != def.MaxDiagnostics ||
		got.MaxCallDepth != def.MaxCallDepth || got.Timeout != def.Timeout {
		t.Errorf("Resolve() with only MaxOutputBytes set = %+v, want every other field at its default %+v", got, def)
	}
}

func TestResolveParsesTimeout(t *testing.T) {
	timeout := "45s"
	got := (&LimitsConfig{Timeout: &timeout}).Resolve()
	if got.Timeout.String() != "45s" {
		t.Errorf("Timeout = %v, want 45s", got.Timeout)
	}
}
