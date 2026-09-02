package cli

import (
	"fmt"
	"strings"
)

// onceString is a flag.Value that errors if set more than once, so
// docs/cli-contract.md's "duplicate scalar options ... fail" rule is
// enforced uniformly instead of Go's flag package default of silent
// last-value-wins.
type onceString struct {
	name string
	val  *string
	set  bool
}

func (o *onceString) String() string {
	if o == nil || o.val == nil {
		return ""
	}
	return *o.val
}

func (o *onceString) Set(v string) error {
	if o.set {
		return fmt.Errorf("--%s specified more than once", o.name)
	}
	*o.val = v
	o.set = true
	return nil
}

// onceBool is the boolean analog of onceString. It implements the
// flag.boolFlag interface (an unexported interface satisfied by any Value
// with `IsBoolFlag() bool`) so `--force` works without requiring `=true`.
type onceBool struct {
	name string
	val  *bool
	set  bool
}

func (o *onceBool) String() string {
	if o == nil || o.val == nil {
		return "false"
	}
	if *o.val {
		return "true"
	}
	return "false"
}

func (o *onceBool) IsBoolFlag() bool { return true }

func (o *onceBool) Set(v string) error {
	if o.set {
		return fmt.Errorf("--%s specified more than once", o.name)
	}
	switch v {
	case "true", "1", "":
		*o.val = true
	case "false", "0":
		*o.val = false
	default:
		return fmt.Errorf("--%s: invalid boolean value %q", o.name, v)
	}
	o.set = true
	return nil
}

// repeatableList accumulates values across repeated flag occurrences and
// also splits each occurrence on commas, matching docs/cli-contract.md's
// "repeatable or comma-separated" options (--include, --exclude, --format,
// --fail-on) and the plain comma-list option (--tags).
type repeatableList struct {
	values *[]string
}

func (r *repeatableList) String() string {
	if r == nil || r.values == nil {
		return ""
	}
	return strings.Join(*r.values, ",")
}

func (r *repeatableList) Set(v string) error {
	for _, part := range strings.Split(v, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		*r.values = append(*r.values, part)
	}
	return nil
}
