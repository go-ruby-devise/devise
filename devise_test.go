// Copyright (c) the go-ruby-devise/devise authors
//
// SPDX-License-Identifier: BSD-3-Clause

package devise

import (
	"errors"
	"time"
)

// fakeModel is an in-memory [Model] for tests: a bag of attributes that records
// how many times it was saved and can be made to fail Save.
type fakeModel struct {
	attrs   map[string]any
	saveErr error
	saves   int
}

func newModel(kv ...any) *fakeModel {
	m := &fakeModel{attrs: map[string]any{}}
	for i := 0; i+1 < len(kv); i += 2 {
		m.attrs[kv[i].(string)] = kv[i+1]
	}
	return m
}

func (m *fakeModel) Get(attr string) any    { return m.attrs[attr] }
func (m *fakeModel) Set(attr string, v any) { m.attrs[attr] = v }
func (m *fakeModel) Save() error {
	m.saves++
	return m.saveErr
}

// errSave is the canonical Save failure used across tests.
var errSave = errors.New("save failed")

// fixedNow returns a clock pinned to t.
func fixedNow(t time.Time) func() time.Time {
	return func() time.Time { return t }
}

// baseTime is a stable reference instant for time-dependent assertions.
var baseTime = time.Date(2026, 7, 6, 12, 0, 0, 0, time.UTC)

// testConfig returns a DefaultConfig with a pinned clock and low bcrypt cost so
// tests stay fast.
func testConfig() *Config {
	c := DefaultConfig()
	c.Stretches = 4 // bcrypt MinCost — fastest valid hash
	c.Now = fixedNow(baseTime)
	return c
}

// tableFinder builds a [Finder] over a fixed set of models, matching a record
// when every requested attribute equals the model's.
func tableFinder(models ...*fakeModel) Finder {
	return func(attrs map[string]any) (Model, bool) {
		for _, m := range models {
			match := true
			for k, v := range attrs {
				if m.attrs[k] != v {
					match = false
					break
				}
			}
			if match {
				return m, true
			}
		}
		return nil, false
	}
}

// countingTrueFinder returns a Finder that reports a match (true) for its first
// n calls and no match afterwards — used to exercise the token uniqueness retry
// loops. The returned model is irrelevant to those loops.
func countingTrueFinder(n int) Finder {
	calls := 0
	return func(map[string]any) (Model, bool) {
		calls++
		if calls <= n {
			return &fakeModel{attrs: map[string]any{}}, true
		}
		return nil, false
	}
}
