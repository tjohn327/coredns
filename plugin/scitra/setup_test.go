// SPDX-License-Identifier: Apache-2.0
package scitra

import (
	"testing"

	"github.com/coredns/caddy"
)

func TestSetup(t *testing.T) {
	c := caddy.NewTestController("dns", "scitra")
	if err := setup(c); err != nil {
		t.Fatalf("Setup without arguments returned unexpected error: %v", err)
	}

	c = caddy.NewTestController("dns", "scitra prefix fd::/8")
	if err := setup(c); err != nil {
		t.Fatalf("Setup without prefix returned unexpected error: %v", err)
	}

	c = caddy.NewTestController("dns", "scitra prefix fd::/16")
	if err := setup(c); err == nil {
		t.Fatalf("Expected invalid prefix error, but got: %v", err)
	}
}
