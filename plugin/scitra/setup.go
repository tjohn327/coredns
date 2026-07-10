// SPDX-License-Identifier: Apache-2.0
package scitra

import (
	"fmt"
	"net/netip"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
)

// init registers this plugin.
func init() { plugin.Register("scitra", setup) }

func setup(c *caddy.Controller) error {
	var err error
	prefix := netip.MustParsePrefix("fc00::/8")

	c.Next() // skip first token ("scitra")
	for c.Next() {
		switch c.Val() {
		case "prefix":
			if !c.NextArg() {
				return plugin.Error("scitra", c.ArgErr())
			}
			prefix, err = netip.ParsePrefix(c.Val())
			if err != nil {
				return plugin.Error("scitra", err)
			}
			if !prefix.Addr().Unmap().Is6() || prefix.Bits() != 8 {
				return plugin.Error("scitra", fmt.Errorf("invalid prefix"))
			}
		default:
			return plugin.Error("scitra", fmt.Errorf("unrecognized arguments"))
		}
	}

	// Add plugin to CoreDNS
	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		return Scitra{Next: next, Prefix: prefix.Addr().As16()[0]}
	})
	return nil
}
