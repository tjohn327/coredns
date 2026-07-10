// SPDX-License-Identifier: Apache-2.0
package scitra

import (
	"net"
	"testing"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/stretchr/testify/assert"
)

func TestAddrTranslation(t *testing.T) {
	s := Scitra{Next: nil, Prefix: byte(0xfc)}

	testCases := []struct {
		Name         string
		Input        addr.Addr
		Expected     net.IP
		ErrAssertion assert.ErrorAssertionFunc
	}{
		{
			Name:         "BGP-compatible ASN",
			Input:        addr.MustParseAddr("1-0:0:fc02,10.128.1.1"),
			Expected:     net.ParseIP("fc00:10fc:200::ffff:a80:101"),
			ErrAssertion: assert.NoError,
		},
		{
			Name:         "public SCION ASN",
			Input:        addr.MustParseAddr("64-2:0:9,10.0.0.0"),
			Expected:     net.ParseIP("fc04:800:900::ffff:a00:0"),
			ErrAssertion: assert.NoError,
		},
		{
			Name:         "IPv6 host address",
			Input:        addr.MustParseAddr("1-0:0:fc02,fd00::1"),
			Expected:     net.ParseIP("fc00:10fc:200::1"),
			ErrAssertion: assert.NoError,
		},
		{
			Name:         "ISD too large",
			Input:        addr.MustParseAddr("4096-ff00:0:0,127.0.0.1"),
			Expected:     nil,
			ErrAssertion: assert.Error,
		},
		{
			Name:         "ASN too large",
			Input:        addr.MustParseAddr("1-ff00:0:0,127.0.0.1"),
			Expected:     nil,
			ErrAssertion: assert.Error,
		},
	}

	for _, test := range testCases {
		t.Run(test.Name, func(t *testing.T) {
			ip, err := s.scion2ip(test.Input)
			test.ErrAssertion(t, err)
			if err == nil {
				assert.Equal(t, test.Expected, ip)
			}
		})
	}
}
