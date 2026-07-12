// SPDX-License-Identifier: Apache-2.0
package scitra

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/test"
	"github.com/miekg/dns"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubZone answers questions from a fixed RR set (exact qname+qtype match),
// standing in for the file plugin as scitra's Next handler.
type stubZone struct {
	rrs []dns.RR
}

func (z stubZone) Name() string { return "stub" }

func (z stubZone) ServeDNS(_ context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	q := r.Question[0]
	for _, rr := range z.rrs {
		h := rr.Header()
		if strings.EqualFold(h.Name, q.Name) && h.Rrtype == q.Qtype {
			m.Answer = append(m.Answer, rr)
		}
	}
	if err := w.WriteMsg(m); err != nil {
		return dns.RcodeServerFailure, err
	}
	return dns.RcodeSuccess, nil
}

func TestServeDNSNativeFirst(t *testing.T) {
	zoneRRs := []string{
		"dual.scion. 300 IN A 10.155.0.1",
		"dual.scion. 300 IN AAAA fd00:beef:155::1",
		`dual.scion. 300 IN TXT "scion=1-155,10.20.3.155"`,
		`only.scion. 300 IN TXT "scion=1-150,10.150.0.81"`,
		"plain.scion. 300 IN A 10.1.2.3",
	}
	var rrs []dns.RR
	for _, s := range zoneRRs {
		rr, err := dns.NewRR(s)
		require.NoError(t, err)
		rrs = append(rrs, rr)
	}
	s := Scitra{Next: stubZone{rrs: rrs}, Prefix: 0xfc}

	type answer struct {
		Type uint16
		Addr string
	}
	testCases := []struct {
		Name     string
		QName    string
		QType    uint16
		Expected []answer
	}{
		{
			Name:     "native AAAA preserved on dual-homed name",
			QName:    "dual.scion.",
			QType:    dns.TypeAAAA,
			Expected: []answer{{dns.TypeAAAA, "fd00:beef:155::1"}},
		},
		{
			Name:     "native A preserved on dual-homed name",
			QName:    "dual.scion.",
			QType:    dns.TypeA,
			Expected: []answer{{dns.TypeA, "10.155.0.1"}},
		},
		{
			Name:     "SCION-only name synthesizes AAAA",
			QName:    "only.scion.",
			QType:    dns.TypeAAAA,
			Expected: []answer{{dns.TypeAAAA, "fc00:1000:9600::ffff:a96:51"}},
		},
		{
			Name:     "SCION-only name suppresses A",
			QName:    "only.scion.",
			QType:    dns.TypeA,
			Expected: nil,
		},
		{
			Name:     "name without scion TXT passes through",
			QName:    "plain.scion.",
			QType:    dns.TypeA,
			Expected: []answer{{dns.TypeA, "10.1.2.3"}},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			req := new(dns.Msg)
			req.SetQuestion(tc.QName, tc.QType)
			rec := dnstest.NewRecorder(&test.ResponseWriter{})
			_, err := s.ServeDNS(context.Background(), rec, req)
			require.NoError(t, err)
			require.NotNil(t, rec.Msg)
			assert.Equal(t, dns.RcodeSuccess, rec.Msg.Rcode)

			var got []answer
			for _, rr := range rec.Msg.Answer {
				switch v := rr.(type) {
				case *dns.A:
					got = append(got, answer{dns.TypeA, v.A.String()})
				case *dns.AAAA:
					got = append(got, answer{dns.TypeAAAA, v.AAAA.String()})
				default:
					t.Fatalf("unexpected answer RR type %T", rr)
				}
			}
			assert.Equal(t, tc.Expected, got)
		})
	}
}

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
