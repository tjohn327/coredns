// SPDX-License-Identifier: Apache-2.0
package scitra

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"

	"github.com/coredns/coredns/plugin"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/plugin/pkg/nonwriter"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
	"github.com/scionproto/scion/pkg/addr"
)

const name = "scitra"

var log = clog.NewWithPlugin("scitra")

type Scitra struct {
	Next   plugin.Handler
	Prefix byte
}

func (s Scitra) Name() string { return name }

func (s Scitra) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {

	var scionAddr addr.Addr
	var mappedAddr net.IP
	var hasScion bool

	if len(r.Question) != 1 {
		return plugin.NextOrFailure(name, s.Next, ctx, w, r)
	}

	qtype := r.Question[0].Qtype
	name := r.Question[0].Name
	if qtype == dns.TypeA || qtype == dns.TypeAAAA {
		var err error
		scionAddr, hasScion, err = s.queryScionAddress(ctx, w, name)
		if err != nil {
			return 0, err
		}
		if hasScion {
			log.Debugf("%v is at %v", name, scionAddr)
			mappedAddr, err = s.scion2ip(scionAddr)
			if err != nil {
				log.Infof("scion2ip failed, because %v", err)
				hasScion = false
			}
		}
	}
	if !hasScion {
		// pass to the next plugin
		return plugin.NextOrFailure(name, s.Next, ctx, w, r)

	} else if hasScion && qtype == dns.TypeA {
		// suppress response, we only answer AAAA requests for SCION hosts
		log.Debugf("suppressed A-record request for %v", name)
		return s.emptyResponse(w, r)
	}

	// answer with a SCION-mapped IPv6 address
	state := request.Request{W: w, Req: r}
	re := new(dns.Msg)
	re.SetReply(r)
	re.Authoritative = true
	rr := new(dns.AAAA)
	rr.Hdr = dns.RR_Header{Name: state.QName(), Rrtype: dns.TypeAAAA, Class: state.QClass()}
	rr.AAAA = mappedAddr
	re.Answer = append(re.Answer, rr)

	log.Debugf("translated %v to %v", scionAddr, mappedAddr)
	err := w.WriteMsg(re)
	return 0, err
}

// queryScionAddress sends a request for name's TXT records to the next plugin
// and returns a SCION address if one was found in the respose.
func (s Scitra) queryScionAddress(
	ctx context.Context, w dns.ResponseWriter, name string,
) (addr.Addr, bool, error) {

	r := new(dns.Msg)
	r.Id = 1337
	r.MsgHdr.Opcode = dns.OpcodeQuery
	r.MsgHdr.RecursionDesired = true
	r.Question = append(r.Question, dns.Question{
		Name:   name,
		Qtype:  dns.TypeTXT,
		Qclass: dns.ClassINET,
	})

	nw := nonwriter.New(w)
	rcode, err := plugin.NextOrFailure(name, s.Next, ctx, nw, r)
	if err != nil {
		return addr.Addr{}, false, err
	}
	re := nw.Msg

	if rcode == dns.RcodeSuccess {
		for _, ans := range re.Answer {
			if txt, ok := (ans).(*dns.TXT); ok {
				for _, s := range txt.Txt {
					parts := strings.SplitN(s, "=", 2)
					if len(parts) == 2 && parts[0] == "scion" {
						a, err := addr.ParseAddr(parts[1])
						if err == nil && a.Host.Type() == addr.HostTypeIP {
							return a, true, nil
						}
					}
				}
			}
		}
	}
	return addr.Addr{}, false, nil
}

// emptyResponse returns an empty response to the client.
func (s Scitra) emptyResponse(w dns.ResponseWriter, r *dns.Msg) (int, error) {
	re := new(dns.Msg)
	re.SetReply(r)
	err := w.WriteMsg(re)
	return 0, err
}

func (s Scitra) scion2ip(scionAddr addr.Addr) (net.IP, error) {
	addr := make([]byte, 16)
	ip := scionAddr.Host.IP().Unmap()

	// Prefix
	addr[0] = s.Prefix

	// ISD-ASN
	var ia uint32
	isd := uint32(scionAddr.IA.ISD())
	if isd >= (1 << 12) {
		return addr, fmt.Errorf("ISD cannot be encoded (%v)", scionAddr)
	}
	asn := scionAddr.IA.AS()
	if asn < (1 << 19) {
		ia = (isd << 20) | uint32(asn)
	} else if 0x2_0000_0000 <= asn && asn <= 0x2_0007_ffff {
		ia = (isd << 20) | (1 << 19) | (uint32(asn) & 0x7ffff)
	} else {
		return addr, fmt.Errorf("ASN cannot be encoded (%v)", scionAddr)
	}
	binary.BigEndian.PutUint32(addr[1:5], ia)

	// Local prefix and Subnet ID
	if ip.Is6() {
		var localPrefix [3]byte
		// Should SCION-IP-Translator compatibility be announced with another TXT record?
		binary.BigEndian.PutUint16(localPrefix[:2], 0) // TODO: local prefix
		localPrefix[2] = 0                             // TODO: subnet
		copy(addr[5:8], localPrefix[:])
	}

	// Host Address / Interface
	if ip.Is4() {
		binary.BigEndian.PutUint32(addr[8:12], 0xffff)
		ipv4 := ip.As4()
		copy(addr[12:16], ipv4[:4])
	} else {
		ipv6 := ip.As16()
		copy(addr[8:16], ipv6[8:16])
	}

	return addr, nil
}
