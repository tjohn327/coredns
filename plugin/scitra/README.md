# scitra

## Name

*scitra* - resolves SCION TXT records to SCION-mapped IPv6 addresses

## Description

This CoreDNS plugin is a companion to [SCION-IP Address Translators][1] that returns special AAAA
addresses (SCION-mapped IP addresses) for host that announce SCION support in a TXT record.

TXT records recognized by this plugin must have the form "scion=<ISD-ASN>,<Host>" where <ISD-ASN> is
a SCION AS and <Host> is an IPv4 or IPv6 address.

Native records take precedence: if the name also has real A/AAAA records (a dual-homed host), an
A or AAAA query is answered with those records unchanged. Only for SCION-only names (no native
record of the requested type) does the plugin synthesize a SCION-mapped AAAA and suppress A
answers. This makes it safe to publish `scion=` TXT records on every SCION-capable name,
including hosts that are also reachable over plain IP.

[1] https://github.com/netsys-lab/scion-ip-translator

## Syntax

```txt
scitra [prefix PREFIX]
```

* `prefix` **PREFIX** is an 8 bit long IPv6 prefix in CIDR notation that is used by translators to
  identify SCION-mapped IPv6 addresses. The default prefix is `fc00::/8`.

## Compilation

This plugin must run before `file` (and `forward`) in `plugin.cfg` since it resolves the
SCION TXT record through its `Next` chain:

```txt
# add this line right before file:file
scitra:scitra
```

## Example

Forward queries to another DNS server and rewrite SCION addresses.
```txt
. {
    forward . 1.1.1.1
    scitra
    cache
}
```

## Provenance

Vendored from [netsys-lab/coredns-scitra](https://github.com/netsys-lab/coredns-scitra),
licensed under Apache-2.0 (see upstream repository for the full license text; SPDX headers in
the source files are preserved). This copy is built against a local fork of `miekg/dns` that
adds a typed `scion` SvcParamKey and a `scionproto/scion` fork pin (see this repository's
`go.mod`).
