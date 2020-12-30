
## `local resolver = require'resolver'`

DNS client/resolver in Lua.

## API

------------------------------------------------------------- ----------------
`resolver|r:query(host, port, name, [qtypes], [opt]) -> ans`  query a DNS server directly
`resolver:new(opt) -> r`                                      create a resolver object
`r:lookup(name, [qtypes]) -> addrs`                           address lookup
`r:reverse_lookup(addr) -> hosts`                             reverse lookup
------------------------------------------------------------- ----------------

NOTE: the functions above return `nil,err` on I/O or protocol errors but
raise on user errors.

IMPORTANT: call `math.randomseed` prior to using this module to decrease
the chance of cache poisoning attacks.

Supported record types: A, NS, CNAME, SOA, PTR, MX, TXT, AAAA, SRV, SPF.

Unsupported types must be queried by number and they will be received
unparsed in the `rdata` field.

## API

### `resolver|r:query(host, port, name, [qtypes], [opt]) -> answers`

Performs a DNS standard query to a host:port and returns an array of DNS
records. If the server returns an error code, the fields `errorcode`
and `error` will also be present.

### `resolver:new(opt) -> r`

Creates a resolver object. The options table can contain:

* `hosts`

	a list of DNS server IP addresses. Each entry can be either a
	single hostname string or a table holding both the hostname string and
	the port number. The resolver locks on to the first/next server that works.

* `query_timeout`

	the timeout in seconds for a single query (request + reply). Defaults to 2.

* `no_recurse`

	disables the "recursion desired" (RD) flag in the request. Defaults to `false`.

Each entry in the `answers` returned table value is also a hash-like Lua table
which usually takes some of the following fields:

* `name`

	The resource record name.
* `type`

	The current resource record type, possible values are `1` (`TYPE_A`),
	`5` (`TYPE_CNAME`), `28` (`TYPE_AAAA`), and any other values allowed by RFC 1035.
* `address`

	The IPv4 or IPv6 address in their textual representations when the
	resource record type is either `1` (`TYPE_A`) or `28` (`TYPE_AAAA`),
	respectively. Secussesive 16-bit zero groups in IPv6 addresses will not
	be compressed by default, if you want that, you need to call the
	`compress_ipv6_addr` static method instead.
* `section`

	The identifier of the section that the current answer record belongs to.
	Possible values are `1` (`SECTION_AN`), `2` (`SECTION_NS`), and `3`
	(`SECTION_AR`).
* `cname`

	The (decoded) record data value for `CNAME` resource records.
	Only present for `CNAME` records.
* `ttl`

	The time-to-live (TTL) value in seconds for the current resource
	record.
* `class`

	The current resource record class, possible values are `1` (`CLASS_IN`)
	or any other values allowed by RFC 1035.
* `preference`

	The preference integer number for `MX` resource records. Only present for
	`MX` type records.
* `exchange`

	The exchange domain name for `MX` resource records. Only present for
	`MX` type records.
* `nsdname`

	A domain-name which specifies a host which should be authoritative for
	the specified class and domain. Usually present for `NS` type records.
* `rdata`

	The raw resource data (RDATA) for resource records that are not recognized.
* `txt`

	The record value for `TXT` records. When there is only one character
	string in this record, then this field takes a single Lua string.
	Otherwise this field takes a Lua table holding all the strings.
* `ptrdname`

	The record value for `PTR` records.

### `r:reverse_lookup(address) -> answers, err`

Performs a PTR lookup for both IPv4 and IPv6 addresses.

