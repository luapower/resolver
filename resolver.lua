
-- DNS resolver in Lua.
-- Written by Cosmin Apreutesei. Public Domain.

local ffi      = require'ffi'
local bit      = require'bit'
local time     = require'time'.time
local errors   = require'errors'
local glue     = require'glue'
local lrucache = require'lrucache'

local band = bit.band
local shr = bit.rshift
local shl = bit.lshift
local char = string.char
local format = string.format
local add = table.insert
local concat = table.concat

local resolver = {}

--error handling -------------------------------------------------------------

--errors raised with with check() and check_io() instead of assert() or error()
--enable methods wrapped with protect() to catch those errors, free temporary
--resources and return nil,err instead of raising. we thus distinguish between
--invalid usage (bugs on this side, which raise), protocol errors (bugs on the
--other side which don't raise but should be reported) and I/O errors (network
--failures which can be temporary and thus make the call retriable).

local dns_error  = errors.errortype'dns'
local sock_error = errors.errortype'socket'

local function check(self, v, ...)
	if v then return v, ... end
	local err, errcode = ...
	errors.raise(dns_error{resolver = self, message = err, errorcode = errcode,
		addtraceback = self.debug and self.debug.tracebacks})
end

local function check_io(self, v, ...)
	if v then return v, ... end
	local err, errcode = ...
	errors.raise(sock_error{resolver = self, message = err, errorcode = errcode,
		addtraceback = self.debug and self.debug.tracebacks})
end

local function close_all(self)
	if self.udp_socket then self.udp_socket:close() ; self.udp_socket = nil end
	if self.tcp_socket then self.tcp_socket:close(0); self.tcp_socket = nil end
end
dns_error .init = close_all
sock_error.init = close_all

local function protect(self, method)
	self[method] = errors.protect('dns socket', self[method])
end

--build request --------------------------------------------------------------

local qtypes = {
	A      =  1,
	NS     =  2,
	CNAME  =  5,
	SOA    =  6,
	PTR    = 12,
	MX     = 15,
	TXT    = 16,
	AAAA   = 28,
	SRV    = 33,
	SPF    = 99,
}

local function labels(s)
	return char(#s)..s
end
local function names(s)
	return s:gsub('([^.]+)%.?', labels)..'\0'
end

local function u16s(x)
	return char(shr(x, 8), band(x, 0xff))
end

local function querys(qname, qtype) --query: name qtype(2) class(2)
	assert(qname:sub(1, 1) ~= '.')
	local qtype = qtypes[qtype] or tonumber(qtype)
	return names(qname)..u16s(qtype)..u16s(1)
end

--NOTE: most DNS servers do not support multiple queries because it makes
--them vulnerable to amplification attacks, so we don't implement it here.
local function build_request(qname, qtype, no_recurse)
	local id = math.random(0, 65535)
	local flags = no_recurse and '\0\0' or '\1\0'
	local qs = u16s(id)..flags..u16s(1)..'\0\0\0\0\0\0'..querys(qname, qtype)
	return qs, id
end

--parse response -------------------------------------------------------------

local function ip4(self, p, i, n) --ipv4 in binary
	check(self, n >= i+4)
	return format('%d.%d.%d.%d', p[i], p[i+1], p[i+2], p[i+3]), i+4
end

local function ip6(self, p, i, n) --ipv6 in binary
	check(self, n >= i+16)
	local t = {}
	for i = 0, 15, 2 do
		local a, b = p[i], p[i+1]
		if a == 0 then
			add(t, format('%x', b))
		else
			add(t, format('%x%02x', a, b))
		end
	end
	return concat(t, ':'), i+16
end

local function u16(self, p, i, n) --u16 in big-endian
	check(self, n >= i+2)
	return shl(p[i], 8) + p[i+1], i+2
end

local function u32(self, p, i, n) --u32 in big-endian
	check(self, n >= i+4)
	return shl(p[i], 24) + shl(p[i+1], 16) + shl(p[i+2], 8) + p[i+3], i+4
end

local function label(self, p, i, n, maxlen) --string: len(1) text
	check(self, n >= i+1)
	local len = p[i]; i=i+1
	check(self, len > 0 and len <= maxlen)
	check(self, n >= i+len)
	return ffi.string(p+i, len), i+len
end

local function name(self, p, i, n) --name: label1... end|pointer
	local labels = {}
	while true do
		check(self, n >= i+1)
		local len = p[i]; i=i+1
		if len == 0 then --end: len(1) = 0
			break
		elseif band(len, 0xc0) ~= 0 then --pointer: offset(2) with b1100-0000-0000-0000 mask
			check(self, n >= i+1)
			local name_i = shl(band(len, 0x3f), 8) + p[i]; i=i+1
			local suffix = name(self, p, name_i, n)
			add(labels, suffix)
			break
		else --label: len(1) text
			local s; s, i = label(self, p, i-1, n, 63)
			add(labels, s)
		end
	end
	local s = concat(labels, '.')
	check(self, #s <= 253)
	return s, i
end

local qtype_names = glue.index(qtypes)

local function parse_answer(self, ans, p, i, n)
	ans.name  , i = name(self, p, i, n)
	local typ , i = u16(self, p, i, n)
	ans.class , i = u16(self, p, i, n)
	ans.ttl   , i = u32(self, p, i, n)
	local len , i = u16(self, p, i, n)
	typ = qtype_names[typ]
	ans.type = typ
	check(self, n >= i+len)
	n = i+len
	if typ == 'A' then
		ans.a, i = ip4(self, p, i, n)
	elseif typ == 'CNAME' then
		ans.cname, i = name(self, p, i, n)
	elseif typ == 'AAAA' then
		ans.aaaa, i = ip6(self, p, i, n)
	elseif typ == 'MX' then
		ans.mx_priority , i = u16(self, p, i, n)
		ans.mx          , i = name(self, p, i, n)
	elseif typ == 'SRV' then
		ans.srv_priority , i = u16(self, p, i, n)
		ans.srv_weight   , i = u16(self, p, i, n)
		ans.srv_port     , i = ua16(self, p, i, n)
		ans.srv_target   , i = name(self, p, i, n)
	elseif typ == 'NS' then
		ans.ns, i = name(self, p, i, n)
	elseif typ == 'TXT' or typ == 'SPF' then
		local key = typ == 'TXT' and 'txt' or 'spf'
		local s; s, i = label(self, p, i, n, 255)
		if i < n then --more string fragments
			local t = {s}
			repeat
				local s; s, i = label(self, p, i, n, 255)
				add(t, s)
			until i == n
			s = concat(t)
		end
		ans[key] = s
	elseif typ == 'PTR' then
		ans.ptr, i = name(self, p, i, n)
	elseif typ == 'SOA' then
		ans.soa_mname     , i = name(self, p, i, n)
		ans.soa_rname     , i = name(self, p, i, n)
		ans.soa_serial    , i = u32(self, p, i, n)
		ans.soa_refresh   , i = u32(self, p, i, n)
		ans.soa_retry     , i = u32(self, p, i, n)
		ans.soa_expire    , i = u32(self, p, i, n)
		ans.soa_minimum   , i = u32(self, p, i, n)
	else --unknown type, return the raw value
		ans.rdata, i = ffi.string(p+i, n-i), n
	end
	return i
end

local function parse_section(self, answers, section, p, i, n, entries, should_skip)
	for _ = 1, entries do
		local ans = {section = section}
		if not should_skip then
			add(answers, ans)
		end
		i = parse_answer(self, ans, p, i, n)
	end
	return i
end

local resolver_errstrs = {
	'format error',     -- 1
	'server failure',   -- 2
	'name error',       -- 3
	'not implemented',  -- 4
	'refused',          -- 5
}

local function parse_response(self, p, n, qid, authority_section, additional_section)

	-- header layout: ident(2) flags(2) n1(2) n2(2) n3(2) n4(2)
	local id    , i = u16(self, p, 0, n)
	local flags , i = u16(self, p, i, n)
	local n1    , i = u16(self, p, i, n) --number of questions
	local n2    , i = u16(self, p, i, n) --number of answers
	local n3    , i = u16(self, p, i, n) --number of authority entries
	local n4    , i = u16(self, p, i, n) --number of additional entries

	if id ~= qid then
		return nil, 'id mismatch'
	end
	if band(flags, 0x200) ~= 0 then
		return nil, 'truncated'
	end
	check(self, band(flags, 0x8000) ~= 0, 'bad QR flag')

	--skip question section: (qname qtype(2) qclass(2)) ...
	for _ = 1, n1 do
		_, i = name(self, p, i, n) --qname
		_, i = u16(self, p, i, n) --qtype
		_, i = u16(self, p, i, n) --qclass
	end

	local answers = {}

	local code = band(flags, 0xf)
	if code ~= 0 then
		answers.error = resolver_errstrs[code] or 'unknown'
		answers.errorcode = code
	end

	authority_section = qtype == 'SOA' or authority_section

	i = parse_section(self, answers, 'answer', p, i, n, n2)
	if authority_section or additional_section then
		i = parse_section(self, answers, 'authority', p, i, n, n3, not authority_section)
		if additional_section then
			i = parse_section(self, answers, 'additional', p, i, n, n4)
		end
	end

	return answers
end

--dns client -----------------------------------------------------------------

resolver.query_timeout = 2
resolver.no_recurse = false
resolver.authority_section = false
resolver.additional_section = false

local function tcp_query(self, host, port, expires, query, id)
	local tcp = check_io(self, self.tcp())
	self.tcp_socket = tcp
	check_io(self, tcp:connect(host, port, expires))
	check_io(self, tcp:sendall(u16s(#query) .. query), nil, expires)
	check_io(self, tcp:recvall(buf, 2, expires))
	local len = u16(self, buf, 0, 2)
	check(self, len <= sz)
	check_io(self, tcp:recvall(buf, len, expires))
	close_all(self)
	return parse_response(self, buf, len, id,
		opt.authority_section, opt.additional_section)
end

function resolver:query(host, port, qname, qtype, opt)
	port = port or 53
	opt = opt and glue.object(self, opt) or self
	local expires = self.clock() + opt.query_timeout
	local query, id = build_request(qname, qtype or 'A', opt.no_recurse)

	if #query > 512 or opt.tcp_only then
		return tcp_query(self, host, port, expires, query, id)
	end

	udp = check_io(self, self.udp())
	self.udp_socket = udp
	check_io(self, udp:connect(host, port))
	check_io(self, udp:send(query, nil, expires))

	--get & discard udp packets until we get the one with our id in it.
	--if we get a truncated message, we try again on a one-shot TCP connection.
	local sz = 4096
	local buf = ffi.new('uint8_t[?]', sz)
	for _ = 1, 128 do --ironically, this defeats the purpose of randomized ids.
		local len = check_io(self, udp:recv(buf, sz, expires))
		local answers, err = parse_response(self, buf, len, id,
			opt.authority_section, opt.additional_section)
		if answers then
			close_all(self)
			return answers
		elseif err == 'truncated' then
			close_all(self)
			return tcp_query(self, host, port, expires, query, id, qn)
		else
			assert(err == 'id mismatch')
		end
	end
	check(self, false, 'id mismatch')
end
protect(resolver, 'query')

function resolver:bind_libs(libs)
	for lib in libs:gmatch'[^%s]+' do
		if lib == 'sock' then
			local sock = require'sock'
			self.tcp = sock.tcp
			self.udp = sock.udp
			self.addr = sock.addr
			--scheduling
			self.newthread = sock.newthread
			self.resume = sock.resume
			self.start = sock.start
			self.clock = sock.clock
		else
			assert(false)
		end
	end
end

--name resolver --------------------------------------------------------------

resolver.max_cache_entries = 1e5

local function next_host(self)
	self.host_index = (self.host_index % #self.host_ais) + 1
	self.host_ai = self.host_ais[self.host_index]
end

function resolver:new(opt)
	local self = glue.update({}, self, opt)
	if self.libs then
		self:bind_libs(self.libs)
	end
	self.host_ais = {}
	for i = 1, #self.hosts do
		self.host_ais[i] = assert(self.addr(self.hosts[i], 53))
		print(self.host_ais[i]:tostring())
	end
	self.host_index = 0
	next_host(self)
	self.cache = lrucache{max_size = self.max_cache_entries}
	return self
end

function resolver:lookup(name, qtype, maxtries)
	qtype = qtype or 'A'
	local key = qtype..' '..name
	local res = self.cache:get(key)
	if res and time() > res.expires then
		self.cache:remove_val(res)
		res = nil
	end
	if not res then
		local err; res, err = self:query(self.host_ai, nil, name, qtype)
		if not res then --change host and retry
			print('error', err, self.host_ai:tostring(), name)
			next_host(self)
			return self:lookup(name, qtype, maxtries)
		end
		res.expires = 0
		--TODO:
		--res.expires = time() + res.ttl
		self.cache:put(key, res)
	end
	return res
end

local function hex4(s)
	return ('%04x'):format(tonumber(s, 16))
end
local function arpa_str(s)
	if s:find(':', 1, true) then --ipv6
		local _, n = s:gsub('[^:]+', hex4) --add leading zeroes and count blocks
		if n < 8 then --decompress
			local i = s:find('::', 1, true)
			if i == 1 then
				s = s:gsub('^::',      ('0000:'):rep(8 - n), 1)
			elseif i == #s-1 then
				s = s:gsub('::$',      (':0000'):rep(8 - n), 1)
			else
				s = s:gsub('::' , ':'..('0000:'):rep(8 - n), 1)
			end
		end
		return (s:gsub(':', ''):reverse():gsub('.', '%0.')..'ip6.arpa')
	else
		return (s:gsub('^(%d+)%.(%d+)%.(%d+)%.(%d+)$', '%4.%3.%2.%1.in-addr.arpa'))
	end
end

function resolver:reverse_lookup(addr)
	local s = arpa_str(addr)
	if not s then return nil, 'invalid address' end
	return self:lookup(s, 'PTR')
end

--self-test ------------------------------------------------------------------

if not ... then

	local r = assert(resolver:new{
		libs = 'sock',
		hosts = {
			'8.8.8.8',
			--{host = '8.8.4.4', port = 53},
		},
		query_timeout = 20,
		--tcp_only = true,
	})

	local function lookup(hostname)
		local answers, err = r:lookup(hostname)
		if answers.error then
			print(format('%s [%d]', answers.error, answers.errorcode))
		end
		for i, ans in ipairs(answers) do
			print(format('%-16s %-16s type: %s  ttl: %3d',
				ans.name,
				ans.a or ans.cname,
				ans.type,
				ans.ttl))
		end
	end
	for _,s in ipairs{
		'luapower.com',
		'openresty.org',
		'www.google.com',
		'lua.org',
	} do
		r.resume(r.newthread(lookup), s)
	end
	r.start()

end


return resolver
