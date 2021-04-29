
-- DNS resolver in Lua.
-- Written by Cosmin Apreutesei. Public Domain.
-- Original code by Yichun Zhang (agentzh). BSD License.

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

local function check(q, v, ...)
	if v then return v, ... end
	local err, errcode = ...
	errors.raise(dns_error{socket = q.socket, message = err, errorcode = errcode,
		addtraceback = q.tracebacks})
end

function dns_error:init()
	if self.socket then
		self.socket:close(0)
		self.socket = nil
	end
end
sock_error.init = dns_error.init

local function check_io(q, v, ...)
	if v then return v, ... end
	local err, errcode = ...
	errors.raise(sock_error{socket = q.socket, message = err, errorcode = errcode,
		addtraceback = q.tracebacks})
end

local function protect(f)
	return errors.protect('dns socket', f)
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
	assert(#s <= 63)
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
	return names(qname)..u16s(qtype)..'\0\1'
end

--NOTE: most DNS servers do not support multiple queries because it makes
--them vulnerable to amplification attacks, so we don't implement them either.
--NOTE: queries with a single name cannot be > 512 bytes, the UDP sending limit.
local function build_query(q)
	assert(q.name <= 253)
	local flags = u16s(q.no_recurse and 0 or 1)
	--request: id(2) flags(2) query_num(2) zero(2) zero(2) zero(2) query
	return u16s(q.id)..flags..'\0\1\0\0\0\0\0\0'..querys(q.name, q.type)
end

--parse response -------------------------------------------------------------

local function ip4(q, p, i, n) --ipv4 in binary
	check(q, n >= i+4)
	return format('%d.%d.%d.%d', p[i], p[i+1], p[i+2], p[i+3]), i+4
end

local function ip6(q, p, i, n) --ipv6 in binary
	check(q, n >= i+16)
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

local function u16(q, p, i, n) --u16 in big-endian
	check(q, n >= i+2)
	return shl(p[i], 8) + p[i+1], i+2
end

local function u32(q, p, i, n) --u32 in big-endian
	check(q, n >= i+4)
	return shl(p[i], 24) + shl(p[i+1], 16) + shl(p[i+2], 8) + p[i+3], i+4
end

local function label(q, p, i, n, maxlen) --string: len(1) text
	check(q, n >= i+1)
	local len = p[i]; i=i+1
	check(q, len > 0 and len <= maxlen)
	check(q, n >= i+len)
	return ffi.string(p+i, len), i+len
end

local function name(q, p, i, n) --name: label1... end|pointer
	local labels = {}
	while true do
		check(q, n >= i+1)
		local len = p[i]; i=i+1
		if len == 0 then --end: len(1) = 0
			break
		elseif band(len, 0xc0) ~= 0 then --pointer: offset(2) with b1100-0000-0000-0000 mask
			check(q, n >= i+1)
			local name_i = shl(band(len, 0x3f), 8) + p[i]; i=i+1
			local suffix = name(q, p, name_i, n)
			add(labels, suffix)
			break
		else --label: len(1) text
			local s; s, i = label(q, p, i-1, n, 63)
			add(labels, s)
		end
	end
	local s = concat(labels, '.')
	check(q, #s <= 253)
	return s, i
end

local qtype_names = glue.index(qtypes)

local function parse_answer(q, ans, p, i, n)
	ans.name  , i = name(q, p, i, n)
	local typ , i = u16(q, p, i, n)
	ans.class , i = u16(q, p, i, n)
	ans.ttl   , i = u32(q, p, i, n)
	local len , i = u16(q, p, i, n)
	typ = qtype_names[typ]
	ans.type = typ
	check(q, n >= i+len)
	n = i+len
	if typ == 'A' then
		ans.a, i = ip4(q, p, i, n)
	elseif typ == 'CNAME' then
		ans.cname, i = name(q, p, i, n)
	elseif typ == 'AAAA' then
		ans.aaaa, i = ip6(q, p, i, n)
	elseif typ == 'MX' then
		ans.mx_priority , i = u16(q, p, i, n)
		ans.mx          , i = name(q, p, i, n)
	elseif typ == 'SRV' then
		ans.srv_priority , i = u16(q, p, i, n)
		ans.srv_weight   , i = u16(q, p, i, n)
		ans.srv_port     , i = ua16(q, p, i, n)
		ans.srv_target   , i = name(q, p, i, n)
	elseif typ == 'NS' then
		ans.ns, i = name(q, p, i, n)
	elseif typ == 'TXT' or typ == 'SPF' then
		local key = typ == 'TXT' and 'txt' or 'spf'
		local s; s, i = label(q, p, i, n, 255)
		if i < n then --more string fragments
			local t = {s}
			repeat
				local s; s, i = label(q, p, i, n, 255)
				add(t, s)
			until i == n
			s = concat(t)
		end
		ans[key] = s
	elseif typ == 'PTR' then
		ans.ptr, i = name(q, p, i, n)
	elseif typ == 'SOA' then
		ans.soa_mname     , i = name(q, p, i, n)
		ans.soa_rname     , i = name(q, p, i, n)
		ans.soa_serial    , i = u32(q, p, i, n)
		ans.soa_refresh   , i = u32(q, p, i, n)
		ans.soa_retry     , i = u32(q, p, i, n)
		ans.soa_expire    , i = u32(q, p, i, n)
		ans.soa_minimum   , i = u32(q, p, i, n)
	else --unknown type, return the raw value
		ans.rdata, i = ffi.string(p+i, n-i), n
	end
	return i
end

local function parse_section(q, answers, section, p, i, n, entries, should_skip)
	for _ = 1, entries do
		local ans = {section = section}
		if not should_skip then
			add(answers, ans)
		end
		i = parse_answer(q, ans, p, i, n)
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

local function parse_qid(q, p, n)
	return u16(q, p, 0, n)
end

local function parse_response(q, p, n)

	-- header layout: qid(2) flags(2) n1(2) n2(2) n3(2) n4(2)
	local id    , i = u16(q, p, 0, n)
	local flags , i = u16(q, p, i, n)
	local n1    , i = u16(q, p, i, n) --number of questions
	local n2    , i = u16(q, p, i, n) --number of answers
	local n3    , i = u16(q, p, i, n) --number of authority entries
	local n4    , i = u16(q, p, i, n) --number of additional entries

	if band(flags, 0x200) ~= 0 then
		return nil, 'truncated'
	end
	check(q, band(flags, 0x8000) ~= 0, 'bad QR flag')

	--skip question section: (qname qtype(2) qclass(2)) ...
	for _ = 1, n1 do
		local qname; qname, i = name(q, p, i, n)
		local qtype; qtype, i = u16(q, p, i, n)
		local class; class, i = u16(q, p, i, n)
		check(q, qname == q.name)
		check(q, qtype == q.type)
		check(q, class == 1)
	end

	local answers = {}

	local code = band(flags, 0xf)
	if code ~= 0 then
		answers.error = resolver_errstrs[code] or 'unknown'
		answers.errorcode = code
	end

	local additional_section = q.additional_section
	local authority_section = q.type == 'SOA' or q.authority_section

	i = parse_section(q, answers, 'answer', p, i, n, n2)
	if authority_section or additional_section then
		i = parse_section(q, answers, 'authority', p, i, n, n3, not authority_section)
		if additional_section then
			i = parse_section(q, answers, 'additional', p, i, n, n4)
		end
	end

	return answers
end

--[[
--resolver -------------------------------------------------------------------

The problem: DNS uses UDP but we want to be able to resolve multiple names
concurrently from different coroutines, so we need to account for the fact
that responses may come out-of-order, some may not come at all, and some may
come way later than the timeout of the query which we must always respect.

The solution: when calling the resolver's lookup function from a sock thread,
a query object is created and queued. Then the calling thread suspends itself.
A scheduler that runs in its own thread reads responses as they come, matches
queries in the queue based on id and resumes their corresponding threads
with the answers. If/when the queue gets empty, the scheduler suspends
itself, waiting to be resumed again when the first new request arrives.

Timed out queries are not dequeued right away to avoid reusing an id for a
query for which an answer might still come later.

]]

local query = {}

query.type = 'A'
query.timeout = 2
query.no_recurse = false
query.authority_section = false
query.additional_section = false
query.tracebacks = false
query.tcp_only = false

--NOTE: DNS servers don't support request pipelining so we use one-shot sockets.
local function tcp_query(self, q)

	local tcp = check_io(q, self.tcp())
	q.socket = tcp --pin it so that it's closed automatically on error.

	local expires = q.expires

	check_io(q, tcp:connect(self.ns.ai, nil, expires))
	check_io(q, tcp:sendall(u16s(#q.qs) .. q.qs), nil, expires)

	local len_buf = ffi.new'uint8_t[2]'
	check_io(q, tcp:recvall(len_buf, 2, expires))
	local len = u16(q, len_buf, 0, 2)
	check(q, len <= 4096)

	local buf = ffi.new('uint8_t[?]', len)
	check_io(q, tcp:recvall(buf, len, expires))

	tcp:close(0)
	q.socket = nil

	return parse_response(q, buf, len)
end

local function gen_qid(self, now)
	for i = 1, 10 do --expect a 50% chance of collision at around 362 qids.
		local qid = math.random(0, 65535)
		local q = self.queue[qid]
		if not q then
			return qid
		elseif q.timedout and now > q.expires + 120 then --safe to reuse this id.
			self.queue[qid] = nil
			return qid
		end
	end
	return nil, 'busy' --queue clogged with live ids.
end

local function query(self, q)

	local q = glue.object(query, q)
	local now = self.clock()
	q.expires = now + q.timeout
	q.id = check_io(q, gen_qid(self, now))
	q.qs = build_query(q)

	if q.tcp_only or self.ns.tcp_only then
		return tcp_query(self, q)
	end

	check_io(q, self.ns.udp:send(q.qs, nil, q.expires))

	--queue the query.
	q.thread = self.currentthread()
	self.queue[q.id] = q.id
	self.wait_n = self.wait_n + 1

	--resume the scheduler if it's dormant.
	if self.wait_n == 1 then
		self.scheduler.resume()
	end

	--suspend. the scheduler will resume us with the recv() return values.
	local buf, len = check_io(self.suspend())

	--parse the reply.
	local answers, err = parse_response(q, buf, len)
	if ok then
		return answers
	elseif err == 'truncated' then
		return tcp_query(self, q)
	else
		return nil, err
	end

end

--NOTE: we could use a heap for this but I bet this is faster for up-to 1K records.
local function queue_min_expires(self, now)
	local t = 1/0
	for _,q in pairs(self.queue) do
		if not q.timedout then
			t = math.min(t, q.expires)
		end
	end
	return t
end

local function schedule(self)
	local sz = 4096
	local buf = ffi.new('uint8_t[?]', sz)
	repeat
		while self.wait_n > 0 do
			local expires = queue_min_expires(self, self.clock())
			local len, err = udp:recv(buf, sz, expires)
			if not len then
				print('UDP recv error', err) --TODO: switch server?
			else
				local qid = parse_qid(self, buf, 0, sz)
				local q = self.queue[qid]
				if not q then
					print('Unknown QID', qid)
				else
					self.wait_n = self.wait_n - 1
					if self.clock() > q.expires then
						q.timedout = true
						self.resume(q.thread, nil, 'timeout')
					else
						self.queue[qid] = nil
						self.resume(q.thread, buf, len)
					end
				end
			end
		end
	until self.suspend() == 'stop' --merely suspended coroutines are not gc'ed
end

resolver.max_cache_entries = 1e5

local function bind_libs(self, libs)
	for lib in libs:gmatch'[^%s]+' do
		if lib == 'sock' then
			local sock = require'sock'
			self.tcp = sock.tcp
			self.udp = sock.udp
			self.addr = sock.addr
			--scheduling
			self.newthread = sock.newthread
			self.suspend = sock.suspend
			self.resume = sock.resume
			self.currentthread = sock.currentthread
			self.start = sock.start
			self.clock = sock.clock
		else
			assert(false)
		end
	end
end

local function next_ns(self)
	self.ns_index = (self.ns_index % #self.nst) + 1
	self.ns = self.nst[self.ns_index]
end

function resolver:new(opt)
	local self = glue.update({}, self, opt)

	if self.libs then
		bind_libs(self, self.libs)
	end

	self.nst = {}
	for i,ns in ipairs(self.nameservers) do
		local host, port, tcp_only
		if type(ns) == 'table' then
			host = ns.host or ns[1]
			port = ns.port or ns[2] or 53
			tcp_only = ns.tcp_only
		else
			host, port = ns, 53
		end
		local ai = assert(self.addr(host, port))
		local udp = assert(self.udp())
		assert(udp:connect(ai))
		self.nst[i] = {ai = ai, udp = udp, tcp_only = tcp_only}
		print(ai:tostring())
	end

	self.ns_index = 0
	next_ns(self)

	self.cache = lrucache{max_size = self.max_cache_entries}

	self.queue = {} --{qid->q}
	self.wait_n = 0

	self.scheduler = self.newthread(schedule)

	return self
end

function resolver:lookup(qname, qtype, maxtries)
	qtype = qtype or 'A'
	local key = qtype..' '..qname
	local res = self.cache:get(key)
	if res and time() > res.expires then
		self.cache:remove_val(res)
		res = nil
	end
	if not res then
		local err; res, err = query(self, qname, qtype)
		if sent then

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
				return tcp_query(self, host, port, expires, query, id, opt)
			else
				assert(err == 'id mismatch')
			end
		end
		check(self, false, 'id mismatch')

		if not res then --change host and retry
			return nil, err
			--print('error', err, self.host_ai:tostring(), name)
			--next_host(self)
			--return self:lookup(name, qtype, maxtries)
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
		nameservers = {
			'8.8.8.8',
			{host = '8.8.4.4', port = 53},
		},
		query_timeout = 20,
		tcp_only = true,
	})

	local function lookup(hostname)
		local answers, err = r:lookup(hostname)
		if not answers then
			print('ERROR', err, hostname)
		end
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
