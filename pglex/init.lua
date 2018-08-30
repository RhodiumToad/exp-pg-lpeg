--

local lpeg = require 'lpeg'
local re = require 're'

lpeg.setmaxstack(10)

local P,S,R,V,Cc = lpeg.P, lpeg.S, lpeg.R, lpeg.V, lpeg.Cc

-- Load data tables from separate file for convenience
local sdata = require 'pglex.scandata'
local tokid, kw, idtok = sdata.tokid, sdata.kw, sdata.idtok

local function derivable(t)
	local function derive(t,nt)
		return setmetatable(nt, { __index = t })
	end
	return setmetatable(t, { __call = derive })
end

local function factory(f)
	return setmetatable({},
		{ __index = function(t,i) local p = f(i) rawset(t,i,p) return p end })
end

-- Common definitions

-- These are match-time capture functions - the first result is
-- true/false to indicate match or no match, following results are
-- capture values
local function nonsurrogate(s,p,m)
	m = tonumber(m,16)
	return m < 0xD800 or m > 0xDFFF, utf8.char(m)
end
local function hisurr(s,p,m)
	m = tonumber(m,16)
	return m >= 0xD800 and m <= 0xDBFF, (m & 0x3FF) << 10
end
local function losurr(s,p,m)
	m = tonumber(m,16)
	return m >= 0xDC00 and m <= 0xDFFF, m & 0x3FF
end

-- "hi" and "lo" are already numbers from previous capture funcs
local function do_surrogates(hi,lo)
	return utf8.char(hi + lo + 0x10000)
end

local function unicode_err(s,p,v)
	if type(v)=='number' then
		error("invalid use of unicode "..(v >= 0x400 and "high" or "low").." surrogate")
	else
		error "invalid unicode escape"
	end
end

local common_defs = derivable {

	NL		= S("\r\n"),
	HSPC	= S(" \t\f"),			-- horizontal whitespace

	-- I don't trust the predefined versions because locales.
	-- But we have to assume ASCII.
	DIGIT	= R("09"),
	HEXIT	= R("09","AF","af"),
	OCT		= R("07"),
	ALPHA	= R("AZ","az"),

	HIGH	= R("\128\255"),		-- high-bit-set bytes

	-- Literal strings not patterns so we can use them in substitutions
	-- note that after -> they do not take % prefixes
	SQ		= [[']],
	DQ		= [["]],
	BSLASH	= [[\]],

	-- unicode surrogate and error functions
	nonsurrogate	= nonsurrogate,
	hisurr			= hisurr,
	losurr			= losurr,
	do_surrogates	= do_surrogates,
	unicode_err		= unicode_err,
}

-- Table of unicode escape patterns keyed by escape character

local uepat = factory(function(e)
		local upat = [[
	str				<- {~ (surrogate_pair
						   / (%UECHR -> '') (hexstr => nonsurrogate)
						   / %UECHR (hisurr => unicode_err)
						   / %UECHR (losurr => unicode_err)
						   / %UECHR (%UECHR -> '')
						   / %UECHR ('' => unicode_err)
						   / .)* ~}
	surrogate_pair	<- (%UECHR hisurr %UECHR losurr) -> do_surrogates
	hisurr			<- (hexstr => hisurr)
	losurr			<- (hexstr => losurr)
	hexstr			<- ('+' %HEXIT^6) / %HEXIT^4
]]
		if e:find([=[[%x+'"%s]]=]) then
			error("invalid Unicode escape character")
		end
		return re.compile(upat, common_defs{ UECHR = P(e) })
end)


local function kwlookup(k)
	local id = kw[k:upper()]
	return k:lower(), (id or tokid.IDENT)
end

-- Legal characters for operators in SQL spec
local opsql = S("+-*/<>=")
-- Legal characters for operators in PG but not in SQL spec
local opnsql = S("~!@#^&|`?%")

local defs = common_defs{

	-- Legal characters for operators
	OPCHR	= opnsql + opsql,
	OPSQL	= opsql,
	OPNSQL	= opnsql,

	-- These must be returned as self-tokens if they appear alone
	-- OPSQL must be a subset of SELF, so write it this way
	SELF	= S(",()[].;:%^") + opsql,

	-- P(false) for SCS off, or P(func) where func returns true/false (slower)
	SCS		= P(true),

	-- V"proper_newline" to behave as per spec, V"buggy_newline" to follow PG
	NEWLINE = V"buggy_newline",

	-- pre-resolved constant captures for token IDs

	I_BCONST	= Cc(tokid.BCONST),
	I_XCONST	= Cc(tokid.XCONST),
	I_SCONST	= Cc(tokid.SCONST),
	I_IDENT		= Cc(tokid.IDENT),
	I_Op		= Cc(tokid.Op),
	I_PARAM		= Cc(tokid.PARAM),
	I_FCONST	= Cc(tokid.FCONST),
	I_ICONST	= Cc(tokid.ICONST),

	I_TYPECAST		= Cc(tokid.TYPECAST),
	I_DOT_DOT		= Cc(tokid.DOT_DOT),
	I_COLON_EQUALS	= Cc(tokid.COLON_EQUALS),
	I_EQUALS_GREATER= Cc(tokid.EQUALS_GREATER),
	I_LESS_EQUALS	= Cc(tokid.LESS_EQUALS),
	I_GREATER_EQUALS= Cc(tokid.GREATER_EQUALS),
	I_NOT_EQUALS	= Cc(tokid.NOT_EQUALS),

	C_NIL		= Cc(nil),

	kwlookup	= kwlookup,

	tonumber	= function(s,t)
		local n = tonumber(s)
		if n > 0x7FFFFFFF then
			if t == tokid.ICONST then
				return s, tokid.FCONST
			elseif t == tokid.PARAM then
				return string.format("%d", (n & 0xFFFFFFFF) | (n & 0x80000000 > 0 and ~0xFFFFFFFF or 0)), t
			end
		end
		return string.format("%.20g",n), t
	end,

	idtrunc		= function(s) return s:sub(1,63) end,

	self		= function(c) return c, string.byte(c) end,

	-- simple octal or hex escapes
	do_oct = function(s) return string.char(tonumber(s,8)) end,
	do_hex = function(s) return string.char(tonumber(s,16)) end,

	esc_chr	= { b = "\b", f = "\f", n = "\n", r = "\r", t = "\t" },

	bquote = function(s) return 'b'..s end,
	xquote = function(s) return 'x'..s end,

	-- U&'...' UESCAPE '...'
	do_uesc = function(s,e) return uepat[e or '\\']:match(s) end,

	-- general error functions
	quote_err	= function() error "unterminated quoted string" end,
	dquote_err	= function() error "unterminated delimited identifier" end,
	dq_empty_err= function() error "zero-length delimited identifier" end,
	dolq_err	= function() error "unterminated dollar-quoted string" end,
	comment_err = function() error "unterminated comment" end,
	lex_err		= function() error "unexpected lexical error" end,
}

-- Actual grammar

local pat_def = [=[

-- Entry point:
--	returns the token start pos, token value, token type,
--	and position to resume scan

	token_with_ws	<-	ws_or_comment {} token {}
					 /	ws_or_comment !.
					 /	('' => lex_err)

-- Basic token production:
--	returns token value and type
--
-- decimal should precede integer (lest 12.34 parse as 12 leaving .34),
-- and identifier must be after all the string variants (lest E'foo' be
-- parsed as identifier "E"). self and . must be at the end. Other cases
-- are unambiguous.

	token			<-	bstring					%I_BCONST
					 /	xstring					%I_XCONST
					 /	nstring										-- hack
					 /	estring					%I_SCONST
					 /	stringlit				%I_SCONST
					 /	uquote					%I_SCONST
					 /	(udquote -> idtrunc)	%I_IDENT
					 /	dolq					%I_SCONST
					 /	(dquote -> idtrunc)		%I_IDENT
					 /	special
					 /	operator
					 /	param
					 /	decimal
					 /	integer
					 /	identifier
					 /	(%SELF -> self)		-- not strictly needed
					 /	( . -> self)

-- Comments.
--
-- Simple comments are from -- to end of line (or input)
--
-- Bracketed comments are from /* to */, can contain nested
-- bracketed comments, but not nested simple comments.

	simple_comment	<-	'--' (!%NL .)* (%NL / !.)

	bracket_comment <-	'/*' ( comment_inner / ('' => comment_err) )
	comment_inner	<-	'*/'
					 /	(bracket_comment / .) comment_inner

	comment			<-	simple_comment
					 /	bracket_comment

-- Comments are treated as though they were newlines. (PG gets this
-- pretty badly wrong.)

	proper_newline	<-	%NL / comment
	buggy_newline	<-	%NL / simple_comment
	newline			<-	%NEWLINE	-- chooses which from {defs}

-- General whitespace. <ws_or_comment> is the same as <ws>? when not
-- being bug-compatible.

	ws				<-	(%HSPC / newline)+
	ws_or_comment	<-	(%HSPC / %NL / comment)*

-- Whitespace that includes a newline

	ws_nl			<-	%HSPC* newline ws?

-- Primitive hex/octal sequences for use in string escapes.

	oct3			<-	%OCT %OCT^-2
	hex2			<-	%HEXIT %HEXIT?
	hex4			<-	%HEXIT^4
	hex6			<-	%HEXIT^6
	hex8			<-	%HEXIT^8

-- Basic quoted string (standard-conforming)
--
-- No escapes, but '' becomes ', and the string can be continued
-- across whitespace containing newlines

	quote			<-	%SQ ( {~ quote_inner* ~} %SQ / ('' => quote_err) )
	quote_inner		<-	(%SQ ws_nl %SQ) -> ''
					 /	(%SQ %SQ) -> SQ
					 /	!%SQ .

-- quoted string that does not allow internal '' quotes, for B'' and X''
-- (still allows line continuations)

	bquote			<-	(%SQ -> '') ( bquote_inner* (%SQ -> '') / ('' => quote_err) )
	bquote_inner	<-	(%SQ ws_nl %SQ) -> ''
					 /	!%SQ .

-- Quoted string with \-escapes

	equote			<-	%SQ ( {~ equote_inner* ~} %SQ / ('' => quote_err) )
	equote_inner	<-	(%SQ ws_nl %SQ) -> ''
					 /	(%SQ %SQ) -> SQ
					 /	(%BSLASH eescape) -> 1
					 /	!%SQ .

	eescape			<-	(oct3 -> do_oct)			-- \nnn octal (1-3 digits)
					 /	'x' (hex2 -> do_hex)		-- \xXX hex (1-2 digits)
					 /	esurrogate_pair				-- unicode surrogate pair
					 /	'u' (hex4 => nonsurrogate)	-- accepts only nonsurrogates
					 /	'U' (hex8 => nonsurrogate)	-- ditto
					 /	hisurr => unicode_err		-- bare high surrogate error
					 /	losurr => unicode_err		-- bare low surrogate error
					 /	[Uu] ('' => unicode_err)	-- unmatched \[Uu] must be an error
					 /	([bfnrt] -> esc_chr)		-- known \c escapes
					 /	{.}							-- \c taken as literal c

	esurrogate_pair <-	(hisurr %BSLASH losurr) -> do_surrogates
	hisurr			<-	'u' (hex4 => hisurr) / 'U' (hex8 => hisurr)
	losurr			<-	'u' (hex4 => losurr) / 'U' (hex8 => losurr)

-- B'...' or X'...' string (no escapes)

	bstring			<-	{~ ([Bb] -> 'b') bquote ~}
	xstring			<-	{~ ([Xx] -> 'x') bquote ~}

-- E'...' string with escapes

	estring			<-	[Ee] equote

-- Bare literal that we have to treat differently according to %SCS

	stringlit		<-	%SCS quote
					 /	!%SCS equote

-- Horrible hack; treat N'...' as if NCHAR '...' as two separate
-- tokens. We do this by not consuming the '...' part on the first go.
-- The '...' part is sensitive to standard_conforming_strings, so we
-- have to use <stringlit> for it not <quote>. Return just the
-- keyword, and note the handling of it in <token>.

	nstring			<-	[Nn] &(stringlit) ((''->'NCHAR') -> kwlookup)

-- Double quoted strings for identifiers
--
-- These can't be continued across lines, and aren't allowed to be
-- empty.

	dquote			<-	%DQ ( ((%DQ !%DQ) => dq_empty_err)
							 / {~ dquote_inner* ~} %DQ
							 / ('' => dquote_err) )
	dquote_inner	<-	(%DQ %DQ) -> DQ
					 /	(!%DQ .)

-- Dollar quotes
--
-- The identifier part (between $..$) is like the identifier rule with
-- the exception of not allowing $.

	dq1				<-	%ALPHA / %HIGH / '_'
	dq2				<-	dq1 / %DIGIT
	dq_id			<-	dq1 dq2*

	dolq			<-	dolq_start ( {~ dolq_rest ~} / ('' => dolq_err) )
	dolq_start		<-	('$' {:qid: dq_id? :} '$')
	dolq_rest		<-	('$' =qid '$') -> ''
					 /	. dolq_rest

-- Unicode string U&'...' [UESCAPE '...']
-- Unicode identifier U&"..." [UESCAPE '...']

	uescape			<-	[uU][eE][sS][cC][aA][pP][eE]
	uesc_clause		<-	ws? uescape ws? %SQ { !%SQ . } %SQ

	uquote			<-	[Uu] "&" (quote uesc_clause?) -> do_uesc
	udquote			<-	[Uu] "&" (dquote uesc_clause?) -> do_uesc

-- unquoted identifier which might be a keyword

	ident1			<-	%ALPHA / %HIGH / '_'
	ident2			<-	ident1 / %DIGIT / '$'

	bare_identifier <-	ident1 ident2*

	identifier		<-	( bare_identifier -> kwlookup )

-- Operators are tricky.
--
-- We need to stop building an operator if we see /* because that
-- starts a comment. We also need to avoid taking a + or - on the
-- end of an operator UNLESS there is a non-SQL operator character
-- in play.
--
-- Furthermore, single-character operators that are in %SELF are
-- returned as their own tokens, not Op. So we exclude them from
-- this rule, and let the (later in sequence) alternative in <token>
-- pick them up. (We can't just put a %SELF rule first, unlike in
-- flex, because we don't have a longest-matching rule and
-- multi-character operators that start with a %SELF character must
-- come here.)
--
-- Worse, operators in op_special might be followed by only + or - in
-- which case they must resolve as op_special, while if they're
-- followed by other opchars, including sequences starting with [+-],
-- they must resolve here. e.g.:
--
--  "=>"   - op_special
--  "=>+"  - op_special, +
--  "=>*"  - operator
--  "=>+*" - operator
--
-- So we check in order for:
--  1. op_special followed by ([+-]* nonop) - eat only the op_special
--     and leave the rest
--  2. "!=" operator, which unlike the other op_specials contains a
--     non-sql character - we must match it only if not followed by
--     more operator characters (but we don't check for [+-])
--  3. operator starting with non-sql character and more than one
--     character long - eat it all
--  4. operator starting with sql character and more than one character
--     long - proceed until we find either a non-sql character, in which
--     case switch to matching all operator characters, or we are looking
--     at nothing other than [+-], in which case stop
--  5. single-character operator that's not in %SELF (note that all
--     one-character sql operators are required to be in %SELF)
--

	operator		<-	op_special &(op_sql_end)
					 /	"!=" nonop					%C_NIL	%I_NOT_EQUALS
					 /	{ %OPNSQL op_rest_nonsql }					%I_Op
					 /	nonc { %OPSQL &op_char op_rest_sql }		%I_Op
					 /	!%SELF { %OPCHR } nonop						%I_Op

	-- matches only if we're not looking at a comment start
	nonc			<-	!"/*" !"--"

	-- matches only if we can't continue adding to an operator
	nonop			<-	!(nonc %OPCHR)

	-- matches longest sequence of [+-]+ that does not contain --
	plusminus		<-	([+]+ / [-] ![-])+

	-- matches if we're _not_ looking at a [+-] sequence that ends
	-- the operator
	nonplus			<-	!(plusminus nonop)

	-- matches if we're at the end of an SQL-char operator
	op_sql_end		<-	plusminus? nonop

	-- match one character that extends the operator
	op_char			<-	nonc nonplus %OPCHR

	-- match one sql-legal character that extends the operator
	op_sqlchar		<-	nonc nonplus %OPSQL

	op_rest_sql		<-	op_sqlchar* (&(op_sql_end) / &(%OPNSQL) op_rest_nonsql)
	op_rest_nonsql	<-	(nonc %OPCHR)+

	op_special		<-	"<=" 	%C_NIL	%I_LESS_EQUALS
					 /	">=" 	%C_NIL	%I_GREATER_EQUALS
					 /	"=>" 	%C_NIL	%I_EQUALS_GREATER
					 /	"<>" 	%C_NIL	%I_NOT_EQUALS

-- Special tokens: these are single tokens with their own ids that
-- can't be confused with operators

	special			<-	"::" 	%C_NIL	%I_TYPECAST
					 /	".." 	%C_NIL	%I_DOT_DOT
					 /	":=" 	%C_NIL	%I_COLON_EQUALS

-- Numbers
--
-- Prefer decimal before integer in alternations, otherwise 12.34 would
-- match an integer "12" leaving .34 behind. We don't distinguish
-- decimal and float constants (both are FCONST) but we need to force
-- anything with an exponent to be decimal.
--
-- raw_decimal has to be careful not to match on "1..10", which we want
-- to parse as integer, DOT_DOT, integer.
--
-- decimal has some ugly hacks so that an integer followed by an
-- incomplete exponent matches as decimal rather than integer. There is
-- no justification for doing this except to make it match what the PG
-- lexer does (which is driven by the desire to avoid backtracking in
-- flex).

	raw_integer		<-	%DIGIT+
	raw_decimal		<-	('.' %DIGIT+) / (%DIGIT+ '.' !'.' %DIGIT*)
	exponent		<-	[Ee] [+-]? %DIGIT+

	decimal			<-	{ (raw_decimal exponent?)
						 / (raw_integer exponent)
						 / (raw_integer &([Ee]))
						} %I_FCONST
	integer			<-	( ({ raw_integer } %I_ICONST) -> tonumber )

-- Parameters

	param			<-	'$' ( ({ raw_integer } %I_PARAM) -> tonumber )

]=];

-- Compile.

local pat = re.compile(pat_def, defs)

return pat
