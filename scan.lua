#!/usr/local/bin/lua53

local pat = require "pglex"

local str = io.read("a")
local len = #str
local pos = 1
local tok

tpos,tok,ttype,pos = pat:match(str,1)
while pos do
	--print(tpos,ttype,idtok[ttype],tok)
	tpos,tok,ttype,pos = pat:match(str,pos)
end
