local c = component
local d = c.proxy(c.list('data')()) -- data card
local m = c.proxy(c.list('modem')()) -- modem
local a = m.address
local r = d.random
local h = d.sha256

local server = '02092c46-1a19-4751-ab21-648aa7adf15f'
local sharedKey = d.decode64('4qInyb1WQ5DDrWvsWpbWww==')

local ipad = ''
local opad = ''
for i=1,64 do
	ipad = ipad .. '\x36'
	opad = opad .. '\x5c'
end

local function x(data, pad)
	assert(#data == #pad, 'Length of data and padding must match')
	res = ''
	for i=1,#data do
		res = res .. string.char(bit32.bxor(data:byte(i), pad:byte(i)))
	end
	return res
end

local function e(msg, key)
	if #key < 64 then
		for i=#key,63 do
			key = key .. '\x00'
		end
	elseif #key > 64 then
		key = h(key)
	end
	
	return h(x(key, opad) .. h(x(key, ipad) .. msg))
end

-----STATES------
-- 0 - ASSOCIATE
-- 1 - ASSOCIATING
-- 2 - ASSOCIATED
-----------------
local state = 0
local cl = ''
local cr = ''
local bf = ''
local smsg = ''
local last = false

-- See fsbl_server.lua for message format

local drone = c.proxy(c.list('drone')())
_G['print'] = drone.setStatusText

m.open(1)
while true do
	if state == 0 then -- try to associate
		print('Associating...')
		cl = r(32)
		m.send(server, 1, '0' .. a .. server .. cl .. '1')
		state = 1
	end
	
	local success = true
	local event, localAddress, remoteAddress, port, dist, msg = computer.pullSignal(5)
	if event == 'modem_message' then
		success, err = pcall(function()
			local msgState = msg:sub(1,1)
			if msgState == '1' then
				print('Authenticating...')
				assert(state == 1, 'Invalid state') -- ensure state
				assert(msg:sub(2, 37) == server, 'Invalid remote address') -- check server address
				assert(msg:sub(38, 73) == a, 'Invalid local address') -- check our address
				assert(e(msg:sub(1, 105) .. cl, sharedKey) == msg:sub(106, #msg), 'Invalid signature')
				-- remote is legit
				cr = msg:sub(74, 105) -- set remote challenge
				state = 2
				
				cl = r(32) -- update local challenge
				smsg = '2' .. a .. server .. cl
				m.send(server, 1,  smsg .. e(smsg .. cr, sharedKey))
			elseif msgState == '3' then
				print('Downloading...')
				assert(state == 2, 'Invalid state')
				assert(msg:sub(2, 37) == server, 'Invalid remote address') -- check server address
				assert(msg:sub(38, 73) == a, 'Invalid local address') -- check our address
				last = msg:sub(106, 106) == '1' -- last segment?
				local dataLen = bit32.lshift(string.byte(msg:sub(123, 123)), 8) + string.byte(msg:sub(124, 124))
				bf = bf .. d.decrypt(msg:sub(125, 125 + dataLen - 1), sharedKey, msg:sub(107, 122)) -- extract data
				assert(e(msg:sub(1, 125 + dataLen - 1) .. cl, sharedKey) == msg:sub(125 + dataLen, #msg), 'Invalid signature') -- check signature
				-- message is ok
				cr = msg:sub(74, 105) -- set remote challenge
				
				cl = r(32)
				smsg = '4'.. a .. server .. cl
				m.send(server, 1,  smsg .. e(smsg .. cr, sharedKey))
				if last then
					load(bf)()
					error('Payload exited')
				end
			else
				error('Invalid state')
			end
		end)
		if not success then
			print(err)
		end
	elseif not (event and success) then -- timeout
		state = 0
		bf = ''
	end
end

