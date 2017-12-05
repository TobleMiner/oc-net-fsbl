local c = component
local d = c.proxy(c.list('data')()) -- data card
local m = c.proxy(c.list('modem')()) -- modem
local a = m.address
local r = d.random
local e = d.ecdsa

local server = '02092c46-1a19-4751-ab21-648aa7adf15f'
local serverKey = d.deserializeKey(d.decode64('MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEPMgMMSOVXt3I9Le+PEawc17T5l0kaSViYV2tjrtG40cLuTLD+SC2PY9gMq/7QpetuyRYrfsc5kGbHWwe2Wk1DOdhtBQlyKHuk+YZVanPd71Rs1tETk6VGc2SMBYhyZeU'), "ec-public")
local key = d.deserializeKey(d.decode64('ME4CAQAwEAYHKoZIzj0CAQYFK4EEACIENzA1AgEBBDDigM/6GNqBVDiud20CAaHncqISsu9NJNqiT14/Y9gMP70sd+hxL/BktwWZpTt9m1g='), "ec-private")
local txPower = 100
local fsblChannel = 1

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
local symKey = ''

-----MESSAGES-----
-- 0 - ASSOCIATE: "0" + own address + remote address + 32 byte challenge + crypt mode
-- 1 - ASSOCIATE_RESPONSE: "1" + own address + remote address + 32 byte challenge + ecdsa(privateKey, 1 + own address + remote address + 32 byte challenge + challenge from associate)
-- 2 - IDENTIFY: "2" + own address + remote address + 32 byte challenge + ecdsa(privateKey, "2" + own address + remote address + 32 byte challenge + challenge from associate response)
-- 3 - DATA: "3" + own address + remote address + 32 byte challenge + last_segment + iv + len_data + data + ecdsa(privateKey, 1 + own address + remote address + 32 byte challenge from identify)
-- 4 - ACK: "4" + own address + remote address + 32 byte challenge + ecdsa(privateKey, "2" + own address + remote address + 32 byte challenge + challenge from data)

----CRYPT MODE----
-- 0 - AES-128 + ECDH + ECDSA
-- 1 - AES-128 + SHA1-HMAC

local drone = c.proxy(c.list('drone')())
_G['print'] = drone.setStatusText

m.setStrength(txPower)
m.open(fsblChannel)
while true do
	if state == 0 then -- try to associate
		print('Associating...')
		cl = r(32)
		m.send(server, 1, '0' .. a .. server .. cl .. '0')
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
				assert(e(msg:sub(1, 105) .. cl, serverKey, msg:sub(106, #msg)), 'Invalid signature')
				-- remote is legit
				cr = msg:sub(74, 105) -- set remote challenge
				state = 2
				symKey = d.ecdh(key, serverKey):sub(1, 16)
				
				cl = r(32) -- update local challenge
				smsg = '2' .. a .. server .. cl
				m.send(server, 1,  smsg .. e(smsg .. cr, key))
			elseif msgState == '3' then
				print('Downloading...')
				assert(state == 2, 'Invalid state')
				assert(msg:sub(2, 37) == server, 'Invalid remote address') -- check server address
				assert(msg:sub(38, 73) == a, 'Invalid local address') -- check our address
				last = msg:sub(106, 106) == '1' -- last segment?
				local dataLen = bit32.lshift(string.byte(msg:sub(123, 123)), 8) + string.byte(msg:sub(124, 124))
				bf = bf .. d.decrypt(msg:sub(125, 125 + dataLen - 1), symKey, msg:sub(107, 122)) -- extract data
				assert(e(msg:sub(1, 125 + dataLen - 1) .. cl, serverKey, msg:sub(125 + dataLen, #msg)), 'Invalid signature') -- check signature
				-- message is ok
				cr = msg:sub(74, 105) -- set remote challenge
				
				cl = r(32)
				smsg = '4'.. a .. server .. cl
				m.send(server, 1,  smsg .. e(smsg .. cr, key))
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

