local Logger = require('logger')

local PRIVATE_KEY = 'ME4CAQAwEAYHKoZIzj0CAQYFK4EEACIENzA1AgEBBDDWUs7flwx0sJs0UsqYI2SkTqYF+oFgbp3GQHLLXv2aTa7FNw2e6aHT7TBU/3JPVPY='
local DATA_CHUNK_SIZE = 2048 -- Do not increase to more than 65535! Even going any higher than 2048 will cause power issues
local BOOT_PORT = 1
local DEBUG_LEVEL = Logger.INFO
local SESSION_TIMEOUT = 2000


local util = require('util')

local event = require('event')

local component = require('component')
local dataCard = component.data
local modem = component.modem



local ProgramSource = util.class()

local StringProgramSource = util.class(ProgramSource)

function StringProgramSource:init(program)
	self.program = program
end

function StringProgramSource:getProgram()
	return self.program
end


local FileProgramSource = util.class(ProgramSource)

function FileProgramSource:init(fname)
	self.fname = fname
end

function FileProgramSource:getProgram()
	local hndl = io.open(self.fname, 'r')
	local prgrm = hndl:read('*all')
	hndl:close()
	return prgrm
end


local Client = util.class()

function Client:init(address, key, programSource)
	self.address = address
	self.key = key
	self.programSource = programSource
end

function Client:getAddress()
	return self.address
end

function Client:getKey()
	return self.key
end

function Client:getProgram()
	return self.programSource:getProgram()
end


local State = {}

State.IDLE = 0
State.ASSOCIATED = 1
State.TRUSTED = 2

local MESSAGE = {}
MESSAGE.ASSOCIATE = '0'
MESSAGE.ASSOCIATE_RESPONSE = '1'
MESSAGE.IDENTIFY = '2'
MESSAGE.DATA = '3'
MESSAGE.ACK = '4'

local CryptoHandler = util.class()

function CryptoHandler:init(dataCard)
	self.dataCard = dataCard
	self.clients = {}
end

function CryptoHandler:addClient(client)
	self.clients[client:getAddress()] = client
end

function CryptoHandler:getClient(address)
	return self.clients[address]
end

function CryptoHandler:createSessionCryptoHandler(session)
	return self.SessionCryptoHandler.new(self, session)
end

function CryptoHandler:getDataCard()
	return self.dataCard
end

function CryptoHandler.getIdentifier()
	error('CryptoHandler.getIdentifier() not implemented')
end


local SessionCryptoHandler = util.class()

function SessionCryptoHandler:init(cryptoHandler, session)
	self.cryptoHandler = cryptoHandler
	self.session = session
end

function SessionCryptoHandler:getSymmetricKey(key)
	error('SessionCryptoHandler:getSymmetricKey(key) not implemented')
end

function SessionCryptoHandler:sign(msg)
	error('SessionCryptoHandler:sign(msg) not implemented')
end

function SessionCryptoHandler:checkSign(msg, key, signature)
	error('SessionCryptoHandler:checkSign(msg, key, signature) not implemented')
end



local EccCryptoHandler = util.class(CryptoHandler)

function EccCryptoHandler:init(dataCard, privateKey)
	self:getClass().getSuperClass().init(self, dataCard)
	self.privateKey = dataCard.deserializeKey(dataCard.decode64(privateKey), "ec-private")
end

function EccCryptoHandler:getPrivateKey()
	return self.privateKey
end

function EccCryptoHandler.getIdentifier()
	return '0'
end


EccCryptoHandler.SessionCryptoHandler = util.class(SessionCryptoHandler)

function EccCryptoHandler.SessionCryptoHandler:init(cryptoHandler, session)
	self:getClass().getSuperClass().init(self, cryptoHandler, session)
	self.pubKey = cryptoHandler:getDataCard().deserializeKey(dataCard.decode64(session:getClient():getKey()), "ec-public")
	self.symmetricKey = cryptoHandler:getDataCard().ecdh(self.cryptoHandler:getPrivateKey(), self.pubKey):sub(1, 16)
end

function EccCryptoHandler.SessionCryptoHandler:sign(msg)
	return self.cryptoHandler:getDataCard().ecdsa(msg, self.cryptoHandler:getPrivateKey())
end

function EccCryptoHandler.SessionCryptoHandler:checkSign(msg, signature)
	return self.cryptoHandler:getDataCard().ecdsa(msg, self.pubKey, signature)
end

function EccCryptoHandler.SessionCryptoHandler:getSymmetricKey()
	return self.symmetricKey
end



local SymmetricCryptoHandler = util.class(CryptoHandler)

function SymmetricCryptoHandler.getIdentifier()
	return '1'
end


SymmetricCryptoHandler.SessionCryptoHandler = util.class(SessionCryptoHandler)

function SymmetricCryptoHandler.SessionCryptoHandler:init(cryptoHandler, session)
	self:getClass().getSuperClass().init(self, cryptoHandler, session)
	self.key = cryptoHandler:getDataCard().decode64(session:getClient():getKey())
end

function SymmetricCryptoHandler.SessionCryptoHandler:getSymmetricKey()
	return self.key
end

local ipad = ''
local opad = ''
for i=1,64 do
	ipad = ipad .. '\x36'
	opad = opad .. '\x5c'
end

local function xorn(data, pad)
	assert(#data == #pad, 'Length of data and padding must match')
	res = ''
	for i=1,#data do
		res = res .. string.char(bit32.bxor(data:byte(i), pad:byte(i)))
	end
	return res
end

local function hmacSha256(dataCard, msg, key)
	local h = dataCard.sha256
	if #key < 64 then
		for i=#key,63 do
			key = key .. '\x00'
		end
	elseif #key > 64 then
		key = h(key)
	end
	
	return h(xorn(key, opad) .. h(xorn(key, ipad) .. msg))
end

function SymmetricCryptoHandler.SessionCryptoHandler:sign(msg)
	return hmacSha256(self.cryptoHandler:getDataCard(), msg, self.key)
end

-- TODO: Replace with constant time or(xorn()) 
function SymmetricCryptoHandler.SessionCryptoHandler:checkSign(msg, signature)
	return self:sign(msg) == signature
end



local Session = util.class()

function Session:init(server, client, channel, dataCard, modem)
	self.logger = Logger.new('Session ' .. client:getAddress(), DEBUG_LEVEL)
	self.server = server
	self.sessionCryptoHandler = nil
	self.client = client
	self.channel = channel
	self.challengeTx = nil
	self.challengeRx = nil
	self.state = State.IDLE
	self.dataCard = dataCard
	self.modem = modem
	self.dataOffset = 0
	self.timeout = nil
end

function Session:handle(msgType, msg, localAddress, remoteAddress)
	local success, err = pcall(function()
		if msgType == MESSAGE.ASSOCIATE then
			assert(msg:sub(2, 37) == remoteAddress, 'Invalid remote address') -- check client address
			assert(msg:sub(38, 73) == localAddress, 'Invalid local address') -- check our address

			local txChallenge = msg:sub(74, 105)
			self:setChallengeTx(txChallenge)
			local rxChallenge = self:genChallenge()
			self:setChallengeRx(rxChallenge)
			
			local response = MESSAGE.ASSOCIATE_RESPONSE .. localAddress .. remoteAddress .. rxChallenge
			response = response .. self.sessionCryptoHandler:sign(response .. txChallenge)
			
			self:setState(State.ASSOCIATED)
			
			self:resetTimeout()
			self.modem.send(self:getClient():getAddress(), self.channel, response)
		elseif msgType == MESSAGE.IDENTIFY then
			self.logger:debug('Identify received')
			assert(self:getState() == State.ASSOCIATED, 'Invalid state')

			assert(msg:sub(2, 37) == remoteAddress, 'Invalid remote address') -- check client address
			assert(msg:sub(38, 73) == localAddress, 'Invalid local address') -- check our address
			
			local signature = msg:sub(106, #msg)
			assert(self.sessionCryptoHandler:checkSign(msg:sub(1, 105) .. self:getChallengeRx(), signature), 'Invalid signature')

			self:setState(State.TRUSTED)
			
			self:setChallengeRx(self:genChallenge())
			self:setChallengeTx(msg:sub(74, 105))
			
			self:resetTimeout()
			self:sendSegment(localAddress)
		elseif msgType == MESSAGE.ACK then
			self.logger:debug('ACK received')
			assert(self:getState() == State.TRUSTED, 'Invalid state')

			assert(msg:sub(2, 37) == remoteAddress, 'Invalid remote address') -- check client address
			assert(msg:sub(38, 73) == localAddress, 'Invalid local address') -- check our address
			
			local signature = msg:sub(106, #msg)
			assert(self.sessionCryptoHandler:checkSign(msg:sub(1, 105) .. self:getChallengeRx(), signature), 'Invalid signature')

			self:setChallengeRx(self:genChallenge())
			self:setChallengeTx(msg:sub(74, 105))

			self:resetTimeout()
			self:sendSegment(localAddress)
		else
			error('Invalid message type')
		end
	end)
	if not success then
		self.logger:warn('Failed to handle message: ' .. err)
	end
end

function Session:sendSegment(localAddress)
	local program = self:getClient():getProgram()
	local offset = self:getDataOffset()
	local lastSegment = true
	local lengthSegment = #program - offset
	if lengthSegment > DATA_CHUNK_SIZE then
		lengthSegment = DATA_CHUNK_SIZE
		lastSegment = false
	end
	self:setDataOffset(offset + lengthSegment)
	
	local data = program:sub(offset + 1, offset + lengthSegment)
	local iv = self:genIV()
	local dataEnc = dataCard.encrypt(data, self.sessionCryptoHandler:getSymmetricKey(), iv)
	local dataLen = #dataEnc
	self.logger:debug(dataLen)
	local response = MESSAGE.DATA .. localAddress .. self:getClient():getAddress() .. self:getChallengeRx() .. (lastSegment and '1' or '0')  .. iv .. string.char(bit32.band(bit32.rshift(dataLen, 8), 0xFF)) .. string.char(bit32.band(dataLen, 0xFF)) .. dataEnc
	self.logger:debug(self:getChallengeTx())
	local signature = self.sessionCryptoHandler:sign(response .. self:getChallengeTx())
	response = response .. signature
	self.logger:info(string.format('Sending chunk %d/%d (%d)', math.ceil((offset + lengthSegment) / DATA_CHUNK_SIZE), math.ceil(#program / DATA_CHUNK_SIZE), lengthSegment))
	self.modem.send(self:getClient():getAddress(), self.channel, response)	
	if lastSegment then
		self:kill('transfer finished')
	end
end

function Session:genChallenge()
	return self.dataCard.random(32)
end

function Session:genIV()
	return self.dataCard.random(16)
end

function Session:getState()
	return self.state
end

function Session:setState(state)
	self.state = state
end

function Session:getClient()
	return self.client
end

function Session:getChallengeTx()
	return self.challengeTx
end

function Session:setChallengeTx(challenge)
	self.challengeTx = challenge
end

function Session:getChallengeRx()
	return self.challengeRx
end

function Session:setChallengeRx(challenge)
	self.challengeRx = challenge
end

function Session:getDataOffset()
	return self.dataOffset
end

function Session:setDataOffset(offset)
	self.dataOffset = offset
end

function Session:setSessionCryptoHandler(handler)
	self.sessionCryptoHandler = handler
end

function Session:resetTimeout()
	if self.timeout then
		event.cancel(self.timeout)
	end
	self.timeout = event.timer(SESSION_TIMEOUT / 1000, function()
		self:terminate('timeout')
	end)
end

function Session:kill(reason)
	if self.timeout then
		event.cancel(self.timeout)
	end
	self:terminate(reason)
end

function Session:terminate(reason)
	self.logger:info('Session terminated: ' .. tostring(reason))
	self.timeout = nil
	self.server:removeSession(self)
end


local FSBLServer = util.class()

-----MESSAGES-----
-- 0 - ASSOCIATE: "0" + own address + remote address + 32 byte challenge
-- 1 - ASSOCIATE_RESPONSE: "1" + own address + remote address + 32 byte challenge + ecdsa(privateKey, 1 + own address + remote address + 32 byte challenge + challenge from associate)
-- 2 - IDENTIFY: "2" + own address + remote address + 32 byte challenge + ecdsa(privateKey, "2" + own address + remote address + 32 byte challenge + challenge from associate response)
-- 3 - DATA: "3" + own address + remote address + 32 byte challenge + last_segment + iv + len_data + data + ecdsa(privateKey, 1 + own address + remote address + 32 byte challenge from identify)
-- 4 - ACK: "4" + own address + remote address + 32 byte challenge + ecdsa(privateKey, "2" + own address + remote address + 32 byte challenge + challenge from data/last ack)

function FSBLServer:init(dataCard, modem, channel, txPower)
	self.dataCard = dataCard
	self.modem = modem
	self.channel = channel or 1
	self.txPower = txPower or 100
	self.sessions = {}
	self.cryptoHandlers = {}
	self.logger = Logger.new('FSBL', DEBUG_LEVEL)
end

function FSBLServer:createSession(client, cryptoHandler)
	local session = Session.new(self, client, self.channel, self.dataCard, self.modem)
	session:setSessionCryptoHandler(cryptoHandler:createSessionCryptoHandler(session))
	self.logger:info('Creating session for '..client:getAddress())
	self.sessions[client:getAddress()] = session
	return session
end

function FSBLServer:getSession(address)
	return self.sessions[address]
end

function FSBLServer:removeSession(session)
	self.sessions[session:getClient():getAddress()] = nil
end

function FSBLServer:addCryptoHandler(cryptoHandler)
	self.cryptoHandlers[cryptoHandler.getIdentifier()] = cryptoHandler
end

function FSBLServer:getCryptoHandler(cryptoId)
	return self.cryptoHandlers[cryptoId]
end

function FSBLServer:run()
	self.modem.open(self.channel)
	self.modem.setStrength(self.txPower)
	while true do
		local event, localAddress, remoteAddress, port, dist, msg = event.pull('modem_message')
		if event == 'modem_message' then
			local success, err = pcall(function()
				assert(type(msg) == 'string', 'Invalid message, string expected')
				
				local msgType = msg:sub(1,1)
				if msgType == MESSAGE.ASSOCIATE then
					self.logger:debug('Assoc received')
					
					if self:getSession(remoteAddress) then
						error(string.format("Session for '%s' already exists, ignoring association request", remoteAddress))					
					end
					
					local cryptoId = msg:sub(#msg, #msg)
					local cryptoHandler = self:getCryptoHandler(cryptoId)
					
					if not cryptoHandler then
						error(string.format("No crypto handler for id '%s' found", cryptoId))
					end
					
					local client = cryptoHandler:getClient(remoteAddress)
				
					if not client then
						error(string.format("No client for address '%s' found", remoteAddress))
					end

					self:createSession(client, cryptoHandler):handle(msgType, msg, localAddress, remoteAddress)			
				else
					
					local session = self:getSession(remoteAddress)
					assert(session, "No session")

					session:handle(msgType, msg, localAddress, remoteAddress)
				end
			end)
			if not success then
				self.logger:warn('Failed to handle modem message: ' .. err)
			end
		end
	end
end

local server = FSBLServer.new(dataCard, modem, BOOT_PORT, 100)
local eccCryptoHandler = EccCryptoHandler.new(dataCard, PRIVATE_KEY)
eccCryptoHandler:addClient(Client.new('fca5e547-77ab-4580-bb39-dfdd91ba53bc', 'MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAESg/9Uke2jzGzf0YgySFrALuWoxw4Fvuq9pg9AWxquReeq7U33Cyhv0uIRu/8e2zGy+gPnaH4GYHMTZ7xBkWXX+txtt0f2ajWFkm32v0EDX0VzkP0J0gJKVFTjzRsfKti', 
FileProgramSource.new('woodchuck.lua')))
server:addCryptoHandler(eccCryptoHandler)
server:run()