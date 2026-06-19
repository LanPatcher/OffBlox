--!strict
-- RenameOnJoin.server.lua
-- Place this in ServerScriptService (drop the file in directly, or paste
-- the contents into a new Script).
--
-- Workflow:
--   1. Each external client runs Studio with RobloxStudioPatcher.dll
--      injected. The DLL reads its local username.txt and, the moment
--      Roblox makes its first outbound UDP packet to the server, slips
--      one extra "magic" datagram in front that carries the username.
--   2. The server-side copy of the DLL filters those magic datagrams
--      out of recvfrom (Roblox never sees them) and stashes them in an
--      in-memory IP -> username map.
--   3. Roblox completes its real connection. PlayerAdded fires.
--   4. THIS script asks the DLL's loopback HTTP listener
--      (127.0.0.1:19999) what username belongs to the new player's IP,
--      then sets Player.Name accordingly.
--
-- Requirements:
--   * HttpService.HttpEnabled = true (set via game settings or run
--     `game:GetService("HttpService").HttpEnabled = true` once in the
--     command bar).
--   * Your identity-check patch must already allow server scripts to
--     write Player.Name; you've confirmed that's done.

local HttpService = game:GetService("HttpService")
local Players = game:GetService("Players")

-- The DLL listens on 127.0.0.1 only - loopback, never exposed to the
-- network. The port is hard-coded in username_server.cpp (kPort=19999).
local DLL_HTTP_BASE = "http://127.0.0.1:19999"

-- Roblox doesn't expose an incoming connection's IP directly via the
-- Player object (privacy). For LOCAL test setups where you control all
-- clients, you can pull it from the JoinData or from the GamePort
-- replicator - but the simplest fallback is to ask the DLL for the
-- "most recent" username it received and apply that on PlayerAdded.
-- We try ip-specific lookup first, and fall back to the generic
-- /username endpoint if we can't determine the IP.

local function tryFetchByIp(ip: string?): string?
	if not ip or ip == "" then
		return nil
	end
	local url = ("%s/lookup?ip=%s"):format(DLL_HTTP_BASE, ip)
	local ok, body = pcall(function()
		return HttpService:GetAsync(url, true)
	end)
	if not ok or type(body) ~= "string" or body == "" then
		return nil
	end
	return (body:gsub("[\r\n%s]+$", ""):gsub("^[\r\n%s]+", ""))
end

local function tryFetchSelfUsername(): string?
	local ok, body = pcall(function()
		return HttpService:GetAsync(DLL_HTTP_BASE .. "/username", true)
	end)
	if not ok or type(body) ~= "string" or body == "" then
		return nil
	end
	return (body:gsub("[\r\n%s]+$", ""):gsub("^[\r\n%s]+", ""))
end

-- If your platform exposes the client's IP somewhere reachable, plug it
-- in here and return it. Otherwise leave returning nil and the script
-- will fall back to the self-username endpoint.
local function resolveClientIp(player: Player): string?
	-- Common spot in some Studio versions: player:GetJoinData() may
	-- include a server-only "SourceGameId" but rarely the IP. If you
	-- have a custom side-channel (e.g. a NetworkClient field your
	-- patched binary exposes), wire it in here.
	return nil
end

local function renamePlayer(player: Player)
	-- Don't rename players the server already named via auth (e.g. real
	-- Roblox accounts in a published game).
	if player.UserId > 0 and player.Name ~= "" and not player.Name:match("^Player%d+$") then
		return
	end

	local ip = resolveClientIp(player)
	local desired = tryFetchByIp(ip) or tryFetchSelfUsername()
	if not desired or desired == "" or desired == player.Name then
		return
	end

	local ok, err = pcall(function()
		player.Name = desired
	end)
	if not ok then
		warn(("[RenameOnJoin] failed to rename %s -> %s: %s"):format(
			player.Name, desired, tostring(err)))
	else
		print(("[RenameOnJoin] %s -> %s"):format(player.Name, desired))
	end
end

Players.PlayerAdded:Connect(renamePlayer)

-- Catch players already in the game when this script first runs.
for _, p in ipairs(Players:GetPlayers()) do
	task.spawn(renamePlayer, p)
end
