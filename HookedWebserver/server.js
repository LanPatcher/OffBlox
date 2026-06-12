/**
 * HookedWebserver — Adaptive Self-Hosting Roblox Backend
 * ========================================================
 * Multiple instances of this script (or a packaged EXE) can run at the same
 * time.  The FIRST instance that successfully binds the HTTP port becomes the
 * active Server.  Every other instance becomes a Watchdog — it polls the
 * server's /ping endpoint and, the moment the server goes silent, immediately
 * races to take over the port.  This gives you:
 *
 *   • Zero-config multi-instance support  (run as many copies as you like)
 *   • Automatic failover / self-restart   (if the server process crashes,
 *                                          the next watchdog wins the port)
 *   • No external dependencies            (pure Node.js built-ins only)
 *
 * Usage:
 *   node server.js [--port 80] [--fallback 8080]
 *   Start.bat
 */

'use strict';

const http   = require('http');
const https  = require('https');
const fs     = require('fs');
const path   = require('path');
const crypto = require('crypto');
const url    = require('url');

// ─────────────────────────────────────────────────────────────────────────────
// Config
// ─────────────────────────────────────────────────────────────────────────────

const CFG_PATH = path.join(__dirname, 'config.json');
let CFG = {};
try { CFG = JSON.parse(fs.readFileSync(CFG_PATH, 'utf8')); } catch (_) {}

// CLI overrides: --port 80  --fallback 8080
const argv = process.argv.slice(2);
function argVal(flag) {
  const i = argv.indexOf(flag);
  return i !== -1 ? argv[i + 1] : null;
}

const PORT          = parseInt(argVal('--port')     || CFG.port          || 80,   10);
const FALLBACK_PORT = parseInt(argVal('--fallback') || CFG.fallbackPort  || 8080, 10);
const HOST          = CFG.host          || '0.0.0.0';
const WD_INTERVAL   = CFG.watchdogIntervalMs || 5000;
const WD_RETRIES    = CFG.watchdogRetries    || 3;
const LOG_REQS      = CFG.logRequests !== false;
const DATA_DIR      = path.resolve(__dirname, CFG.dataDir || 'data');
const WWW_DIR       = path.resolve(__dirname, CFG.wwwDir  || 'www');
const USER          = CFG.hardcodedUser || {};
const STUDIO_VER    = CFG.studioVersion || {};

const INSTANCE_ID   = crypto.randomBytes(4).toString('hex').toUpperCase();

// ─────────────────────────────────────────────────────────────────────────────
// Logging
// ─────────────────────────────────────────────────────────────────────────────

function ts() { return new Date().toISOString(); }
function log(tag, ...args) { console.log(`[${ts()}] [${INSTANCE_ID}] [${tag}]`, ...args); }

// ─────────────────────────────────────────────────────────────────────────────
// MIME types (for static file serving)
// ─────────────────────────────────────────────────────────────────────────────

const MIME = {
  '.html': 'text/html', '.htm': 'text/html',
  '.css':  'text/css',
  '.js':   'application/javascript',
  '.json': 'application/json',
  '.png':  'image/png', '.jpg': 'image/jpeg', '.gif': 'image/gif',
  '.ico':  'image/x-icon',
  '.svg':  'image/svg+xml',
  '.txt':  'text/plain',
  '.pem':  'text/plain',
  '.lua':  'text/plain',
  '.xml':  'text/xml',
  '.ashx': 'text/plain',
};

// ─────────────────────────────────────────────────────────────────────────────
// Utility helpers
// ─────────────────────────────────────────────────────────────────────────────

function parseBody(req) {
  return new Promise((resolve) => {
    let raw = '';
    req.on('data', c => { raw += c; });
    req.on('end', () => {
      let json = null;
      try { json = JSON.parse(raw); } catch (_) {}
      resolve({ raw, json });
    });
  });
}

function parseQuery(reqUrl) {
  return Object.fromEntries(new url.URL(reqUrl, 'http://x').searchParams);
}

function send(res, status, body, ct) {
  const b = typeof body === 'string' ? body : JSON.stringify(body);
  ct = ct || (typeof body === 'object' ? 'application/json' : 'text/plain');
  res.writeHead(status, {
    'Content-Type': ct,
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Authorization, Content-Type, Roblox-Place-Id, Roblox-Universe-Id, content-md5, x-api-key, roblox-entry-attributes, roblox-entry-userids',
    'Access-Control-Allow-Methods': 'GET, POST, DELETE, PUT, PATCH, OPTIONS',
    'Access-Control-Expose-Headers': 'content-md5, roblox-entry-version, roblox-entry-created-time, roblox-entry-version-created-time, roblox-entry-attributes, roblox-entry-userids',
  });
  res.end(b);
}

function sendJson(res, body, status) { send(res, status || 200, body); }
function sendText(res, body, status) { send(res, status || 200, body, 'text/plain'); }
function sendErr(res, status, code, msg) {
  sendJson(res, { errors: [{ code, message: msg }] }, status);
}

function b64url(s) {
  return Buffer.from(s).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function makeFakeJwt(extra) {
  const now = Math.floor(Date.now() / 1000);
  const iat = now - 5;
  const exp = iat + 1800;
  const hdr = b64url(JSON.stringify({ alg: 'ES256', typ: 'JWT', kid: 'hardcoded-key-1' }));
  const pay = b64url(JSON.stringify(Object.assign({
    sub: USER.sub || '701953216',
    type: 'User',
    iss: 'http://localhost/oauth/',
    aud: 'roblox_studio_client',
    exp, iat,
    nonce: 'id-roblox',
    name: USER.name,
    nickname: USER.nickname,
    preferred_username: USER.preferred_username,
    created_at: USER.created_at,
    profile: USER.profile,
    picture: USER.picture,
    email: USER.email,
    email_verified: USER.email_verified,
    verified: USER.verified,
    age_bracket: USER.age_bracket,
    premium: USER.premium,
    roles: USER.roles,
    internal_user: USER.internal_user,
    attributes: USER.attributes,
    banned: false,
  }, extra || {})));
  const sig = b64url('hardcoded_signature');
  return `${hdr}.${pay}.${sig}`;
}

// ─────────────────────────────────────────────────────────────────────────────
// DataStore storage helpers
// ─────────────────────────────────────────────────────────────────────────────

function dsDir(universeId, scope, datastore) {
  return path.join(DATA_DIR, 'datastores', String(universeId), encodeURIComponent(scope), encodeURIComponent(datastore));
}

function dsFile(dir, key) {
  return path.join(dir, encodeURIComponent(key) + '.json');
}

function dsRead(file) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch (_) { return null; }
}

function dsWrite(file, data) {
  const dir = path.dirname(file);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(file, JSON.stringify(data));
}

// ─────────────────────────────────────────────────────────────────────────────
// Static file serving (fallback for assets, images, pem keys etc.)
// ─────────────────────────────────────────────────────────────────────────────

function serveStatic(req, res, pathname) {
  // strip query, decode
  pathname = decodeURIComponent(pathname.split('?')[0]);
  const candidates = [
    path.join(WWW_DIR, pathname),
    path.join(WWW_DIR, pathname, 'index.php'),   // will be ignored (no PHP)
  ];
  for (const fp of candidates) {
    if (fs.existsSync(fp) && fs.statSync(fp).isFile()) {
      // skip .php files — handled by JS routes
      if (fp.endsWith('.php')) break;
      const ext = path.extname(fp).toLowerCase();
      const ct  = MIME[ext] || 'application/octet-stream';
      res.writeHead(200, { 'Content-Type': ct, 'Access-Control-Allow-Origin': '*' });
      fs.createReadStream(fp).pipe(res);
      return true;
    }
  }
  return false;
}

// ─────────────────────────────────────────────────────────────────────────────
// Route handlers
// ─────────────────────────────────────────────────────────────────────────────

async function routePing(req, res) {
  sendText(res, 'OK');
}

// GET /
async function routeRoot(req, res) {
  send(res, 200, '<center>Hello! Stop asking why, please!</center>', 'text/html');
}

// GET|POST /datastore/  (simple legacy action=get/set/remove/increment/sorted)
async function routeDatastore(req, res, qs, body) {
  const params = Object.assign({}, qs, body.json || {});
  const action     = params.action    || '';
  const universeId = '1';

  switch (action) {
    case 'set': {
      if (!params.key || !params.name) return sendErr(res, 400, 'MissingParam', 'key and name required');
      const dir  = dsDir(universeId, params.scope || 'global', params.name);
      const file = dsFile(dir, params.key);
      const old  = dsRead(file) || {};
      const ver  = (old.version || 0) + 1;
      dsWrite(file, { value: params.value !== undefined ? params.value : null, version: ver, updatedAt: new Date().toISOString(), createdAt: old.createdAt || new Date().toISOString() });
      return sendJson(res, { data: { Value: params.value }, version: ver });
    }
    case 'get': {
      if (!params.key || !params.name) return sendErr(res, 400, 'MissingParam', 'key and name required');
      const file = dsFile(dsDir(universeId, params.scope || 'global', params.name), params.key);
      const rec  = dsRead(file);
      return sendJson(res, rec ? { data: { Value: rec.value }, version: rec.version } : { data: null });
    }
    case 'remove': {
      if (!params.key || !params.name) return sendErr(res, 400, 'MissingParam', 'key and name required');
      const file = dsFile(dsDir(universeId, params.scope || 'global', params.name), params.key);
      if (fs.existsSync(file)) fs.unlinkSync(file);
      return sendJson(res, { data: null });
    }
    case 'increment': {
      if (!params.key || !params.name) return sendErr(res, 400, 'MissingParam', 'key and name required');
      const dir   = dsDir(universeId, params.scope || 'global', params.name);
      const file  = dsFile(dir, params.key);
      const old   = dsRead(file) || {};
      const delta = parseFloat(params.value) || 1;
      const newVal = (parseFloat(old.value) || 0) + delta;
      const ver   = (old.version || 0) + 1;
      dsWrite(file, { value: newVal, version: ver, updatedAt: new Date().toISOString(), createdAt: old.createdAt || new Date().toISOString() });
      return sendJson(res, { data: { Value: newVal }, version: ver });
    }
    case 'sorted': {
      if (!qs.name) return sendErr(res, 400, 'MissingParam', 'name required');
      const dir      = dsDir(universeId, qs.scope || 'global', qs.name);
      const pageSize = parseInt(qs.pageSize) || 50;
      const asc      = qs.ascending !== 'false';
      const minV     = qs.inclusiveMinValue != null ? parseFloat(qs.inclusiveMinValue) : null;
      const maxV     = qs.inclusiveMaxValue != null ? parseFloat(qs.inclusiveMaxValue) : null;
      let entries    = [];
      if (fs.existsSync(dir)) {
        for (const f of fs.readdirSync(dir).filter(f => f.endsWith('.json'))) {
          const r = dsRead(path.join(dir, f));
          if (!r) continue;
          const v = parseFloat(r.value);
          if (minV !== null && v < minV) continue;
          if (maxV !== null && v > maxV) continue;
          entries.push({ key: decodeURIComponent(f.replace('.json', '')), value: v });
        }
      }
      entries.sort((a, b) => asc ? a.value - b.value : b.value - a.value);
      return sendJson(res, { data: entries.slice(0, pageSize), exclusiveStartKey: null });
    }
    default:
      return sendErr(res, 400, 'BadAction', `Unknown action: ${action}`);
  }
}

// Open Cloud DataStore API — /datastores/v1/universes/{id}/standard-datastores/...
async function routeOpenCloudDS(req, res, parts, qs, body, method) {
  // parts[0] = 'datastores', parts[1] = 'v1', parts[2] = 'universes',
  // parts[3] = universeId, parts[4] = 'standard-datastores', ...
  const universeId = parts[3] || '1';
  const rest       = parts.slice(5);  // after 'standard-datastores'

  if (method === 'OPTIONS') return send(res, 204, '');

  // list datastores
  if (rest.length === 0 || (rest.length === 1 && rest[0] === '')) {
    const base = path.join(DATA_DIR, 'datastores', universeId);
    let names  = [];
    if (fs.existsSync(base)) {
      for (const scope of fs.readdirSync(base)) {
        const sdir = path.join(base, scope);
        if (fs.statSync(sdir).isDirectory()) {
          for (const ds of fs.readdirSync(sdir)) names.push(decodeURIComponent(ds));
        }
      }
    }
    return sendJson(res, { datastores: names.map(n => ({ name: n })), nextPageCursor: null });
  }

  // /datastore/entries[/entry[/increment|versions[/version]]]
  if (rest[0] === 'datastore') {
    const dsName = qs.datastoreName || qs.dataStoreName || '';
    const scope  = qs.scope || 'global';
    const dir    = dsDir(universeId, scope, dsName);

    if (rest[1] === 'entries') {
      if (rest[2] === 'entry') {
        const key  = qs.entryKey || qs.key || '';
        const file = dsFile(dir, key);

        if (rest[3] === 'increment') {
          // POST increment
          const delta = parseFloat(qs.incrementBy || (body.json && body.json.incrementBy) || 1);
          const old   = dsRead(file) || {};
          const newVal = (parseFloat(old.value) || 0) + delta;
          const ver   = (old.version || 0) + 1;
          dsWrite(file, { value: newVal, version: ver, updatedAt: new Date().toISOString(), createdAt: old.createdAt || new Date().toISOString() });
          res.setHeader('roblox-entry-version', String(ver));
          res.setHeader('Access-Control-Allow-Origin', '*');
          res.setHeader('Access-Control-Expose-Headers', 'roblox-entry-version');
          return sendJson(res, newVal);
        }

        if (rest[3] === 'versions') {
          const rec = dsRead(file);
          if (!rec) return sendJson(res, { versions: [], nextPageCursor: null });
          return sendJson(res, { versions: [{ version: String(rec.version), createdTime: rec.updatedAt, objectCreatedTime: rec.createdAt, contentLength: JSON.stringify(rec.value).length, deleted: false }], nextPageCursor: null });
        }

        if (method === 'GET') {
          const rec = dsRead(file);
          if (!rec) return send(res, 404, JSON.stringify({ errors: [{ code: 'EntryNotFound', message: 'Entry not found' }] }), 'application/json');
          res.writeHead(200, { 'Content-Type': 'application/json', 'roblox-entry-version': String(rec.version), 'roblox-entry-created-time': rec.createdAt, 'roblox-entry-version-created-time': rec.updatedAt, 'Access-Control-Allow-Origin': '*', 'Access-Control-Expose-Headers': 'roblox-entry-version,roblox-entry-created-time,roblox-entry-version-created-time' });
          res.end(JSON.stringify(rec.value));
          return;
        }

        if (method === 'POST' || method === 'PATCH') {
          const value = body.json !== null ? body.json : body.raw;
          const old   = dsRead(file) || {};
          const ver   = (old.version || 0) + 1;
          dsWrite(file, { value, version: ver, updatedAt: new Date().toISOString(), createdAt: old.createdAt || new Date().toISOString() });
          res.writeHead(200, { 'Content-Type': 'application/json', 'roblox-entry-version': String(ver), 'Access-Control-Allow-Origin': '*', 'Access-Control-Expose-Headers': 'roblox-entry-version' });
          res.end(JSON.stringify({ version: String(ver) }));
          return;
        }

        if (method === 'DELETE') {
          if (fs.existsSync(file)) fs.unlinkSync(file);
          return send(res, 204, '');
        }

        return sendErr(res, 405, 'MethodNotAllowed', 'Method not allowed');
      }

      // list entries
      let entries = [];
      if (fs.existsSync(dir)) {
        for (const f of fs.readdirSync(dir).filter(f => f.endsWith('.json'))) {
          entries.push({ key: decodeURIComponent(f.replace('.json', '')), scope });
        }
      }
      return sendJson(res, { keys: entries, nextPageCursor: null });
    }
  }

  return sendErr(res, 404, 'NotFound', 'Path not found');
}

// GET /fflags/  (huge JSON blob — return the full hardcoded set)
const FFLAGS_JSON = JSON.stringify({
  "FFlagCoreScriptShowVisibleAgeV2":"True","FFlagCoreScriptShowVisibleAge":"True",
  "DFFlagFindFirstChildOfClassEnabled":"True","FFlagStudioCSGAssets":"True",
  "FFlagCSGLoadBlocking":"False","FFlagCSGPhysicsLevelOfDetailEnabled":"True",
  "FFlagFormFactorDeprecated":"False","FFlagFontSmoothScalling":"True",
  "FFlagAlternateFontKerning":"True","FFlagFontSourceSans":"True",
  "FFlagRenderNewFonts":"True","FFlagDMFeatherweightEnabled":"True",
  "FFlagRenderFeatherweightEnabled":"True","FFlagRenderFeatherweightUseGeometryGenerator":"True",
  "FFlagScaleExplosionLifetime":"True","FFlagEnableNonleathalExplosions":"True",
  "DFFlagHttpCurlHandle301":"True","FFlagSearchToolboxByDataModelSearchString":"True",
  "FFlagClientABTestingEnabled":"False","FFlagStudioSmoothTerrainForNewPlaces":"True",
  "FFlagUsePGSSolver":"True","FFlagSimplifyKeyboardInputPath":"False",
  "FFlagNewInGameDevConsole":"True","FFlagTextFieldUTF8":"True",
  "FFlagTypesettersReleaseResources":"True","FFlagLuaBasedBubbleChat":"True",
  "FFlagUseCanManageApiToDetermineConsoleAccess":"False","FFlagConsoleCodeExecutionEnabled":"True",
  "DFFlagCustomEmitterInstanceEnabled":"True","FFlagCustomEmitterRenderEnabled":"True",
  "FFlagCustomEmitterLuaTypesEnabled":"True","FFlagStudioInSyncWebKitAuthentication":"False",
  "FFlagGlowEnabled":"True","FFlagUseNewAppBridgeInputWindows":"False",
  "DFFlagUseNewFullscreenLogic":"True","FFlagRenderMaterialsOnMobile":"True",
  "FFlagMaterialPropertiesEnabled":"True","FFlagSurfaceLightEnabled":"True",
  "FFlagStudioPropertyErrorOutput":"True","DFFlagUseR15Character":"True",
  "DFFlagEnableHipHeight":"True","DFFlagUseStarterPlayerCharacter":"True",
  "DFFlagFilteringEnabledDialogFix":"True","FFlagCSGMeshColorToolsEnabled":"True",
  "FFlagStudioUseSrcAssets":"True","FFlagStudioUseSrcAssetsForPlugins":"True",
  "FFlagEnableRomarkStudioOperations":"True","FFlagStudioHandleErrors":"True",
  "FFlagStudioProposeNewCameraNavigation":"True",
  "FFlagDebugDisableTelemetryV2":"True"
});

async function routeFflags(req, res) {
  send(res, 200, FFLAGS_JSON, 'application/json');
}

// GET /currency/balance/
async function routeCurrencyBalance(req, res) {
  sendJson(res, { robux: 9999999999 });
}

// GET /game/placelauncher.ashx
async function routePlaceLauncher(req, res, qs) {
  const ip   = qs.ip         || '127.0.0.1';
  const port = qs.port       || '53640';
  const user = qs.user       || '';
  const id   = qs.id         || '533';
  const mem  = qs.membership || 'None';
  const app  = qs.app        || '';

  // also persist to data/SavedData for legacy reads
  const savedDir = path.join(DATA_DIR, 'SavedData');
  if (!fs.existsSync(savedDir)) fs.mkdirSync(savedDir, { recursive: true });
  if (user) {
    fs.writeFileSync(path.join(savedDir, 'user.ini'),       user);
    fs.writeFileSync(path.join(savedDir, 'id.ini'),         id);
    fs.writeFileSync(path.join(savedDir, 'membership.ini'), mem);
    fs.writeFileSync(path.join(savedDir, 'app.ini'),        app);
    fs.writeFileSync(path.join(savedDir, 'ip.ini'),         ip);
    fs.writeFileSync(path.join(savedDir, 'port.ini'),       port);
  }

  const joinUrl = `http://localhost/game/Join.ashx?placeid=1818&ip=${ip}&port=${port}&user=${user}&id=${id}&membership=${mem}&app=${app}`;
  sendJson(res, { jobId: 'Test', status: 2, joinScriptUrl: joinUrl, authenticationUrl: 'http://localhost/Login/Negotiate.ashx', authenticationTicket: '1', message: null });
}

// GET /game/load-place-info/
async function routeLoadPlaceInfo(req, res) {
  sendJson(res, { CreatorId: 1, CreatorType: 'User', PlaceVersion: 1, GameId: 123456, IsRobloxPlace: true });
}

// GET /game/Join.ashx  — builds and signs the join script
async function routeJoinAshx(req, res, qs) {
  const user   = qs.user       || 'player';
  const ip     = qs.ip         || '127.0.0.1';
  const port   = qs.port       || '53640';
  const id     = qs.id         || '533';
  const app    = qs.app        || 'http://localhost/v1.0/avatar-fetch?v1=true';
  const mem    = qs.membership || 'None';

  // try to load the static joinguest.txt template from www, fall back to inline
  const tplPath = path.join(WWW_DIR, 'game', 'Join.ashx', 'joinguest.txt');
  let script;
  if (fs.existsSync(tplPath)) {
    script = fs.readFileSync(tplPath, 'utf8')
      .replace(/%user%/g,       user)
      .replace(/%ip%/g,         ip)
      .replace(/%port%/g,       port)
      .replace(/%id%/g,         id)
      .replace(/%app%/g,        app)
      .replace(/%membership%/g, mem);
  } else {
    script = buildJoinScript({ user, ip, port, id, app, mem });
  }

  const signed = signScript(script);
  sendText(res, signed);
}

function buildJoinScript({ user, ip, port, id, app, mem }) {
  return `nc = game:GetService("NetworkClient")
nc:PlayerConnect(${id}, "${ip}", ${port}, 10)
game:SetMessage("Connecting to server...")
plr = game.Players.LocalPlayer
plr.Name = "${user}"
plr.CharacterAppearance = "${app}"
pcall(function() plr:SetMembershipType(Enum.MembershipType.TurboBuildersClub) end)
pcall(function() plr:SetAccountAge(365) end)
game:GetService("Visit"):SetUploadUrl("")
game.Players:SetChatStyle("ClassicAndBubble")
nc.ConnectionAccepted:connect(function(peer, repl)
    game:SetMessageBrickCount()
    local mkr = repl:SendMarker()
    mkr.Received:connect(function()
        game:SetMessage("Requesting Character...")
        repl:RequestCharacter()
        game:SetMessage("Waiting for character...")
        chngd = plr.Changed:connect(function(prop)
            if prop == "Character" then chngd:disconnect() end
        end)
        game:ClearMessage()
    end)
    repl.Disconnection:connect(function()
        game:SetMessage("This game has shut down")
    end)
end)
nc.ConnectionFailed:connect(function() game:SetMessage("Failed to connect to the game") end)
nc.ConnectionRejected:connect(function() game:SetMessage("Network protocol mismatch") end)`;
}

// sign() — RSA-SHA1 with the local PrivateKey.pem if available, otherwise stub
function signScript(script) {
  const keyPath = path.join(WWW_DIR, 'game', 'Join.ashx', 'PrivateKey.pem');
  if (!fs.existsSync(keyPath)) {
    // stub signature
    return `--rbxsig%AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=% ${script}`;
  }
  const key  = fs.readFileSync(keyPath);
  const sign = crypto.createSign('SHA1');
  sign.update(script);
  const sig = sign.sign(key, 'base64');
  return `--rbxsig%${sig}% ${script}`;
}

// GET /game/global.ashx/
async function routeGlobalAshx(req, res) {
  const script = `printidentity()
wait(15)
pcall(function() game:GetService("InsertService"):SetFreeModelUrl("http://www.roblox.com/Game/Tools/InsertAsset.ashx?type=fm&q=%s&pg=%d&rs=%d") end)
pcall(function() game:GetService("InsertService"):SetFreeDecalUrl("http://www.roblox.com/Game/Tools/InsertAsset.ashx?type=fd&q=%s&pg=%d&rs=%d") end)
game:GetService("ScriptInformationProvider"):SetAssetUrl("http://localhost/asset/")
game:GetService("InsertService"):SetBaseSetsUrl("http://localhost/Game/Tools/InsertAsset.ashx?nsets=10&type=base")
game:GetService("InsertService"):SetUserSetsUrl("http://localhost/Game/Tools/InsertAsset.ashx?nsets=20&type=user&userid=%d&t=2")
game:GetService("InsertService"):SetCollectionUrl("http://localhost/Game/Tools/InsertAsset.ashx?sid=%d")
game:GetService("InsertService"):SetAssetUrl("http://localhost/asset/?id=%d")
game:GetService("InsertService"):SetAssetVersionUrl("http://localhost/Asset/?assetversionid=%d")
game:GetService("InsertService"):SetTrustLevel(0)
pcall(function() game:GetService("SocialService"):SetFriendUrl("http://localhost/Game/LuaWebService/HandleSocialRequest.ashx?method=IsFriendsWith&playerid=%d&userid=%d") end)
pcall(function() game:GetService("SocialService"):SetBestFriendUrl("http://localhost/Game/LuaWebService/HandleSocialRequest.ashx?method=IsBestFriendsWith&playerid=%d&userid=%d") end)
pcall(function() game:GetService("SocialService"):SetGroupUrl("http://localhost/Game/LuaWebService/HandleSocialRequest.ashx?method=IsInGroup&playerid=%d&groupid=%d") end)
pcall(function() game:GetService("SocialService"):SetGroupRankUrl("http://localhost/Game/LuaWebService/HandleSocialRequest.ashx?method=GetGroupRank&playerid=%d&groupid=%d") end)
pcall(function() game:GetService("SocialService"):SetGroupRoleUrl("http://localhost/Game/LuaWebService/HandleSocialRequest.ashx?method=GetGroupRole&playerid=%d&groupid=%d") end)
local ScriptContext = game:GetService("ScriptContext")`;
  sendText(res, signScript(script));
}

// GET /game/index.php | /game/
async function routeGameIndex(req, res, qs) {
  sendJson(res, { success: true });
}

// GET /game/LuaWebService/HandleSocialRequest.ashx
async function routeSocialRequest(req, res, qs) {
  const method = qs.method || '';
  if (method === 'IsFriendsWith' || method === 'IsBestFriendsWith') {
    sendText(res, 'true');
  } else if (method === 'IsInGroup') {
    sendText(res, 'false');
  } else if (method === 'GetGroupRank') {
    sendText(res, '0');
  } else if (method === 'GetGroupRole') {
    sendText(res, 'Guest');
  } else {
    sendText(res, 'false');
  }
}

// OAuth routes
async function routeOAuthDiscovery(req, res) {
  sendJson(res, {
    issuer:                               'http://localhost/oauth/',
    authorization_endpoint:               'http://localhost/oauth/v1/authorize',
    token_endpoint:                       'http://localhost/oauth/v1/token',
    introspection_endpoint:               'http://localhost/oauth/v1/token/introspect',
    revocation_endpoint:                  'http://localhost/oauth/v1/token/revoke',
    resources_endpoint:                   'http://localhost/oauth/v1/token/resources',
    userinfo_endpoint:                    'http://localhost/oauth/v1/userinfo',
    jwks_uri:                             'http://localhost/oauth/v1/certs',
    registration_endpoint:                'https://create.roblox.com/dashboard/credentials',
    service_documentation:                'https://create.roblox.com/docs/reference/cloud',
    scopes_supported:                     ['openid','profile','email','verification','credentials','age','premium','roles','attributes'],
    response_types_supported:             ['none','code'],
    subject_types_supported:              ['public'],
    id_token_signing_alg_values_supported:['ES256'],
    claims_supported:                     ['sub','type','iss','aud','exp','iat','nonce','name','nickname','preferred_username','created_at','profile','picture','email','email_verified','verified','age_bracket','premium','roles','internal_user','attributes'],
    token_endpoint_auth_methods_supported:['client_secret_post','client_secret_basic'],
  });
}

async function routeOAuthAuthorize(req, res, qs) {
  const redirectUri = qs.redirect_uri || '';
  const state       = qs.state        || '';
  const code        = 'hardcoded_auth_code_2023';
  if (redirectUri) {
    const sep      = redirectUri.includes('?') ? '&' : '?';
    let location   = `${redirectUri}${sep}code=${encodeURIComponent(code)}`;
    if (state) location += `&state=${encodeURIComponent(state)}`;
    res.writeHead(302, { Location: location, 'Access-Control-Allow-Origin': '*' });
    res.end();
    return;
  }
  sendJson(res, { code, state });
}

async function routeOAuthToken(req, res, body) {
  const clientId = (body.json && body.json.client_id) || 'roblox_studio_client';
  sendJson(res, {
    access_token:  'hardcoded_access_token',
    token_type:    'Bearer',
    expires_in:    1800,
    refresh_token: 'hardcoded_refresh_token',
    scope:         'openid credentials profile age roles premium',
    id_token:      makeFakeJwt({ aud: clientId }),
  });
}

async function routeOAuthUserInfo(req, res) {
  const now = Math.floor(Date.now() / 1000);
  sendJson(res, Object.assign({}, USER, {
    sub: USER.sub || '701953216',
    type: 'User',
    iss: 'http://localhost/oauth/',
    aud: 'roblox_studio_client',
    exp: now + 3600,
    iat: now,
    nonce: 'hardcoded_nonce',
  }));
}

async function routeOAuthIntrospect(req, res) {
  const now = Math.floor(Date.now() / 1000);
  sendJson(res, { active: true, scope: 'openid profile email verification credentials age premium roles attributes', client_id: 'roblox_studio_client', token_type: 'Bearer', exp: now + 3600, iat: now, sub: USER.sub || '701953216', iss: 'http://localhost/oauth/' });
}

async function routeOAuthCerts(req, res) {
  sendJson(res, { keys: [{ kty: 'EC', crv: 'P-256', use: 'sig', alg: 'ES256', kid: 'hardcoded-key-1', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', y: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' }] });
}

async function routeOAuthRevoke(req, res) { sendJson(res, {}); }
async function routeOAuthResources(req, res) { sendJson(res, { resources: [] }); }

// GET /users/
async function routeUsers(req, res) {
  sendJson(res, { data: [{ id: parseInt(USER.sub) || 701953216, name: USER.name, displayName: USER.preferred_username }] });
}

// GET /currency/balance/
// Already defined above as routeCurrencyBalance

// GET /avatar-thumbnail/image/
async function routeAvatarThumbnail(req, res) {
  const imgPath = path.join(WWW_DIR, 'avatar-thumbnail', 'image', 'img.png');
  if (fs.existsSync(imgPath)) {
    res.writeHead(200, { 'Content-Type': 'image/png', 'Access-Control-Allow-Origin': '*' });
    fs.createReadStream(imgPath).pipe(res);
  } else {
    sendText(res, '');
  }
}

// GET /asset-thumbnail/json/
async function routeAssetThumbnail(req, res) {
  sendJson(res, { Url: 'http://localhost/Thumbs/gameicon.ashx', Final: true, SubstitutionType: 0 });
}

// GET /asset-thumbnail/json/realimg/
async function routeAssetThumbnailRealImg(req, res) {
  const imgPath = path.join(WWW_DIR, 'asset-thumbnail', 'json', 'realimg', 'img.png');
  if (fs.existsSync(imgPath)) {
    res.writeHead(200, { 'Content-Type': 'image/png', 'Access-Control-Allow-Origin': '*' });
    fs.createReadStream(imgPath).pipe(res);
  } else {
    sendJson(res, { Url: 'http://localhost/Thumbs/gameicon.ashx', Final: true, SubstitutionType: 0 });
  }
}

// GET /version  /version/
async function routeVersion(req, res) {
  sendJson(res, {
    version:              STUDIO_VER.version             || '0.691.0.6910867',
    clientVersionUpload:  STUDIO_VER.clientVersionUpload || 'version-f0b439683245446c',
    bootstrapperVersion:  STUDIO_VER.bootstrapperVersion || '1.0.0.0',
    nextClientVersion:        STUDIO_VER.version             || '0.691.0.6910867',
    nextClientVersionUpload:  STUDIO_VER.clientVersionUpload || 'version-f0b439683245446c',
    flagOnly: true,
  });
}

// GET /v2/client-version/{channel}/
async function routeClientVersion(req, res) {
  sendJson(res, {
    version:              STUDIO_VER.version             || '0.691.0.6910867',
    clientVersionUpload:  STUDIO_VER.clientVersionUpload || 'version-f0b439683245446c',
    bootstrapperVersion:  STUDIO_VER.bootstrapperVersion || '1.0.0.0',
    nextClientVersion:        STUDIO_VER.version,
    nextClientVersionUpload:  STUDIO_VER.clientVersionUpload,
    flagOnly: true,
  });
}

// GET /validate/
async function routeValidate(req, res) { sendText(res, 'true'); }

// GET /ownership/hasasset
async function routeHasAsset(req, res) { sendText(res, 'true'); }

// GET /marketplace/purchase/  /marketplace/submitpurchase/
async function routePurchase(req, res) { sendJson(res, { success: true, status: 'AlreadyOwned' }); }

// GET /marketplace/productinfo/  /marketplace/productDetails/
async function routeProductInfo(req, res, qs) {
  const assetId = parseInt(qs.assetId || qs.assetid || 93722443);
  sendJson(res, { AssetId: assetId, ProductId: 13831621, Name: 'place.rbxl', Description: ':) everything will be ok', AssetTypeId: 19, Creator: { Id: 1, Name: 'ROBLOX', CreatorType: 'User', CreatorTargetId: 1 }, IconImageAssetId: 0, Created: '2012-09-28T01:09:47.077Z', Updated: '2017-01-03T00:25:45.88Z', PriceInRobux: null, PriceInTickets: null, Sales: 0, IsNew: false, IsForSale: true, IsPublicDomain: false, IsLimited: false, IsLimitedUnique: false, Remaining: null, MinimumMembershipLevel: 0, ContentRatingTypeId: 0 });
}

// GET /marketplace/game-pass-product-info/
async function routeGamePassProductInfo(req, res) { sendJson(res, { IsForSale: true, ProductId: 1, IconImageAssetId: 0, TargetId: 1, AssetTypeId: 40 }); }

// GET /marketplace/validatepurchase/
async function routeValidatePurchase(req, res) { sendJson(res, { success: true }); }

// GET /moderation/  /moderation/v2/
async function routeModeration(req, res) { sendJson(res, { success: true, filtered: '', moderated: false }); }

// GET /presence/register-game-presence
async function routePresence(req, res) { sendJson(res, { success: true }); }

// GET /device/initialize/
async function routeDeviceInit(req, res) {
  sendJson(res, { browserTrackerId: 1, appDeviceIdentifier: 1 });
}

// GET /v2/settings/application/{app}/  — PCDesktopClient, PCStudioApp, etc.
async function routeSettings(req, res) {
  sendJson(res, { applicationSettings: {} });
}

// GET /v9/settings/user-opt-in/
async function routeUserOptIn(req, res) { sendJson(res, { value: null }); }

// GET /v9/settings/verify/show-age-verification-overlay/{id}/
async function routeAgeVerify(req, res) { sendJson(res, { value: false }); }

// GET /v2/persistence/{universeId}/datastores/objects/object?datastore=aaa&objectKey=global%2Faaa
async function routePersistenceObject(req, res, parts, qs, body, method) {
  const universeId = parts[2] || '0';
  const datastore  = qs.datastore  || qs.datastoreName || '';
  const objectKey  = decodeURIComponent(qs.objectKey || '');
  // objectKey format: "scope/key"
  const slashIdx   = objectKey.indexOf('/');
  const scope      = slashIdx !== -1 ? objectKey.slice(0, slashIdx) : 'global';
  const key        = slashIdx !== -1 ? objectKey.slice(slashIdx + 1) : objectKey;

  const dir  = dsDir(universeId, scope, datastore);
  const file = dsFile(dir, key);

  if (method === 'GET') {
    const rec = dsRead(file);
    if (!rec) return sendJson(res, { data: [] });
    const rawVal = typeof rec.value === 'string' ? rec.value : JSON.stringify(rec.value);
    return sendJson(res, {
      data: [{
        Key: { Scope: scope, Target: key, Key: datastore },
        Value: rawVal,
      }]
    });
  }

  if (method === 'POST' || method === 'PATCH') {
    const value = body.json !== null ? body.json : body.raw;
    const old   = dsRead(file) || {};
    const ver   = (old.version || 0) + 1;
    dsWrite(file, { value, version: ver, updatedAt: new Date().toISOString(), createdAt: old.createdAt || new Date().toISOString() });
    return sendJson(res, { data: [{ Key: { Scope: scope, Target: key, Key: datastore }, Value: typeof value === 'string' ? value : JSON.stringify(value) }] });
  }

  if (method === 'DELETE') {
    if (fs.existsSync(file)) fs.unlinkSync(file);
    return send(res, 204, '');
  }

  return sendErr(res, 405, 'MethodNotAllowed', 'Method not allowed');
}

// GET /v2/persistence/  (legacy key-value store)
async function routePersistence(req, res, qs, body, method) {
  const scope  = qs.scope  || 'u';
  const key    = qs.key    || '';
  const target = qs.target || '';
  const file   = path.join(DATA_DIR, 'persistence', encodeURIComponent(scope) + '_' + encodeURIComponent(key) + (target ? '_' + encodeURIComponent(target) : '') + '.json');
  if (method === 'GET') {
    const rec = dsRead(file);
    if (!rec) return sendJson(res, { data: [] }, 200);
    const rawVal = typeof rec.value === 'string' ? rec.value : JSON.stringify(rec.value);
    return sendJson(res, {
      data: [{
        Key: { Scope: scope, Target: target || key, Key: key },
        Value: rawVal,
      }]
    });
  }
  if (method === 'POST') {
    const value = body.raw || '';
    const dir   = path.dirname(file);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(file, JSON.stringify({ value }));
    return sendText(res, '');
  }
  return sendErr(res, 405, 'MethodNotAllowed', 'Method not allowed');
}

// GET /universes/{id}  /v2/universes/{id}/configuration  etc.
async function routeUniverse(req, res, parts, qs) {
  // simple stub
  sendJson(res, { id: 1, name: 'OffBlox', description: '', creator: { id: 1, type: 'User', name: 'Dev' }, rootPlaceId: 1818, isActive: true });
}

// GET /studio/  /studio-login/  /studio-open-place/
async function routeStudio(req, res, qs) {
  sendJson(res, { success: true });
}

// GET /timespent/
async function routeTimespent(req, res) { sendJson(res, {}); }

// GET /guac-v2/  (RCC analytics stub)
async function routeGuac(req, res) { sendJson(res, {}); }

// GET /protocol-handler-launch/
async function routeProtocolHandler(req, res) { sendJson(res, {}); }

// GET /universal-app-configuration/
async function routeUniversalAppConfig(req, res) { sendJson(res, {} ); }

// GET /product-experimentation-platform/
async function routeProductExperimentation(req, res) { sendJson(res, { assignments: [] }); }

// GET /info/
async function routeInfo(req, res) { sendJson(res, { instanceId: INSTANCE_ID, role: 'server', version: '1.0.0' }); }

// GET /v1/users/og/{id}/currency or friends — legacy per-user endpoints
async function routeLegacyUserData(req, res, parts) {
  const last = parts[parts.length - 1];
  if (last === 'currency') return sendJson(res, { robux: 9999999999, tickets: 0 });
  if (last === 'friends')  return sendJson(res, { data: [] });
  return sendJson(res, {});
}

// GET /v1/users/og/authenticated/...
async function routeAuthenticatedUser(req, res, parts) {
  const last = parts[parts.length - 1];
  if (last === 'roles')          return sendJson(res, { roles: ['Developer'] });
  if (last === 'app-launch-info') return sendJson(res, { ageBracket: 0, countryCode: 'US', isPremium: true, id: parseInt(USER.sub) || 701953216, name: USER.name, displayName: USER.preferred_username });
  return sendJson(res, {});
}

// GET /v1.0/avatar-fetch  /v1.1/avatar-fetch
async function routeAvatarFetch(req, res) {
  sendJson(res, { resolvedAvatarType: 'R15', equippedGearVersionIds: [], backAccessoryVersionIds: [], frontAccessoryVersionIds: [], neckAccessoryVersionIds: [], shoulderAccessoryVersionIds: [], waistAccessoryVersionIds: [], faceAccessoryVersionIds: [], hairAccessoryVersionIds: [], hatAccessoryVersionIds: [], assetAndAssetTypeIds: [], animationAssetIds: {}, bodyColors: { headColorId: 1, torsoColorId: 1, rightArmColorId: 1, leftArmColorId: 1, rightLegColorId: 1, leftLegColorId: 1 }, scales: { height: 1, width: 1, head: 1, depth: 1, proportion: 0, bodyType: 0 } });
}

// ─────────────────────────────────────────────────────────────────────────────
// Master router
// ─────────────────────────────────────────────────────────────────────────────

async function handleRequest(req, res) {
  const method   = req.method.toUpperCase();
  const parsed   = url.parse(req.url, true);
  const pathname = decodeURIComponent(parsed.pathname).replace(/\/+$/, '') || '/';
  const qs       = parseQuery(req.url);

  if (LOG_REQS) log('REQ', method, pathname);

  // CORS preflight
  if (method === 'OPTIONS') return send(res, 204, '');

  // Parse body for POST/PUT/PATCH
  const body = (method === 'POST' || method === 'PUT' || method === 'PATCH')
    ? await parseBody(req)
    : { raw: '', json: null };

  // Path parts (no leading empty string)
  const parts = pathname.split('/').filter(Boolean);
  const p0    = parts[0] || '';
  const p1    = parts[1] || '';
  const p2    = parts[2] || '';
  const p3    = parts[3] || '';
  const p4    = parts[4] || '';

  try {
    // ── Core utility ──────────────────────────────────────────────────────────
    if (pathname === '/')                                return routeRoot(req, res);
    if (pathname === '/ping' || pathname === '/ping.php') return routePing(req, res);
    if (pathname === '/info')                            return routeInfo(req, res);
    if (pathname === '/validate')                        return routeValidate(req, res);

    // ── DataStore (legacy action=... API) ─────────────────────────────────────
    if (p0 === 'datastore')                              return routeDatastore(req, res, qs, body);

    // ── Open Cloud DataStore (/datastores/v1/universes/...) ───────────────────
    if (p0 === 'datastores')                             return routeOpenCloudDS(req, res, parts, qs, body, method);

    // ── FFlags ────────────────────────────────────────────────────────────────
    if (p0 === 'fflags')                                 return routeFflags(req, res);

    // ── Currency ──────────────────────────────────────────────────────────────
    if (p0 === 'currency')                               return routeCurrencyBalance(req, res);

    // ── Game endpoints ────────────────────────────────────────────────────────
    if (p0 === 'game') {
      if (p1 === 'Join.ashx')                            return routeJoinAshx(req, res, qs);
      if (p1 === 'join' || p1 === 'join.php')            return routeJoinAshx(req, res, qs);
      if (p1 === 'placelauncher.ashx')                   return routePlaceLauncher(req, res, qs);
      if (p1 === 'load-place-info')                      return routeLoadPlaceInfo(req, res);
      if (p1 === 'global.ashx')                          return routeGlobalAshx(req, res);
      if (p1 === 'LuaWebService')                        return routeSocialRequest(req, res, qs);
      if (p1 === 'Start-RCCService')                     return sendText(res, 'RCCService started.');
      if (p1 === 'newjoin')                              return routeJoinAshx(req, res, qs);
      if (p1 === '2020' && p2 === 'join')                return routeJoinAshx(req, res, qs);
      return routeGameIndex(req, res, qs);
    }

    // ── OAuth ─────────────────────────────────────────────────────────────────
    if (p0 === 'oauth') {
      if (p1 === '' || !p1)                              return routeOAuthDiscovery(req, res);
      if (p1 === 'v1') {
        if (p2 === 'authorize')                          return routeOAuthAuthorize(req, res, qs);
        if (p2 === 'token') {
          if (p3 === 'introspect')                       return routeOAuthIntrospect(req, res);
          if (p3 === 'revoke')                           return routeOAuthRevoke(req, res);
          if (p3 === 'resources')                        return routeOAuthResources(req, res);
          return routeOAuthToken(req, res, body);
        }
        if (p2 === 'userinfo')                           return routeOAuthUserInfo(req, res);
        if (p2 === 'certs')                              return routeOAuthCerts(req, res);
      }
      return routeOAuthDiscovery(req, res);
    }

    // ── Users ─────────────────────────────────────────────────────────────────
    if (p0 === 'users')                                  return routeUsers(req, res);

    // ── Avatar thumbnail ──────────────────────────────────────────────────────
    if (p0 === 'avatar-thumbnail')                       return routeAvatarThumbnail(req, res);

    // ── Asset thumbnail ───────────────────────────────────────────────────────
    if (p0 === 'asset-thumbnail') {
      if (p2 === 'realimg')                              return routeAssetThumbnailRealImg(req, res);
      return routeAssetThumbnail(req, res);
    }

    // ── Version ───────────────────────────────────────────────────────────────
    if (p0 === 'version')                                return routeVersion(req, res);

    // ── Ownership ─────────────────────────────────────────────────────────────
    if (p0 === 'ownership') {
      if (p1 === 'hasasset')                             return routeHasAsset(req, res);
      return routeHasAsset(req, res);
    }

    // ── Marketplace ───────────────────────────────────────────────────────────
    if (p0 === 'marketplace') {
      if (p1 === 'purchase' || p1 === 'submitpurchase')  return routePurchase(req, res);
      if (p1 === 'validatepurchase')                     return routeValidatePurchase(req, res);
      if (p1 === 'game-pass-product-info')               return routeGamePassProductInfo(req, res);
      if (p1 === 'productinfo' || p1 === 'productDetails') return routeProductInfo(req, res, qs);
      return sendJson(res, {});
    }

    // ── Moderation ────────────────────────────────────────────────────────────
    if (p0 === 'moderation')                             return routeModeration(req, res);

    // ── Presence ──────────────────────────────────────────────────────────────
    if (p0 === 'presence')                               return routePresence(req, res);

    // ── Device ────────────────────────────────────────────────────────────────
    if (p0 === 'device')                                 return routeDeviceInit(req, res);

    // ── Studio ────────────────────────────────────────────────────────────────
    if (p0 === 'studio' || p0 === 'studio-login' || p0 === 'studio-open-place') return routeStudio(req, res, qs);

    // ── v2 ────────────────────────────────────────────────────────────────────
    if (p0 === 'v2') {
      if (p1 === 'client-version')                       return routeClientVersion(req, res);
      if (p1 === 'settings')                             return routeSettings(req, res);
      if (p1 === 'persistence' && p3 === 'datastores')   return routePersistenceObject(req, res, parts, qs, body, method);
      if (p1 === 'persistence')                          return routePersistence(req, res, qs, body, method);
      if (p1 === 'universes')                            return routeUniverse(req, res, parts, qs);
      if (p1 === 'groups_roles' || p1 === 'groups-roles') return sendJson(res, { data: [] });
      return sendJson(res, {});
    }

    // ── v9 ────────────────────────────────────────────────────────────────────
    if (p0 === 'v9') {
      if (p1 === 'settings' && p2 === 'user-opt-in')     return routeUserOptIn(req, res);
      if (p1 === 'settings' && p2 === 'verify')          return routeAgeVerify(req, res);
      return sendJson(res, {});
    }

    // ── v1 (Open Cloud / legacy) ──────────────────────────────────────────────
    if (p0 === 'v1') {
      // /v1/users/og/authenticated/...
      if (p1 === 'users' && p2 === 'og' && p3 === 'authenticated') return routeAuthenticatedUser(req, res, parts);
      // /v1/users/og/{id}/currency  or  friends
      if (p1 === 'users' && p2 === 'og')                           return routeLegacyUserData(req, res, parts);
      if (p1 === 'universes')                                      return routeUniverse(req, res, parts, qs);
      return sendJson(res, {});
    }

    // ── v1.0 / v1.1 (avatar-fetch) ────────────────────────────────────────────
    if ((p0 === 'v1.0' || p0 === 'v1.1') && p1 === 'avatar-fetch') return routeAvatarFetch(req, res);

    // ── Misc stubs ────────────────────────────────────────────────────────────
    if (p0 === 'timespent')                              return routeTimespent(req, res);
    if (p0 === 'guac-v2')                                return routeGuac(req, res);
    if (p0 === 'protocol-handler-launch')                return routeProtocolHandler(req, res);
    if (p0 === 'universal-app-configuration')            return routeUniversalAppConfig(req, res);
    if (p0 === 'product-experimentation-platform')       return routeProductExperimentation(req, res);
    if (p0 === 'game-auth')                              return sendJson(res, { success: true });
    if (p0 === 'scripts')                                return sendText(res, '');
    if (p0 === 'My' || p0 === 'Login')                  return sendJson(res, { success: true });
    if (p0 === 'Setting' || p0 === 'settings')          return sendJson(res, {});
    if (p0 === 'Thumbs')                                 return routeAvatarThumbnail(req, res);

    // ── Static file fallback ──────────────────────────────────────────────────
    if (serveStatic(req, res, pathname)) return;

    // ── 404 ───────────────────────────────────────────────────────────────────
    log('404', pathname);
    sendErr(res, 404, 'NotFound', `${pathname} not found`);

  } catch (err) {
    log('ERR', err.message);
    try { sendErr(res, 500, 'InternalError', err.message); } catch (_) {}
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Adaptive hosting — try to become server, or run as watchdog
// ─────────────────────────────────────────────────────────────────────────────

let activeServer = null;
let isServerRole = false;

function tryBindServer(port) {
  return new Promise((resolve) => {
    const server = http.createServer(handleRequest);

    server.once('error', (err) => {
      if (err.code === 'EADDRINUSE' || err.code === 'EACCES') {
        resolve(null);   // port taken — another instance is server
      } else {
        log('SERVER_ERR', err.message);
        resolve(null);
      }
    });

    server.listen(port, HOST, () => {
      resolve(server);
    });
  });
}

async function becomeServer(port) {
  let server = await tryBindServer(port);

  if (!server && port !== FALLBACK_PORT) {
    log('INFO', `Port ${port} busy, trying fallback ${FALLBACK_PORT}...`);
    server = await tryBindServer(FALLBACK_PORT);
    if (server) port = FALLBACK_PORT;
  }

  if (server) {
    activeServer = server;
    isServerRole = true;
    log('SERVER', `Active — listening on port ${port}`);

    server.on('error', (err) => {
      log('SERVER_ERR', err.message, '— will restart watchdog');
      isServerRole = false;
      activeServer = null;
      startWatchdog();
    });
    return true;
  }

  return false;
}

// ─────────────────────────────────────────────────────────────────────────────
// Watchdog — polls /ping; takes over as server when the current server dies
// ─────────────────────────────────────────────────────────────────────────────

function pingServer(port) {
  return new Promise((resolve) => {
    const opts = { hostname: '127.0.0.1', port, path: '/ping', method: 'GET', timeout: 2000 };
    const req = http.request(opts, (r) => { resolve(r.statusCode === 200); r.resume(); });
    req.on('error', () => resolve(false));
    req.on('timeout', () => { req.destroy(); resolve(false); });
    req.end();
  });
}

async function watchdogLoop(port) {
  let failures = 0;
  log('WATCHDOG', `Standby — polling http://127.0.0.1:${port}/ping every ${WD_INTERVAL}ms`);

  while (true) {
    await sleep(WD_INTERVAL);

    if (isServerRole) {
      // We are already the server — no need to poll
      failures = 0;
      continue;
    }

    const alive = await pingServer(port);
    if (alive) {
      failures = 0;
    } else {
      failures++;
      log('WATCHDOG', `Ping failed (${failures}/${WD_RETRIES})`);
      if (failures >= WD_RETRIES) {
        log('WATCHDOG', 'Server appears dead — racing to take over...');
        failures = 0;
        const won = await becomeServer(port);
        if (!won) {
          log('WATCHDOG', 'Another instance got there first — back to standby');
        }
      }
    }
  }
}

function startWatchdog() {
  watchdogLoop(PORT).catch((err) => log('WATCHDOG_ERR', err.message));
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

// ─────────────────────────────────────────────────────────────────────────────
// Entry point
// ─────────────────────────────────────────────────────────────────────────────

(async () => {
  log('BOOT', `HookedWebserver starting (instance ${INSTANCE_ID})`);
  log('BOOT', `Data dir: ${DATA_DIR}`);
  log('BOOT', `WWW  dir: ${WWW_DIR}`);

  // Ensure data directories exist
  for (const d of [DATA_DIR, path.join(DATA_DIR, 'datastores'), path.join(DATA_DIR, 'persistence'), path.join(DATA_DIR, 'SavedData')]) {
    if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
  }

  const won = await becomeServer(PORT);

  if (!won) {
    log('BOOT', `Server already running on port ${PORT} — entering watchdog mode`);
  }

  // Always run the watchdog regardless of role
  // (if we ARE the server, the watchdog loop skips polling and just idles)
  startWatchdog();

  // Keep process alive
  process.on('SIGINT',  () => { log('SHUTDOWN', 'SIGINT received'); process.exit(0); });
  process.on('SIGTERM', () => { log('SHUTDOWN', 'SIGTERM received'); process.exit(0); });
})();
