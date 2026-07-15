# Re-enabling client→server replication (FilteringEnabled = false) in OffBlox

Goal: let the client executor's arbitrary DataModel changes replicate to the
server, with FE toggleable on our own client. Reference: a July‑24‑2018
`RobloxPlayerBeta.exe` (x86, VMProtected but RTTI intact) + `2018M.exe`
RccService (x86, **not** VMProtected) — the last builds before FE enforcement.

All OffBlox addresses below are RVAs on `OffBlox.exe` (x64, ImageBase
`0x140000000`).

---

## 1. What we confirmed

- OffBlox is a single binary for client and server, and it **retains the entire
  replication toolkit** (it uses it server→client): `ChangePropertyItem`,
  `NewInstanceItem`, `DeleteInstanceItem`, `EventInvocationItem`,
  `ClientReplicator`, plus the `Deserialized*` receive side. So this is a
  **re-drive / re-enable** problem, not a from-scratch serializer rebuild.
- FilteringEnabled is **hardwired on**: the getter at `0x6FF1D0` is
  `mov al,1; ret`. ~120 call sites read it. Flipping it globally freezes the
  client because per-frame physics/CFrame reads (cluster `0x2b5xxxx`) take an
  FE-off branch that is effectively dead code in this build.
- The property is real but vestigial (getter ignores the member). Setting it in
  Lua does nothing.

## 2. Protocol (2018 reference)

Client→server changes are serialized as **Items** and queued by the
`ClientReplicator`, drained each frame by its send job:
- `ChangePropertyItem` — a single property change.
- `NewInstanceItem` / `DeleteInstanceItem` — create / delete.
- `EventInvocationItem` — RemoteEvent (this one already works under FE).

## 3. OffBlox anchors (outgoing property path)

- `RBX::Network::Replicator::ChangePropertyItem`
  - RTTI name @ file `0xC200030`; **vtable RVA `0x8CB81A0`**.
  - **ctor `0x28C3200`** — `ChangePropertyItem(this, base?, instance, propDesc, value, propId)`:
    - `+0x00` vtable
    - `+0x40` = instance pointer (arg r8)
    - `+0x48` = property descriptor (arg r9)
    - `+0x50/+0x58` = value (moved in from `[rsp+0x50]`, 16 bytes — a Variant)
    - `+0x60` = propId dword (`[rsp+0x60]`), `+0x64` word = 0
  - base ctor called first: `0x14279C880`.
- **Outgoing serialize loop `0x274C700`** (per-instance; virtual, vtable-dispatched):
  - Reads replicator members `[this+0x2B90]` (a stream/writer),
    `[this+0x35A0]` (outgoing-property subsystem object) and gate byte
    `[this+0x35A8]`.
  - Gate call `0x1428A4FC0(this+0x35A0, this, item)` → bool "should send".
  - Calls the `ChangePropertyItem` ctor at `0x274CE94`.
- Single-property helper that also builds an item: `0x27BB440`
  (ctor call at `0x27BB663`; its only caller is `0x74957D9`).
- Instance-added-to-replication handler: `0x2896E60` (logs "Child instance
  added to replication" @ ref `0x2897544`). Note: it does **not** call the FE
  getter directly — the outgoing-property *subscription* decision is made
  elsewhere (a cached flag, see below), not here.

## 4. Cached FE flags (replicator-level)

Two sites cache `!FE` ("may replicate") into replicator members at init:
- `0x4C193C2`: `call FE_getter; test al,al; sete al; mov [rsi+0xA43], al`
- `0x4C31E48`: `call FE_getter; test al,al; sete al; mov [rbx+0xCC3], al`
  (lazy getter fn `0x4C31E20`, callers `0x4C33E72/0x4C34F2A/0x4C35038` — the
  ClientReplicator join/serialize code.)

Forcing both to 1 (tested) did **not** enable replication and did **not**
freeze. Conclusion: "may replicate = true" is necessary but not sufficient — the
client still never *subscribes to / enqueues* arbitrary property changes,
because the per-instance outgoing subscription was never wired at join (FE on).

## 5. The real missing link

Under FE-off the client must, for every replicated instance, **track property
changes and enqueue `ChangePropertyItem`s** into the replicator's pending set
that `0x274C700` drains. In this build that tracking/subscription is not wired.
Two viable implementations:

### Option A — re-enable native subscription (least code if found)
Find the per-instance "set up outgoing property watcher" that the 2018 client
runs when FE is off (gated by the cached `!FE` flag at subscription time, not by
the per-frame physics getter reads). Flip only that gate, client-side, applied
before join. Risk: must be the *subscription* gate, not a physics read, or it
refreezes. Not yet located — needs the 2018 `ClientReplicator::replicateProperties`
/ `newReplicationContainer` path mapped and diffed against OffBlox.

### Option B — DLL-driven enqueue (controllable, recommended)
Hook the client property-set (`Instance::raisePropertyChanged`) and, for changes
the executor makes on a replicated instance, **construct a `ChangePropertyItem`
via `0x28C3200` and push it onto the client replicator's pending container**,
then let `0x274C700` send it. Still needs:
1. Client `ClientReplicator*` accessor (from NetworkClient/DataModel).
2. The pending container offset + its push method (drained by `0x274C700`;
   the container is reached via the replicator `this`, offsets around
   `+0x2B90`/`+0x35A0` — needs the send loop fully walked).
3. A `PropertyDescriptor*` + boxed value for the changed property (the executor
   already has the instance + property; the descriptor is reachable from the
   class descriptor).

## 6. FE toggle design

Keep a DLL global `g_feEnabled` (default true = vanilla). The executor exposes
`setfilteringenabled(bool)` (or a pipe command). When set false, the DLL turns on
the Option‑A/B outgoing path; when true, it stops enqueuing. Do **not** flip the
`0x6FF1D0` getter (freeze) — the toggle drives our added enqueue path, not the
engine's dead FE-off branches.

## 6b. Flag-consumer check (done)

`0x60B33B0` reads/writes `+0xCC3` heavily (reads `0x60b3665/0x60b3673/0x60b385c`,
writes `0x60b386a/0x60b3b1e`) but makes **no** real calls (only the two
`__CxxThrow`/cookie thunks `0x147218CB2/0xCBE`). So it's replicator **state
copy/merge**, not the send tick — the `+0xCC3` flag is just plumbed state, which
is why forcing it did nothing. The actual outgoing tick is **virtual**
(`0x274C700` has no direct callers), so the next trace must go through the
`ClientReplicator` vtable, not flag readers.

## 6c. Implemented so far (OffBloxExec, client)

- **Send loop = `Replicator` vtable slot 134 = `[this+0x430]`**; `ClientReplicator`
  vtable start = `0x8C98EF8` (slot 134 lands at `0x8C99328`, holding base impl
  `0x274C700`). Confirmed via RTTI on 5 replicator vtables.
- Added a **vtable hook on the ClientReplicator's slot 134** (`Hook_ReplSend`,
  installed by `HookVTableSlot`). It fires only for the client's own replicator,
  captures the live `ClientReplicator*` once (`g_clientRepl`), and dumps its key
  members (`+0x2B90` stream, `+0x35A0` outgoing subsystem, `+0x35A8` gate,
  `+0xCC3`/`+0xA43` may-replicate) to the pipe log. **Capture/validate only — it
  never writes engine state, so it's safe to ship enabled.** 4 register args are
  forwarded to preserve the ABI (the method reads r8).
- Added the runtime FE toggle scaffolding (`g_feOn`), executor-settable, for the
  enqueue phase.

Rationale: the exact enqueue offsets (outgoing-subsystem "add item", the
`ChangePropertyItem` value/propDesc/propId sourcing) can't be pinned with
confidence statically — `0x1428ADB20` turned out to be a log call, not the add.
Guessing them blind crashes the client on toggle. The capture hook produces the
live layout needed to write the enqueue correctly instead of guessing.

## 6d. The send-enable gate + first working lever (IMPLEMENTED)

Key finding: the send path has **no FE gate** — `0x273F490` (the check at the top
of the single-property serializer `0x27BB440`) filters by *property replication
attributes*, not FilteringEnabled. So once a change is in the replicator's changed
set it WILL be serialized and sent.

The outgoing send loop (slot 134) is gated at its head by **`ClientReplicator`
slot 92 (`0x274E1B0`)**:
```
al = globalFFlag[rva 0xC178AB8] && ([replicator+0x12C] == 1)
```
`[replicator+0x12C]` is the replicator's mode; a *sending* replicator has 1. The
client's own replicator holds a different value, so its outgoing send is skipped.

**Implemented (OffBloxExec, client, toggle-gated OFF):**
- `!fe on` / `!fe off` pipe commands set `g_feOn`.
- `ApplyFeReplication()` (game thread, SEH) sets our captured client replicator's
  `+0x12C` to 1 when on (restores the original when off). Targeted to our own
  replicator only; does NOT touch the global FE getter (no freeze).
- `DumpReplicator` now prints `+0x12c(mode,1=send)=N` so we see the original mode.

**Test:** rebuild OffBloxExec; connect the client pipe; note the
`+0x12c(mode,...)=N` in the capture line; send `!fe on`; then from the executor
`local p=Instance.new("Part") p.Anchored=true p.Parent=workspace` and check the
other client/server.

**If it sends but nothing lands / nothing sends:** two follow-ups, in order —
1. Ensure `globalFFlag @ rva 0xC178AB8` is non-zero (else slot92 always false).
2. If the send loop runs but the *changed set is empty*, the client isn't
   TRACKING changes — then wire tracking: on the executor property-set, mark the
   instance/property into `[replicator+0x35A0]`'s pending set (the outgoing
   subsystem) so the (working, FE-gate-free) serializer picks it up.

## 6e. AUTHORITATIVE mechanism (from 2016 source) - THE fix

The 2016 `Network/` source resolves everything:

- **Client FE state is dictated by the server at join.** `ClientReplicator.cpp:865`
  reads `networkFilterEnabled` from the join bitstream; `:884` does
  `if (networkFilterEnabled) strictFilter.reset(new StrictNetworkFilter(this))`.
  No filter object => FE-off client.
- **Server writes that bit** at `ServerReplicator.cpp:748`:
  `bitStream << (!isCloudEdit() && workspace->getNetworkFilteringEnabled())`.
  `getNetworkFilteringEnabled()` is the C++ getter == **`0x6FF1D0`** (Roblox
  hardcoded it to `mov al,1`; ~120 call sites). We already patch it to `false`
  on the server (dllmain `ForceFilteringDisabled`, at VM-lock). So the server
  sends **join-bit = false** => the joining client builds **no `strictFilter`**.
- **FE-off client replicates** (`ClientReplicator::isLegalSendProperty`): with no
  `strictFilter`, it returns `true`, so `Replicator::filterChangedProperty ==
  Accept` and `onPropertyChanged` pushes a `ChangePropertyItem` onto `pendingItems`;
  the client's normal `sendItemsPacket` (runs every frame) serializes it via
  `writeChangedProperty` and sends it. The server (also FE-off, getter false)
  accepts it. **No dead send-loop, no mode flip needed.**
- The `SendData: unknown network format` you saw is the client's per-type value
  serializer running (proof it's FE-off and sending) and hitting a value type
  with no registered network format - an edge case, not the whole path.

### Consequence / how to use it
The client is set FE-off **at join**, so it must **join AFTER the server has
locked its VM** (when `0x6FF1D0` is patched false). A client that connected
earlier stays FE-on for that session - **rejoin it**. Property changes on
server-known (received) instances then replicate; brand-new client-created
instances additionally need a `NewInstanceItem` (separate, not required for the
"change an existing part" case).

### CORRECTION (verified against the enforced binary): the join-bit path does NOT apply
The 2016 conditional (`if (networkFilterEnabled) strictFilter.reset(...)`) does
**not** survive FE enforcement. In OffBlox the `StrictNetworkFilter` ctor is
`0x27F17E0`, called at `0x2832B96` inside the join handler `0x2831EF0`, and the
construction there is **unconditional** - the client builds the whitelist filter
regardless of the server's bit (that's the whole point of "enforcement"). So the
server-bit approach can't turn FE off on the client.

### THE fix (implemented, client-side)
The filter is stored as a shared_ptr on the replicator: **`[ClientReplicator+0x1B0]`**
= `StrictNetworkFilter*`, `+0x1B8` = control block (store site: `0x2832BA9`).
`ClientReplicator::isLegalSendProperty` returns `true` when `strictFilter` is null,
so we **null `[+0x1B0]`/`[+0x1B8]` on the live client replicator every send tick**
(`ForceClientFeOff` in OffBloxExec, from the slot-134 capture hook). That is the
legitimate FE-off state (`if (strictFilter)` is checked everywhere), so the client
now sends property/instance/event changes through its live `sendItemsPacket`, and
the server (getter patched false) accepts them. Timing-independent; no server bit
needed. The server getter patch is still kept so the server ACCEPTS incoming.

### 6f. FINAL fix — STATIC strictFilter-null patch (the server-style patch, client-side)
Instead of nulling `[replicator+0x1B0]` at runtime every tick (needs live capture +
an MI D-scan, timing-fragile), we null the filter **at the store site**, statically,
once at DLL load — the exact analog of the server getter patch.

Join handler `0x2831EF0` builds the filter unconditionally and stores it:
```
0x2832B96  call 0x27F17E0        ; StrictNetworkFilter ctor (returns &temp sharedptr)
0x2832B9B  mov  rcx,[rax]        ; rcx = new filter ptr      <-- PATCH
0x2832B9E  mov  rdx,[rax+8]      ; rdx = new control block   <-- PATCH
0x2832BA9  mov  [rdi+0x1B0],rcx  ; strictFilter.ptr  = rcx
0x2832BB7  mov  [rdi+0x1B8],rdx  ; strictFilter.ctrl = rdx
```
Patch at RVA **`0x2832B9B`** (7 bytes):
`48 8B 08 48 8B 50 08` → `31 C9 31 D2 90 90 90` (`xor ecx,ecx; xor edx,edx; nop×3`).
Now `strictFilter` is stored NULL → the replicator is born FE-off. Covers property
changes, NewInstance, and events in one shot (all guarded by `if (strictFilter)`,
all return Accept when null). Implemented in `OffBloxExec::Install()` via
`PatchVerify(..., "client FE-off: strictFilter never stored (born null)")`. The
freshly-built filter object leaks (unreferenced) — negligible. The per-tick runtime
nulling + capture hooks are retained only as confirmation (they now find it already
null and no-op). Verified: shipping `Clients/OffBlox/OffBlox.exe` has the expected
`48 8B 08 48 8B 50 08` at that offset.

### 6g. FE-off is TWO-SIDED; the client half is done, the server half is not
Symptom after the static strictFilter-null patch: some scripts disconnect the
player, and new client-created Parts don't appear on the server. Read together with
the 2016 `ServerReplicator` source, this is diagnostic, not random:
- The disconnect = the client is NOW emitting replication it never did before
  (strictFilter null opened the send path), and the enforced server rejects it:
  `requestDisconnect(DisconnectReason_SendPacketError)` (ServerReplicator.cpp:963/
  1100/1428) plus the security-mask / `HATE_ILLEGAL_SCRIPTS` anti-exploit kicks
  (:2132, :1836-1846). A legit FE client never sends non-whitelisted items, so the
  server treats ours as an exploit and drops it.
- New instances specifically also require the client's OUTGOING NewInstance
  subscription to be wired (`ClientReplicator::isLegalSendInstance`, source :623 —
  returns true with null filter, but something upstream must still enqueue the
  NewInstanceItem). Whether the enforced client wires that at all is the open Q.

**Send-side probe added** (`Hook_ReplSend`, slot 134 = outgoing serialize loop
`0x274C700`, which only runs when the client has queued outgoing items): it now
logs `OUTGOING send-loop fired #N`. Test = create a Part and watch:
- bumps on Part creation => send side works; the blocker is SERVER-side
  (accept incoming client replication without kicking) — next work is server DLL.
- never bumps => client isn't enqueuing (outgoing subscription missing) => Option B
  (DLL-driven enqueue) on the client.

### Note on `workspace.FilteringEnabled` reading `true` on the client
The getter `0x6FF1D0` is **virtual** (0 direct callers; dispatched via Workspace's
vtable) and ~120 physics/render sites read it per frame. Flipping its body to
`mov al,0` (as on the server) makes those sites take an unimplemented FE-off branch
and **freezes the client** (verified earlier). There is no single Lua thunk to
patch cheaply because the read dispatches virtually. The value is cosmetic (doesn't
gate our replication, which is driven by the strictFilter state). Making the Lua
read return false safely requires pinning the FilteringEnabled PropertyDescriptor's
per-property getValue thunk (registration at `0x362791`) — deferred as low-value.

### 6h. The join-time disconnect = a THROW in the outgoing value serializer
Runtime evidence (client log): `SendData: Attempted to send value with unknown
network format` -> `Error while sending. sender type: SendData` -> disconnect, at
JOIN, before any script. Server sees `Disconnect ... RemotePeer error message:
Unknown` and drops the player.

Root cause: `serializeValue` (RVA **`0x2724260`**, spans `0x2724260-0x27259f0`)
dispatches on a network type-id (`type->vtable[2](type)`), and its unknown-type
branch (2016's `return false`) was compiled to a **throw** (error string
`0x148C93AD8`, 12 throw sites across the recursive serializers; representative site
`0x1427257E6`: build error string -> `call 0x147218CAC` -> `int3`). The throw
unwinds the whole outgoing packet, so RakNet reports a send failure and tears down
the connection. With `strictFilter` null the client now serializes its full changed
set at join, and one property whose value type has no OUTGOING wire format in this
build throws immediately. **This proves the client send path works** — it's a
serializer gap, not a filter/subscription gap.

**Wrapper installed** (`Hook_SerializeValue`, inline hook on `0x2724260`): LOG-ONLY.
Logs each distinct `outgoing value type-id=N` then calls the original unchanged.
IMPORTANT: an earlier version wrapped the original in `__try/__except` to swallow
the throw — that CRASHED the client (catching the engine's C++ throw via SEH is
invalid in this build's EH model; it turned the graceful disconnect into a hard
crash). So the wrapper must never SEH-guard the call to the original. The last
`outgoing value type-id=N` before the disconnect names the culprit. Next: map that
id -> type, then skip that type PRE-throw (compare id against the handled set inside
the wrapper and return false without calling the original) or reject the property
before it is queued — never by catching the throw.

### 6i. 2022L PDB reference (win_studio_x64_0.550.488.5480525/RobloxStudioBeta.pdb)
A FE-enforced client WITH symbols. Parsed via a hand-rolled MSF reader
(`/tmp/msf.py`,`/tmp/pubs.py`; pdbparse hangs on the 877MB DBI, llvm needs root).
Key confirmations (2022 RVAs, structure only - OffBlox differs, uses `ChangePropertyItem`
not the 2022 `SharedChangePropertyItem`):
- `ClientReplicator::isLegalSendProperty` 0x1099B30, `isLegalSendInstance` 0x10999E0.
- `StrictNetworkFilter::filterChangedProperty` 0x10A9000, `filterNew`, `filterDelete`.
- The StrictNetworkFilter **WhiteList includes** BasePart, Player, Players, Tool,
  Humanoid, Seat, VehicleSeat, GuiObject/GuiButton/ScreenGui, ProximityPrompt,
  RemoteFunction, Sound, TextChatService, etc. (one `WhiteList::insert<Class>` symbol
  each). So the filter is DESIGNED to permit specific client->server replication -
  nulling it wholesale is wrong; it floods the join with un-encodable value types.

### 6j. THE serializer throw is what disconnects/crashes - patched to return false
`serializeValue` has 4 `else`/unknown-format branches (RVAs `0x272757B`,`0x27275CC`,
`0x27257E6`,`0x2725839`), all referencing error string `0x148C93AD8` and THROWING
(2016 returned false here). Hooking serializeValue's prologue CRASHES the client, so
instead each throw branch is byte-patched to `xor eax,eax; jmp 0x27257CB` (the
function's own pop/ret epilogue) = clean `return false`, skipping the un-encodable
value instead of aborting the packet. Only the `else` branches change; handled types
serialize normally. Applied in `OffBloxExec::Install()` (4x `PatchVerify`, verified
against the shipping exe). Born-null strictFilter patch is kept. If the join still
drops, the culprit is a container/variant serializer throw OUTSIDE serializeValue
(sites `0x2729548/739`, `0x2993233/3CD`, `0x299493E/AF2`, `0x2995A2A/A4D`) or the
caller doesn't tolerate a false return (would need a pre-commit filter instead).

### 6k. Whole-filter null is a dead end - reverted to whitelist-intact; the wall is TWO-SIDED
Empirical result of forcing serializeValue's unknown-format branches to `return
false` (instead of throw): the client CRASHES mid-join (half-written packet, engine
faults downstream) - worse than the throw's graceful disconnect. So on the CLIENT,
an un-encodable property can neither throw (disconnect) nor return false (crash);
it must never be QUEUED. That is exactly what the whitelist does. Conclusion: nulling
the whole strictFilter (static born-null OR runtime) is unworkable and is now fully
DISABLED (born-null patch removed; the 4 serializeValue patches removed; the runtime
`ForceClientFeOff` calls in Hook_ReplSend/Hook_ProcessPacket/DrainAndRunAll commented
out). The client again joins cleanly with the whitelist intact and the executor works.

What the 2022L PDB proves about scope: the StrictNetworkFilter whitelist permits
client->server PROPERTY changes on specific classes (BasePart/Player/Humanoid/Tool/
Seat... - character-control surface), NOT arbitrary client-created NEW instances.
Real FE enforcement blocks a client from creating replicated instances at the SERVER.
So "client-created Part replicates to server" is blocked on BOTH ends:
1. CLIENT: sending non-whitelisted properties hits un-encodable types (crash/dc).
2. SERVER: the enforced ServerReplicator rejects/kicks client-originated instances
   and non-whitelisted property writes (DisconnectReason_SendPacketError + the
   anti-exploit security masks in ServerReplicator.cpp).

Realistic paths forward (pick per goal):
  (A) Server-side: since we control the server (OffBlox + RobloxStudioCommunication.dll),
      patch the ServerReplicator INCOMING path to accept client-originated
      instance/property items without kicking. This is the actual enabler and is
      separable from the rbxsig/cookie/anti-impersonation systems (do NOT touch those).
  (B) Client-side, scoped: broaden ONLY to encodable properties of whitelisted
      classes (e.g. add BasePart properties to the whitelist map) so the server still
      accepts them - limited to what enforcement already tolerates.
  (A) is required for true arbitrary replication; (B) alone stays within the
  whitelist's ceiling.

### 6l. SERVER is blocked - the 4 receive gates (located + patched)
Confirmed from 2016 source + 2022L PDB: the enforced `ServerReplicator` rejects
incoming client items at four virtual receive filters, and the propSync rejection
counter escalates repeated rejects to a KICK. Located in OffBlox via the
`"remotePlayer already exists"` (0x148CB0B90) and `"PlayerPropChange"` (0x148CAF486)
strings + the ServerReplicator vtable (@ .rdata `0x8CB0098`, slot0 =
isLegalReceiveInstance). OffBlox RVAs + patch (in dllmain `AcceptClientReplication`,
run at VM-lock next to the getter patch):

| function                       | RVA        | vtable slot   | patch            | meaning        |
|--------------------------------|------------|---------------|------------------|----------------|
| isLegalReceiveInstance         | 0x2866A20  | 0x8CB0098 +0  | B0 01 C3         | return true    |
| isLegalReceiveProperty         | 0x2866E10  | +0x18         | B0 01 C3         | return true    |
| filterReceivedChangedProperty  | 0x286F340  | +0xA0         | 31 C0 C3         | Accept (0)     |
| filterReceivedParent           | 0x286B670  | +0xA8         | 31 C0 C3         | Accept (0)     |

Accept-at-entry also short-circuits `propSync.onReceivedPropertyChanged` -> the
anti-exploit rejection counter never trips (no kick). Orthogonal to rbxsig/cookie/
anti-impersonation (untouched). Entry-byte verify guards each patch.

NOTE (client side still gated): the client keeps its whitelist (so the join stays
clean). BasePart IS whitelisted, so a client-created Part + its whitelisted props
should now go end-to-end. For ARBITRARY property replication the client filter must
additionally be broadened to BasePart (encodable types only, to avoid the serializer
crash) - next step if the whitelisted path works.

### 6m. Send path WORKS; the wall is the schema-based class encoding (client->server)
Milestone: with the client send-gates auto-opened post-join
(`isLegalSendInstance` 0x27AA970, `isLegalSendProperty` 0x27AAB00 -> `mov al,1;ret`,
applied ~8s after VM start via the resume hook) and the server receive-gates
accepting, the client NOW sends new instances and they REACH the server. Confirmed
end-to-end transport.

Remaining blockers (both are dormant FE outgoing subsystems, not byte flips):
1. **New instances -> server "invalid class network type for new class item"**
   (deterministic; string @ OffBlox `0x148CBA529`). OffBlox is a MODERN schema build:
   classes are identified by a `NetworkSchema` id from
   `NetworkSchema::classNetworkIdFromLocalDescriptor` (2022 `0x1063420`, a DenseHashMap
   lookup ClassDescriptor->uint16), and new instances go through
   `MegaReplicator`/`SharedNewInstanceItem`. The opened path is the OLDER
   `ClientReplicator::isLegalSendInstance` gate, so the client emits the class in a
   format/dictionary the server's SCHEMA deserializer reads wrong (fails at byte 9).
   Likely two coexisting replication systems (old `NewInstanceItem` + new
   `SharedNewInstanceItem`); the client send must go through the schema/Mega path (or
   write the schema class id + teach), not the legacy classDictionary path.
2. **Property changes on existing instances -> never enqueued.** `isLegalSendProperty`
   is only the filter; nothing generates the outgoing `ChangePropertyItem`. Under FE
   the client subscribes instances for INCOMING only. Needs outgoing change-tracking
   wired (2022 `Replicator::handlePropertyChanged` 0x106A700 /
   `megaOnPropertyChanged` 0x106C5D0 are the schema-path hooks).

Assessment: finishing = reimplementing FE-off outgoing replication on a modern
schema-based build with two coexisting systems (class-schema teach + outgoing change
tracking). Transport is proven; this is a large protocol effort, not a small patch.

### 6n. "invalid class network type" is a FILTER REJECTION, not a decode error
Decisive finding: in `readInstanceNew` (0x28D32F0) the client's class network id IS
decoded fine (ClassInfo array @ [rep+0x2E00][+0xB8..0xC0], stride 0xB8, id range check
-> `jae 0x28D4032` = the "invalid network id" path, NOT hit). Then it runs a SEPARATE
strictFilter class check:
```
0x28D36BF  mov rcx,[r12+0x2E50]      ; server strictFilter
0x28D36C7  test rcx,rcx / je accept  ; null filter -> accept
0x28D36CC  mov rdx,r13               ; r13 = [ClassInfo+8] (the class)
0x28D36CF  call 0x14285C770          ; filterNew(class) -> Accept(0)/Reject(1)
0x28D36D4  cmp eax,1
0x28D36D7  je  0x28D401B             ; Reject -> throw "invalid class network TYPE"
0x28D36DD  jmp 0x28D3714            ; accept
```
So the error is the server's StrictNetworkFilter rejecting the client-created class -
a DIFFERENT gate from `isLegalReceiveInstance` (0x2866A20). FIX: NOP the reject branch
`je 0x28D401B` @ **0x28D36D7** (`0F 84 3E 09 00 00` -> 6x 0x90) so it falls through to
the accept path. Added to dllmain `AcceptClientReplication` (server, VM-lock). This is
the missing piece for client-created instances to land.

TWO reject paths exist (gated by global flag @ 0x28D36B2), each `cmp eax,1; je
<type-err>`: `je 0x28D401B @ 0x28D36D7` AND `je 0x28D4092 @ 0x28D370E`. BOTH must be
NOPed (patching only the first still throws via the second - the flag-off path is the
one actually taken). dllmain now NOPs both.

### 6o. Live property changes: the real gate is filterReplicatorChangedProperty
New instances replicate (with initial props), but live property EDITS did not - opening
`isLegalSendProperty` (0x27AAB00) was the wrong gate for the schema/Mega path. The
actual outgoing property-change flow is: property changes -> `megaOnPropertyChanged`
(2022 0x106C5D0) -> calls `ClientReplicator::filterReplicatorChangedProperty` (2022
0x1098C10, vtable slot 106); if it returns Reject(1) the change is NEVER enqueued;
Accept(0) -> tail-calls `handlePropertyChanged` (2022 0x106A700, slot 107) which
enqueues. Located in OffBlox at **`0x27A9710`** (vtable slot 133; identified by the
early `call` + `cmp byte [rbx+0x3A10],0` + Player class-id cast 0x224/0x226 - the exact
2022 structure). Patched to `xor eax,eax; ret` (Accept) in OpenClientSendGates
(OffBloxExec, auto-applied ~8s post-join). Now client property edits should enqueue.

### 6p. The real property-change blocker: handlePropertyChanged's slot-92 gate
Chain confirmed in OffBlox: property change -> `megaOnPropertyChanged` (0x27515C0)
-> slot 133 `filterReplicatorChangedProperty` (0x27A9710, patched Accept) -> tail-call
slot 134 `handlePropertyChanged` (0x274C700, the enqueue). But handlePropertyChanged
BAILS early at `call [rax+0x2E0]` = ClientReplicator vtable slot 92 (`0x274E1B0`):
```
movzx eax,[globalFFlag]; test al,al; je ret_false
cmp [rcx+0x12C],1 ; sete al ; ret        ; true only if SENDING replicator (mode==1)
```
The client's replicator has mode != 1, so slot 92 -> false -> `je 0x274C9F5` (reject),
never enqueues. New instances use a different enqueue path (onDescendantAdded), which
is why they replicated but live property edits did not. FIX: patch slot 92
(`0x274E1B0`) entry -> `mov al,1; ret` (always "sending replicator"). Added to
OpenClientSendGates (post-join). NOTE: earlier forcing slot92/mode=1 at JOIN crashed
(outgoing structures uninitialized); applying it ~8s POST-join (structures up, client
already sending new instances) avoids that.

### 6q. Live property changes: blocked by MISSING outgoing repl-data (not gate-patchable)
Full chain confirmed reachable on the client: propChange -> dispatcher (0x28A86D0,
replicator flag [+0x4694] is SET to 1 - written at 0x27B32A6/0x27B436E/0x2864B97 - so
the client IS iterated) -> megaOnPropertyChanged (0x27515C0) -> filterReplicatorChangedProperty
(0x27A9710, patched Accept) -> handlePropertyChanged (0x274C700). But handlePropertyChanged
requires the instance to be registered in the replicator's OUTGOING tracking:
```
0x274C761 rbx = replicator.vfn[0x260]()      ; outgoing repl-data for the change
0x274C797 test rbx,rbx ; je reject            ; must be non-null
0x274C7A0 test r14,r14 ; je reject            ; r14 = [rbx+0xC8] must be non-null
0x274C7A9 cmp r15,rbx  ; jne reject           ; instance arg must match repl-data
```
On the client these are null/mismatch because FE wires INCOMING tracking only - client
instances have no outgoing replication-data. The gates guard against operating on that
missing data; NOPing them feeds null pointers downstream -> crash (confirmed class of
bug). NEW instances work because the NewInstance send captures property VALUES at
send-time via a different path that doesn't need per-instance change-tracking.

CONCLUSION: live property replication needs the client's OUTGOING per-instance change
tracking (the replication-data + Changed-signal subscription) actually created for
instances - a subsystem FE leaves unwired. This is a reimplementation (register each
replicated instance for outgoing tracking so vfn[0x260] returns valid data), NOT a byte
patch. Server side does NOT filter incoming property changes (the 0x27446A0 receive
dispatcher's property handlers have no strictFilter reject), so once the client SENDS,
the server will apply them.

## 7. Immediate next steps
1. Walk `0x274C700` fully to name the pending container + push/drain method and
   the `ClientReplicator` accessor (Option B plumbing).
2. In the 2018 client, map `ClientReplicator` property-subscription setup to
   confirm whether Option A's single gate exists (VMP permitting; fall back to
   the clean `2018M.exe` for the shared serialize/enqueue code).
3. Prototype Option B enqueue behind `g_feEnabled`, test with one property
   change on one instance before generalizing.

## 7. DEFINITIVE DIAGNOSIS (this session) — outgoing property path fully traced

The entire outgoing property pipeline is INTACT and UNGATED except for the very
first link. Traced end-to-end on OffBlox.exe:

- `onCombinedSignal` = **0x28a6550**. Pure type-dispatcher on arg `r8d`:
  type0->0x28a6620, type1->0x28a6c50, **type2 (PROPERTY_CHANGED)->0x28a86d0**,
  type3->0x28a8020, type6->0x28a6120. **No per-instance/listenToChanges gate** —
  if it is called with type2, the property WILL be processed.
- Property-changed dispatcher = **0x28a86d0**. Args: rcx=Replicator,
  rdx=changeStruct (`[+8]=Instance*`, `[+0x18]`/`[+0x28]` = cached pending slots,
  null-guarded), r8=signalData (`[+8]=PropertyDescriptor*`).
  - Branches on global byte `G` @ **RVA 0xC584710** (default **0xd0**, nonzero):
    - G!=0 (current): **Mega** path. Gate `0x14299f440(repl,inst,propDesc,out)`
      then enqueue `0x14299f740`.
    - G==0: **legacy** path. filter `0x273f490` then enqueue `0x28b8490`
      (writes changed-set at **Replicator+0xad8**).
- Enqueue gate **0x14299f440** is NOT a subscription check — it passes for any
  replicable property (`[propDesc+0x68][0x37]!=0` AND attribute filter
  `0x273f490`) and fills the out-struct {instance,propDesc,value}. So for normal
  replicable props it returns TRUE.
- Send loop (slot134) **0x274C700** drains the **+0x35a0** outgoing subsystem
  (virtual `[sub+0x260]`/`[sub+0x2e0]`, gate `0x1428a4fc0` reading `+0x35a8`,
  stream `+0x2b90`). It does NOT touch +0xad8 — so the LEGACY path alone is a
  dead end (fills +0xad8, never drained). The **Mega** enqueue (0x14299f740)
  feeds +0x35a0 and IS what the send loop drains.

### Conclusion
Downstream (onCombinedSignal type2 -> dispatcher -> Mega gate -> enqueue ->
+0x35a0 subsystem -> send loop) is complete and ungated. New-instance
replication proves the subsystem+send work. The SOLE missing link: the client
never calls `onCombinedSignal` with type2 for replicated instances — the
**property-changed subscription/bind is stripped** (child-added is bound
separately, which is why NewInstance works). onCombinedSignal (0x28a6550) has NO
direct code/data xref (bound via boost bind thunk), so the bind site can't be
flipped by a simple xref patch.

### Chosen fix — native bridge (non-destructive, real ChangePropertyItems)
Re-add the subscription at the trigger level and drive the engine's OWN enqueue:
on each property change of a replicated instance, call
`0x28a86d0(g_clientRepl, &{.+8=Instance*, +0x18=0, +0x28=0}, &{.+8=PropertyDescriptor*})`.
This runs the real Mega enqueue -> +0x35a0 -> native send. No reparent, no
tearing instances out (so characters/NPCs/services are all safe), no cross-client
flood. Needs: (1) a per-change trigger giving (Instance*, PropertyDescriptor*)
— cleanest is a Lua `Changed` connection in the preamble calling a DLL export;
(2) DLL export resolves Instance* from the Lua object + PropertyDescriptor* by
name via reflection, builds the two stack structs, calls 0x28a86d0; (3) echo
guard (short per-(instance,prop) ignore window) if the server echoes back.

## 8. NATIVE BRIDGE plan (chosen approach) + cross-map reality

User chose the NATIVE engine path (drive the real ChangePropertyItem enqueue) over
an automatic RemoteEvent bridge.

CROSS-MAP REALITY: OffBlox.exe shares NO usable byte-signatures with the 2022
RobloxStudioBeta reference (win_studio_x64_0.550) — not even stable Luau API
functions (pushcclosurek prologue absent). The 2022 PDB is usable ONLY for
STRUCTURE/signatures, never addresses. Every OffBlox address must be found by
internal analysis and validated by (blind) user testing.

Reference signatures/structure from 2022 PDB (addresses are 2022, NOT OffBlox):
- Instance::raisePropertyChanged(const PropertyDescriptor&) @2022 0x1229D40 —
  fires combinedSignal @ instance+0xd0 with type=2; checks descriptor flags
  [desc+0x40]&5==1 && !(flags&0x30); FNV-hashes desc into changed set @ inst+0x88.
- lua_pushcclosurek(L,fn,name,nups,cont) @2022 0x21C4B30.
- ClassDescriptor::findPropertyDescriptor(const char* name) @2022 0x223EE60.

OffBlox anchors already known (this build):
- dispatcher (property-change enqueue) 0x28A86D0; args
  rcx=Replicator, rdx=changeStruct{+8=Instance*, +0x18=0, +0x28=0},
  r8=signalData{+8=PropertyDescriptor*}. Mega path (global byte @0xC584710=0xd0)
  -> gate 0x14299F440 (passes for replicable props) -> enqueue 0x14299F740 ->
  subsystem +0x35A0 -> send loop 0x274C700 (slot134).
- onCombinedSignal 0x28A6550 (type2->0x28A86D0, ungated).
- Luau API (OffBlox RVAs): lua_resume 0x664CD40, resume 0x664CE00,
  lua_newthread 0x6648FB0, lua_rawget 0x6649F10, luaS_newlstr 0x6674D50.
  pushcclosurek expected in same lapi region (0x664xxxx) — TODO find.

DESIGN (register-C-under-lock):
1. Resolve OffBlox pushcclosurek; register global C fn `__ofrepl(inst, propName)`.
2. Preamble: connect `Changed` on replicated instances (skip physics props
   Position/CFrame/Velocity/etc. — physics replicates via its own path, exactly
   as in 2016), call `__ofrepl(self, prop)`. Runs UNDER the DataModel lock (it's
   inside a live Lua callback) so the dispatcher call is safe.
3. `__ofrepl` (C): extract Instance* from the userdata; get its ClassDescriptor
   (offset TBD); findPropertyDescriptor(propName) -> PropertyDescriptor*; build
   changeStruct+signalData on stack; call 0x28A86D0(g_clientRepl, cs, sd).
4. Echo: skip if the incoming value equals the last-enqueued value for that
   (inst,prop) within a short window (server echo convergence usually suffices).

STAGED, low-risk builds (blind, so validate before enabling enqueue):
- Build V1: register __ofrepl, preamble Changed hook, __ofrepl only LOGS
  (instance ptr, prop name, resolved descriptor). NO dispatcher call. Confirms
  pushcclosurek, instance extraction, descriptor resolution via pipe log.
- Build V2: enable the dispatcher call. Confirms enqueue + native send.
- Open items to verify at V2: does the send flush without mode==1 (new-instance
  send works without it, so likely yes); echo behavior.

TODO OffBlox addresses to find (internal analysis): pushcclosurek; Instance
userdata payload layout (Instance* offset); Instance->ClassDescriptor offset.

## 9. V1 IMPLEMENTED (log-only queue drain) + primitives found

OffBlox primitives located (internal analysis, high confidence):
- lua_pushcclosurek = 0x6649540 (structure matches ref; L->global @ L+0x28).
- lua_setfield-family = 0x6649FB0 (takes L,int idx,const char* key; GLOBALSINDEX
  handling) - NOT verified set-vs-get; unused (chose queue approach instead).
- Luau tags this build: number=3, string=6, table=7, function=8, thread=10;
  userdata tag TBD (V1 logs it).

V1 mechanism (no pushcclosurek/setfield needed):
- Preamble queues {instance,propName} into bare globals __ofq/__ofp (count __ofn,
  gen __ofg), skipping physics props. Same TaskDefer/mainGT channel as
  __offblox_player (proven to work).
- DLL Hook_resume -> DrainOfq(L): throttled 150ms, reads __ofn/__ofg via fresh
  thread + RawGetGlobal, reads __ofq[i]/__ofp[i] via PushInt+rawget, LOGS the
  instance userdata tag + raw pointer + words at +0x00/10/18/20/28/30/38 and the
  prop name. NO enqueue yet -> cannot crash.
- Purpose: pin the Instance* offset inside the Luau userdata from the log, then
  V2 does: Instance* -> ClassDescriptor -> findPropertyDescriptor(prop) ->
  build changeStruct{+8=inst,+0x18=0,+0x28=0}+signalData{+8=desc} ->
  call dispatcher 0x28A86D0(g_clientRepl, cs, sd). Echo guard + send-flush
  (mode==1?) verified at V2.
