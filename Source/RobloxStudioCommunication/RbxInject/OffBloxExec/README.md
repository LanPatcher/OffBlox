# OffBloxExec

A DLL that runs Luau on the live OffBlox DataModel, receiving scripts over a bidirectional named pipe (a C# client can connect). Same engine as the in-process console build — only the I/O differs. The console project is untouched.

**RbxInject loads this DLL automatically, and only when the host is NOT launched with `-task StartServer`** (i.e. normal client/Studio). The StartServer build drives execution from its in-process console instead; loading both would double-hook the engine, so RbxInject skips this DLL in that case.

## What it does

On load it:

1. Patches loadstring's two "not available" gates (RobloxScript-context + LoadStringEnabled) so loadstring compiles in every context.
2. Inline-hooks the engine's internal coroutine `resume` for an on-thread execution point.
3. Auto-detects the live game VM (the DataModel whose `Workspace` has more than one child) and only executes there.
4. Runs each received script with elevated Proto capabilities (full Instance/DataModel access), on throwaway threads whose fake ExtraSpace is nulled before GC.

## Pipe

- Name: `\\.\pipe\OffBloxExec` (duplex, message mode).
- **client → DLL:** each message (one `WriteFile`) is one Luau script to run.
- **DLL → client:** status / error / result messages, e.g. `server VM locked ...`, `ran: <code>`, `run error: ...`, and `=> <value>` when a script returns a string/number.

> `print(...)` output still goes to the host process stdout, not the pipe. The pipe returns status, errors, and the script's **return value**. (Live `print` capture would need an added LogService hook.)

## Build

Add `OffBloxExec.vcxproj` to the `RobloxStudioCommunication` solution (Add → Existing Project) and build **Release | x64**, or build it standalone from a *Developer Command Prompt for VS*:

```
msbuild OffBloxExec.vcxproj /p:Configuration=Release /p:Platform=x64
```

> It's a C++ project — build with **MSBuild / Visual Studio, not `dotnet`**.

A post-build step copies `OffBloxExec.dll` into `Clients\OffBlox\` next to `RbxInject.dll`, so RbxInject can load it. Static CRT (`/MT`), no runtime deps.

## Run

1. Launch OffBlox normally (any task except `-task StartServer`). RbxInject injects `OffBloxExec.dll` automatically — check `Clients\OffBlox\RbxInject.log` for a `pipe=0x...` line.
2. Connect the client and send scripts.

### C# client (included, in `Client/`)

```
cd Client
dotnet run                 # interactive: type a line, Enter to run, blank line quits
dotnet run -- myscript.lua # send a whole file as one script
```

### Minimal C# to embed elsewhere

```csharp
using var pipe = new NamedPipeClientStream(".", "OffBloxExec", PipeDirection.InOut);
pipe.Connect(5000);
pipe.ReadMode = PipeTransmissionMode.Message;
byte[] b = System.Text.Encoding.UTF8.GetBytes("workspace:GetChildren()[1].Name");
pipe.Write(b, 0, b.Length);   // one Write == one script
```

## Notes

- Install-time messages (`gate patched`, `installed`) happen before any client connects, so they appear in a debugger (DebugView / `OutputDebugString`), not the pipe. Everything after a client connects goes to the pipe.
- The first script you send triggers game-VM detection; you'll get `server VM locked (workspace children=N) - ready` once, then commands run there.
- Multi-line scripts are fine — send the whole thing as a single pipe message.
