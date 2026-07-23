# Steam Platform Capture Execution Plan

## Dependency Graph

Steam manifest resolver
  -> normal Steam URI launch
    -> scoped new-process discovery
      -> existing injection and target control
        -> hook registration outside DllMain
          -> build and runtime validation

## Tasks

- [x] Replace the Hogwarts-specific direct-AppID path with a generic manifest resolver.
- [x] Launch recognised Steam apps through the registered `steam://rungameid` protocol.
- [x] Discover and inject only newly-created processes inside the resolved game root.
- [x] Add a minimal parser self-check and static regression checks.
- [x] Keep Steam hook registration out of DllMain and require a marker handshake before injection is
  reported as successful.
- [x] Publish inline DXGI state only from the actual MinHook installation result; do not infer it from
  Steam paths or Overlay module presence.
- [x] Return synchronous Steam hook-registration failures to the injector instead of allowing a
  target-control identifier to mask them.
- [x] Remove the duplicate Steam DXGI factory IAT/GetProcAddress entry after runtime logs showed
  repeated re-entry before the trampoline returned.
- [x] Build Development x64 and inspect errors.
- [ ] Run the authorised Steam smoke test without triggering a frame capture. Pending explicit
  approval because launching a Steam title can touch save/cloud state.
- [x] Build Release x86/x64 into the existing output directories without creating a zip.

## Risks and Mitigations

| Risk | Mitigation |
|---|---|
| Injection happens after early graphics initialisation | Remove the old 500 ms delay and inject as soon as a scoped process appears. |
| Launcher is selected instead of the game | Prefer the exact selected EXE, then allow a bounded install-root fallback. |
| Selected EXE is itself a root bootstrapper | Prefer a larger same-named EXE deeper in the game tree without adding a per-game rule. |
| Steam Overlay detours DXGI before late injection | Acknowledge the PID marker in DllMain, register hooks later outside loader lock, and dispatch through inline DXGI only after its trampoline is ready. |
| Inline and IAT both publish the Steam factory hook | Keep factory IAT entries untouched and return the MinHook-detoured DXGI export from dynamic resolution. |
| DXGI is absent when Steam hook registration begins | Load the system DXGI module and complete the factory trampoline transaction synchronously outside DllMain; return failure instead of publishing a pending success. |
| A mod ships a game-local DXGI proxy | Treat this as a separate per-module chaining problem; do not claim the System32-only transaction covers modified games. |
| Existing game process is selected | Snapshot PIDs before launch and ignore all existing processes. |
| Steam state or saves are changed | Use the registered Steam URI; never forge AppID state or write the game directory. |
| Protected game rejects injection | Return an explicit injection failure; do not add bypass behaviour. |

## Checkpoints

- Resolver and static checks pass before any runtime launch.
- Development build passes before Steam smoke testing.
- Runtime must show a normal Steam launch before declaring Steam integration fully field-validated.
- Release outputs may be rebuilt after compile/static validation, but must retain the pending runtime
  note until the user runs an authorised Steam smoke test.
