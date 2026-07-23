# Spec: D3D12 Raytracing Capture/Replay Backport

## Objective

Backport the smallest upstream RenderDoc fixes needed to prevent incomplete D3D12 raytracing
captures and incorrect raytracing replay, without importing the v1.45 resource-ID refactor or
changing SqCap injection, stealth, branding, or RDC format compatibility.

## Tech Stack

- C++ / D3D12 / DXR
- RenderDoc-derived capture and replay implementation
- Visual Studio 2022 MSBuild, Development x64

## Commands

- Build: `cmd /c "E:\work\sqcap_src\build_me.bat"`
- Static scope check:
  `git diff --name-only -- renderdoc/driver/d3d12 tasks/d3d12-rt-backport-*.md`
- Existing capture smoke test:
  `x64\Development\sanqicapture.exe replay "<capture.rdc>"`

## Project Structure

- `renderdoc/driver/d3d12/d3d12_device.*`: capture lifecycle and queue readback storage
- `renderdoc/driver/d3d12/d3d12_initstate.cpp`: resource and acceleration-structure initial data
- `renderdoc/driver/d3d12/d3d12_manager.cpp`: shader-table address patching and auditing
- `renderdoc/driver/d3d12/d3d12_command_list4_wrap.cpp`: DXR command serialisation/replay
- `renderdoc/driver/d3d12/d3d12_command_queue_wrap.cpp`: capture-time queue readback

## Code Style

Match the repository Chromium-derived `.clang-format` style and preserve the upstream implementation
shape. Adapt only API names that differ in the fork.

## Testing Strategy

- Compile the complete Development x64 solution.
- Check that the selected changes match upstream behavior at each affected branch.
- Replay an existing D3D12 raytracing RDC and inspect the resulting exit status/log.
- A new capture is required to prove capture-time completeness; an old RDC can only prove replay
  compatibility.

## Boundaries

- Always: preserve existing SqCap injection/stealth behavior and current D3D12 section version.
- Ask first: broad upstream merges, resource-ID refactors, or RDC format bumps.
- Never: overwrite unrelated dirty files, commit, push, or silently save an RDC after a detected
  capture-time readback failure.

## Success Criteria

- Sampler heaps are classified from the heap descriptor, not descriptor zero.
- AS patchbuffer lookup uses a stable chunk offset rather than a mutable event ID.
- Queue readback uses an unwrapped internal resource to avoid capture-end races.
- Fatal initial-state/AS readback failures abort and discard the capture instead of saving it.
- Upload-heap initial contents preserve the actual resource type.
- Development x64 builds successfully and existing capture replay reaches the normal replay path.

## Open Questions

- Whether all visually missing content is caused by these known upstream bugs requires a new capture
  and side-by-side inspection after the patched build.
