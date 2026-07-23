# D3D12 Raytracing Backport Tasks

- [x] Backport queue readback race fix.
  - Acceptance: internal readback resource is never wrapped.
  - Verify: build and inspect all `QueueReadbackData` uses.
- [x] Backport fatal capture failure handling.
  - Acceptance: initial-state/AS readback failure discards the frame and reports a reason.
  - Verify: build plus branch-level source inspection.
- [x] Backport upload-heap initial-content type fix.
  - Acceptance: `D3D12InitialContents` receives the actual resource type.
  - Verify: exact one-line upstream semantic match.
- [x] Backport sampler heap classification fix.
  - Acceptance: direct, indirect, and audit paths use `heap->GetDesc().Type`.
  - Verify: no old `GetDescriptors()->GetType()` classification remains in RT patching.
- [x] Backport stable AS patchbuffer lookup.
  - Acceptance: replay keys dynamic AS builds with the chunk offset.
  - Verify: exact upstream semantic match and build.
- [x] Build and replay smoke test.
  - Acceptance: Development x64 build succeeds and an existing RDC reaches replay.
