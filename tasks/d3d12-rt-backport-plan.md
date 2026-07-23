# Plan: D3D12 Raytracing Capture/Replay Backport

1. Backport upstream capture integrity fixes:
   - `d20295cf4` queue readback race avoidance.
   - `1a3a79da0` fatal capture failure detection.
2. Backport upstream initial-state correction:
   - `d00c563e8` preserve upload-heap resource type.
3. Backport upstream DXR replay/patching fixes:
   - `3c5a63f2a` classify sampler heaps from heap metadata.
   - `13b6d9a85` key AS patchbuffers by chunk offset.
4. Format only touched C++ files and inspect the exact diff.
5. Build Development x64 and smoke-test an existing RDC.
6. Record which claims are compile-proven, replay-proven, and still require a fresh capture.
