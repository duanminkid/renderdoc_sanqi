#!/usr/bin/env python3

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PROCESS_SOURCE = ROOT / "renderdoc/os/win32/win32_process.cpp"
ENTRY_SOURCE = ROOT / "renderdoc/os/win32/win32_libentry.cpp"
HOOK_SOURCE = ROOT / "renderdoc/os/win32/win32_hook.cpp"
D3D11_SOURCE = ROOT / "renderdoc/driver/d3d11/d3d11_hooks.cpp"
HOOK_HEADER = ROOT / "renderdoc/hooks/hooks.h"
DIALOG_SOURCE = ROOT / "qrenderdoc/Windows/Dialogs/CaptureDialog.cpp"
DIALOG_UI = ROOT / "qrenderdoc/Windows/Dialogs/CaptureDialog.ui"


def require(source: str, text: str, label: str) -> None:
    if text not in source:
        raise AssertionError(f"{label}: missing {text!r}")


def forbid(source: str, text: str, label: str) -> None:
    if text in source:
        raise AssertionError(f"{label}: forbidden {text!r}")


def main() -> None:
    process_source = PROCESS_SOURCE.read_text(encoding="utf-8")
    entry_source = ENTRY_SOURCE.read_text(encoding="utf-8")
    hook_source = HOOK_SOURCE.read_text(encoding="utf-8")
    d3d11_source = D3D11_SOURCE.read_text(encoding="utf-8")
    hook_header = HOOK_HEADER.read_text(encoding="utf-8")
    dialog_source = DIALOG_SOURCE.read_text(encoding="utf-8")
    dialog_ui = DIALOG_UI.read_text(encoding="utf-8")

    # ponytail: this textual check intentionally guards a small, stable set of branch invariants.
    # Upgrade to an AST-based check only if these functions begin moving or generating code.
    require(dialog_ui, 'name="D3D11Compatibility"', "launch UI")
    require(dialog_ui, "D3D11 Compatibility Launch", "launch UI")
    require(dialog_source, '"SQC_D3D11_DEFERRED_LIGHT_PROFILE"', "saved launch setting")
    require(
        dialog_source,
        "!ret.inject && ui->D3D11Compatibility->isChecked()",
        "launch-only setting",
    )
    require(
        dialog_source,
        "if(!ret.inject || !IsD3D11CompatibilityProfile(mod))",
        "attach marker filtering",
    )
    require(
        dialog_source,
        "compatibilityModificationCount == 1",
        "ordered setting preservation",
    )
    require(
        entry_source,
        'SQCEnvIsOne("SQC_D3D11_DEFERRED_LIGHT_PROFILE")',
        "canonical target marker",
    )
    require(
        process_source,
        "coordinatedD3D11Target = yuanShenDirectTarget || deferredD3D11LightTarget",
        "injector coordination",
    )
    require(
        process_source,
        "ApplyEnvModifications(envValues, env, false);",
        "ordered environment evaluation",
    )
    require(
        process_source,
        "D3D11 Compatibility Launch cannot be combined with D3D11 Proxy Launch.",
        "proxy rejection",
    )
    require(
        process_source,
        "D3D11 Compatibility Launch cannot capture child processes.",
        "child capture rejection",
    )
    require(
        process_source,
        "cannot be used with Steam URI launch.",
        "Steam rejection",
    )
    require(
        process_source,
        "process coordinator.",
        "attach coordinator rejection",
    )
    require(
        entry_source,
        "d3d11DirectSystemLoad = yuanShenDirectSystemLoad || deferredD3D11LightProfile",
        "target profile selection",
    )
    require(
        entry_source,
        "? LibraryHookRegistration::D3D11AndDXGI",
        "D3D11/DXGI-only registration",
    )
    require(
        hook_source,
        'SQCEnvIsOne("SQC_D3D11_DEFERRED_LIGHT_PROFILE")',
        "generic inline transaction selection",
    )
    require(
        hook_source,
        "d3d11CompatibilityInlineHooks || yuanShenInlineHooks || dxgiInlineHooks",
        "generic full-inline transaction",
    )
    require(
        hook_header,
        "D3D11AndDXGIInlineHooksDispatchReady()",
        "dedicated full inline readiness",
    )
    require(
        d3d11_source,
        "LibraryHooks::D3D11AndDXGIInlineHooksDispatchReady()",
        "D3D11 trampoline dispatch",
    )
    require(
        entry_source,
        "LibraryHooks::D3D11AndDXGIInlineHooksDispatchReady()",
        "generic hook-ready validation",
    )

    enable_failure = hook_source[
        hook_source.index('"%s inline MH_EnableHook failed status=%d"') :
        hook_source.index("return false;", hook_source.index('"%s inline MH_EnableHook failed status=%d"'))
    ]
    forbid(
        enable_failure,
        "InterlockedExchange(&s_SQCInlineHooksDispatchReady, 0)",
        "enable failure cleanup keeps DXGI trampoline dispatch live until teardown",
    )
    forbid(
        enable_failure,
        "InterlockedExchange(&s_SQCD3D11AndDXGIInlineHooksDispatchReady, 0)",
        "enable failure cleanup keeps D3D11 trampoline dispatch live until teardown",
    )

    begin_registration = hook_source[
        hook_source.index("void LibraryHooks::BeginHookRegistration()") :
        hook_source.index("bool LibraryHooks::HooksApplied()")
    ]
    forbid(
        begin_registration,
        "InterlockedExchange(&s_SQCInlineHooksDispatchReady, 0)",
        "repeat registration cannot hide live DXGI detours",
    )
    forbid(
        begin_registration,
        "InterlockedExchange(&s_SQCD3D11AndDXGIInlineHooksDispatchReady, 0)",
        "repeat registration cannot hide live D3D11 detours",
    )

    require(entry_source, '"SQC_YUANSHEN_DIRECT_SYSTEM_LOAD"', "YuanShen profile")
    require(entry_source, '"SQC_HOGWARTS_GAME_CAPTURE"', "Hogwarts profile")
    require(
        entry_source,
        'SQCProcessNameMatches(processPath, L"YuanShen.exe")',
        "YuanShen-only module stealth",
    )

    injection_core = (process_source + entry_source + hook_source + d3d11_source).lower()
    if "starrail.exe" in injection_core or "sqc_starrail" in injection_core:
        raise AssertionError("generic injection core contains a StarRail-specific predicate")

    print("D3D11 compatibility profile static checks passed.")


if __name__ == "__main__":
    main()
