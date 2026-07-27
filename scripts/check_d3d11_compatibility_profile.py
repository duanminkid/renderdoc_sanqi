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
PERSISTENT_CONFIG = ROOT / "qrenderdoc/Code/Interface/PersistantConfig.h"


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
    persistent_config = PERSISTENT_CONFIG.read_text(encoding="utf-8")

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
        persistent_config,
        "D3D11InlineCaptureExecutables",
        "validated executable strategy persistence",
    )
    require(
        dialog_source,
        "NormaliseCaptureExecutable",
        "canonical executable strategy identity",
    )
    require(
        dialog_source,
        "SetD3D11InlineCapturePreference",
        "successful strategy learning",
    )
    forbid(
        dialog_source,
        "MigrateMostRecentD3D11InlinePreference",
        "unverified most-recent setting migration",
    )
    require(
        dialog_source,
        "QStandardPaths::findExecutable(executable)",
        "PATH executable strategy identity",
    )
    require(
        dialog_source,
        "if(settings.inject || compatibilityModificationCount > 0)",
        "loaded setting preserves learned auto strategy when unspecified",
    )
    require(
        dialog_source,
        "on_D3D11Compatibility_clicked(bool checked)",
        "manual strategy disable handler",
    )
    require(
        dialog_source,
        "if(checked || m_Inject || m_Ctx.Replay().CurrentRemote().IsValid())",
        "manual disable does not learn or affect remote capture",
    )
    require(
        dialog_source,
        "m_D3D11PreferenceGeneration++;",
        "manual disable invalidates pending preference callbacks",
    )
    require(
        dialog_source,
        "d3d11PreferenceGeneration == m_D3D11PreferenceGeneration",
        "stale preference callback rejection",
    )
    manual_disable = dialog_source[
        dialog_source.index("void CaptureDialog::on_D3D11Compatibility_clicked") :
        dialog_source.index("void CaptureDialog::vulkanLayerWarn_mouseClick")
    ]
    if manual_disable.index("m_D3D11PreferenceGeneration++;") > manual_disable.index(
        "SetD3D11InlineCapturePreference"
    ):
        raise AssertionError("manual disable invalidates pending callbacks after deleting preference")
    preference_callback_start = dialog_source.index("const uint64_t d3d11PreferenceGeneration")
    preference_callback = dialog_source[
        preference_callback_start :
        dialog_source.index("if(ui->queueFrameCap->isChecked())", preference_callback_start)
    ]
    if preference_callback.index(
        "d3d11PreferenceGeneration == m_D3D11PreferenceGeneration"
    ) > preference_callback.index("SetD3D11InlineCapturePreference"):
        raise AssertionError("stale callback guard is evaluated after writing preference")
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
        'AddEnvMod(env, "SQC_D3D11_DEFERRED_LIGHT_PROFILE", "1");',
        "legacy YuanShen selector publishes generic D3D11 family",
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
        "d3d11InlineCaptureProfile =\n      yuanShenDirectSystemLoad || deferredD3D11LightProfile",
        "target profile selection",
    )
    target_profile_selection = entry_source[
        entry_source.index("const bool yuanShenDirectSystemLoad") :
        entry_source.index("const bool hogwartsGameCapture")
    ]
    require(
        target_profile_selection,
        'if(yuanShenDirectSystemLoad)\n'
        '    SetEnvironmentVariableA("SQC_D3D11_DEFERRED_LIGHT_PROFILE", "1")',
        "legacy YuanShen marker conditionally backfills generic D3D11 family in target",
    )
    if target_profile_selection.index(
        'SetEnvironmentVariableA("SQC_D3D11_DEFERRED_LIGHT_PROFILE", "1")'
    ) > target_profile_selection.index("const bool deferredD3D11LightProfile"):
        raise AssertionError("legacy YuanShen marker is backfilled after generic family selection")
    require(
        entry_source,
        'f == "yuanshen.exe" && !d3d11InlineCaptureProfile',
        "generic D3D11 family bypasses YuanShen diagnostic early-out",
    )
    require(
        process_source,
        "if(deferredD3D11LightProfile && !directSystemLoad)",
        "generic launch-only guard preserves YuanShen attach and proxy fallback",
    )
    direct_hook_start = entry_source[
        entry_source.index("INTERNAL_StartYuanShenDirectHooks") :
        entry_source.index("INTERNAL_StartSteamHooks")
    ]
    require(
        direct_hook_start,
        'SetEnvironmentVariableA("SQC_D3D11_DEFERRED_LIGHT_PROFILE", "1")',
        "legacy YuanShen remote start publishes generic D3D11 family",
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
        "d3d11InlineCaptureHooks || dxgiInlineHooks",
        "generic full-inline transaction",
    )
    required_inline_hooks = hook_source[
        hook_source.index('if(libraryName == "d3d11.dll")') :
        hook_source.index("return false;", hook_source.index('if(libraryName == "d3d11.dll")'))
    ]
    for function_name in (
        "D3D11CreateDevice",
        "D3D11CreateDeviceAndSwapChain",
        "CreateDXGIFactory",
        "CreateDXGIFactory1",
        "CreateDXGIFactory2",
    ):
        require(
            required_inline_hooks,
            f'functionName == "{function_name}"',
            f"required D3D11 family hook {function_name}",
        )
    require(
        hook_source,
        "const size_t expectedHooks = hogwartsDXGIOnly ? 3 : 5;",
        "D3D11 family requires all five inline hooks",
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
    require(
        process_source,
        "IsSteamManagedPath(app)",
        "generic Steam path routing",
    )
    require(
        process_source,
        'AddEnvMod(steamEnv, "SQC_STEAM_GAME_CAPTURE", "1");',
        "generic Steam family marker",
    )
    forbid(
        entry_source,
        "steamCapture ? LibraryHookRegistration",
        "Steam API registration remains All",
    )
    registration_selection = entry_source[
        entry_source.index("LibraryHooks::RegisterHooks(") :
        entry_source.index("const bool d3d11HooksApplied")
    ]
    require(
        registration_selection,
        "d3d11InlineCaptureProfile",
        "D3D11 family owns narrow D3D11 registration",
    )
    require(
        registration_selection,
        "hogwartsGameCapture",
        "Hogwarts owns narrow D3D12 registration",
    )
    require(
        registration_selection,
        "LibraryHookRegistration::All",
        "unclassified and Steam targets retain All API registration",
    )
    forbid(
        registration_selection.lower(),
        "steam",
        "Steam cannot participate in narrow API registration selection",
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
