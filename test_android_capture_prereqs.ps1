[CmdletBinding()]
param(
    [string]$DeviceId,
    [string]$PackageName,
    [string]$AdbPath = "$PSScriptRoot/x64/Development/plugins/android/adb.exe",
    [string]$ArtifactsPath = "$PSScriptRoot/x64/Development/plugins/android"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $AdbPath)) {
    throw "adb was not found at '$AdbPath'. Build/stage the Android artifacts first."
}

function Invoke-CheckedAdb {
    param([string[]]$Arguments)

    $output = (& $AdbPath @Arguments 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) {
        throw "adb $($Arguments -join ' ') failed with exit code $LASTEXITCODE.`n$output"
    }
    return $output
}

function Stop-Preflight {
    param([string]$Message)

    [Console]::Error.WriteLine($Message)
    exit 2
}

$deviceOutput = (& $AdbPath devices -l 2>&1 | Out-String).Trim()
if ($LASTEXITCODE -ne 0) {
    throw "adb devices failed with exit code $LASTEXITCODE.`n$deviceOutput"
}

$devices = @()
foreach ($line in ($deviceOutput -split "`r?`n")) {
    if ($line -match '^(?<id>\S+)\s+(?<state>device|unauthorized|offline)\b') {
        $devices += [PSCustomObject]@{
            Id = $Matches.id
            State = $Matches.state
            Description = $line
        }
    }
}

if ($DeviceId) {
    $selected = @($devices | Where-Object Id -eq $DeviceId)
    if ($selected.Count -eq 0) {
        Stop-Preflight "Android device '$DeviceId' was not reported by adb.`n$deviceOutput"
    }
} else {
    $authorized = @($devices | Where-Object State -eq "device")
    if ($authorized.Count -eq 0) {
        $blocked = @($devices | Where-Object State -ne "device")
        if ($blocked.Count -gt 0) {
            Stop-Preflight "No authorized Android device is available. Unlock the phone and accept the USB debugging prompt.`n$deviceOutput"
        } else {
            Stop-Preflight "No Android device is connected. Connect a phone with USB debugging enabled."
        }
    }
    if ($authorized.Count -gt 1) {
        Stop-Preflight "Multiple authorized Android devices are connected. Pass -DeviceId.`n$deviceOutput"
    }
    $selected = $authorized
}

$device = $selected[0]
if ($device.State -ne "device") {
    Stop-Preflight "Android device '$($device.Id)' is $($device.State). Unlock/authorize it before capture."
}

$adbTarget = @("-s", $device.Id)
$apiLevel = Invoke-CheckedAdb ($adbTarget + @("shell", "getprop", "ro.build.version.sdk"))
$abiList = Invoke-CheckedAdb ($adbTarget + @("shell", "getprop", "ro.product.cpu.abilist"))
if ([string]::IsNullOrWhiteSpace($abiList)) {
    $abiList = Invoke-CheckedAdb ($adbTarget + @("shell", "getprop", "ro.product.cpu.abi"))
}

$helperSuffix = if ($abiList -match '(^|,)arm64-v8a(,|$)') {
    "arm64"
} elseif ($abiList -match '(^|,)armeabi-v7a(,|$)') {
    "arm32"
} else {
    throw "Device ABI '$abiList' is unsupported. This MVP currently ships ARM64/ARM32 helpers only."
}
$helperApk = Join-Path $ArtifactsPath "com.sqcap.capture.sqcaptur.$helperSuffix.apk"
if (-not (Test-Path -LiteralPath $helperApk)) {
    throw "Matching Android helper APK is missing: $helperApk"
}

$features = Invoke-CheckedAdb ($adbTarget + @("shell", "pm", "list", "features"))
$vulkanSupported = $features -match 'android\.hardware\.vulkan'

$result = [ordered]@{
    DeviceId = $device.Id
    ApiLevel = $apiLevel
    AbiList = $abiList
    NativeGpuLayers = ([int]$apiLevel -ge 29)
    VulkanFeature = $vulkanSupported
    HelperApk = $helperApk
}

if ($PackageName) {
    $packagePath = Invoke-CheckedAdb ($adbTarget + @("shell", "pm", "path", $PackageName))
    if ($packagePath -notmatch '^package:') {
        throw "Target package '$PackageName' is not installed on device '$($device.Id)'."
    }

    $packageDump = Invoke-CheckedAdb ($adbTarget + @("shell", "dumpsys", "package", $PackageName))
    $activity = Invoke-CheckedAdb ($adbTarget + @(
        "shell", "cmd", "package", "resolve-activity",
        "-c", "android.intent.category.LAUNCHER", $PackageName
    ))
    if ([string]::IsNullOrWhiteSpace($activity) -or $activity -match 'No activity found') {
        throw "Target package '$PackageName' has no resolvable launcher Activity."
    }

    $result.PackageName = $PackageName
    $result.Debuggable = $packageDump -match '(?m)\bDEBUGGABLE\b'
    $result.LaunchActivity = $activity
}

[PSCustomObject]$result | Format-List

if (-not $vulkanSupported) {
    Write-Warning "The device does not advertise an Android Vulkan feature; the Vulkan-first capture path may be unavailable."
}

if ([int]$apiLevel -lt 29) {
    Write-Warning "Android API $apiLevel predates native GPU debug layers. Capture will require the existing JDWP fallback."
}

if ($PackageName -and -not $result.Debuggable) {
    Write-Warning "Target package '$PackageName' is not marked debuggable; the non-root MVP may not capture it."
}
