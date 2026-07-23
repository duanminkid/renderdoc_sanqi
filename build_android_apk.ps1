[CmdletBinding()]
param(
    [ValidateSet("all", "arm64-v8a", "armeabi-v7a")]
    [string]$Abi = "all",

    [ValidateSet("Development", "Release")]
    [string]$HostConfiguration = "Development",

    [string]$JavaHome = $env:JAVA_HOME,
    [string]$SdkRoot = $env:ANDROID_SDK_ROOT,
    [string]$NdkRoot = $env:ANDROID_NDK_ROOT,
    [string]$PlatformToolsRoot = "D:/Android/android-sdk/platform-tools",
    [string]$BuildToolsVersion = "26.0.1",
    [string]$ApkTarget = "android-23",
    [switch]$SkipBuild
)

$ErrorActionPreference = "Stop"
$RepoRoot = $PSScriptRoot

function Resolve-ToolRoot {
    param(
        [string]$Configured,
        [string[]]$Candidates,
        [string]$RequiredRelativePath,
        [string]$Description
    )

    foreach ($candidate in @($Configured) + $Candidates) {
        if ([string]::IsNullOrWhiteSpace($candidate)) {
            continue
        }

        $root = [IO.Path]::GetFullPath($candidate)
        if (Test-Path -LiteralPath (Join-Path $root $RequiredRelativePath)) {
            return $root
        }
    }

    throw "$Description not found. Expected '$RequiredRelativePath'. Pass the path explicitly."
}

function Invoke-Checked {
    param(
        [string]$Executable,
        [string[]]$Arguments,
        [string]$Description
    )

    & $Executable @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Description failed with exit code $LASTEXITCODE."
    }
}

$JavaHome = Resolve-ToolRoot $JavaHome @(
    "C:/Program Files/Java/jdk1.8.0_202",
    "C:/Program Files/Java/jdk-1.8"
) "bin/javah.exe" "JDK 8"

$SdkRoot = Resolve-ToolRoot $SdkRoot @(
    "D:/tools/sdk-tools-windows-3859397"
) "build-tools/$BuildToolsVersion/aapt.exe" "Android SDK build-tools $BuildToolsVersion"

$NdkRoot = Resolve-ToolRoot $NdkRoot @(
    "D:/tools/android-ndk-r14b-windows-x86_64/android-ndk-r14b"
) "build/cmake/android.toolchain.cmake" "Android NDK"

$PlatformToolsRoot = Resolve-ToolRoot $PlatformToolsRoot @(
    (Join-Path $SdkRoot "platform-tools")
) "adb.exe" "Android platform-tools"

$cmakeCommand = Get-Command cmake.exe -ErrorAction Stop
$ninjaCommand = Get-Command ninja.exe -ErrorAction Stop
$pythonLauncher = Get-Command py.exe -ErrorAction Stop

$buildTools = Join-Path $SdkRoot "build-tools/$BuildToolsVersion"
$aapt = Join-Path $buildTools "aapt.exe"
$apksigner = Join-Path $buildTools "apksigner.bat"
$androidJar = Join-Path $SdkRoot "platforms/$ApkTarget/android.jar"

foreach ($required in @(
    (Join-Path $JavaHome "bin/java.exe"),
    (Join-Path $JavaHome "bin/javac.exe"),
    (Join-Path $JavaHome "bin/javah.exe"),
    (Join-Path $JavaHome "bin/jar.exe"),
    $aapt,
    $apksigner,
    $androidJar
)) {
    if (-not (Test-Path -LiteralPath $required)) {
        throw "Required Android build tool not found: $required"
    }
}

$env:JAVA_HOME = $JavaHome
$env:ANDROID_SDK_ROOT = $SdkRoot
$env:ANDROID_NDK_ROOT = $NdkRoot
$env:PATH = "$(Join-Path $JavaHome 'bin');$env:PATH"

Invoke-Checked $pythonLauncher.Source @(
    (Join-Path $RepoRoot "scripts/check_android_package_identity.py")
) "Android package identity check"

$abis = if ($Abi -eq "all") { @("arm64-v8a", "armeabi-v7a") } else { @($Abi) }
$stageDir = Join-Path $RepoRoot "x64/$HostConfiguration/plugins/android"
New-Item -ItemType Directory -Path $stageDir -Force | Out-Null

foreach ($currentAbi in $abis) {
    $abiSuffix = if ($currentAbi -eq "arm64-v8a") { "arm64" } else { "arm32" }
    $buildDir = Join-Path $RepoRoot "build-android-$abiSuffix"
    $packageName = "com.sqcap.capture.sqcaptur.$abiSuffix"
    $apk = Join-Path $buildDir "bin/$packageName.apk"

    $configureArgs = @(
        "-S", $RepoRoot,
        "-B", $buildDir,
        "-G", "Ninja",
        "-DBUILD_ANDROID=1",
        "-DANDROID_ABI=$currentAbi",
        "-DCMAKE_BUILD_TYPE=Release",
        "-DSTRIP_ANDROID_LIBRARY=On",
        "-DUSE_INTERCEPTOR_LIB=Off",
        "-DCMAKE_MAKE_PROGRAM:FILEPATH=$($ninjaCommand.Source)",
        "-DANDROID_BUILD_TOOLS_VERSION:STRING=$BuildToolsVersion",
        "-DAPK_TARGET_ID:STRING=$ApkTarget",
        "-DJava_JAVA_EXECUTABLE:FILEPATH=$(Join-Path $JavaHome 'bin/java.exe')",
        "-DJava_JAVAC_EXECUTABLE:FILEPATH=$(Join-Path $JavaHome 'bin/javac.exe')",
        "-DJava_JAVAH_EXECUTABLE:FILEPATH=$(Join-Path $JavaHome 'bin/javah.exe')",
        "-DJava_JAR_EXECUTABLE:FILEPATH=$(Join-Path $JavaHome 'bin/jar.exe')",
        "-DJava_JAVADOC_EXECUTABLE:FILEPATH=$(Join-Path $JavaHome 'bin/javadoc.exe')"
    )

    if (-not $SkipBuild) {
        Invoke-Checked $cmakeCommand.Source $configureArgs "CMake configure for $currentAbi"
        Invoke-Checked $cmakeCommand.Source @("--build", $buildDir, "--parallel", "8") `
            "Android APK build for $currentAbi"
    }

    if (-not (Test-Path -LiteralPath $apk)) {
        throw "Android build completed without producing $apk"
    }

    $badging = (& $aapt dump badging $apk) -join "`n"
    if ($LASTEXITCODE -ne 0 -or $badging -notmatch "package: name='$([regex]::Escape($packageName))'") {
        throw "APK package identity verification failed for $apk"
    }
    if ($badging -notmatch "application-debuggable") {
        throw "APK is not marked debuggable: $apk"
    }
    if ($badging -notmatch "native-code: '$([regex]::Escape($currentAbi))'") {
        throw "APK does not contain native code for ${currentAbi}: $apk"
    }

    Invoke-Checked $apksigner @("verify", "--verbose", $apk) "APK signature verification"
    Copy-Item -LiteralPath $apk -Destination (Join-Path $stageDir "$packageName.apk") -Force
    Write-Output "Staged $packageName.apk"
}

foreach ($platformTool in @("adb.exe", "AdbWinApi.dll", "AdbWinUsbApi.dll")) {
    $source = Join-Path $PlatformToolsRoot $platformTool
    if (-not (Test-Path -LiteralPath $source)) {
        throw "Required platform tool not found: $source"
    }
    Copy-Item -LiteralPath $source -Destination (Join-Path $stageDir $platformTool) -Force
}

Write-Output "Android capture artifacts are ready in: $stageDir"
