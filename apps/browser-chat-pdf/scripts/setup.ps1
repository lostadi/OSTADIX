#!/usr/bin/env pwsh

[CmdletBinding()]
param(
    [Parameter()]
    [string] $InstallDir,

    [Parameter()]
    [switch] $NoOpen,

    [Parameter()]
    [switch] $RunTests
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$SourceRoot = [IO.Path]::GetFullPath((Join-Path $ScriptDir ".."))
$AllowlistPath = Join-Path $ScriptDir "runtime-files.txt"
$MarkerText = "chatprint-managed-install-v1"

function Get-RuntimeFiles {
    $Entries = [Collections.Generic.List[string]]::new()
    foreach ($RawLine in [IO.File]::ReadAllLines($AllowlistPath)) {
        $Line = $RawLine.Trim()
        if (-not $Line -or $Line.StartsWith("#")) {
            continue
        }
        if ([IO.Path]::IsPathRooted($Line) -or $Line.Contains("\") -or
            $Line -eq ".." -or $Line.StartsWith("../") -or
            $Line.Contains("/../") -or $Line.EndsWith("/..") -or
            $Line.Contains("//")) {
            throw "Unsafe runtime allowlist entry: $Line"
        }
        $Entries.Add($Line)
    }
    if ($Entries.Count -eq 0) {
        throw "Runtime allowlist is empty"
    }
    return $Entries.ToArray()
}

function Assert-BasicValidation {
    param(
        [Parameter(Mandatory)] [string] $Root,
        [Parameter(Mandatory)] [string[]] $RuntimeFiles
    )

    foreach ($Relative in $RuntimeFiles) {
        $Candidate = Join-Path $Root $Relative
        if (-not (Test-Path -LiteralPath $Candidate -PathType Leaf)) {
            throw "Missing regular runtime file: $Relative"
        }
        $Item = Get-Item -LiteralPath $Candidate -Force
        if (($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Runtime file must not be a symbolic link: $Relative"
        }
    }

    $Manifest = Get-Content -LiteralPath (Join-Path $Root "manifest.json") -Raw | ConvertFrom-Json
    if ($Manifest.manifest_version -ne 3) {
        throw "manifest.json is not Manifest V3"
    }

    $ExpectedPermissions = @("activeTab", "scripting", "storage") | Sort-Object
    $ActualPermissions = @($Manifest.permissions) | Sort-Object
    if (($ExpectedPermissions -join "`n") -cne ($ActualPermissions -join "`n")) {
        throw "Manifest permissions must be exactly: activeTab, scripting, storage"
    }

    foreach ($Forbidden in @(
        "host_permissions",
        "optional_permissions",
        "optional_host_permissions",
        "externally_connectable",
        "key",
        "update_url"
    )) {
        if ($Manifest.PSObject.Properties.Name -contains $Forbidden) {
            throw "Manifest must not define $Forbidden"
        }
    }
}

function Test-InstallCurrent {
    param(
        [Parameter(Mandatory)] [string] $Destination,
        [Parameter(Mandatory)] [string] $Marker,
        [Parameter(Mandatory)] [string[]] $RuntimeFiles
    )

    if (-not (Test-Path -LiteralPath $Destination -PathType Container) -or
        -not (Test-Path -LiteralPath $Marker -PathType Leaf)) {
        return $false
    }
    if ((Get-Content -LiteralPath $Marker -Raw).Trim() -cne $MarkerText) {
        return $false
    }

    $InstalledItems = @(Get-ChildItem -LiteralPath $Destination -Recurse -Force)
    foreach ($Item in $InstalledItems) {
        if (($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            return $false
        }
    }
    $InstalledFiles = @($InstalledItems | Where-Object { -not $_.PSIsContainer })
    if ($InstalledFiles.Count -ne $RuntimeFiles.Count) {
        return $false
    }
    foreach ($Relative in $RuntimeFiles) {
        $SourceHash = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $SourceRoot $Relative)).Hash
        $InstalledPath = Join-Path $Destination $Relative
        if (-not (Test-Path -LiteralPath $InstalledPath -PathType Leaf)) {
            return $false
        }
        $InstalledHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $InstalledPath).Hash
        if ($SourceHash -cne $InstalledHash) {
            return $false
        }
    }
    return $true
}

function Open-ExtensionManager {
    $Candidates = @(
        @{ Path = (Join-Path $env:LOCALAPPDATA "Google\Chrome\Application\chrome.exe"); Url = "chrome://extensions" },
        @{ Path = (Join-Path $env:ProgramFiles "Google\Chrome\Application\chrome.exe"); Url = "chrome://extensions" },
        @{ Path = (Join-Path $env:LOCALAPPDATA "BraveSoftware\Brave-Browser\Application\brave.exe"); Url = "brave://extensions" },
        @{ Path = (Join-Path $env:ProgramFiles "BraveSoftware\Brave-Browser\Application\brave.exe"); Url = "brave://extensions" },
        @{ Path = (Join-Path $env:ProgramFiles "Microsoft\Edge\Application\msedge.exe"); Url = "edge://extensions" },
        @{ Path = (Join-Path $env:LOCALAPPDATA "Microsoft\Edge\Application\msedge.exe"); Url = "edge://extensions" }
    )
    if (${env:ProgramFiles(x86)}) {
        $Candidates += @(
            @{ Path = (Join-Path ${env:ProgramFiles(x86)} "Google\Chrome\Application\chrome.exe"); Url = "chrome://extensions" },
            @{ Path = (Join-Path ${env:ProgramFiles(x86)} "Microsoft\Edge\Application\msedge.exe"); Url = "edge://extensions" }
        )
    }

    foreach ($Candidate in $Candidates) {
        if (Test-Path -LiteralPath $Candidate.Path -PathType Leaf) {
            Start-Process -FilePath $Candidate.Path -ArgumentList $Candidate.Url | Out-Null
            return $true
        }
    }
    return $false
}

$RuntimeFiles = @(Get-RuntimeFiles)
Assert-BasicValidation -Root $SourceRoot -RuntimeFiles $RuntimeFiles

$Node = Get-Command node -ErrorAction SilentlyContinue
if ($Node) {
    & $Node.Source (Join-Path $ScriptDir "validate.mjs") --root $SourceRoot
    if ($LASTEXITCODE -ne 0) {
        throw "Full source validation failed"
    }
}

if ($RunTests) {
    $Npm = Get-Command npm -ErrorAction SilentlyContinue
    if (-not $Npm) {
        throw "npm is required by -RunTests"
    }
    Push-Location $SourceRoot
    try {
        & $Npm.Source ci --ignore-scripts
        if ($LASTEXITCODE -ne 0) { throw "npm ci failed" }
        & $Npm.Source test
        if ($LASTEXITCODE -ne 0) { throw "npm test failed" }
    }
    finally {
        Pop-Location
    }
}

if (-not $InstallDir) {
    if (-not $env:LOCALAPPDATA) {
        throw "LOCALAPPDATA is unavailable; pass -InstallDir explicitly"
    }
    $InstallDir = Join-Path $env:LOCALAPPDATA "Chatprint\extension"
}
$InstallPath = [IO.Path]::GetFullPath($InstallDir)
$InstallParent = Split-Path -Parent $InstallPath
if (-not $InstallParent -or $InstallPath -eq [IO.Path]::GetPathRoot($InstallPath)) {
    throw "Refusing unsafe install path: $InstallPath"
}
New-Item -ItemType Directory -Path $InstallParent -Force | Out-Null
$MarkerPath = "$InstallPath.chatprint-managed"

if (Test-Path -LiteralPath $MarkerPath) {
    $MarkerItem = Get-Item -LiteralPath $MarkerPath -Force
    if (-not (Test-Path -LiteralPath $MarkerPath -PathType Leaf) -or
        ($MarkerItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        (Get-Content -LiteralPath $MarkerPath -Raw).Trim() -cne $MarkerText) {
        throw "Foreign management marker exists: $MarkerPath"
    }
}
if (Test-Path -LiteralPath $InstallPath) {
    $InstallItem = Get-Item -LiteralPath $InstallPath -Force
    if (($InstallItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Refusing a symbolic-link install directory: $InstallPath"
    }
    if (-not (Test-Path -LiteralPath $MarkerPath -PathType Leaf)) {
        throw "Refusing to replace foreign directory without Chatprint marker: $InstallPath"
    }
}

$BackupPath = $null
$StagePath = $null
if (Test-InstallCurrent -Destination $InstallPath -Marker $MarkerPath -RuntimeFiles $RuntimeFiles) {
    Write-Host "Chatprint is already current at $InstallPath"
}
else {
    $StagePath = Join-Path $InstallParent (".chatprint-stage-" + [Guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Path $StagePath | Out-Null
    try {
        foreach ($Relative in $RuntimeFiles) {
            $SourceFile = Join-Path $SourceRoot $Relative
            $DestinationFile = Join-Path $StagePath $Relative
            $DestinationParent = Split-Path -Parent $DestinationFile
            New-Item -ItemType Directory -Path $DestinationParent -Force | Out-Null
            Copy-Item -LiteralPath $SourceFile -Destination $DestinationFile
            $SourceHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $SourceFile).Hash
            $DestinationHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $DestinationFile).Hash
            if ($SourceHash -cne $DestinationHash) {
                throw "Copy verification failed: $Relative"
            }
        }

        Assert-BasicValidation -Root $StagePath -RuntimeFiles $RuntimeFiles
        if ($Node) {
            & $Node.Source (Join-Path $ScriptDir "validate.mjs") --root $StagePath --quiet
            if ($LASTEXITCODE -ne 0) { throw "Full staged-install validation failed" }
        }

        if (Test-Path -LiteralPath $InstallPath) {
            $Timestamp = [DateTime]::UtcNow.ToString("yyyyMMddTHHmmssZ")
            $BackupPath = "$InstallPath.backup-$Timestamp-$PID"
            Move-Item -LiteralPath $InstallPath -Destination $BackupPath
        }

        try {
            Move-Item -LiteralPath $StagePath -Destination $InstallPath
            $StagePath = $null
        }
        catch {
            if ($BackupPath -and -not (Test-Path -LiteralPath $InstallPath) -and
                (Test-Path -LiteralPath $BackupPath)) {
                Move-Item -LiteralPath $BackupPath -Destination $InstallPath
            }
            throw
        }

        $MarkerTemp = "$MarkerPath.tmp.$PID"
        [IO.File]::WriteAllText($MarkerTemp, "$MarkerText`n")
        Move-Item -LiteralPath $MarkerTemp -Destination $MarkerPath -Force

        Write-Host "Installed Chatprint at $InstallPath"
        if ($BackupPath) {
            Write-Host "Previous managed install backed up at $BackupPath"
        }
    }
    finally {
        if ($StagePath -and (Test-Path -LiteralPath $StagePath)) {
            Remove-Item -LiteralPath $StagePath -Recurse -Force
        }
    }
}

$ClipboardNote = ""
try {
    Set-Clipboard -Value $InstallPath -ErrorAction Stop
    $ClipboardNote = " (path copied to clipboard)"
}
catch {
    # Clipboard support is optional on headless systems.
}

$Opened = $false
if (-not $NoOpen) {
    $Opened = Open-ExtensionManager
}

Write-Host ""
Write-Host "Finish in your desktop browser:"
if ($NoOpen -or -not $Opened) {
    Write-Host "  1. Open chrome://extensions (or edge://extensions / brave://extensions)."
}
else {
    Write-Host "  1. Use the extensions page that was opened."
}
Write-Host "  2. Turn on Developer mode."
Write-Host "  3. Click Load unpacked and select:"
Write-Host "     $InstallPath$ClipboardNote"
Write-Host ""
Write-Host "Chromium requires that final Load unpacked confirmation; normal extensions cannot bypass it."
