# Run once to install Netwatch's Windows prerequisites, then start capture,
# detection, forecasting, and the interactive Go CLI. Re-running is safe.
# The React frontend and the Go dashboard are intentionally not started.
# Usage: powershell -ExecutionPolicy Bypass -File .\start-netwatch.ps1 [-Interface 'Wi-Fi']
param(
    [string]$Interface = 'auto',
    [ValidateSet('cuda', 'cpu')][string]$Device = 'cuda',
    [switch]$SkipSetup,
    [string]$ModelAccount = 'kaustuk000',
    [string]$ModelRevision = 'v1.0.0',
    [switch]$Help
)

if ($Help) {
    'Usage: .\start-netwatch.cmd [-Interface Wi-Fi] [-Device cuda|cpu] [-SkipSetup] [-ModelAccount account] [-ModelRevision tag]'
    'Installs missing prerequisites, starts capture and both models, then opens the interactive CLI.'
    'No frontend or dashboard is started.'
    return
}

$ErrorActionPreference = 'Stop'
$repoRoot = $PSScriptRoot
$runtimeRoot = Join-Path $repoRoot 'artifacts\runtime'
$cliExe = Join-Path $runtimeRoot 'netwatch-cli.exe'
$pythonExe = Join-Path $repoRoot '.venv\Scripts\python.exe'
$currentModel = Join-Path $repoRoot 'artifacts\current'

function Update-NetwatchPath {
    $machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    $extra = @('C:\Program Files\Git\cmd', 'C:\Program Files\Go\bin',
               'C:\Program Files\Wireshark', 'C:\Windows\System32\Npcap')
    $jdk8 = Get-ChildItem -Directory 'C:\Program Files\Eclipse Adoptium' -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like 'jdk-8*' } | Sort-Object Name -Descending | Select-Object -First 1
    if ($jdk8) {
        $env:JAVA_HOME = $jdk8.FullName
        $extra = @(Join-Path $jdk8.FullName 'bin') + $extra
    }
    $env:Path = (($extra | Where-Object { Test-Path -LiteralPath $_ }) -join ';') + ';' + $machinePath + ';' + $userPath
}

function Install-NetwatchPackage([string]$PackageId, [switch]$Interactive) {
    if ($SkipSetup) { throw "$PackageId is required. Re-run without -SkipSetup to install it." }
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        throw "$PackageId is required and winget is unavailable. Install Windows App Installer, then re-run."
    }
    Write-Host "Installing $PackageId..."
    $wingetArgs = @('install', '--id', $PackageId, '--exact', '--source', 'winget',
                    '--accept-source-agreements', '--accept-package-agreements')
    if ($Interactive) { $wingetArgs += '--interactive' } else { $wingetArgs += '--silent' }
    & winget @wingetArgs
    if ($LASTEXITCODE -ne 0) { throw "$PackageId installation failed (exit $LASTEXITCODE)." }
    Update-NetwatchPath
}

function Require-Tool([string]$Command, [string]$PackageId, [switch]$Interactive) {
    Update-NetwatchPath
    if (Get-Command $Command -ErrorAction SilentlyContinue) { return }
    Install-NetwatchPackage $PackageId -Interactive:$Interactive
    if (-not (Get-Command $Command -ErrorAction SilentlyContinue)) {
        throw "$PackageId installed, but $Command is still not on PATH. Open a new PowerShell session and re-run."
    }
}

function Invoke-Checked([string]$Description, [scriptblock]$Command) {
    Write-Host "== $Description"
    & $Command
    if ($LASTEXITCODE -ne 0) { throw "$Description failed (exit $LASTEXITCODE)." }
}

function Get-NetwatchJavacVersion {
    # JDK 8 prints a successful version check to stderr. Windows PowerShell
    # treats that as NativeCommandError when ErrorActionPreference is Stop.
    $ErrorActionPreference = 'Continue'
    $version = (& javac -version 2>&1 | ForEach-Object { $_.ToString() } | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) { throw "javac version check failed: $version" }
    return $version
}

function Resolve-NetwatchInterface([string]$Requested) {
    if ($Requested -ne 'auto') { return $Requested }
    $up = @(Get-NetAdapter -ErrorAction Stop | Where-Object Status -eq 'Up')
    $routes = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -AddressFamily IPv4 -ErrorAction Stop |
        Where-Object { $up.Name -contains $_.InterfaceAlias } |
        Sort-Object { $_.RouteMetric + $_.InterfaceMetric })
    if ($routes.Count -gt 0) { return $routes[0].InterfaceAlias }
    throw 'No active routed capture interface was found. Connect LAN/Wi-Fi or pass -Interface NAME.'
}

Push-Location $repoRoot
try {
    Require-Tool 'git' 'Git.Git'
    Require-Tool 'go' 'GoLang.Go'
    $goVersion = (& go version | Out-String).Trim()
    if ($goVersion -notmatch 'go(\d+)\.(\d+)' -or [int]$Matches[1] -lt 1 -or
        ([int]$Matches[1] -eq 1 -and [int]$Matches[2] -lt 21)) {
        if ($SkipSetup) { throw "Netwatch needs Go 1.21 or newer; found '$goVersion'." }
        Write-Host "Upgrading Go 1.21+ (found '$goVersion')..."
        & winget upgrade --id GoLang.Go --exact --source winget --silent --accept-source-agreements --accept-package-agreements
        if ($LASTEXITCODE -ne 0) { throw 'Go upgrade failed. Install Go 1.21 or newer, then re-run.' }
        Update-NetwatchPath
        $goVersion = (& go version | Out-String).Trim()
        if ($goVersion -notmatch 'go(\d+)\.(\d+)' -or [int]$Matches[1] -lt 1 -or
            ([int]$Matches[1] -eq 1 -and [int]$Matches[2] -lt 21)) {
            throw "Go is still too old after upgrade: '$goVersion'. Open a new PowerShell session and re-run."
        }
    }
    Require-Tool 'uv' 'astral-sh.uv'
    Require-Tool 'javac' 'EclipseAdoptium.Temurin.8.JDK'
    $javacVersion = Get-NetwatchJavacVersion
    if ($javacVersion -notmatch '^javac (1\.8\.|8\.)') {
        if ($SkipSetup) { throw "CICFlowMeter needs JDK 8; found '$javacVersion'. Re-run without -SkipSetup." }
        Install-NetwatchPackage 'EclipseAdoptium.Temurin.8.JDK'
        $javacVersion = Get-NetwatchJavacVersion
        if ($javacVersion -notmatch '^javac (1\.8\.|8\.)') {
            throw "CICFlowMeter needs JDK 8; found '$javacVersion' after installation."
        }
    }

    # Wireshark's interactive installer includes Npcap; its silent installer does not.
    Require-Tool 'tshark' 'WiresharkFoundation.Wireshark' -Interactive
    Require-Tool 'dumpcap' 'WiresharkFoundation.Wireshark' -Interactive
    $Interface = Resolve-NetwatchInterface $Interface
    Write-Host "Selected active capture interface: $Interface"
    $captureDevices = @(& tshark -D 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw 'Npcap/capture devices are unavailable. Run the Wireshark installer interactively, select Install Npcap, then re-run.'
    }
    if (-not ($captureDevices | Where-Object { $_.ToString().Contains($Interface) })) {
        throw "Capture interface '$Interface' was not found. Available devices:`n$($captureDevices -join "`n")"
    }

    if (-not $SkipSetup) {
        Invoke-Checked 'Sync Python dependencies' { & uv sync --frozen }
        if (-not (Test-Path -LiteralPath $pythonExe)) { throw "Python environment missing: $pythonExe" }

        $flowDir = Join-Path $repoRoot 'tools\CICFlowMeter'
        if (-not (Test-Path -LiteralPath (Join-Path $flowDir 'gradlew.bat'))) {
            Invoke-Checked 'Fetch CICFlowMeter submodule' { & git submodule update --init tools/CICFlowMeter }
        }
        if (-not (Test-Path -LiteralPath (Join-Path $flowDir 'gradlew.bat'))) {
            throw 'CICFlowMeter Gradle wrapper is missing after submodule checkout.'
        }
        $flowCommit = (& git -C $flowDir rev-parse HEAD 2>$null | Out-String).Trim()
        if ($flowCommit -ne 'acaf8bea8611fb4b996b4d33964dfd9155d9efdf') {
            throw "CICFlowMeter is at $flowCommit, not the pinned setup commit. Preserve local changes and restore the submodule before re-running."
        }
        Push-Location $flowDir
        try {
            $gradleOverride = Join-Path $repoRoot 'tools\repo\cicflowmeter.gradle'
            Invoke-Checked 'Build CICFlowMeter' { & .\gradlew.bat -q -I $gradleOverride compileJava '-PpcapDir=-' '-PoutputDir=-' }
        } finally { Pop-Location }

        if (-not (Test-Path -LiteralPath $currentModel)) {
            $modelRepo = "$ModelAccount/netwatch-flow-cascade"
            Invoke-Checked "Download model $modelRepo@$ModelRevision" {
                & uv run --frozen --with huggingface_hub python tools/publish/download.py --repo $modelRepo --revision $ModelRevision
            }
            $downloaded = Join-Path $repoRoot 'artifacts\huggingface\download\netwatch-flow-cascade'
            if (-not (Test-Path -LiteralPath (Join-Path $downloaded 'serving.json'))) {
                throw 'Model download finished without serving.json. Check the published model and Hugging Face access.'
            }
            New-Item -ItemType Junction -Path $currentModel -Target $downloaded | Out-Null
        }
    }

    if (-not (Test-Path -LiteralPath $pythonExe)) {
        throw "Python environment missing: $pythonExe. Re-run without -SkipSetup."
    }
    foreach ($relative in @('flow_encoder.pt', 'detection_encoder.pt', 'forecasting_encoder.pt',
                             'compressor.pt', 'world_model.pt', 'serving.json')) {
        if (-not (Test-Path -LiteralPath (Join-Path $currentModel $relative))) {
            throw "Model checkpoint missing: $relative. Existing artifacts/current was not replaced."
        }
    }
    if (-not (Get-ChildItem (Join-Path $currentModel 'detector') -Filter 'head_*.pt' -ErrorAction SilentlyContinue)) {
        throw 'No detector heads found in artifacts/current/detector.'
    }

    New-Item -ItemType Directory -Force $runtimeRoot | Out-Null
    $env:GOCACHE = Join-Path $repoRoot 'cli\.gocache'
    $env:GOPATH = Join-Path $repoRoot 'cli\.gopath'
    Push-Location (Join-Path $repoRoot 'cli')
    try { Invoke-Checked 'Build Netwatch CLI' { & go build -o $cliExe . } }
    finally { Pop-Location }

    Write-Host '== Start capture, detection, and forecast (no frontend or dashboard)'
    & (Join-Path $repoRoot 'tools\run_windows.ps1') -Interface $Interface -Device $Device -NoDashboard
    if (-not $?) { throw 'Netwatch services failed to start.' }

    Write-Host ''
    Write-Host 'Netwatch CLI is ready. Type help for commands, model for a model snapshot, or exit to leave the CLI.'
    Write-Host 'Services continue in the background after the CLI exits. Logs: artifacts\runtime\logs'
    & $cliExe --config (Join-Path $repoRoot 'cli\config.yaml')
    if ($LASTEXITCODE -ne 0) { throw "Netwatch CLI exited with code $LASTEXITCODE." }
} finally {
    Pop-Location
}
