param(
    [string]$Interface = 'auto',
    [ValidateSet('cuda', 'cpu')][string]$Device = 'cuda',
    [switch]$Status,
    [switch]$NoDashboard,
    [switch]$Restart
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$runtimeRoot = Join-Path $repoRoot 'artifacts\runtime'
$logRoot = Join-Path $runtimeRoot 'logs'
$captureRoot = Join-Path $runtimeRoot 'capture'

function Show-NetwatchStatus {
    $services = if ($NoDashboard) {
        @(
            @{ Name = 'Detection'; Url = 'http://127.0.0.1:8902/detections' },
            @{ Name = 'Forecast'; Url = 'http://127.0.0.1:8901/forecast' }
        )
    } else {
        @(
            @{ Name = 'Capture'; Url = 'http://127.0.0.1:8787/api/status' },
            @{ Name = 'Detection'; Url = 'http://127.0.0.1:8787/api/detections' },
            @{ Name = 'Forecast'; Url = 'http://127.0.0.1:8787/api/forecast' }
        )
    }
    foreach ($service in $services) {
        try {
            $response = Invoke-RestMethod -Uri $service.Url -TimeoutSec 5
            if ($service.Name -eq 'Capture') {
                "Capture: connected=$($response.connected), interface=$($response.interface)"
                if ($response.route_mismatch) {
                    "WARNING: capture is on $($response.interface), but the active route is $($response.active_route_interface). Rerun tools/run_windows.ps1 -Interface auto -Restart."
                }
            } elseif ($service.Name -eq 'Detection') {
                "Detection: $($response.status), device=$($response.device), packets=$($response.packets), scored=$($response.events_scored)"
                if ($response.device) { "Detection model: Running in $($response.device.ToUpperInvariant())" }
                $first = $response.thresholds.PSObject.Properties | Select-Object -First 1
                if ($first -and $first.Value.live_calibration) {
                    $cal = $first.Value.live_calibration
                    "Detection live calibration: ready=$($cal.ready), elapsed=$([math]::Round($cal.elapsed_s / 3600, 2))/$([math]::Round($cal.window_s / 3600, 2)) h, $($cal.samples) scored flows per family"
                }
            } else {
                "Forecast: $($response.status), device=$($response.device) $($response.reason)"
                if ($response.device) { "World model: Running in $($response.device.ToUpperInvariant())" }
                if ($response.threshold -and $response.threshold.live_calibration) {
                    $cal = $response.threshold.live_calibration
                    "World-model live calibration: ready=$($cal.ready), elapsed=$([math]::Round($cal.elapsed_s / 3600, 2))/$([math]::Round($cal.window_s / 3600, 2)) h, $($cal.samples) scored flows"
                }
            }
        } catch {
            "$($service.Name): unavailable ($($_.Exception.Message))"
        }
    }
}

if ($Status) {
    Show-NetwatchStatus
    return
}

if ($Interface -eq 'auto') {
    $up = @(Get-NetAdapter -ErrorAction Stop | Where-Object Status -eq 'Up')
    $routes = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -AddressFamily IPv4 -ErrorAction Stop |
        Where-Object { $up.Name -contains $_.InterfaceAlias } |
        Sort-Object { $_.RouteMetric + $_.InterfaceMetric })
    if ($routes.Count -eq 0) { throw 'No active routed interface found. Connect LAN/Wi-Fi or pass -Interface NAME.' }
    $Interface = $routes[0].InterfaceAlias
}
Write-Host "Selected capture interface: $Interface"
$safeInterface = $Interface -replace '[^A-Za-z0-9_-]', '_'
$captureRoot = Join-Path $runtimeRoot "capture-$safeInterface"
$forecastRoot = Join-Path $runtimeRoot "forecast-$safeInterface"
$detectionCalibration = Join-Path $runtimeRoot "calibration\detection-4h-$safeInterface.sqlite"
$worldCalibration = Join-Path $runtimeRoot "calibration\world-4h-$safeInterface.sqlite"
if ($Interface -eq 'Wi-Fi') {
    $oldDetectionCalibration = Join-Path $runtimeRoot 'calibration\detection-4h.sqlite'
    $oldWorldCalibration = Join-Path $runtimeRoot 'calibration\world-4h.sqlite'
    if (Test-Path -LiteralPath $oldDetectionCalibration) { $detectionCalibration = $oldDetectionCalibration }
    if (Test-Path -LiteralPath $oldWorldCalibration) { $worldCalibration = $oldWorldCalibration }
}
$previousInterfaceFile = Join-Path $runtimeRoot 'capture-interface.txt'

$env:Path = [Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' +
    [Environment]::GetEnvironmentVariable('Path', 'User')
$javaRoot = Get-ChildItem -Directory 'C:\Program Files\Eclipse Adoptium' -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -like 'jdk-8*' } | Select-Object -First 1
if ($javaRoot) {
    $env:JAVA_HOME = $javaRoot.FullName
    $env:Path = (Join-Path $javaRoot.FullName 'bin') + ';' + $env:Path
}
$env:Path = 'C:\Program Files\Wireshark;C:\Windows\System32\Npcap;' + $env:Path
$pythonExe = Join-Path $repoRoot '.venv\Scripts\python.exe'
$modelRegistry = Join-Path $repoRoot 'artifacts\current\serving.json'
if (-not (Test-Path -LiteralPath $pythonExe) -or -not (Test-Path -LiteralPath $modelRegistry)) {
    throw 'Run tools/setup.sh --dataset none with Git Bash before starting Netwatch.'
}
Push-Location $repoRoot
try {
    & $pythonExe -m models.serving.device --device $Device
    if ($LASTEXITCODE -ne 0) { throw 'Model device check failed. Run uv sync --frozen, or explicitly select -Device cpu.' }
} finally { Pop-Location }
foreach ($tool in @('java', 'javac', 'tshark', 'dumpcap', 'go')) {
    Get-Command $tool -ErrorAction Stop | Out-Null
}
$captureDevices = @(& tshark -D 2>&1)
if ($LASTEXITCODE -ne 0) { throw 'Wireshark cannot list capture devices. Install Npcap first.' }
if (-not ($captureDevices | Where-Object { $_.ToString().Contains("($Interface)") })) {
    throw "Capture interface '$Interface' is not available to Npcap. Available devices:`n$($captureDevices -join "`n")"
}
New-Item -ItemType Directory -Force $logRoot, $captureRoot | Out-Null

# All three model/capture processes must use the same interface. On a rerun
# after a LAN/Wi-Fi switch, restart only processes launched from this checkout.
$previousInterface = if (Test-Path -LiteralPath $previousInterfaceFile) {
    (Get-Content -LiteralPath $previousInterfaceFile -Raw).Trim()
} else { '' }
$runningDetector = Get-CimInstance Win32_Process | Where-Object {
    $_.Name -eq 'python.exe' -and $_.CommandLine -and $_.CommandLine.Contains($repoRoot) -and
    $_.CommandLine.Contains('models.serving.detect_live') -and $_.CommandLine.Contains('--port')
} | Select-Object -First 1
$detectorOnSelectedInterface = $runningDetector -and (
    $runningDetector.CommandLine.Contains('"--interface" "' + $Interface + '"') -or
    $runningDetector.CommandLine.Contains("--interface `"$Interface`"") -or
    $runningDetector.CommandLine.Contains("--interface $Interface ")
)
$detectorOnSelectedDevice = $runningDetector -and ($runningDetector.CommandLine -match ('--device["\s]+{0}(?:["\s]|$)' -f $Device))
$runningForecast = Get-CimInstance Win32_Process | Where-Object {
    $_.Name -eq 'python.exe' -and $_.CommandLine -and $_.CommandLine.Contains($repoRoot) -and
    $_.CommandLine.Contains('models.serving.live') -and $_.CommandLine.Contains('--port')
} | Select-Object -First 1
$forecastOnSelectedDevice = $runningForecast -and ($runningForecast.CommandLine -match ('--device["\s]+{0}(?:["\s]|$)' -f $Device))
if ($Restart -or ($previousInterface -and $previousInterface -ne $Interface) -or
    ($runningDetector -and (-not $detectorOnSelectedInterface -or -not $detectorOnSelectedDevice)) -or
    ($runningForecast -and -not $forecastOnSelectedDevice)) {
    Write-Host "Restarting this checkout's services for interface '$Interface' (previous '$previousInterface')."
    $managed = @(Get-CimInstance Win32_Process | Where-Object {
        $_.Name -in @('python.exe', 'dumpcap.exe', 'netwatch.exe') -and
        $_.CommandLine -and $_.CommandLine.Contains($repoRoot) -and (
            $_.CommandLine.Contains('models.serving.detect_live') -or
            $_.CommandLine.Contains('models.serving.live') -or
            ($_.CommandLine.Contains('dashboard') -and $_.CommandLine.Contains('netwatch.exe')) -or
            ($_.Name -eq 'dumpcap.exe' -and $_.CommandLine.Contains((Join-Path $runtimeRoot 'capture')))
        )
    })
    foreach ($managedProcess in $managed) {
        if (-not (Get-Process -Id $managedProcess.ProcessId -ErrorAction SilentlyContinue)) { continue }
        try { & taskkill.exe /PID $managedProcess.ProcessId /T /F 2>&1 | Out-Null }
        catch { } # /T may already have stopped this child before its turn.
        for ($wait = 0; $wait -lt 20 -and (Get-Process -Id $managedProcess.ProcessId -ErrorAction SilentlyContinue); $wait++) {
            Start-Sleep -Milliseconds 100
        }
        if (Get-Process -Id $managedProcess.ProcessId -ErrorAction SilentlyContinue) {
            throw "Could not stop Netwatch process $($managedProcess.ProcessId) before switching interfaces."
        }
    }
    Start-Sleep -Seconds 1
}

function Start-NetwatchService([string]$Name, [string]$Executable, [string[]]$Arguments, [string]$Signature) {
    $existing = Get-CimInstance Win32_Process | Where-Object {
        $_.ExecutablePath -eq $Executable -and $_.CommandLine -and $_.CommandLine.Contains($Signature)
    } | Select-Object -First 1
    if ($existing) {
        "$Name already running (PID $($existing.ProcessId))"
        return
    }
    $quotedArguments = $Arguments | ForEach-Object { '"' + $_.Replace('"', '\"') + '"' }
    $process = Start-Process -FilePath $Executable -ArgumentList $quotedArguments -WorkingDirectory $repoRoot `
        -WindowStyle Hidden -RedirectStandardOutput (Join-Path $logRoot "$Name-$safeInterface.out.log") `
        -RedirectStandardError (Join-Path $logRoot "$Name-$safeInterface.err.log") -PassThru
    "$Name started (PID $($process.Id))"
}

$cliExe = Join-Path $runtimeRoot 'netwatch.exe'
# Rebuild whenever the dashboard is not running, so it never serves a build older than the source (an unchanged
# rebuild is quick); a running executable is locked and is replaced only by -Restart, which stopped it above.
$dashboardRunning = Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -eq $cliExe } | Select-Object -First 1
if (-not $NoDashboard -and ($Restart -or -not $dashboardRunning)) {
    $env:GOCACHE = Join-Path $repoRoot 'cli\.gocache'
    $env:GOPATH = Join-Path $repoRoot 'cli\.gopath'
    Push-Location (Join-Path $repoRoot 'cli')
    try {
        & go build -o $cliExe .
        if ($LASTEXITCODE -ne 0) { throw 'Netwatch CLI build failed.' }
    } finally { Pop-Location }
}

Start-NetwatchService 'capture' (Get-Command dumpcap).Source @(
    '-i', $Interface, '-F', 'pcap', '-b', 'duration:30', '-b', 'files:40',
    '-w', (Join-Path $captureRoot 'live.pcap')
) $captureRoot
Start-NetwatchService 'detection' $pythonExe @(
    '-u', '-m', 'models.serving.detect_live', '--interface', $Interface, '--device', $Device, '--port', '8902',
    '--live-calibration-hours', '4',
    '--calibration-db', $detectionCalibration,
    '--incident-db', (Join-Path $runtimeRoot 'incidents.sqlite'),
    '--incident-import-log', (Join-Path $logRoot 'detection-before-history.log')
) 'models.serving.detect_live'
Start-NetwatchService 'forecast' $pythonExe @(
    '-u', '-m', 'models.serving.live', '--input', $captureRoot, '--work', $forecastRoot,
    '--device', $Device, '--port', '8901', '--live-calibration-hours', '4',
    '--calibration-db', $worldCalibration
) 'models.serving.live'
Set-Content -LiteralPath $previousInterfaceFile -Value $Interface
if (-not $NoDashboard) {
    Start-NetwatchService 'dashboard' $cliExe @(
        'dashboard', '--interface', $Interface, '--model-service', 'lag', '--no-browser', '--port', '8787',
        '--config', (Join-Path $repoRoot 'cli\config.yaml')
    ) 'dashboard'
    'Dashboard: http://127.0.0.1:8787'
} else {
    'Dashboard/frontend: not started. Detection: http://127.0.0.1:8902/detections; forecast: http://127.0.0.1:8901/forecast'
}
'The forecast needs more than four minutes of capture and may take longer to build on high-volume traffic; detection starts immediately.'
for ($attempt = 0; $attempt -lt 45; $attempt++) {
    try {
        $captureReady = $NoDashboard -or (Invoke-RestMethod -Uri 'http://127.0.0.1:8787/api/status' -TimeoutSec 2).connected
        $detectorReady = (Invoke-RestMethod -Uri 'http://127.0.0.1:8902/detections' -TimeoutSec 2).status -eq 'RUNNING'
        if ($captureReady -and $detectorReady) { break }
    } catch { }
    Start-Sleep -Seconds 2
}
Show-NetwatchStatus
