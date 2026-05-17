param(
    [int]$Port = 8000,
    [string]$HostAddress = "0.0.0.0",
    [string]$PythonVersion = "3.12",
    [string]$ModelPath = "",
    [string]$LabelEncoderPath = "",
    [string]$CaptureInterface = "",
    [string]$CaptureFilter = "tcp or udp",
    [switch]$NoCapture,
    [switch]$UseWindowsFirewall,
    [switch]$SkipInstall,
    [switch]$OpenDashboard
)

$ErrorActionPreference = "Stop"

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Resolve-Python {
    param([string]$RequestedVersion)

    $candidates = @(
        @("py", "-$RequestedVersion"),
        @("py", "-3.11"),
        @("python", "")
    )

    foreach ($candidate in $candidates) {
        $command = $candidate[0]
        $versionArg = $candidate[1]

        try {
            $args = @()
            if ($versionArg) {
                $args += $versionArg
            }
            $args += "--version"
            $versionOutput = & $command @args 2>&1
            if ($LASTEXITCODE -ne 0) {
                continue
            }

            $versionText = ($versionOutput | Out-String).Trim()
            if ($versionText -match "3\.13\.0a") {
                Write-Warning "Skipping $versionText because alpha Python builds break some IDS dependencies."
                continue
            }

            $runArgs = @()
            if ($versionArg) {
                $runArgs += $versionArg
            }

            return @{
                Command = $command
                Args = $runArgs
                Version = $versionText
            }
        }
        catch {
            continue
        }
    }

    throw "Could not find a stable Python install. Install Python 3.12, then run: .\start_ids.ps1"
}

$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $projectRoot

Write-Host ""
Write-Host "ET-IDS full launcher" -ForegroundColor Cyan
Write-Host "Project: $projectRoot"

if (-not (Test-IsAdministrator)) {
    Write-Warning "Live packet capture on Windows usually requires PowerShell to be run as Administrator."
}

if (-not $NoCapture) {
    Write-Host "Live capture: enabled"
    Write-Host "Capture filter: $CaptureFilter"
    Write-Host "Npcap is required for Scapy live capture on Windows: https://npcap.com/#download"
}
else {
    Write-Host "Live capture: disabled"
}

$python = Resolve-Python -RequestedVersion $PythonVersion
Write-Host "Python: $($python.Version)"

if (-not $SkipInstall) {
    Write-Host "Installing/updating Python requirements..."
    & $python.Command @($python.Args + @("-m", "pip", "install", "-r", "requirements.txt"))
    if ($LASTEXITCODE -ne 0) {
        throw "Dependency installation failed."
    }
}

if ($ModelPath) {
    $env:IDS_MODEL_PATH = $ModelPath
}

if ($LabelEncoderPath) {
    $env:IDS_LABEL_ENCODER_PATH = $LabelEncoderPath
}

if ($CaptureInterface) {
    $env:IDS_CAPTURE_INTERFACE = $CaptureInterface
}

if ($CaptureFilter) {
    $env:IDS_CAPTURE_FILTER = $CaptureFilter
}

$env:IDS_AUTO_START = if ($NoCapture) { "false" } else { "true" }
$env:IDS_BLOCK_MODE = if ($UseWindowsFirewall) { "windows_firewall" } else { "memory" }

$dashboardUrl = "http://localhost:$Port"
Write-Host ""
Write-Host "Starting ET-IDS dashboard..." -ForegroundColor Green
Write-Host "Open: $dashboardUrl"
Write-Host "Press Ctrl+C to stop the server."
Write-Host ""

if ($OpenDashboard) {
    Start-Process $dashboardUrl
}

& $python.Command @($python.Args + @("-m", "uvicorn", "fastapi_ids_backend:app", "--host", $HostAddress, "--port", "$Port"))
