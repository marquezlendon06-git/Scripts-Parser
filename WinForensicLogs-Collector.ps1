<#
.SYNOPSIS
    Collects Windows event logs and system artifacts for forensic investigation.

.DESCRIPTION
    Exports security-relevant Windows event logs and optional system artifacts
    (network config, processes, services, scheduled tasks) to a timestamped
    folder under C:\ForensicLogs\. Supports full collection or targeted
    collection of specific log channels.

.PARAMETER Logs
    One or more event log names to collect. When omitted, all logs are collected.

.PARAMETER IncludeArtifacts
    Also collect system artifacts (SystemInfo, NetworkInfo, Processes, Services,
    ScheduledTasks) during a targeted -Logs run. Always collected in full mode.

.PARAMETER ListLogs
    Print all available log names and exit without collecting anything.

.PARAMETER SkipZip
    Do not compress the output folder after collection. By default, the folder
    is zipped and a SHA256 hash of the archive is printed.

.PARAMETER Help
    Show this help message and exit.

.EXAMPLE
    .\Collect-ForensicLogs.ps1
    Full collection — all logs, system artifacts, and a zipped archive.

.EXAMPLE
    .\Collect-ForensicLogs.ps1 -Logs "Security"
    Collect only the Security event log, then zip.

.EXAMPLE
    .\Collect-ForensicLogs.ps1 -Logs "Security","System" -IncludeArtifacts
    Collect two specific logs plus all system artifacts, then zip.

.EXAMPLE
    .\Collect-ForensicLogs.ps1 -SkipZip
    Full collection without compressing the output folder.

.EXAMPLE
    .\Collect-ForensicLogs.ps1 -ListLogs
    List all available log names.
#>
param (
    [string[]]$Logs             = @(),
    [switch]$IncludeArtifacts,
    [switch]$SkipZip,
    [switch]$ListLogs,
    [Alias('h')]
    [switch]$Help
)

$AllLogs = @(
    "Security",
    "System",
    "Application",
    "Microsoft-Windows-PowerShell/Operational",
    "Microsoft-Windows-Sysmon/Operational",
    "Microsoft-Windows-Windows Defender/Operational",
    "Microsoft-Windows-TaskScheduler/Operational",
    "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
    "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational",
    "Microsoft-Windows-DNS-Client/Operational",
    "Microsoft-Windows-NetworkProfile/Operational",
    "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
    "Microsoft-Windows-LSA/Operational",
    "Microsoft-Windows-Authentication/AuthenticationPolicyFailures-DomainController",
    "Microsoft-Windows-PrintService/Operational",
    "Microsoft-Windows-Windows Defender/WHC",
    "Microsoft-Windows-AppLocker/EXE and DLL",
    "Microsoft-Windows-AppLocker/MSI and Script",
    "Microsoft-Windows-BitLocker/BitLocker Management",
    "Microsoft-Windows-CodeIntegrity/Operational",
    "Microsoft-Windows-WMI-Activity/Operational",
    "Microsoft-Windows-Bits-Client/Operational",
    "Microsoft-Windows-WinRM/Operational",
    "Microsoft-Windows-SMBClient/Connectivity",
    "Microsoft-Windows-SMBServer/Operational",
    "Microsoft-Windows-Kerberos/Operational",
    "Microsoft-Windows-CAPI2/Operational",
    "Microsoft-Windows-Security-Mitigations/KernelMode"
)

if ($Help) {
    Write-Host ""
    Write-Host "Collect-ForensicLogs.ps1" -ForegroundColor Cyan
    Write-Host "Windows forensic log and artifact collector" -ForegroundColor Gray
    Write-Host ""
    Write-Host "USAGE" -ForegroundColor Yellow
    Write-Host "  .\Collect-ForensicLogs.ps1 [OPTIONS]"
    Write-Host ""
    Write-Host "OPTIONS" -ForegroundColor Yellow
    Write-Host "  -Logs <string[]>     " -ForegroundColor White -NoNewline
    Write-Host "Collect one or more specific logs (comma-separated)"
    Write-Host "  -IncludeArtifacts    " -ForegroundColor White -NoNewline
    Write-Host "Also collect SystemInfo, Network, Processes, Services, Tasks"
    Write-Host "                       (always included in full mode)"
    Write-Host "  -SkipZip             " -ForegroundColor White -NoNewline
    Write-Host "Skip compression of the output folder (zip is created by default)"
    Write-Host "  -ListLogs            " -ForegroundColor White -NoNewline
    Write-Host "Print all available log names and exit"
    Write-Host "  -Help, -h            " -ForegroundColor White -NoNewline
    Write-Host "Show this help message and exit"
    Write-Host ""
    Write-Host "EXAMPLES" -ForegroundColor Yellow
    Write-Host "  .\Collect-ForensicLogs.ps1" -ForegroundColor Gray
    Write-Host "      Full collection (all logs + artifacts)"
    Write-Host ""
    Write-Host '  .\Collect-ForensicLogs.ps1 -Logs "Security"' -ForegroundColor Gray
    Write-Host "      Collect only the Security event log"
    Write-Host ""
    Write-Host '  .\Collect-ForensicLogs.ps1 -Logs "Security","System" -IncludeArtifacts' -ForegroundColor Gray
    Write-Host "      Collect two specific logs plus all system artifacts"
    Write-Host ""
    Write-Host '  .\Collect-ForensicLogs.ps1 -ListLogs' -ForegroundColor Gray
    Write-Host "      Print all available log names"
    Write-Host ""
    Write-Host "OUTPUT" -ForegroundColor Yellow
    Write-Host "  Logs are saved to: C:\ForensicLogs\<ComputerName>_<Timestamp>\"
    Write-Host ""
    exit 0
}

if ($ListLogs) {
    Write-Host "`nAvailable logs for collection:" -ForegroundColor Cyan
    $AllLogs | ForEach-Object { Write-Host "  $_" -ForegroundColor White }
    Write-Host "`nUsage examples:" -ForegroundColor Cyan
    Write-Host '  .\Collect-ForensicLogs.ps1' -ForegroundColor Gray
    Write-Host '  .\Collect-ForensicLogs.ps1 -Logs "Security"' -ForegroundColor Gray
    Write-Host '  .\Collect-ForensicLogs.ps1 -Logs "Security","System"' -ForegroundColor Gray
    Write-Host '  .\Collect-ForensicLogs.ps1 -Logs "Security" -IncludeArtifacts' -ForegroundColor Gray
    exit 0
}

Start-Sleep -Seconds 1

$TargetedMode = $Logs.Count -gt 0

if ($TargetedMode) {
    Write-Host "Initializing Targeted Log Collection..." -ForegroundColor Yellow

    $LogsToCollect = @()
    foreach ($entry in $Logs) {
        if ($AllLogs -contains $entry) {
            $LogsToCollect += $entry
        } else {
            Write-Host "WARNING: '$entry' is not in the known log list and will be skipped." -ForegroundColor Red
            Write-Host "         Run -ListLogs to see available log names." -ForegroundColor DarkYellow
        }
    }

    if ($LogsToCollect.Count -eq 0) {
        Write-Host "No valid logs specified. Exiting." -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "Initializing Full Log Collection..." -ForegroundColor Yellow
    $LogsToCollect = $AllLogs
}

Start-Sleep -Seconds 1

$ComputerName = $env:COMPUTERNAME
$CurrentDate  = Get-Date -Format "yyyyMMdd_HHmmss"
$BaseFolder   = "C:\Temp\ForensicLogs\$ComputerName`_$CurrentDate"

if (!(Test-Path $BaseFolder)) {
    New-Item -ItemType Directory -Path $BaseFolder | Out-Null
}

function Export-LogSafely {
    param (
        [string]$LogName,
        [string]$OutputPath
    )

    try {
        Write-Host "Exporting $LogName..." -ForegroundColor Yellow
        $sanitizedLogName = $LogName.Replace('/', '-')
        $outputFile = Join-Path $OutputPath "$sanitizedLogName.evtx"

        wevtutil epl "$LogName" "$outputFile" 2>$null

        if (Test-Path $outputFile) {
            Write-Host "  Successfully exported $LogName" -ForegroundColor Green
        } else {
            Write-Host "  Failed to export $LogName - file not created" -ForegroundColor Red
        }
    } catch {
        Write-Host "  Error exporting $LogName : $_" -ForegroundColor Red
    }
}

$LogFolder = Join-Path $BaseFolder "EventLogs"
New-Item -ItemType Directory -Path $LogFolder -Force | Out-Null

foreach ($Log in $LogsToCollect) {
    Export-LogSafely -LogName $Log -OutputPath $LogFolder
}

$CollectArtifacts = (-not $TargetedMode) -or $IncludeArtifacts

if ($CollectArtifacts) {
    Write-Host "Exporting System Information..." -ForegroundColor Yellow
    $SystemInfoPath = Join-Path $BaseFolder "SystemInfo.txt"
    systeminfo > $SystemInfoPath

    Write-Host "Exporting Network Configuration..." -ForegroundColor Yellow
    $NetworkInfoPath = Join-Path $BaseFolder "NetworkInfo.txt"
    ipconfig /all > $NetworkInfoPath
    Get-NetAdapter | Format-List * >> $NetworkInfoPath
    Get-NetIPAddress | Format-List * >> $NetworkInfoPath

    Write-Host "Exporting Process List..." -ForegroundColor Yellow
    $ProcessPath = Join-Path $BaseFolder "Processes.txt"
    Get-Process | Format-List * > $ProcessPath

    Write-Host "Exporting Service Information..." -ForegroundColor Yellow
    $ServicesPath = Join-Path $BaseFolder "Services.txt"
    Get-Service | Format-List * > $ServicesPath

    Write-Host "Exporting Scheduled Tasks..." -ForegroundColor Yellow
    $TasksPath = Join-Path $BaseFolder "ScheduledTasks.txt"
    Get-ScheduledTask | Format-List * > $TasksPath
}

$SummaryPath = Join-Path $BaseFolder "CollectionSummary.txt"
@"
Forensic Log Collection Summary
================================
Computer Name   : $ComputerName
Collection Date : $(Get-Date)
Collection Path : $BaseFolder
Collection Mode : $(if ($TargetedMode) { 'Targeted' } else { 'Full' })

Event Logs Collected:
$($LogsToCollect | ForEach-Object { "  - $_" } | Out-String)
$(if ($CollectArtifacts) {
@"
System Artifacts Collected:
  - SystemInfo.txt
  - NetworkInfo.txt
  - Processes.txt
  - Services.txt
  - ScheduledTasks.txt
"@
} else {
"System Artifacts: Skipped (use -IncludeArtifacts to collect)"
})

Note: Some logs may not be available depending on system configuration and permissions.
"@ | Out-File $SummaryPath

Write-Host "`nCollection Complete!" -ForegroundColor Green
Write-Host "Logs saved to : $BaseFolder" -ForegroundColor Cyan
Write-Host "See CollectionSummary.txt for details." -ForegroundColor Yellow

if (-not $SkipZip) {
    $ZipPath = "$BaseFolder.zip"
    Write-Host "`nCompressing output folder..." -ForegroundColor Yellow

    try {
        Compress-Archive -Path "$BaseFolder\*" -DestinationPath $ZipPath -CompressionLevel Optimal -ErrorAction Stop

        $Hash = (Get-FileHash -Path $ZipPath -Algorithm SHA256).Hash
        $ZipSize = [math]::Round((Get-Item $ZipPath).Length / 1MB, 2)

        Write-Host "Archive created  : $ZipPath" -ForegroundColor Cyan
        Write-Host "Archive size     : $ZipSize MB" -ForegroundColor Cyan
        Write-Host "SHA256           : $Hash" -ForegroundColor Cyan

        "$Hash  $ZipPath" | Out-File -FilePath "$ZipPath.sha256" -Encoding UTF8
        Write-Host "Hash file saved  : $ZipPath.sha256" -ForegroundColor Cyan

        if ((Test-Path $ZipPath) -and (Get-Item $ZipPath).Length -gt 0) {
            Remove-Item -Path $BaseFolder -Recurse -Force
            Write-Host "Source folder removed : $BaseFolder" -ForegroundColor Green
        } else {
            Write-Host "WARNING: Zip validation failed - source folder retained at $BaseFolder" -ForegroundColor Red
        }
    } catch {
        Write-Host "WARNING: Failed to create zip archive: $_" -ForegroundColor Red
        Write-Host "         The uncompressed folder is still available at $BaseFolder" -ForegroundColor DarkYellow
    }
} else {
    Write-Host "Zip skipped (-SkipZip specified)." -ForegroundColor DarkYellow
}
