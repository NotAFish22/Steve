<#
Ob_Nowline_PortShockTest.ps1

Purpose:
  Defensive snapshot + firewall block test for unexplained traffic on ports 5228 and 8883.

What it does:
  1. Takes a BEFORE snapshot of processes, services, TCP/UDP endpoints, scheduled tasks,
     PowerShell process command lines, and recent Application/System events.
  2. Adds Windows Defender Firewall rules to block:
       - Outbound TCP connections TO remote ports 5228 and 8883
       - Inbound TCP connections ON local ports 5228 and 8883
       - Outbound TCP from PowerShell executables TO remote ports 5228 and 8883
  3. Waits.
  4. Takes an AFTER snapshot.
  5. Produces comparison CSV/TXT files.

Notes:
  - This does NOT kill processes.
  - This does NOT delete files.
  - This is read-only except for adding firewall rules.
  - Rollback command is printed at the end.
#>

#Requires -RunAsAdministrator

$ErrorActionPreference = "Continue"

# Ports observed in prior Nowline/ColdIdentifier logs.
$PortsToBlock = @(5228, 8883)

# How long to observe after blocking.
$ObservationSeconds = 180

$RuleGroup = "Ob Nowline - Port Shock Test"

$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$Root = Join-Path $env:USERPROFILE "Desktop\Ob_Nowline_PortShock_$Timestamp"

New-Item -Path $Root -ItemType Directory -Force | Out-Null

$TranscriptPath = Join-Path $Root "Ob_Nowline_PortShock_Transcript.txt"
Start-Transcript -Path $TranscriptPath -Force | Out-Null

$TestStart = Get-Date

Write-Host "`n=== Ob Nowline Port Shock Test ===" -ForegroundColor Cyan
Write-Host "Output folder: $Root"
Write-Host "Ports under test: $($PortsToBlock -join ', ')"
Write-Host "Observation wait: $ObservationSeconds seconds"
Write-Host "Firewall rule group: $RuleGroup"
Write-Host "Test start: $TestStart"
Write-Host ""

function Resolve-ProcessInfo {
    param(
        [Parameter(Mandatory=$true)]
        [int]$Pid
    )

    try {
        $p = Get-Process -Id $Pid -ErrorAction Stop
        [PSCustomObject]@{
            PID         = $Pid
            Process    = $p.ProcessName
            Path       = $p.Path
            StartTime  = try { $p.StartTime } catch { $null }
            Company    = try { $p.Company } catch { $null }
            Description= try { $p.Description } catch { $null }
        }
    }
    catch {
        [PSCustomObject]@{
            PID         = $Pid
            Process    = "UnknownOrExited"
            Path       = ""
            StartTime  = $null
            Company    = ""
            Description= ""
        }
    }
}

function Get-ProcessSnapshot {
    param([string]$Tag)

    Write-Host "[$Tag] Capturing process snapshot..." -ForegroundColor Cyan

    $processes = Get-CimInstance Win32_Process |
        Select-Object `
            ProcessId,
            ParentProcessId,
            Name,
            ExecutablePath,
            CommandLine,
            CreationDate,
            @{Name="Owner";Expression={
                try {
                    $owner = Invoke-CimMethod -InputObject $_ -MethodName GetOwner -ErrorAction Stop
                    "$($owner.Domain)\$($owner.User)"
                } catch {
                    ""
                }
            }}

    $processes | Export-Csv -Path (Join-Path $Root "$Tag`_Processes.csv") -NoTypeInformation

    # Parent-child readable tree-ish inventory
    $processes |
        Sort-Object ParentProcessId, ProcessId |
        Format-Table ProcessId, ParentProcessId, Name, ExecutablePath -AutoSize |
        Out-String -Width 300 |
        Set-Content -Path (Join-Path $Root "$Tag`_ProcessTree_View.txt")

    # PowerShell-specific process detail
    $processes |
        Where-Object {
            $_.Name -match "powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32|schtasks"
        } |
        Export-Csv -Path (Join-Path $Root "$Tag`_ScriptCapable_Processes.csv") -NoTypeInformation
}

function Get-NetworkSnapshot {
    param([string]$Tag)

    Write-Host "[$Tag] Capturing TCP/UDP/network snapshot..." -ForegroundColor Cyan

    $tcp = Get-NetTCPConnection -ErrorAction SilentlyContinue |
        ForEach-Object {
            $proc = Resolve-ProcessInfo -Pid $_.OwningProcess

            [PSCustomObject]@{
                LocalAddress  = $_.LocalAddress
                LocalPort     = $_.LocalPort
                RemoteAddress = $_.RemoteAddress
                RemotePort    = $_.RemotePort
                State         = $_.State
                OwningProcess = $_.OwningProcess
                Process       = $proc.Process
                Path          = $proc.Path
                StartTime     = $proc.StartTime
                Company       = $proc.Company
                Description   = $proc.Description
                IsTargetPort  = ($PortsToBlock -contains $_.LocalPort -or $PortsToBlock -contains $_.RemotePort)
            }
        }

    $tcp | Export-Csv -Path (Join-Path $Root "$Tag`_TCPConnections.csv") -NoTypeInformation

    $tcp |
        Where-Object { $_.IsTargetPort -eq $true } |
        Export-Csv -Path (Join-Path $Root "$Tag`_TCP_TargetPorts_5228_8883.csv") -NoTypeInformation

    $udp = Get-NetUDPEndpoint -ErrorAction SilentlyContinue |
        ForEach-Object {
            $proc = Resolve-ProcessInfo -Pid $_.OwningProcess

            [PSCustomObject]@{
                LocalAddress  = $_.LocalAddress
                LocalPort     = $_.LocalPort
                OwningProcess = $_.OwningProcess
                Process       = $proc.Process
                Path          = $proc.Path
                StartTime     = $proc.StartTime
                Company       = $proc.Company
                Description   = $proc.Description
                IsTargetPort  = ($PortsToBlock -contains $_.LocalPort)
            }
        }

    $udp | Export-Csv -Path (Join-Path $Root "$Tag`_UDPEndpoints.csv") -NoTypeInformation

    $udp |
        Where-Object { $_.IsTargetPort -eq $true } |
        Export-Csv -Path (Join-Path $Root "$Tag`_UDP_TargetPorts_5228_8883.csv") -NoTypeInformation
}

function Get-ServiceSnapshot {
    param([string]$Tag)

    Write-Host "[$Tag] Capturing service snapshot..." -ForegroundColor Cyan

    Get-CimInstance Win32_Service |
        Select-Object Name, DisplayName, State, StartMode, ProcessId, PathName, StartName |
        Export-Csv -Path (Join-Path $Root "$Tag`_Services.csv") -NoTypeInformation
}

function Get-ScheduledTaskSnapshot {
    param([string]$Tag)

    Write-Host "[$Tag] Capturing scheduled task snapshot..." -ForegroundColor Cyan

    $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue |
        ForEach-Object {
            $task = $_
            foreach ($action in $task.Actions) {
                [PSCustomObject]@{
                    TaskName    = $task.TaskName
                    TaskPath    = $task.TaskPath
                    State       = $task.State
                    Author      = $task.Author
                    URI         = $task.URI
                    Execute     = $action.Execute
                    Arguments   = $action.Arguments
                    WorkingDir  = $action.WorkingDirectory
                    Description = $task.Description
                }
            }
        }

    $tasks | Export-Csv -Path (Join-Path $Root "$Tag`_ScheduledTasks.csv") -NoTypeInformation

    $tasks |
        Where-Object {
            $_.Execute -match "powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32" -or
            $_.Arguments -match "powershell|pwsh|encodedcommand|-enc|downloadstring|invoke-webrequest|iwr|curl|wget"
        } |
        Export-Csv -Path (Join-Path $Root "$Tag`_ScheduledTasks_ScriptLike.csv") -NoTypeInformation
}

function Get-EventSnapshot {
    param(
        [string]$Tag,
        [datetime]$Since
    )

    Write-Host "[$Tag] Capturing Application/System event snapshot since $Since..." -ForegroundColor Cyan

    $appEvents = Get-WinEvent -FilterHashtable @{
        LogName   = "Application"
        StartTime = $Since
    } -ErrorAction SilentlyContinue |
        Where-Object {
            $_.ProviderName -match "Application Error|Windows Error Reporting|\.NET Runtime|PowerShell|MsiInstaller"
        } |
        Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message

    $appEvents | Export-Csv -Path (Join-Path $Root "$Tag`_Application_CrashAndErrorEvents.csv") -NoTypeInformation

    $sysEvents = Get-WinEvent -FilterHashtable @{
        LogName   = "System"
        StartTime = $Since
    } -ErrorAction SilentlyContinue |
        Where-Object {
            $_.LevelDisplayName -match "Critical|Error|Warning"
        } |
        Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message

    $sysEvents | Export-Csv -Path (Join-Path $Root "$Tag`_System_WarnErrorCriticalEvents.csv") -NoTypeInformation
}

function Apply-PortBlockRules {
    Write-Host "`n[BLOCK] Removing prior test rules, if present..." -ForegroundColor Yellow

    Get-NetFirewallRule -Group $RuleGroup -ErrorAction SilentlyContinue |
        Remove-NetFirewallRule -ErrorAction SilentlyContinue

    Write-Host "[BLOCK] Creating outbound block rules for remote ports..." -ForegroundColor Yellow

    foreach ($Port in $PortsToBlock) {
        New-NetFirewallRule `
            -DisplayName "Ob Shock Block Outbound Remote TCP $Port" `
            -Name "Ob_Shock_Block_Outbound_Remote_TCP_$Port" `
            -Group $RuleGroup `
            -Direction Outbound `
            -Action Block `
            -Protocol TCP `
            -RemotePort $Port `
            -Profile Any `
            -Enabled True `
            -Description "Ob Nowline port shock test: blocks outbound TCP connections to remote port $Port."
    }

    Write-Host "[BLOCK] Creating inbound block rules for local ports..." -ForegroundColor Yellow

    foreach ($Port in $PortsToBlock) {
        New-NetFirewallRule `
            -DisplayName "Ob Shock Block Inbound Local TCP $Port" `
            -Name "Ob_Shock_Block_Inbound_Local_TCP_$Port" `
            -Group $RuleGroup `
            -Direction Inbound `
            -Action Block `
            -Protocol TCP `
            -LocalPort $Port `
            -Profile Any `
            -Enabled True `
            -Description "Ob Nowline port shock test: blocks inbound TCP traffic to local port $Port."
    }

    Write-Host "[BLOCK] Adding PowerShell-specific outbound blocks..." -ForegroundColor Yellow

    $PowerShellPaths = @(
        "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe",
        "$env:SystemRoot\SysWOW64\WindowsPowerShell\v1.0\powershell.exe",
        "$env:ProgramFiles\PowerShell\7\pwsh.exe",
        "${env:ProgramFiles(x86)}\PowerShell\7\pwsh.exe"
    ) | Where-Object { $_ -and (Test-Path $_) }

    foreach ($PowerShellPath in $PowerShellPaths) {
        foreach ($Port in $PortsToBlock) {
            $SafeName = ($PowerShellPath -replace '[^a-zA-Z0-9]', '_')

            New-NetFirewallRule `
                -DisplayName "Ob Shock Block PowerShell Outbound TCP $Port - $([System.IO.Path]::GetFileName($PowerShellPath))" `
                -Name "Ob_Shock_Block_PS_${SafeName}_Remote_TCP_$Port" `
                -Group $RuleGroup `
                -Direction Outbound `
                -Action Block `
                -Program $PowerShellPath `
                -Protocol TCP `
                -RemotePort $Port `
                -Profile Any `
                -Enabled True `
                -Description "Ob Nowline port shock test: blocks this PowerShell executable from outbound TCP to remote port $Port."
        }
    }

    Get-NetFirewallRule -Group $RuleGroup |
        Select-Object DisplayName, Enabled, Direction, Action, Profile |
        Export-Csv -Path (Join-Path $Root "FirewallRules_Applied.csv") -NoTypeInformation
}

function Compare-Snapshots {
    Write-Host "`n[COMPARE] Comparing BEFORE and AFTER snapshots..." -ForegroundColor Cyan

    $beforeProc = Import-Csv (Join-Path $Root "BEFORE_Processes.csv")
    $afterProc  = Import-Csv (Join-Path $Root "AFTER_Processes.csv")

    $beforeIds = $beforeProc | Select-Object -ExpandProperty ProcessId
    $afterIds  = $afterProc  | Select-Object -ExpandProperty ProcessId

    $exited = $beforeProc | Where-Object { $afterIds -notcontains $_.ProcessId }
    $new    = $afterProc  | Where-Object { $beforeIds -notcontains $_.ProcessId }

    $exited | Export-Csv -Path (Join-Path $Root "DIFF_Processes_Exited_AfterBlock.csv") -NoTypeInformation
    $new    | Export-Csv -Path (Join-Path $Root "DIFF_Processes_New_AfterBlock.csv") -NoTypeInformation

    $beforeTargetTcp = Import-Csv (Join-Path $Root "BEFORE_TCP_TargetPorts_5228_8883.csv")
    $afterTargetTcp  = Import-Csv (Join-Path $Root "AFTER_TCP_TargetPorts_5228_8883.csv")

    $beforeTargetTcp | Export-Csv -Path (Join-Path $Root "COMPARE_Before_Target_TCP.csv") -NoTypeInformation
    $afterTargetTcp  | Export-Csv -Path (Join-Path $Root "COMPARE_After_Target_TCP.csv") -NoTypeInformation

    $summary = @()

    $summary += "Ob Nowline Port Shock Test Summary"
    $summary += "================================="
    $summary += "Output folder: $Root"
    $summary += "Test start: $TestStart"
    $summary += "Test end: $(Get-Date)"
    $summary += "Ports blocked: $($PortsToBlock -join ', ')"
    $summary += ""
    $summary += "Process counts:"
    $summary += "  BEFORE: $($beforeProc.Count)"
    $summary += "  AFTER : $($afterProc.Count)"
    $summary += "  Exited after block: $($exited.Count)"
    $summary += "  New after block   : $($new.Count)"
    $summary += ""
    $summary += "Target TCP connections:"
    $summary += "  BEFORE target-port TCP rows: $($beforeTargetTcp.Count)"
    $summary += "  AFTER target-port TCP rows : $($afterTargetTcp.Count)"
    $summary += ""
    $summary += "Important files to inspect:"
    $summary += "  DIFF_Processes_Exited_AfterBlock.csv"
    $summary += "  DIFF_Processes_New_AfterBlock.csv"
    $summary += "  BEFORE_TCP_TargetPorts_5228_8883.csv"
    $summary += "  AFTER_TCP_TargetPorts_5228_8883.csv"
    $summary += "  AFTER_Application_CrashAndErrorEvents.csv"
    $summary += "  AFTER_System_WarnErrorCriticalEvents.csv"
    $summary += "  BEFORE_ScriptCapable_Processes.csv"
    $summary += "  AFTER_ScriptCapable_Processes.csv"
    $summary += "  BEFORE_ScheduledTasks_ScriptLike.csv"
    $summary += "  AFTER_ScheduledTasks_ScriptLike.csv"
    $summary += ""
    $summary += "Rollback firewall rules:"
    $summary += "  Get-NetFirewallRule -Group '$RuleGroup' | Remove-NetFirewallRule"
    $summary += ""

    $summaryPath = Join-Path $Root "SUMMARY_ReadMe.txt"
    $summary | Set-Content -Path $summaryPath

    Write-Host "`nSummary written to:" -ForegroundColor Green
    Write-Host $summaryPath

    Write-Host "`nProcess exits after block:" -ForegroundColor Yellow
    if ($exited.Count -gt 0) {
        $exited | Select-Object ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine | Format-Table -AutoSize
    } else {
        Write-Host "No processes exited between BEFORE and AFTER snapshots." -ForegroundColor Green
    }

    Write-Host "`nTarget-port TCP connections after block:" -ForegroundColor Yellow
    if ($afterTargetTcp.Count -gt 0) {
        $afterTargetTcp | Format-Table -AutoSize
    } else {
        Write-Host "No TCP connections involving target ports after block." -ForegroundColor Green
    }
}

try {
    Write-Host "`n--- BEFORE SNAPSHOT ---" -ForegroundColor Magenta
    Get-ProcessSnapshot -Tag "BEFORE"
    Get-NetworkSnapshot -Tag "BEFORE"
    Get-ServiceSnapshot -Tag "BEFORE"
    Get-ScheduledTaskSnapshot -Tag "BEFORE"
    Get-EventSnapshot -Tag "BEFORE" -Since $TestStart.AddMinutes(-30)

    Write-Host "`n--- APPLYING FIREWALL PORT BLOCK ---" -ForegroundColor Magenta
    Apply-PortBlockRules

    Write-Host "`n--- OBSERVATION WINDOW ---" -ForegroundColor Magenta
    Write-Host "Waiting $ObservationSeconds seconds. Use the PC normally but do not launch extra apps unless needed."
    Start-Sleep -Seconds $ObservationSeconds

    Write-Host "`n--- AFTER SNAPSHOT ---" -ForegroundColor Magenta
    Get-ProcessSnapshot -Tag "AFTER"
    Get-NetworkSnapshot -Tag "AFTER"
    Get-ServiceSnapshot -Tag "AFTER"
    Get-ScheduledTaskSnapshot -Tag "AFTER"
    Get-EventSnapshot -Tag "AFTER" -Since $TestStart

    Compare-Snapshots
}
finally {
    Write-Host "`nRollback command if needed:" -ForegroundColor Cyan
    Write-Host "Get-NetFirewallRule -Group '$RuleGroup' | Remove-NetFirewallRule"

    Stop-Transcript | Out-Null
}