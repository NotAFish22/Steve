<#
versioning_policy:
  file_naming_scheme: "ProcessPortSeeMapsConnections_LocalCollector_v045.ps1"
  top_of_file_version: "v_00045"
  parent_reference:
    - "ProcessPortSeeMapsConnections_LocalCollector_v.ps1 v_00044"
    - "Steve_Security_Nowline_v.yml v_00043"
  increments: "Increase by 1 for each approved change delivered to user"
  auto_increment_rule: "Any time there is a versioning_policy in a file, increment the version by 1 every time a change is made."
  change_summary: >
    Advanced the read-only local Windows collector to v_00045. This version
    fixes the StrictMode string interpolation bug where "$localPort?" was parsed
    as an undefined variable instead of "$localPort" followed by a literal
    question mark. It also restores the suspicious command-line regex that was
    corrupted by escaped HTML/link formatting in chat.

agent:
  name: "ProcessPortSeeMapsConnections_LocalCollector"
  codename: "Steve Local"
  version: "v_00045"
  mode: "read_only_local_windows_endpoint_collector"
  acknowledgment: "Its me Steve"
  activation_keyword: "steve, its me"

  parent_agent:
    name: "Steve_Security_Nowline"
    version: "v_00043"

  mission: >
    Collect local Windows endpoint telemetry in a read-only manner so Steve can
    analyze process-to-port relationships, parent process chains, PowerShell and
    LOLBin activity, persistence context, executable paths, signatures, services,
    local listening sockets, outbound remote endpoints, and crash-follow-up clues.

  safety_boundary:
    allowed:
      - "Read-only local inventory"
      - "Current user/profile mapping"
      - "Known-folder metadata review"
      - "Registry autostart read"
      - "Process and service inspection"
      - "TCP/UDP PID-to-port mapping"
      - "IRQ and device-resource inventory"
      - "Authenticode signature status lookup"
      - "JSON, CSV, README, and HTML dashboard report generation"
    disallowed:
      - "No exploitation"
      - "No credential dumping"
      - "No persistence creation"
      - "No process termination"
      - "No registry modification"
      - "No firewall modification"
      - "No file deletion"
      - "No network scanning beyond local connection inventory"
      - "No reading personal document or image contents by default"
      - "No third-party upload"
#>

[CmdletBinding()]
param(
    [string]$OutputDirectory = "$env:USERPROFILE\Desktop\ProcessPortSeeMapsConnections_Report",

    [bool]$IncludeKnownFolderMetadata = $true,
    [bool]$IncludeRegistryAutoruns = $true,
    [bool]$IncludeSignatures = $true,

    [int]$KnownFolderMaxDepth = 2,
    [int]$KnownFolderMaxItemsPerFolder = 500,

    [bool]$ConsoleSummary = $true,
    [bool]$WriteReadMe = $true,
    [bool]$WriteHtmlDashboard = $true,
    [bool]$OpenDashboard = $true
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

$Script:CollectorName = "ProcessPortSeeMapsConnections_LocalCollector"
$Script:CollectorVersion = "v_00045"
$Script:ParentAgent = "Steve_Security_Nowline v_00043"
$Script:RunStarted = Get-Date
$Script:CurrentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
$Script:IsAdmin = ([Security.Principal.WindowsPrincipal]$Script:CurrentIdentity).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)

$Script:NonFatalErrors = New-Object System.Collections.Generic.List[string]
$Script:FatalErrors = New-Object System.Collections.Generic.List[string]
$Script:PartialDataWarnings = New-Object System.Collections.Generic.List[string]
$Script:VersionFileToken = $Script:CollectorVersion -replace "[^0-9]", ""
$Script:BaseFileName = "ProcessPortSeeMapsConnections_v$Script:VersionFileToken"

function Write-SteveStep {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [ValidateSet("Info", "Warn", "Error", "Success")]
        [string]$Level = "Info"
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $prefix = "[$timestamp] Steve PPCMC ::"

    switch ($Level) {
        "Info" {
            Write-Host "$prefix $Message" -ForegroundColor Cyan
        }
        "Warn" {
            Write-Host "$prefix WARNING: $Message" -ForegroundColor Yellow
        }
        "Error" {
            Write-Host "$prefix ERROR: $Message" -ForegroundColor Red
        }
        "Success" {
            Write-Host "$prefix $Message" -ForegroundColor Green
        }
    }
}

function Add-SteveNonFatalError {
    param([string]$Message)

    if (-not [System.String]::IsNullOrWhiteSpace($Message)) {
        $Script:NonFatalErrors.Add($Message) | Out-Null
    }
}

function Add-SteveFatalError {
    param([string]$Message)

    if (-not [System.String]::IsNullOrWhiteSpace($Message)) {
        $Script:FatalErrors.Add($Message) | Out-Null
    }
}

function Add-StevePartialWarning {
    param([string]$Message)

    if (-not [System.String]::IsNullOrWhiteSpace($Message)) {
        $Script:PartialDataWarnings.Add($Message) | Out-Null
    }
}

function Test-SteveBlank {
    param([string]$Value)

    return [System.String]::IsNullOrWhiteSpace($Value)
}

function Test-SteveObjectHasProperty {
    param(
        [object]$Object,
        [string]$Name
    )

    if ($null -eq $Object) {
        return $false
    }

    return ($Object.PSObject.Properties.Name -contains $Name)
}

function Get-StevePropertyValue {
    param(
        [object]$Object,
        [string]$Name,
        [object]$Default = $null
    )

    if (Test-SteveObjectHasProperty -Object $Object -Name $Name) {
        return $Object.$Name
    }

    return $Default
}

function ConvertTo-SteveSafeString {
    param([object]$Value)

    if ($null -eq $Value) {
        return $null
    }

    try {
        return [string]$Value
    }
    catch {
        return "<unreadable>"
    }
}

function ConvertTo-SteveHtml {
    param([object]$Value)

    if ($null -eq $Value) {
        return ""
    }

    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function New-SteveDirectory {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    try {
        if (-not (Test-Path -LiteralPath $Path)) {
            New-Item -ItemType Directory -Path $Path -Force | Out-Null
        }

        return $true
    }
    catch {
        Add-SteveFatalError "Could not create output directory '$Path': $($_.Exception.Message)"
        return $false
    }
}

function Test-SteveCommandAvailable {
    param([string]$Name)

    try {
        $cmd = Get-Command -Name $Name -ErrorAction Stop
        return ($null -ne $cmd)
    }
    catch {
        return $false
    }
}

function Test-SteveOutputWritable {
    param([string]$Path)

    try {
        if (-not (Test-Path -LiteralPath $Path)) {
            New-Item -ItemType Directory -Path $Path -Force | Out-Null
        }

        $testFile = Join-Path $Path "_steve_write_test.tmp"
        "Steve write test" | Out-File -LiteralPath $testFile -Encoding UTF8 -Force
        Remove-Item -LiteralPath $testFile -Force -ErrorAction SilentlyContinue
        return $true
    }
    catch {
        Add-SteveFatalError "Output directory is not writable '$Path': $($_.Exception.Message)"
        return $false
    }
}

function Get-SteveCollectorHealth {
    param([string]$OutputDirectoryPath)

    $windowsPlatform = $false

    try {
        $windowsPlatform = [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
            [System.Runtime.InteropServices.OSPlatform]::Windows
        )
    }
    catch {
        $windowsPlatform = ($env:OS -like "*Windows*")
    }

    if (-not $windowsPlatform) {
        Add-SteveFatalError "This collector is intended for Windows local endpoint collection."
    }

    $cimAvailable = Test-SteveCommandAvailable -Name "Get-CimInstance"
    $tcpAvailable = Test-SteveCommandAvailable -Name "Get-NetTCPConnection"
    $udpAvailable = Test-SteveCommandAvailable -Name "Get-NetUDPEndpoint"
    $sigAvailable = Test-SteveCommandAvailable -Name "Get-AuthenticodeSignature"
    $registryProviderAvailable = Test-Path "HKLM:\"
    $outputWritable = Test-SteveOutputWritable -Path $OutputDirectoryPath

    if (-not $Script:IsAdmin) {
        Add-StevePartialWarning "Collector is not running elevated. Some process command lines, owners, services, drivers, or signatures may be unavailable."
    }

    if (-not $cimAvailable) {
        Add-SteveFatalError "Get-CimInstance is unavailable. CIM/WMI inventory cannot be collected."
    }

    if (-not $tcpAvailable) {
        Add-StevePartialWarning "Get-NetTCPConnection is unavailable. TCP PID-to-port inventory may be missing."
    }

    if (-not $udpAvailable) {
        Add-StevePartialWarning "Get-NetUDPEndpoint is unavailable. UDP endpoint inventory may be missing."
    }

    if (-not $sigAvailable) {
        Add-StevePartialWarning "Get-AuthenticodeSignature is unavailable. Signature checks will be marked NotChecked."
    }

    if (-not $registryProviderAvailable) {
        Add-StevePartialWarning "PowerShell registry provider appears unavailable. Registry autoruns may be missing."
    }

    return [PSCustomObject]@{
        Collector = $Script:CollectorName
        CollectorVersion = $Script:CollectorVersion
        ParentAgent = $Script:ParentAgent
        RunStarted = $Script:RunStarted
        ComputerName = $env:COMPUTERNAME
        RunUser = $Script:CurrentIdentity.Name
        IsAdmin = $Script:IsAdmin
        WindowsPlatform = $windowsPlatform
        OutputDirectory = $OutputDirectoryPath
        OutputDirectoryWritable = $outputWritable
        CimAvailable = $cimAvailable
        NetTCPIPAvailable = ($tcpAvailable -or $udpAvailable)
        GetNetTCPConnectionAvailable = $tcpAvailable
        GetNetUDPEndpointAvailable = $udpAvailable
        GetAuthenticodeSignatureAvailable = $sigAvailable
        KnownFolderResolutionAvailable = $true
        RegistryProviderAvailable = $registryProviderAvailable
        PartialDataWarnings = @($Script:PartialDataWarnings)
        FatalErrors = @($Script:FatalErrors)
        NonFatalErrors = @($Script:NonFatalErrors)
    }
}

function Get-SteveCimSafe {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ClassName,

        [string]$Namespace = "root/cimv2"
    )

    try {
        return @(Get-CimInstance -Namespace $Namespace -ClassName $ClassName -ErrorAction Stop)
    }
    catch {
        $msg = "Failed to query CIM class '$Namespace/$ClassName': $($_.Exception.Message)"
        Add-SteveNonFatalError $msg

        return @(
            [PSCustomObject]@{
                Error = "Failed to query CIM class"
                ClassName = $ClassName
                Namespace = $Namespace
                Message = $_.Exception.Message
            }
        )
    }
}

function Get-SteveSignatureInfo {
    param([string]$Path)

    if (-not $IncludeSignatures) {
        return [PSCustomObject]@{
            Path = $Path
            SignatureStatus = "NotChecked"
            Signer = $null
            SignatureType = $null
            Error = $null
        }
    }

    if (-not (Test-SteveCommandAvailable -Name "Get-AuthenticodeSignature")) {
        return [PSCustomObject]@{
            Path = $Path
            SignatureStatus = "NotChecked"
            Signer = $null
            SignatureType = $null
            Error = "Get-AuthenticodeSignature unavailable"
        }
    }

    if ((Test-SteveBlank $Path) -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return [PSCustomObject]@{
            Path = $Path
            SignatureStatus = "MissingOrUnreadable"
            Signer = $null
            SignatureType = $null
            Error = $null
        }
    }

    try {
        $sig = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop

        return [PSCustomObject]@{
            Path = $Path
            SignatureStatus = ConvertTo-SteveSafeString $sig.Status
            Signer = if ($sig.SignerCertificate) { ConvertTo-SteveSafeString $sig.SignerCertificate.Subject } else { $null }
            SignatureType = ConvertTo-SteveSafeString $sig.SignatureType
            Error = $null
        }
    }
    catch {
        return [PSCustomObject]@{
            Path = $Path
            SignatureStatus = "SignatureCheckFailed"
            Signer = $null
            SignatureType = $null
            Error = $_.Exception.Message
        }
    }
}

function Resolve-SteveExecutablePath {
    param([string]$RawPath)

    if (Test-SteveBlank $RawPath) {
        return $null
    }

    $candidate = $RawPath.Trim()

    if ($candidate.StartsWith("\??\")) {
        $candidate = $candidate.Substring(4)
    }

    if ($candidate.StartsWith("\SystemRoot\", [System.StringComparison]::OrdinalIgnoreCase)) {
        $candidate = Join-Path $env:windir $candidate.Substring(12)
    }

    if ($candidate.StartsWith("SystemRoot\", [System.StringComparison]::OrdinalIgnoreCase)) {
        $candidate = Join-Path $env:windir $candidate.Substring(11)
    }

    $candidate = [System.Environment]::ExpandEnvironmentVariables($candidate)

    if ($candidate.StartsWith('"')) {
        $secondQuote = $candidate.IndexOf('"', 1)

        if ($secondQuote -gt 1) {
            return $candidate.Substring(1, $secondQuote - 1)
        }
    }

    if ($candidate -match '^[A-Za-z]:\\.*?\.exe') {
        return $Matches[0]
    }

    if ($candidate -match '^[A-Za-z]:\\.*?\.dll') {
        return $Matches[0]
    }

    if ($candidate -match '^[A-Za-z]:\\.*?\.sys') {
        return $Matches[0]
    }

    return $candidate
}

function Get-SteveKnownFolderPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    try {
        switch ($Name) {
            "Desktop" {
                return [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::Desktop)
            }
            "Documents" {
                return [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::MyDocuments)
            }
            "Pictures" {
                return [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::MyPictures)
            }
            default {
                return $null
            }
        }
    }
    catch {
        Add-SteveNonFatalError "Known-folder resolution failed for '$Name': $($_.Exception.Message)"
        return $null
    }
}

function Get-SteveCurrentUserProfile {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()

    $knownFolders = [ordered]@{
        UserProfile = $env:USERPROFILE
        Desktop = Get-SteveKnownFolderPath -Name "Desktop"
        Documents = Get-SteveKnownFolderPath -Name "Documents"
        Pictures = Get-SteveKnownFolderPath -Name "Pictures"
        Downloads = Join-Path $env:USERPROFILE "Downloads"
        AppDataRoaming = $env:APPDATA
        AppDataLocal = $env:LOCALAPPDATA
        Startup = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\Startup"
        ProgramDataStartup = Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\StartUp"
    }

    return [PSCustomObject]@{
        UserName = $identity.Name
        UserSid = $identity.User.Value
        IsAdmin = $Script:IsAdmin
        ComputerName = $env:COMPUTERNAME
        UserDomain = $env:USERDOMAIN
        UserProfile = $env:USERPROFILE
        KnownFolders = $knownFolders
    }
}

function Get-SteveSystemOverview {
    $os = Get-SteveCimSafe -ClassName "Win32_OperatingSystem"
    $cs = Get-SteveCimSafe -ClassName "Win32_ComputerSystem"
    $bios = Get-SteveCimSafe -ClassName "Win32_BIOS"
    $cpu = Get-SteveCimSafe -ClassName "Win32_Processor"

    return [PSCustomObject]@{
        CollectorVersion = $Script:CollectorVersion
        ParentAgent = $Script:ParentAgent
        RunStarted = $Script:RunStarted
        RunUser = [Security.Principal.WindowsIdentity]::GetCurrent().Name
        IsAdmin = $Script:IsAdmin
        ComputerName = $env:COMPUTERNAME
        OperatingSystem = $os | Select-Object Caption, Version, OSArchitecture, LastBootUpTime, InstallDate
        ComputerSystem = $cs | Select-Object Manufacturer, Model, Domain, TotalPhysicalMemory, NumberOfLogicalProcessors
        BIOS = $bios | Select-Object Manufacturer, Name, SerialNumber, SMBIOSBIOSVersion, ReleaseDate
        Processor = $cpu | Select-Object Name, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed
    }
}

function Get-SteveIRQInventory {
    $irq = Get-SteveCimSafe -ClassName "Win32_IRQResource"

    return @(
        $irq | ForEach-Object {
            [PSCustomObject]@{
                IRQNumber = $_.IRQNumber
                Name = $_.Name
                Caption = $_.Caption
                Description = $_.Description
                Hardware = $_.Hardware
                Shareable = $_.Shareable
                Status = $_.Status
                Availability = $_.Availability
                TriggerLevel = $_.TriggerLevel
                TriggerType = $_.TriggerType
                Vector = $_.Vector
            }
        }
    )
}

function Get-StevePnPInventory {
    $devices = Get-SteveCimSafe -ClassName "Win32_PnPEntity"

    return @(
        $devices | ForEach-Object {
            [PSCustomObject]@{
                Name = $_.Name
                Manufacturer = $_.Manufacturer
                PNPClass = $_.PNPClass
                DeviceID = $_.DeviceID
                Service = $_.Service
                Status = $_.Status
                ConfigManagerErrorCode = $_.ConfigManagerErrorCode
            }
        }
    )
}

function Get-SteveDriverInventory {
    $drivers = Get-SteveCimSafe -ClassName "Win32_SystemDriver"

    return @(
        $drivers | ForEach-Object {
            $path = Resolve-SteveExecutablePath $_.PathName
            $sig = Get-SteveSignatureInfo -Path $path

            [PSCustomObject]@{
                Name = $_.Name
                DisplayName = $_.DisplayName
                State = $_.State
                Status = $_.Status
                StartMode = $_.StartMode
                PathName = $_.PathName
                ResolvedPath = $path
                ServiceType = $_.ServiceType
                SignatureStatus = $sig.SignatureStatus
                Signer = $sig.Signer
            }
        }
    )
}

function Get-SteveServiceInventory {
    $services = Get-SteveCimSafe -ClassName "Win32_Service"

    return @(
        $services | ForEach-Object {
            $path = Resolve-SteveExecutablePath $_.PathName
            $sig = Get-SteveSignatureInfo -Path $path

            [PSCustomObject]@{
                Name = $_.Name
                DisplayName = $_.DisplayName
                State = $_.State
                StartMode = $_.StartMode
                Status = $_.Status
                ProcessId = $_.ProcessId
                StartName = $_.StartName
                PathName = $_.PathName
                ResolvedPath = $path
                SignatureStatus = $sig.SignatureStatus
                Signer = $sig.Signer
            }
        }
    )
}

function Test-StevePowerShellName {
    param([string]$Name)

    if (Test-SteveBlank $Name) {
        return $false
    }

    return ($Name.ToLowerInvariant() -in @("powershell.exe", "pwsh.exe", "powershell_ise.exe"))
}

function Test-SteveLegacyPowerShellCandidate {
    param(
        [string]$Name,
        [string]$Path
    )

    if (-not (Test-StevePowerShellName -Name $Name)) {
        return $false
    }

    if ($Name.ToLowerInvariant() -eq "powershell.exe") {
        return $true
    }

    if ($Path -and ($Path -match '(?i)WindowsPowerShell|System32\\WindowsPowerShell|SysWOW64\\WindowsPowerShell')) {
        return $true
    }

    return $false
}

function Test-SteveLolbinName {
    param([string]$Name)

    if (Test-SteveBlank $Name) {
        return $false
    }

    $lolNames = @(
        "powershell.exe",
        "pwsh.exe",
        "powershell_ise.exe",
        "cmd.exe",
        "wscript.exe",
        "cscript.exe",
        "mshta.exe",
        "rundll32.exe",
        "regsvr32.exe",
        "certutil.exe",
        "bitsadmin.exe",
        "msiexec.exe",
        "wmic.exe",
        "schtasks.exe",
        "forfiles.exe",
        "installutil.exe",
        "reg.exe",
        "net.exe",
        "netsh.exe",
        "curl.exe",
        "ftp.exe",
        "makecab.exe",
        "esentutl.exe"
    )

    return ($lolNames -contains $Name.ToLowerInvariant())
}

function Get-SteveProcessInventory {
    $processes = Get-SteveCimSafe -ClassName "Win32_Process"

    return @(
        $processes | ForEach-Object {
            $path = $_.ExecutablePath
            $sig = Get-SteveSignatureInfo -Path $path

            $owner = $null

            try {
                $ownerResult = Invoke-CimMethod -InputObject $_ -MethodName GetOwner -ErrorAction Stop

                if ($ownerResult.ReturnValue -eq 0) {
                    $owner = "$($ownerResult.Domain)\$($ownerResult.User)"
                }
            }
            catch {
                $owner = $null
            }

            $name = ConvertTo-SteveSafeString $_.Name
            $cmd = ConvertTo-SteveSafeString $_.CommandLine
            $isPowerShell = Test-StevePowerShellName -Name $name
            $isLegacyPowerShellCandidate = Test-SteveLegacyPowerShellCandidate -Name $name -Path $path
            $isLolbin = Test-SteveLolbinName -Name $name
            $hasSuspiciousCommand = $false

            if ($cmd -match '(?i)(-enc|encodedcommand|hidden|windowstyle\s+hidden|downloadstring|frombase64string|invoke-expression|\biex\b|executionpolicy\s+bypass|\bnop\b|noprofile|http://|https://|ftp://)') {
                $hasSuspiciousCommand = $true
            }

            [PSCustomObject]@{
                ProcessId = $_.ProcessId
                ParentProcessId = $_.ParentProcessId
                Name = $_.Name
                ExecutablePath = $_.ExecutablePath
                CommandLine = $_.CommandLine
                CreationDate = $_.CreationDate
                ThreadCount = $_.ThreadCount
                HandleCount = $_.HandleCount
                WorkingSetSize = $_.WorkingSetSize
                PrivatePageCount = $_.PrivatePageCount
                ReadOperationCount = $_.ReadOperationCount
                WriteOperationCount = $_.WriteOperationCount
                UserModeTime = $_.UserModeTime
                KernelModeTime = $_.KernelModeTime
                SessionId = $_.SessionId
                Owner = $owner
                SignatureStatus = $sig.SignatureStatus
                Signer = $sig.Signer
                IsPowerShell = $isPowerShell
                IsLegacyPowerShellCandidate = $isLegacyPowerShellCandidate
                IsLolbin = $isLolbin
                HasSuspiciousCommandLine = $hasSuspiciousCommand
            }
        }
    )
}

function Add-SteveParentProcessDetails {
    param([array]$Processes)

    $processById = @{}
    $childCountByParentId = @{}

    foreach ($processItem in $Processes) {
        if ($null -ne $processItem.ProcessId) {
            $processIdKey = [int]$processItem.ProcessId
            $processById[$processIdKey] = $processItem
        }

        if ($null -ne $processItem.ParentProcessId) {
            $parentProcessIdKey = [int]$processItem.ParentProcessId

            if (-not $childCountByParentId.ContainsKey($parentProcessIdKey)) {
                $childCountByParentId[$parentProcessIdKey] = 0
            }

            $childCountByParentId[$parentProcessIdKey] = $childCountByParentId[$parentProcessIdKey] + 1
        }
    }

    return @(
        foreach ($processItem in $Processes) {
            $parent = $null

            if ($null -ne $processItem.ParentProcessId) {
                $parentProcessIdKey = [int]$processItem.ParentProcessId

                if ($processById.ContainsKey($parentProcessIdKey)) {
                    $parent = $processById[$parentProcessIdKey]
                }
            }

            $childCount = 0

            if ($null -ne $processItem.ProcessId) {
                $processIdKey = [int]$processItem.ProcessId

                if ($childCountByParentId.ContainsKey($processIdKey)) {
                    $childCount = $childCountByParentId[$processIdKey]
                }
            }

            [PSCustomObject]@{
                ProcessId = $processItem.ProcessId
                ParentProcessId = $processItem.ParentProcessId
                ParentProcessName = if ($parent) { $parent.Name } else { $null }
                ParentExecutablePath = if ($parent) { $parent.ExecutablePath } else { $null }
                ParentCommandLine = if ($parent) { $parent.CommandLine } else { $null }
                ChildProcessCount = $childCount
                Name = $processItem.Name
                ExecutablePath = $processItem.ExecutablePath
                CommandLine = $processItem.CommandLine
                CreationDate = $processItem.CreationDate
                ThreadCount = $processItem.ThreadCount
                HandleCount = $processItem.HandleCount
                WorkingSetSize = $processItem.WorkingSetSize
                PrivatePageCount = $processItem.PrivatePageCount
                ReadOperationCount = $processItem.ReadOperationCount
                WriteOperationCount = $processItem.WriteOperationCount
                UserModeTime = $processItem.UserModeTime
                KernelModeTime = $processItem.KernelModeTime
                SessionId = $processItem.SessionId
                Owner = $processItem.Owner
                SignatureStatus = $processItem.SignatureStatus
                Signer = $processItem.Signer
                IsPowerShell = $processItem.IsPowerShell
                IsLegacyPowerShellCandidate = $processItem.IsLegacyPowerShellCandidate
                IsLolbin = $processItem.IsLolbin
                HasSuspiciousCommandLine = $processItem.HasSuspiciousCommandLine
            }
        }
    )
}

function Get-SteveTcpInventory {
    if (-not (Test-SteveCommandAvailable -Name "Get-NetTCPConnection")) {
        Add-StevePartialWarning "TCP inventory skipped because Get-NetTCPConnection is unavailable."

        return @(
            [PSCustomObject]@{
                Error = "Get-NetTCPConnection unavailable"
                Message = "TCP inventory skipped"
            }
        )
    }

    try {
        return @(
            Get-NetTCPConnection -ErrorAction Stop | ForEach-Object {
                [PSCustomObject]@{
                    Protocol = "TCP"
                    LocalAddress = $_.LocalAddress
                    LocalPort = $_.LocalPort
                    RemoteAddress = $_.RemoteAddress
                    RemotePort = $_.RemotePort
                    State = $_.State
                    AppliedSetting = $_.AppliedSetting
                    OwningProcess = $_.OwningProcess
                    CreationTime = $_.CreationTime
                    OffloadState = $_.OffloadState
                }
            }
        )
    }
    catch {
        Add-SteveNonFatalError "Failed to query TCP connections: $($_.Exception.Message)"

        return @(
            [PSCustomObject]@{
                Error = "Failed to query TCP connections"
                Message = $_.Exception.Message
            }
        )
    }
}

function Get-SteveUdpInventory {
    if (-not (Test-SteveCommandAvailable -Name "Get-NetUDPEndpoint")) {
        Add-StevePartialWarning "UDP inventory skipped because Get-NetUDPEndpoint is unavailable."

        return @(
            [PSCustomObject]@{
                Error = "Get-NetUDPEndpoint unavailable"
                Message = "UDP inventory skipped"
            }
        )
    }

    try {
        return @(
            Get-NetUDPEndpoint -ErrorAction Stop | ForEach-Object {
                [PSCustomObject]@{
                    Protocol = "UDP"
                    LocalAddress = $_.LocalAddress
                    LocalPort = $_.LocalPort
                    RemoteAddress = $null
                    RemotePort = $null
                    State = "Endpoint"
                    OwningProcess = $_.OwningProcess
                    CreationTime = $_.CreationTime
                }
            }
        )
    }
    catch {
        Add-SteveNonFatalError "Failed to query UDP endpoints: $($_.Exception.Message)"

        return @(
            [PSCustomObject]@{
                Error = "Failed to query UDP endpoints"
                Message = $_.Exception.Message
            }
        )
    }
}

function Join-StevePortsToProcesses {
    param(
        [array]$Processes,
        [array]$Tcp,
        [array]$Udp,
        [array]$Services
    )

    $processById = @{}

    foreach ($processItem in $Processes) {
        if ($null -ne $processItem.ProcessId) {
            $processIdKey = [int]$processItem.ProcessId
            $processById[$processIdKey] = $processItem
        }
    }

    $servicesByProcessId = @{}

    foreach ($serviceItem in $Services) {
        if ($null -ne $serviceItem.ProcessId -and [int]$serviceItem.ProcessId -gt 0) {
            $serviceProcessId = [int]$serviceItem.ProcessId

            if (-not $servicesByProcessId.ContainsKey($serviceProcessId)) {
                $servicesByProcessId[$serviceProcessId] = @()
            }

            $servicesByProcessId[$serviceProcessId] += $serviceItem.Name
        }
    }

    $allNetworkRows = @()
    $allNetworkRows += $Tcp
    $allNetworkRows += $Udp

    return @(
        foreach ($networkRow in $allNetworkRows) {
            if (Test-SteveObjectHasProperty -Object $networkRow -Name "Error") {
                $networkRow
                continue
            }

            $owningProcessId = $null

            if ($null -ne $networkRow.OwningProcess) {
                $owningProcessId = [int]$networkRow.OwningProcess
            }

            $processItem = $null

            if ($null -ne $owningProcessId -and $processById.ContainsKey($owningProcessId)) {
                $processItem = $processById[$owningProcessId]
            }

            $serviceNames = $null

            if ($null -ne $owningProcessId -and $servicesByProcessId.ContainsKey($owningProcessId)) {
                $serviceNames = $servicesByProcessId[$owningProcessId] -join "; "
            }

            [PSCustomObject]@{
                Protocol = $networkRow.Protocol
                LocalAddress = $networkRow.LocalAddress
                LocalPort = $networkRow.LocalPort
                RemoteAddress = $networkRow.RemoteAddress
                RemotePort = $networkRow.RemotePort
                State = $networkRow.State
                OwningProcess = $networkRow.OwningProcess
                ProcessName = if ($processItem) { $processItem.Name } else { $null }
                ExecutablePath = if ($processItem) { $processItem.ExecutablePath } else { $null }
                CommandLine = if ($processItem) { $processItem.CommandLine } else { $null }
                ParentProcessId = if ($processItem) { $processItem.ParentProcessId } else { $null }
                ParentProcessName = if ($processItem) { $processItem.ParentProcessName } else { $null }
                ParentExecutablePath = if ($processItem) { $processItem.ParentExecutablePath } else { $null }
                ParentCommandLine = if ($processItem) { $processItem.ParentCommandLine } else { $null }
                Owner = if ($processItem) { $processItem.Owner } else { $null }
                SignatureStatus = if ($processItem) { $processItem.SignatureStatus } else { $null }
                Signer = if ($processItem) { $processItem.Signer } else { $null }
                ServiceNames = $serviceNames
                IsPowerShell = if ($processItem) { $processItem.IsPowerShell } else { $false }
                IsLegacyPowerShellCandidate = if ($processItem) { $processItem.IsLegacyPowerShellCandidate } else { $false }
                IsLolbin = if ($processItem) { $processItem.IsLolbin } else { $false }
                HasSuspiciousCommandLine = if ($processItem) { $processItem.HasSuspiciousCommandLine } else { $false }
            }
        }
    )
}

function Get-SteveRegistryAutoruns {
    if (-not $IncludeRegistryAutoruns) {
        return @()
    }

    $autorunPaths = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
        "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
        "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
    )

    $results = @()

    foreach ($registryPath in $autorunPaths) {
        if (Test-Path -LiteralPath $registryPath) {
            try {
                $item = Get-ItemProperty -LiteralPath $registryPath -ErrorAction Stop
                $properties = $item.PSObject.Properties | Where-Object {
                    $_.Name -notmatch '^PS'
                }

                foreach ($propertyItem in $properties) {
                    $raw = ConvertTo-SteveSafeString $propertyItem.Value
                    $resolved = Resolve-SteveExecutablePath $raw
                    $sig = Get-SteveSignatureInfo -Path $resolved

                    $results += [PSCustomObject]@{
                        RegistryPath = $registryPath
                        Name = $propertyItem.Name
                        Value = $raw
                        ResolvedPath = $resolved
                        SignatureStatus = $sig.SignatureStatus
                        Signer = $sig.Signer
                    }
                }
            }
            catch {
                Add-SteveNonFatalError "Failed to read registry autorun path '$registryPath': $($_.Exception.Message)"

                $results += [PSCustomObject]@{
                    RegistryPath = $registryPath
                    Name = "<error>"
                    Value = $_.Exception.Message
                    ResolvedPath = $null
                    SignatureStatus = "NotChecked"
                    Signer = $null
                }
            }
        }
    }

    return @($results)
}

function Get-SteveKnownFolderMetadata {
    param([object]$KnownFolders)

    if (-not $IncludeKnownFolderMetadata) {
        return @()
    }

    $interestingExtensions = @(
        ".exe",
        ".dll",
        ".scr",
        ".ps1",
        ".psm1",
        ".psd1",
        ".vbs",
        ".js",
        ".jse",
        ".wsf",
        ".bat",
        ".cmd",
        ".lnk",
        ".hta",
        ".iso",
        ".img",
        ".zip",
        ".rar",
        ".7z"
    )

    $foldersToReview = @(
        "Desktop",
        "Documents",
        "Pictures",
        "Downloads",
        "AppDataRoaming",
        "AppDataLocal",
        "Startup",
        "ProgramDataStartup"
    )

    $results = @()

    foreach ($folderName in $foldersToReview) {
        $folderPath = $KnownFolders[$folderName]

        if ((Test-SteveBlank $folderPath) -or -not (Test-Path -LiteralPath $folderPath)) {
            $results += [PSCustomObject]@{
                Folder = $folderName
                FolderPath = $folderPath
                FileName = $null
                Extension = $null
                FullName = $null
                Size = $null
                Created = $null
                Modified = $null
                IsExecutableOrScript = $null
                Note = "Folder missing or inaccessible"
            }

            continue
        }

        try {
            $items = Get-ChildItem -LiteralPath $folderPath -File -Recurse -Depth $KnownFolderMaxDepth -ErrorAction SilentlyContinue |
                Select-Object -First $KnownFolderMaxItemsPerFolder

            foreach ($item in $items) {
                $extension = if ($item.Extension) { $item.Extension.ToLowerInvariant() } else { "" }
                $isInteresting = $interestingExtensions -contains $extension

                $results += [PSCustomObject]@{
                    Folder = $folderName
                    FolderPath = $folderPath
                    FileName = $item.Name
                    Extension = $item.Extension
                    FullName = $item.FullName
                    Size = $item.Length
                    Created = $item.CreationTime
                    Modified = $item.LastWriteTime
                    IsExecutableOrScript = $isInteresting
                    Note = if ($isInteresting) { "Interesting extension metadata only; content not read" } else { "Metadata only; content not read" }
                }
            }
        }
        catch {
            Add-SteveNonFatalError "Folder metadata enumeration failed for '$folderName': $($_.Exception.Message)"

            $results += [PSCustomObject]@{
                Folder = $folderName
                FolderPath = $folderPath
                FileName = $null
                Extension = $null
                FullName = $null
                Size = $null
                Created = $null
                Modified = $null
                IsExecutableOrScript = $null
                Note = "Folder enumeration failed: $($_.Exception.Message)"
            }
        }
    }

    return @($results)
}

function Test-SteveUserWritablePath {
    param([string]$Path)

    if (Test-SteveBlank $Path) {
        return $false
    }

    $normalized = $Path.ToLowerInvariant()
    $userProfile = if ($env:USERPROFILE) { $env:USERPROFILE.ToLowerInvariant() } else { "" }
    $programData = if ($env:ProgramData) { $env:ProgramData.ToLowerInvariant() } else { "" }

    return (
        ($userProfile -and $normalized.StartsWith($userProfile)) -or
        ($programData -and $normalized.StartsWith($programData)) -or
        ($normalized -like "*\appdata\*") -or
        ($normalized -like "*\users\public\*") -or
        ($normalized -like "*\temp\*") -or
        ($normalized -like "*\downloads\*")
    )
}

function Test-SteveWindowsNameWrongPath {
    param(
        [string]$Name,
        [string]$Path
    )

    if ((Test-SteveBlank $Name) -or (Test-SteveBlank $Path)) {
        return $false
    }

    $windowsNames = @(
        "svchost.exe",
        "lsass.exe",
        "services.exe",
        "winlogon.exe",
        "csrss.exe",
        "smss.exe",
        "explorer.exe",
        "rundll32.exe",
        "regsvr32.exe",
        "powershell.exe",
        "cmd.exe",
        "conhost.exe"
    )

    $n = $Name.ToLowerInvariant()
    $p = $Path.ToLowerInvariant()
    $windir = if ($env:windir) { $env:windir.ToLowerInvariant() } else { "c:\windows" }

    if ($windowsNames -contains $n) {
        if ($n -eq "explorer.exe") {
            return ($p -ne "$windir\explorer.exe")
        }

        return (
            $p -notlike "$windir\system32\*" -and
            $p -notlike "$windir\syswow64\*"
        )
    }

    return $false
}

function Test-SteveSecurityToolName {
    param([string]$Name)

    if (Test-SteveBlank $Name) {
        return $false
    }

    $securityNames = @(
        "msmpeng.exe",
        "nissrv.exe",
        "senseir.exe",
        "sensendr.exe",
        "sense.exe",
        "securityhealthservice.exe",
        "windefend.exe",
        "mde.exe",
        "mdatp.exe"
    )

    return ($securityNames -contains $Name.ToLowerInvariant())
}

function Test-StevePublicRemoteAddress {
    param([string]$Address)

    if (Test-SteveBlank $Address) {
        return $false
    }

    $a = $Address.Trim()

    if ($a -in @("0.0.0.0", "::", "::1", "127.0.0.1", "localhost", "*")) {
        return $false
    }

    if ($a -match '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)') {
        return $false
    }

    if ($a -match '^(169\.254\.|224\.|239\.|255\.)') {
        return $false
    }

    if ($a -match '^(fe80:|ff00:)') {
        return $false
    }

    return $true
}

function Get-SteveFindingScore {
    param(
        [object]$PortProcess,
        [hashtable]$AutorunByPath
    )

    $score = 0
    $signals = New-Object System.Collections.Generic.List[string]
    $questions = New-Object System.Collections.Generic.List[string]

    $name = ConvertTo-SteveSafeString $PortProcess.ProcessName
    $path = ConvertTo-SteveSafeString $PortProcess.ExecutablePath
    $cmd = ConvertTo-SteveSafeString $PortProcess.CommandLine
    $parentName = ConvertTo-SteveSafeString $PortProcess.ParentProcessName
    $state = ConvertTo-SteveSafeString $PortProcess.State
    $remoteAddress = ConvertTo-SteveSafeString $PortProcess.RemoteAddress
    $remotePort = ConvertTo-SteveSafeString $PortProcess.RemotePort
    $localPort = ConvertTo-SteveSafeString $PortProcess.LocalPort

    if (Test-SteveSecurityToolName -Name $name) {
        $score -= 25
        $signals.Add("known_security_tool_expected_behavior") | Out-Null
        $questions.Add("Is this security component installed and expected on this machine?") | Out-Null
    }

    if ($PortProcess.IsLegacyPowerShellCandidate) {
        $score += 20
        $signals.Add("legacy_powershell_review_priority") | Out-Null
        $questions.Add("Why is legacy Windows PowerShell present in this network/process chain, and who launched it?") | Out-Null
    }

    if ($PortProcess.IsPowerShell -and (Test-StevePublicRemoteAddress -Address $remoteAddress)) {
        $score += 35
        $signals.Add("powershell_external_network_connection") | Out-Null
        $questions.Add("Why does PowerShell have an external network connection to $($remoteAddress):$($remotePort)?") | Out-Null
    }

    if ($PortProcess.IsPowerShell -and $state -eq "Listen") {
        $score += 40
        $signals.Add("powershell_listening_socket") | Out-Null
        $questions.Add("Why is PowerShell listening locally on port ${localPort}?") | Out-Null
    }

    if (Test-SteveUserWritablePath -Path $path) {
        $score += 20
        $signals.Add("user_writable_execution_path") | Out-Null
        $questions.Add("Why is this network-capable process running from a user-writable path?") | Out-Null
    }

    if (Test-SteveWindowsNameWrongPath -Name $name -Path $path) {
        $score += 35
        $signals.Add("process_claims_windows_name_wrong_path") | Out-Null
        $questions.Add("Why does this Windows-looking process run outside the expected Windows path?") | Out-Null
    }

    if ($cmd -match '(?i)(-enc|encodedcommand|hidden|windowstyle\s+hidden|downloadstring|frombase64string|invoke-expression|\biex\b|executionpolicy\s+bypass|\bnop\b|noprofile)') {
        $score += 30
        $signals.Add("encoded_or_obfuscated_command_line") | Out-Null
        $questions.Add("Why does the command line include encoded, hidden, bypass, or dynamic execution behavior?") | Out-Null
    }

    if (Test-SteveLolbinName -Name $name) {
        $signals.Add("living_off_the_land_binary_observed") | Out-Null

        if ($cmd -match '(?i)(http|https|ftp|download|urlcache|script|\.sct|\.hta|\.ps1|\.vbs|\.js|base64|bypass)') {
            $score += 25
            $signals.Add("lolbin_context_drift_candidate") | Out-Null
            $questions.Add("Who launched this trusted Windows tool, from where, and for what purpose?") | Out-Null
        }
    }

    if ($parentName -match '(?i)(winword|excel|powerpnt|outlook|chrome|msedge|firefox|7z|winrar|rundll32|regsvr32|mshta|wscript|cscript)') {
        $score += 20
        $signals.Add("high_risk_parent_for_script_or_network_activity") | Out-Null
        $questions.Add("Is parent process ${parentName} expected to launch this network-active child?") | Out-Null
    }

    if ($state -eq "Listen") {
        $score += 10
        $signals.Add("listening_socket") | Out-Null
        $questions.Add("Is this machine expected to accept inbound connections on local port ${localPort}?") | Out-Null
    }

    if (
        (Test-StevePublicRemoteAddress -Address $remoteAddress) -and
        $remotePort -and
        "$remotePort" -notin @("80", "443", "53", "123")
    ) {
        $score += 15
        $signals.Add("public_remote_address_uncommon_remote_port") | Out-Null
        $questions.Add("Is remote endpoint $($remoteAddress):$($remotePort) expected for this process role?") | Out-Null
    }

    if ($PortProcess.SignatureStatus -and $PortProcess.SignatureStatus -eq "Valid") {
        $score -= 10
        $signals.Add("valid_signature_reduces_concern") | Out-Null
    }

    if ($PortProcess.SignatureStatus -and $PortProcess.SignatureStatus -notin @("Valid", "NotChecked")) {
        $score += 15
        $signals.Add("signature_not_valid_or_missing") | Out-Null
        $questions.Add("Why is this network-active process missing a valid signature or signature check?") | Out-Null
    }

    $persistenceSource = $null

    if ($path) {
        $pathKey = $path.ToLowerInvariant()

        if ($AutorunByPath.ContainsKey($pathKey)) {
            $score += 25
            $signals.Add("persistence_source_then_network_candidate") | Out-Null
            $persistenceSource = $AutorunByPath[$pathKey]
            $questions.Add("Did this autostart entry legitimately launch a network-capable process?") | Out-Null
        }
    }

    $band = "green"
    $label = "explained_normal"

    if ($score -gt 0 -and $score -lt 20) {
        $band = "blue"
        $label = "interesting_but_explained_or_low_signal"
    }
    elseif ($score -ge 20 -and $score -lt 40) {
        $band = "yellow"
        $label = "unknown_needs_context"
    }
    elseif ($score -ge 40 -and $score -lt 70) {
        $band = "orange"
        $label = "suspicious_context_drift"
    }
    elseif ($score -ge 70) {
        $band = "red"
        $label = "high_risk_behavior_chain"
    }

    return [PSCustomObject]@{
        Score = $score
        Band = $band
        Label = $label
        Signals = $signals.ToArray()
        Questions = $questions.ToArray()
        PersistenceSource = $persistenceSource
    }
}

function Invoke-SteveAnalysis {
    param(
        [array]$PidPortMap,
        [array]$Autoruns
    )

    $autorunByPath = @{}

    foreach ($autorunItem in $Autoruns) {
        if ($autorunItem.ResolvedPath) {
            $key = $autorunItem.ResolvedPath.ToLowerInvariant()

            if (-not $autorunByPath.ContainsKey($key)) {
                $autorunByPath[$key] = @()
            }

            $autorunByPath[$key] += "$($autorunItem.RegistryPath)::$($autorunItem.Name)"
        }
    }

    $findings = @()

    foreach ($row in $PidPortMap) {
        if (Test-SteveObjectHasProperty -Object $row -Name "Error") {
            continue
        }

        $score = Get-SteveFindingScore -PortProcess $row -AutorunByPath $autorunByPath

        if ($score.Score -gt 0 -or $score.Signals.Count -gt 0) {
            $findings += [PSCustomObject]@{
                Finding = "process_boundary_or_network_context_review"
                Protocol = $row.Protocol
                LocalAddress = $row.LocalAddress
                LocalPort = $row.LocalPort
                RemoteAddress = $row.RemoteAddress
                RemotePort = $row.RemotePort
                State = $row.State
                PID = $row.OwningProcess
                ProcessName = $row.ProcessName
                ParentProcessId = $row.ParentProcessId
                ParentProcessName = $row.ParentProcessName
                ParentExecutablePath = $row.ParentExecutablePath
                Path = $row.ExecutablePath
                User = $row.Owner
                CommandLine = $row.CommandLine
                ServiceNames = $row.ServiceNames
                SignatureStatus = $row.SignatureStatus
                Signer = $row.Signer
                IsPowerShell = $row.IsPowerShell
                IsLegacyPowerShellCandidate = $row.IsLegacyPowerShellCandidate
                IsLolbin = $row.IsLolbin
                Score = $score.Score
                Band = $score.Band
                Label = $score.Label
                Signals = $score.Signals -join "; "
                PersistenceSource = if ($score.PersistenceSource) { $score.PersistenceSource -join "; " } else { $null }
                Questions = $score.Questions -join "; "
            }
        }
    }

    return @($findings | Sort-Object Score -Descending)
}

function Get-SteveRemoteEndpointSummary {
    param([array]$PidPortMap)

    $publicRows = @(
        $PidPortMap | Where-Object {
            (-not (Test-SteveObjectHasProperty -Object $_ -Name "Error")) -and
            (Test-StevePublicRemoteAddress -Address (ConvertTo-SteveSafeString (Get-StevePropertyValue -Object $_ -Name "RemoteAddress" -Default $null)))
        }
    )

    return @(
        $publicRows |
            Group-Object RemoteAddress, RemotePort, ProcessName |
            ForEach-Object {
                $first = $_.Group | Select-Object -First 1

                [PSCustomObject]@{
                    RemoteAddress = $first.RemoteAddress
                    RemotePort = $first.RemotePort
                    ProcessName = $first.ProcessName
                    PID = $first.OwningProcess
                    ConnectionCount = $_.Count
                    States = (@($_.Group | Select-Object -ExpandProperty State -Unique) -join "; ")
                    ExecutablePath = $first.ExecutablePath
                    ParentProcessName = $first.ParentProcessName
                    SignatureStatus = $first.SignatureStatus
                    IsPowerShell = $first.IsPowerShell
                    IsLolbin = $first.IsLolbin
                }
            } |
            Sort-Object ConnectionCount -Descending
    )
}

function New-SteveAgentHandoff {
    param(
        [object]$Summary,
        [array]$ProcessInventory,
        [array]$PidPortMap,
        [array]$Findings,
        [array]$RegistryAutoruns,
        [array]$RemoteEndpointSummary
    )

    $powerShellProcesses = @($ProcessInventory | Where-Object { Get-StevePropertyValue -Object $_ -Name "IsPowerShell" -Default $false })
    $legacyPowerShellProcesses = @($ProcessInventory | Where-Object { Get-StevePropertyValue -Object $_ -Name "IsLegacyPowerShellCandidate" -Default $false })
    $lolbinProcesses = @($ProcessInventory | Where-Object { Get-StevePropertyValue -Object $_ -Name "IsLolbin" -Default $false })
    $networkPowerShell = @($PidPortMap | Where-Object { Get-StevePropertyValue -Object $_ -Name "IsPowerShell" -Default $false })
    $networkLolbins = @($PidPortMap | Where-Object { Get-StevePropertyValue -Object $_ -Name "IsLolbin" -Default $false })
    $highRiskFindings = @($Findings | Where-Object { (Get-StevePropertyValue -Object $_ -Name "Band" -Default "") -in @("orange", "red") })
    $listeningSockets = @($PidPortMap | Where-Object { (Get-StevePropertyValue -Object $_ -Name "State" -Default "") -eq "Listen" })

    $evidenceQuality = "complete"

    if (@($Summary.CollectorHealth.FatalErrors).Count -gt 0) {
        $evidenceQuality = "insufficient_or_failed"
    }
    elseif (@($Summary.CollectorHealth.PartialDataWarnings).Count -gt 0) {
        $evidenceQuality = "partial"
    }

    return [PSCustomObject]@{
        Contract = "Steve_Security_Nowline_JSON_First_Handoff"
        ContractVersion = "v_00045"
        Collector = $Script:CollectorName
        CollectorVersion = $Script:CollectorVersion
        PrimaryQuestion = "What process owns each port, who launched it, where did it come from, and does that make sense?"
        Summary = $Summary
        EvidenceQuality = $evidenceQuality
        PowerShellProcesses = $powerShellProcesses
        LegacyPowerShellProcesses = $legacyPowerShellProcesses
        NetworkActivePowerShell = $networkPowerShell
        LolbinProcesses = $lolbinProcesses
        NetworkActiveLolbins = $networkLolbins
        HighRiskFindings = $highRiskFindings
        ListeningSockets = $listeningSockets
        RemoteEndpointSummary = $RemoteEndpointSummary
        RegistryAutoruns = $RegistryAutoruns
        CrashFollowUpHints = @(
            "If blocking a connection causes crashes, compare crash timestamp against ProcessInventory.CreationDate and PIDToPortMap.CreationTime.",
            "Check whether the blocked process was a service-hosted process before disabling anything.",
            "Preserve the JSON report and Windows Event Log timestamps before making destructive changes.",
            "Do not delete or disable Windows core services without validating service role and dependencies."
        )
    }
}

function Save-SteveJson {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Object,

        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    try {
        $Object | ConvertTo-Json -Depth 32 | Out-File -LiteralPath $Path -Encoding UTF8
    }
    catch {
        Add-SteveNonFatalError "Failed to save JSON '$Path': $($_.Exception.Message)"
        throw
    }
}

function Save-SteveCsv {
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Object,

        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $rows = @($Object)

    if ($rows.Count -eq 0) {
        @([PSCustomObject]@{ Note = "No rows" }) | Export-Csv -LiteralPath $Path -NoTypeInformation -Encoding UTF8
    }
    else {
        $rows | Export-Csv -LiteralPath $Path -NoTypeInformation -Encoding UTF8
    }
}

function New-SteveReadMe {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$DashboardPath,

        [Parameter(Mandatory = $true)]
        [string]$PrimaryJsonPath,

        [Parameter(Mandatory = $true)]
        [object]$Summary
    )

    $text = @"
Its me Steve.

ProcessPortSeeMapsConnections Local Collector completed.

WHAT THIS DID:
- Collected read-only local Windows endpoint metadata.
- Mapped processes, services, registry autoruns, IRQ resources, known folders, and PID-to-port connections.
- Added parent process names, PowerShell/LOLBin flags, remote endpoint summaries, and Steve JSON handoff data.
- Created a local dashboard so you can see what happened.
- Created JSON and CSV files for deeper Steve analysis.

WHAT THIS DID NOT DO:
- Did not delete files.
- Did not change registry.
- Did not kill processes.
- Did not change firewall rules.
- Did not upload anything.
- Did not read personal document or image contents.

OPEN THIS FIRST:
$DashboardPath

BRING THIS FILE BACK TO STEVE:
$PrimaryJsonPath

STATUS:
Collector version: $($Summary.Version)
Parent agent: $($Summary.ParentAgent)
Computer: $($Summary.ComputerName)
Run user: $($Summary.RunUser)
Admin: $($Summary.IsAdmin)
Findings: $($Summary.Counts.Findings)
High-risk findings: $($Summary.Counts.HighRiskFindings)
PowerShell processes: $($Summary.Counts.PowerShellProcesses)
Legacy PowerShell candidates: $($Summary.Counts.LegacyPowerShellCandidates)
Network-active PowerShell rows: $($Summary.Counts.NetworkActivePowerShellRows)

IMPORTANT:
Leakage is not conviction.
A finding means Steve needs to explain the behavior, not that the system is automatically infected.
If collector health says the run was partial, missing data may be a permission or visibility issue.
"@

    $text | Out-File -LiteralPath $Path -Encoding UTF8
}

function New-SteveHtmlDashboard {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [object]$Summary,

        [Parameter(Mandatory = $true)]
        [array]$Findings,

        [Parameter(Mandatory = $true)]
        [string]$PrimaryJsonPath,

        [Parameter(Mandatory = $true)]
        [string]$CollectorHealthPath
    )

    $topFindingsHtml = ""

    if (@($Findings).Count -gt 0) {
        $topFindingsHtml = (
            $Findings | Select-Object -First 25 | ForEach-Object {
                "<tr><td>$(ConvertTo-SteveHtml $_.Band)</td><td>$(ConvertTo-SteveHtml $_.Score)</td><td>$(ConvertTo-SteveHtml $_.ProcessName)</td><td>$(ConvertTo-SteveHtml $_.PID)</td><td>$(ConvertTo-SteveHtml $_.ParentProcessName)</td><td>$(ConvertTo-SteveHtml $_.LocalPort)</td><td>$(ConvertTo-SteveHtml $_.RemoteAddress)</td><td>$(ConvertTo-SteveHtml $_.RemotePort)</td><td>$(ConvertTo-SteveHtml $_.Label)</td><td>$(ConvertTo-SteveHtml $_.Questions)</td></tr>"
            }
        ) -join "`n"
    }
    else {
        $topFindingsHtml = "<tr><td colspan='10'>No findings were scored. This does not prove the system is clean; it means no scored context-drift findings were produced from available telemetry.</td></tr>"
    }

    $fatalErrorsHtml = if (@($Summary.CollectorHealth.FatalErrors).Count -gt 0) {
        (@($Summary.CollectorHealth.FatalErrors) | ForEach-Object {
            "<li>$(ConvertTo-SteveHtml $_)</li>"
        }) -join "`n"
    }
    else {
        "<li>None reported</li>"
    }

    $warningsHtml = if (@($Summary.CollectorHealth.PartialDataWarnings).Count -gt 0) {
        (@($Summary.CollectorHealth.PartialDataWarnings) | ForEach-Object {
            "<li>$(ConvertTo-SteveHtml $_)</li>"
        }) -join "`n"
    }
    else {
        "<li>None reported</li>"
    }

    $html = @"
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>ProcessPortSeeMapsConnections Dashboard</title>
<style>
body { font-family: Segoe UI, Arial, sans-serif; margin: 24px; background: #0f172a; color: #e5e7eb; }
h1 { color: #67e8f9; }
h2 { color: #bfdbfe; }
.card { background: #111827; border: 1px solid #374151; border-radius: 10px; padding: 16px; margin-bottom: 16px; }
table { border-collapse: collapse; width: 100%; background: #020617; }
th, td { border: 1px solid #374151; padding: 8px; font-size: 13px; vertical-align: top; }
th { background: #1f2937; color: #93c5fd; }
.green { color: #86efac; }
.blue { color: #93c5fd; }
.yellow { color: #fde68a; }
.orange { color: #fdba74; }
.red { color: #fca5a5; }
.path { font-family: Consolas, monospace; color: #c4b5fd; word-break: break-all; }
.small { color: #9ca3af; font-size: 13px; }
</style>
</head>
<body>
<h1>Its me Steve — ProcessPortSeeMapsConnections Local Collector</h1>

<div class="card">
<h2>Run Summary</h2>
<p><b>Version:</b> $(ConvertTo-SteveHtml $Summary.Version)</p>
<p><b>Parent agent:</b> $(ConvertTo-SteveHtml $Summary.ParentAgent)</p>
<p><b>Computer:</b> $(ConvertTo-SteveHtml $Summary.ComputerName)</p>
<p><b>Run user:</b> $(ConvertTo-SteveHtml $Summary.RunUser)</p>
<p><b>Admin:</b> $(ConvertTo-SteveHtml $Summary.IsAdmin)</p>
<p><b>Run started:</b> $(ConvertTo-SteveHtml $Summary.RunStarted)</p>
<p><b>Run completed:</b> $(ConvertTo-SteveHtml $Summary.RunCompleted)</p>
</div>

<div class="card">
<h2>What to bring back to Steve</h2>
<p>Primary JSON report:</p>
<p class="path">$(ConvertTo-SteveHtml $PrimaryJsonPath)</p>
<p>Collector health:</p>
<p class="path">$(ConvertTo-SteveHtml $CollectorHealthPath)</p>
</div>

<div class="card">
<h2>Collector Health</h2>
<ul>
<li><b>Windows platform:</b> $(ConvertTo-SteveHtml $Summary.CollectorHealth.WindowsPlatform)</li>
<li><b>Output writable:</b> $(ConvertTo-SteveHtml $Summary.CollectorHealth.OutputDirectoryWritable)</li>
<li><b>CIM available:</b> $(ConvertTo-SteveHtml $Summary.CollectorHealth.CimAvailable)</li>
<li><b>TCP command available:</b> $(ConvertTo-SteveHtml $Summary.CollectorHealth.GetNetTCPConnectionAvailable)</li>
<li><b>UDP command available:</b> $(ConvertTo-SteveHtml $Summary.CollectorHealth.GetNetUDPEndpointAvailable)</li>
<li><b>Signature command available:</b> $(ConvertTo-SteveHtml $Summary.CollectorHealth.GetAuthenticodeSignatureAvailable)</li>
</ul>
<h3>Fatal errors</h3>
<ul>$fatalErrorsHtml</ul>
<h3>Partial-data warnings</h3>
<ul>$warningsHtml</ul>
</div>

<div class="card">
<h2>Counts</h2>
<ul>
<li>Processes: $(ConvertTo-SteveHtml $Summary.Counts.Processes)</li>
<li>Services: $(ConvertTo-SteveHtml $Summary.Counts.Services)</li>
<li>Drivers: $(ConvertTo-SteveHtml $Summary.Counts.Drivers)</li>
<li>PID-to-port rows: $(ConvertTo-SteveHtml $Summary.Counts.PidPortRows)</li>
<li>Findings: $(ConvertTo-SteveHtml $Summary.Counts.Findings)</li>
<li>High-risk findings: $(ConvertTo-SteveHtml $Summary.Counts.HighRiskFindings)</li>
<li>PowerShell processes: $(ConvertTo-SteveHtml $Summary.Counts.PowerShellProcesses)</li>
<li>Legacy PowerShell candidates: $(ConvertTo-SteveHtml $Summary.Counts.LegacyPowerShellCandidates)</li>
<li>Network-active PowerShell rows: $(ConvertTo-SteveHtml $Summary.Counts.NetworkActivePowerShellRows)</li>
<li>Network-active LOLBin rows: $(ConvertTo-SteveHtml $Summary.Counts.NetworkActiveLolbinRows)</li>
</ul>
</div>

<div class="card">
<h2>Cold Bands</h2>
<ul>
<li class="green">Green: $(ConvertTo-SteveHtml $Summary.ColdBands.Green)</li>
<li class="blue">Blue: $(ConvertTo-SteveHtml $Summary.ColdBands.Blue)</li>
<li class="yellow">Yellow: $(ConvertTo-SteveHtml $Summary.ColdBands.Yellow)</li>
<li class="orange">Orange: $(ConvertTo-SteveHtml $Summary.ColdBands.Orange)</li>
<li class="red">Red: $(ConvertTo-SteveHtml $Summary.ColdBands.Red)</li>
</ul>
<p class="small">Reminder: leakage is not conviction. Findings require context review.</p>
</div>

<div class="card">
<h2>Top Findings</h2>
<table>
<tr>
<th>Band</th>
<th>Score</th>
<th>Process</th>
<th>PID</th>
<th>Parent</th>
<th>Local Port</th>
<th>Remote Address</th>
<th>Remote Port</th>
<th>Label</th>
<th>Question</th>
</tr>
$topFindingsHtml
</table>
</div>

</body>
</html>
"@

    $html | Out-File -LiteralPath $Path -Encoding UTF8
}

Write-SteveStep "Starting local read-only endpoint collection."

if (-not (New-SteveDirectory -Path $OutputDirectory)) {
    Write-SteveStep "Output directory could not be created. Stopping." -Level "Error"
    return
}

Write-SteveStep "Running collector self-test and health checks."
$collectorHealth = Get-SteveCollectorHealth -OutputDirectoryPath $OutputDirectory

Write-SteveStep "Collecting current user and profile context."
$profile = Get-SteveCurrentUserProfile

Write-SteveStep "Collecting system overview."
$systemOverview = Get-SteveSystemOverview

Write-SteveStep "Collecting IRQ and hardware resource inventory."
$irqInventory = @(Get-SteveIRQInventory)

Write-SteveStep "Collecting PnP device inventory."
$pnpInventory = @(Get-StevePnPInventory)

Write-SteveStep "Collecting drivers."
$driverInventory = @(Get-SteveDriverInventory)

Write-SteveStep "Collecting services."
$serviceInventory = @(Get-SteveServiceInventory)

Write-SteveStep "Collecting running processes."
$rawProcessInventory = @(Get-SteveProcessInventory)
$processInventory = @(Add-SteveParentProcessDetails -Processes $rawProcessInventory)

Write-SteveStep "Collecting TCP connections."
$tcpInventory = @(Get-SteveTcpInventory)

Write-SteveStep "Collecting UDP endpoints."
$udpInventory = @(Get-SteveUdpInventory)

Write-SteveStep "Joining PID-to-port map with parent-process details."
$pidPortMap = @(Join-StevePortsToProcesses -Processes $processInventory -Tcp $tcpInventory -Udp $udpInventory -Services $serviceInventory)

Write-SteveStep "Collecting registry autoruns."
$registryAutoruns = @(Get-SteveRegistryAutoruns)

Write-SteveStep "Collecting known-folder metadata only. File contents are not read."
$knownFolderMetadata = @(Get-SteveKnownFolderMetadata -KnownFolders $profile.KnownFolders)

Write-SteveStep "Running Steve leakage and context-drift scoring."
$findings = @(Invoke-SteveAnalysis -PidPortMap $pidPortMap -Autoruns $registryAutoruns)

Write-SteveStep "Building remote endpoint summary and JSON handoff."
$remoteEndpointSummary = @(Get-SteveRemoteEndpointSummary -PidPortMap $pidPortMap)

$summary = [PSCustomObject]@{
    Collector = $Script:CollectorName
    Version = $Script:CollectorVersion
    ParentAgent = $Script:ParentAgent
    RunStarted = $Script:RunStarted
    RunCompleted = Get-Date
    ComputerName = $env:COMPUTERNAME
    RunUser = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    IsAdmin = $Script:IsAdmin
    Counts = [PSCustomObject]@{
        IRQs = $irqInventory.Count
        PnPDevices = $pnpInventory.Count
        Drivers = $driverInventory.Count
        Services = $serviceInventory.Count
        Processes = $processInventory.Count
        TcpConnections = $tcpInventory.Count
        UdpEndpoints = $udpInventory.Count
        PidPortRows = $pidPortMap.Count
        RegistryAutoruns = $registryAutoruns.Count
        KnownFolderMetadataRows = $knownFolderMetadata.Count
        Findings = $findings.Count
        HighRiskFindings = @($findings | Where-Object { (Get-StevePropertyValue -Object $_ -Name "Band" -Default "") -in @("orange", "red") }).Count
        PowerShellProcesses = @($processInventory | Where-Object { Get-StevePropertyValue -Object $_ -Name "IsPowerShell" -Default $false }).Count
        LegacyPowerShellCandidates = @($processInventory | Where-Object { Get-StevePropertyValue -Object $_ -Name "IsLegacyPowerShellCandidate" -Default $false }).Count
        LolbinProcesses = @($processInventory | Where-Object { Get-StevePropertyValue -Object $_ -Name "IsLolbin" -Default $false }).Count
        NetworkActivePowerShellRows = @($pidPortMap | Where-Object { Get-StevePropertyValue -Object $_ -Name "IsPowerShell" -Default $false }).Count
        NetworkActiveLolbinRows = @($pidPortMap | Where-Object { Get-StevePropertyValue -Object $_ -Name "IsLolbin" -Default $false }).Count
        ListeningSockets = @($pidPortMap | Where-Object { (Get-StevePropertyValue -Object $_ -Name "State" -Default "") -eq "Listen" }).Count
        RemoteEndpointRows = $remoteEndpointSummary.Count
    }
    ColdBands = [PSCustomObject]@{
        Green = @($findings | Where-Object { (Get-StevePropertyValue -Object $_ -Name "Band" -Default "") -eq "green" }).Count
        Blue = @($findings | Where-Object { (Get-StevePropertyValue -Object $_ -Name "Band" -Default "") -eq "blue" }).Count
        Yellow = @($findings | Where-Object { (Get-StevePropertyValue -Object $_ -Name "Band" -Default "") -eq "yellow" }).Count
        Orange = @($findings | Where-Object { (Get-StevePropertyValue -Object $_ -Name "Band" -Default "") -eq "orange" }).Count
        Red = @($findings | Where-Object { (Get-StevePropertyValue -Object $_ -Name "Band" -Default "") -eq "red" }).Count
    }
    CollectorHealth = $collectorHealth
    Note = "Read-only local metadata collector. Leakage is not conviction. Findings require context review."
}

$agentHandoff = New-SteveAgentHandoff `
    -Summary $summary `
    -ProcessInventory $processInventory `
    -PidPortMap $pidPortMap `
    -Findings $findings `
    -RegistryAutoruns $registryAutoruns `
    -RemoteEndpointSummary $remoteEndpointSummary

$report = [PSCustomObject]@{
    VersioningPolicy = [PSCustomObject]@{
        FileNamingScheme = "ProcessPortSeeMapsConnections_LocalCollector_v.ps1"
        TopOfFileVersion = $Script:CollectorVersion
        ParentReference = @(
            "ProcessPortSeeMapsConnections_LocalCollector_v.ps1 v_00044",
            "Steve_Security_Nowline_v.yml v_00043"
        )
    }
    Summary = $summary
    CollectorHealth = $collectorHealth
    AgentHandoff = $agentHandoff
    SystemOverview = $systemOverview
    CurrentUserProfile = $profile
    IRQInventory = $irqInventory
    PnPInventory = $pnpInventory
    DriverInventory = $driverInventory
    ServiceInventory = $serviceInventory
    ProcessInventory = $processInventory
    TCPInventory = $tcpInventory
    UDPInventory = $udpInventory
    PIDToPortMap = $pidPortMap
    RemoteEndpointSummary = $remoteEndpointSummary
    RegistryAutoruns = $registryAutoruns
    KnownFolderMetadata = $knownFolderMetadata
    Findings = $findings
}

$jsonPath = Join-Path $OutputDirectory "$Script:BaseFileName`_Report.json"
$summaryPath = Join-Path $OutputDirectory "$Script:BaseFileName`_Summary.json"
$collectorHealthPath = Join-Path $OutputDirectory "$Script:BaseFileName`_CollectorHealth.json"
$agentHandoffPath = Join-Path $OutputDirectory "$Script:BaseFileName`_AgentHandoff.json"
$findingsCsvPath = Join-Path $OutputDirectory "$Script:BaseFileName`_Findings.csv"
$pidPortsCsvPath = Join-Path $OutputDirectory "$Script:BaseFileName`_PID_to_Port_Map.csv"
$processCsvPath = Join-Path $OutputDirectory "$Script:BaseFileName`_Processes.csv"
$remoteEndpointCsvPath = Join-Path $OutputDirectory "$Script:BaseFileName`_RemoteEndpointSummary.csv"
$autorunsCsvPath = Join-Path $OutputDirectory "$Script:BaseFileName`_RegistryAutoruns.csv"
$knownFoldersCsvPath = Join-Path $OutputDirectory "$Script:BaseFileName`_KnownFolderMetadata.csv"
$irqCsvPath = Join-Path $OutputDirectory "$Script:BaseFileName`_IRQ.csv"
$driversCsvPath = Join-Path $OutputDirectory "$Script:BaseFileName`_Drivers.csv"
$servicesCsvPath = Join-Path $OutputDirectory "$Script:BaseFileName`_Services.csv"
$readmePath = Join-Path $OutputDirectory "READ_ME_FIRST_ProcessPortSeeMapsConnections.txt"
$dashboardPath = Join-Path $OutputDirectory "ProcessPortSeeMapsConnections_Dashboard.html"

Write-SteveStep "Writing JSON and CSV reports."
Save-SteveJson -Object $report -Path $jsonPath
Save-SteveJson -Object $summary -Path $summaryPath
Save-SteveJson -Object $collectorHealth -Path $collectorHealthPath
Save-SteveJson -Object $agentHandoff -Path $agentHandoffPath
Save-SteveCsv -Object $findings -Path $findingsCsvPath
Save-SteveCsv -Object $pidPortMap -Path $pidPortsCsvPath
Save-SteveCsv -Object $processInventory -Path $processCsvPath
Save-SteveCsv -Object $remoteEndpointSummary -Path $remoteEndpointCsvPath
Save-SteveCsv -Object $registryAutoruns -Path $autorunsCsvPath
Save-SteveCsv -Object $knownFolderMetadata -Path $knownFoldersCsvPath
Save-SteveCsv -Object $irqInventory -Path $irqCsvPath
Save-SteveCsv -Object $driverInventory -Path $driversCsvPath
Save-SteveCsv -Object $serviceInventory -Path $servicesCsvPath

if ($WriteReadMe) {
    Write-SteveStep "Writing READ_ME_FIRST file."
    New-SteveReadMe -Path $readmePath -DashboardPath $dashboardPath -PrimaryJsonPath $jsonPath -Summary $summary
}

if ($WriteHtmlDashboard) {
    Write-SteveStep "Writing local HTML dashboard."
    New-SteveHtmlDashboard -Path $dashboardPath -Summary $summary -Findings $findings -PrimaryJsonPath $jsonPath -CollectorHealthPath $collectorHealthPath
}

if ($ConsoleSummary) {
    Write-Host ""
    Write-Host "Its me Steve." -ForegroundColor Cyan
    Write-Host "ProcessPortSeeMapsConnections Local Collector $Script:CollectorVersion completed." -ForegroundColor Green
    Write-Host ""
    Write-Host "Output directory:" -ForegroundColor Yellow
    Write-Host "  $OutputDirectory"
    Write-Host ""
    Write-Host "Open this first:" -ForegroundColor Yellow
    Write-Host "  $dashboardPath"
    Write-Host ""
    Write-Host "Bring this file back to Steve:" -ForegroundColor Yellow
    Write-Host "  $jsonPath"
    Write-Host ""
    Write-Host "Agent handoff JSON:" -ForegroundColor Yellow
    Write-Host "  $agentHandoffPath"
    Write-Host ""
    Write-Host "Collector health:" -ForegroundColor Yellow
    Write-Host "  $collectorHealthPath"
    Write-Host ""
    Write-Host "Summary:" -ForegroundColor Yellow
    $summary | Select-Object Collector, Version, ParentAgent, ComputerName, RunUser, IsAdmin, RunStarted, RunCompleted | Format-List
    Write-Host ""
    Write-Host "Counts:" -ForegroundColor Yellow
    $summary.Counts | Format-List
    Write-Host ""
    Write-Host "Cold Bands:" -ForegroundColor Yellow
    $summary.ColdBands | Format-List
    Write-Host ""
    Write-Host "Top findings:" -ForegroundColor Yellow
    $findings |
        Select-Object -First 15 Band, Score, ProcessName, PID, ParentProcessName, LocalPort, RemoteAddress, RemotePort, State, Label |
        Format-Table -AutoSize
    Write-Host ""
    Write-Host "Reminder: leakage is not conviction. Review process, parent, path, port, and persistence context before assigning danger." -ForegroundColor Green
}

if ($OpenDashboard -and (Test-Path -LiteralPath $dashboardPath)) {
    try {
        Write-SteveStep "Opening local dashboard."
        Start-Process -FilePath $dashboardPath
    }
    catch {
        Add-SteveNonFatalError "Dashboard could not be opened automatically: $($_.Exception.Message)"
        Write-SteveStep "Dashboard could not be opened automatically. Open it manually from the output directory." -Level "Warn"
    }
}

Write-SteveStep "Collection complete." -Level "Success"

return $report