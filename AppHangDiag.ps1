<#
.SYNOPSIS
    AppHangDiag v1.0 - Diagnose-Sammlung bei Anwendungshaengern/Freezes auf Windows 11 Enterprise.

.DESCRIPTION
    Sammelt System-, Event-, Prozess-, Ressourcen- und Software-Kontextdaten zur direkten
    und nachgelagerten KI-Analyse (report.json + summary.md mit KI-Analyseauftrag + export.zip).

    Betriebsmodi:
      - WPF-GUI (Standard): Prozessauswahl, System-/Prozess-Snapshot, Monitor-Modus mit Auto-Capture.
      - CLI (-Snapshot):    Headless-Erfassung fuer Automation/Remote (Intune, ServiceNow, PSRemoting).

    Optionale Komponenten:
      - ProcDump: Wird automatisch erkannt, wenn procdump64.exe/procdump.exe NEBEN dem Skript liegt
        (Sysinternals, MS-signiert). Ohne ProcDump erfolgt die Erfassung ohne Dump.
      - EVTX-Rohexport: Application/System als .evtx (forensisch vollstaendig, Klartextdaten).
      - App-Profile (M8): Zusatzerfassung fuer Office/Outlook/Teams/Nexus (C2R/Add-ins/Resiliency,
        OST/PST, WebView2, Prozessbaum, TCP/Latenz, Citrix-Session); erweiterbar ohne Codeaenderung
        per AppHangDiag.profiles.json neben dem Skript.
      - Lag-/Crash-Erfassung (Monitor): UI-Latenzmessung (SendMessageTimeout), Lag-Episoden,
        Leistungsverlauf (Ringpuffer), Crash-Capture mit ExitCode-Dekodierung und Ereignis-/WER-/
        Dump-Korrelation, optionaler ProcDump-Crash-Watchdog, Sitzungs-/Episodenprotokoll.
      - Plattform-adaptiv (M0): Erkennung Client / VDI / Citrix-Terminalserver / Server; auf
        Multi-Session sitzungsgefilterte Prozessliste, Sitzungs-Ressourcenaggregat, HDX-Metriken
        und Citrix-UPM-/Profilcontainer-Diagnose (M9, read-only).

.PARAMETER Snapshot
    CLI-Modus: fuehrt eine Erfassung ohne GUI durch.
.PARAMETER ProcessName
    CLI: Prozessname (ohne .exe) fuer prozessbezogene Erfassung.
.PARAMETER TargetPid
    CLI: Prozess-ID fuer prozessbezogene Erfassung (hat Vorrang vor ProcessName).
.PARAMETER IncludeEvtx
    EVTX-Rohexport (Application/System) in das Exportpaket aufnehmen.
.PARAMETER IncludeAppLogs
    App-Logdateien gemaess App-Profil einsammeln (z.B. Teams, Nexus). Limits: max. 5 Dateien je Pfad,
    5 MB je Datei, 25 MB gesamt; Ablage unter AppLogs\ im Capture-Ordner und im ZIP.
.PARAMETER Dump
    CLI: ProcDump-Dump (-ma) erstellen, sofern ProcDump vorhanden und Zielprozess gesetzt.
.PARAMETER EventWindowHours
    Zeitfenster fuer Event-/WER-/Reliability-Auswertung in Stunden (Default 72).
.PARAMETER OutputRoot
    Ausgabeverzeichnis (Default: Dokumente\AppHangDiag).

.EXAMPLE
    .\AppHangDiag.ps1
    Startet die WPF-GUI.

.EXAMPLE
    .\AppHangDiag.ps1 -Snapshot -ProcessName outlook -IncludeEvtx -IncludeAppLogs
    Headless-Erfassung inkl. EVTX und App-Logs gemaess Profil.

.EXAMPLE
    powershell.exe -ExecutionPolicy Bypass -File .\AppHangDiag.ps1 -Snapshot -TargetPid 4711 -Dump

.NOTES
    Version : 1.3.1
    Ziel-OS : Windows 11 Enterprise (22H2/23H2/24H2), PowerShell 5.1 (WPF), kompatibel zu PS 7
    Hinweise: Ohne Adminrechte sind Modul-Listen und Dumps fremder/elevierter Prozesse ggf. nicht lesbar.
              ProcDump loest je nach EDR-Policy Telemetrie aus (signiertes MS-Tool, i.d.R. unkritisch).
#>
#requires -Version 5.1
[CmdletBinding()]
param(
    [switch]$Snapshot,
    [string]$ProcessName,
    [int]$TargetPid = 0,
    [switch]$IncludeEvtx,
    [switch]$IncludeAppLogs,
    [switch]$Dump,
    [ValidateRange(1, 720)][int]$EventWindowHours = 72,
    [string]$OutputRoot = (Join-Path $env:USERPROFILE 'Documents\AppHangDiag')
)

Set-StrictMode -Off
$ErrorActionPreference = 'Continue'

#region Globals
$Script:AppVersion = '1.3.1'
$Script:ScriptDir  = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }

# ProcDump-Erkennung: nur wenn Binary neben dem Skript liegt (Entscheidung 1a)
$Script:ProcDumpExe = $null
foreach ($n in @('procdump64.exe', 'procdump.exe')) {
    $p = Join-Path $Script:ScriptDir $n
    if (Test-Path -LiteralPath $p) { $Script:ProcDumpExe = $p; break }
}

$Script:IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
#endregion Globals

#region Bibliothek (wird 1:1 in Capture-Runspace uebernommen)

function Write-DiagLog {
    param([string]$Message, [ValidateSet('INFO','WARN','ERROR','OK')][string]$Level = 'INFO')
    $line = '{0:HH:mm:ss} [{1,-5}] {2}' -f (Get-Date), $Level, $Message
    if ($script:DiagLogQueue) { [void]$script:DiagLogQueue.Add($line) }
    else { Write-Host $line }
}

function Get-LocalizedCounterName {
    # Aufloesung Performance-Counter-Index -> lokalisierter Name (deutsches OS!)
    param([int]$Index)
    if (-not $script:PerfNameMap) {
        $script:PerfNameMap = @{}
        try {
            $raw = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Perflib\CurrentLanguage' -Name Counter -ErrorAction Stop).Counter
            for ($i = 0; $i -lt ($raw.Count - 1); $i += 2) {
                $k = 0
                if ([int]::TryParse($raw[$i], [ref]$k)) {
                    if (-not $script:PerfNameMap.ContainsKey($k)) { $script:PerfNameMap[$k] = $raw[$i + 1] }
                }
            }
        } catch {
            Write-DiagLog "Perflib-Namensaufloesung fehlgeschlagen: $($_.Exception.Message)" 'WARN'
        }
    }
    return $script:PerfNameMap[$Index]
}

function Get-PendingReboot {
    $reasons = New-Object System.Collections.Generic.List[string]
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $reasons.Add('CBS RebootPending') }
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $reasons.Add('WindowsUpdate RebootRequired') }
    try {
        $pfro = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations
        if ($pfro) { $reasons.Add('PendingFileRenameOperations') }
    } catch { }
    [pscustomobject]@{ Pending = ($reasons.Count -gt 0); Gruende = @($reasons) }
}

function Get-SystemInfo {
    Write-DiagLog 'M1: Systeminformationen erfassen...'
    $os  = Get-CimInstance Win32_OperatingSystem
    $cs  = Get-CimInstance Win32_ComputerSystem
    $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
    $dv  = $null
    try { $dv = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop).DisplayVersion } catch { }
    $gpu = @(Get-CimInstance Win32_VideoController -ErrorAction SilentlyContinue | ForEach-Object {
        [pscustomobject]@{
            Name         = $_.Name
            Treiber      = $_.DriverVersion
            TreiberDatum = $(if ($_.DriverDate) { Get-Date $_.DriverDate -Format 'yyyy-MM-dd' } else { $null })
        }
    })
    $power = ''
    try { $power = ((powercfg.exe /getactivescheme) 2>$null | Out-String).Trim() } catch { }
    $boot    = $os.LastBootUpTime
    $up      = (Get-Date) - $boot
    $freePct = [math]::Round(($os.FreePhysicalMemory / $os.TotalVisibleMemorySize) * 100, 1)
    $pr      = Get-PendingReboot
    [pscustomobject]@{
        Hostname             = $env:COMPUTERNAME
        Benutzer             = "$env:USERDOMAIN\$env:USERNAME"
        OS                   = $os.Caption
        DisplayVersion       = $dv
        OSVersion            = $os.Version
        Build                = $os.BuildNumber
        Modell               = "$($cs.Manufacturer) $($cs.Model)".Trim()
        CPU                  = $cpu.Name
        LogischeProzessoren  = $cs.NumberOfLogicalProcessors
        RamGB                = [math]::Round($cs.TotalPhysicalMemory / 1GB, 1)
        RamFreiProzent       = $freePct
        CpuLastProzent       = $cpu.LoadPercentage
        LetzterStart         = (Get-Date $boot -Format s)
        UptimeStunden        = [math]::Round($up.TotalHours, 1)
        Energieplan          = $power
        PendingReboot        = $pr.Pending
        PendingRebootGruende = $pr.Gruende
        GPU                  = $gpu
    }
}

function Get-HangEvents {
    param([int]$Hours = 72)
    Write-DiagLog "M2: Eventlogs auswerten (letzte $Hours h)..."
    $start   = (Get-Date).AddHours(-$Hours)
    $result  = New-Object System.Collections.Generic.List[object]
    $queries = @(
        @{ LogName = 'Application'; Id = @(1000, 1001, 1002) },   # App Error / WER / App Hang
        @{ LogName = 'System';      Id = @(41, 129, 153, 7011) }, # Kernel-Power / Storage-Reset / IO-Retry / Service-Timeout
        @{ LogName = 'OAlerts';     Id = $null },                 # Microsoft Office Alerts (falls Office vorhanden)
        @{ LogName = 'Application'; Id = $null; Provider = 'Citrix Profile management'; Level = @(2, 3); Tag = 'UPM' } # UPM Error/Warning
    )
    foreach ($q in $queries) {
        $ev = @()
        $filter = @{ LogName = $q.LogName; StartTime = $start }
        if ($q.Id) { $filter['Id'] = $q.Id }
        if ($q.Provider) { $filter['ProviderName'] = $q.Provider }
        if ($q.Level) { $filter['Level'] = $q.Level }
        try {
            $ev = @(Get-WinEvent -FilterHashtable $filter -ErrorAction Stop)
        } catch {
            if ($_.Exception.Message -notmatch 'No events|Keine Ereignisse|not exist|existiert nicht|nicht gefunden|kein Ereignisprotokoll|no event log') {
                Write-DiagLog "Eventlog $($q.LogName): $($_.Exception.Message)" 'WARN'
            }
        }
        foreach ($e in $ev) {
            $msg = $e.Message
            if (-not $msg) { $msg = '(keine Meldung / Provider-Metadaten fehlen)' }
            $exe = $null
            if ($msg -match '(?i)([\w\.\-\+~]+\.exe)') { $exe = $Matches[1].Trim() }
            # Signatur fuer Dedup/Gruppierung: 1000 nach exe+Modul+Code, WER-1001 nach Ereignisname + P1, sonst exe/Provider
            $sig = $exe
            if ($e.Id -eq 1000 -and $q.LogName -eq 'Application' -and -not $q.Tag) {
                $xc = $null; $fm = $null
                if ($msg -match '(?i)(?:Ausnahmecode|Exception code):\s*(0x[0-9a-f]+)') { $xc = $Matches[1].ToLower() }
                if ($msg -match '(?i)(?:Name des fehlerhaften Moduls|Fehlerhafter Modulname|Faulting module name):\s*([^,\r\n]+)') { $fm = $Matches[1].Trim() }
                $sigParts = @()
                if ($exe) { $sigParts += $exe }
                if ($fm)  { $sigParts += $fm }
                if ($xc)  { $sigParts += $xc }
                if ($sigParts.Count -gt 1) { $sig = ($sigParts -join ' | ') }
            }
            if ($e.Id -eq 1001) {
                $en = $null; $p1 = $null
                if ($msg -match '(?:Ereignisname|Event Name):\s*(\S+)') { $en = $Matches[1] }
                if ($msg -match 'P1:\s*(.*?)\s*P2:') { $p1 = $Matches[1].Trim() }
                $sig = 'WER'
                if ($en) { $sig = $en }
                if ($p1) { $sig = "$sig P1:$p1" }
            }
            if ($q.LogName -eq 'OAlerts') {
                $first = (@($msg -split "`r?`n") | Select-Object -First 1)
                if ($first) { $sig = ('OAlert: ' + $first.Trim()) }
                if ($sig -and $sig.Length -gt 60) { $sig = $sig.Substring(0, 60) }
            }
            if ($q.Tag -eq 'UPM') {
                $first = (@($msg -split "`r?`n") | Select-Object -First 1)
                $sig = 'UPM'
                if ($first) { $sig = ('UPM: ' + $first.Trim()) }
                if ($sig.Length -gt 60) { $sig = $sig.Substring(0, 60) }
            }
            if (-not $sig) { $sig = $e.ProviderName }
            $result.Add([pscustomobject]@{
                Zeit     = (Get-Date $e.TimeCreated -Format s)
                Log      = $q.LogName
                Id       = $e.Id
                Quelle   = $e.ProviderName
                Level    = $e.LevelDisplayName
                Prozess  = $exe
                Signatur = $sig
                Meldung  = $msg
            })
        }
    }
    $sorted = @($result.ToArray() | Sort-Object Zeit -Descending)
    $hangs  = @($sorted | Where-Object { $_.Id -eq 1002 })
    # Dedup: Gruppierung identischer Signaturen (kollabiert z.B. WER-Queue-Flush-Massenmeldungen)
    $gruppen = @($sorted | Group-Object -Property { '{0}|{1}|{2}' -f $_.Log, $_.Id, $_.Signatur } |
        Sort-Object Count -Descending | ForEach-Object {
            $neuest  = $_.Group | Select-Object -First 1
            $aeltest = $_.Group | Select-Object -Last 1
            [pscustomobject]@{
                Anzahl   = $_.Count
                Zuletzt  = $neuest.Zeit
                Erste    = $aeltest.Zeit
                Log      = $neuest.Log
                Id       = $neuest.Id
                Quelle   = $neuest.Quelle
                Signatur = $neuest.Signatur
                Beispiel = $neuest.Meldung
            }
        })
    $wer1001 = @($sorted | Where-Object { $_.Id -eq 1001 })
    $lke     = @($wer1001 | Where-Object { $_.Signatur -like 'LiveKernelEvent*' })
    $bsod    = @($wer1001 | Where-Object { $_.Signatur -like 'BlueScreen*' })
    [pscustomobject]@{
        FensterStunden       = $Hours
        AnzahlGesamt         = $sorted.Count
        AppHangs1002         = $hangs.Count
        AppCrashes1000       = @($sorted | Where-Object { $_.Id -eq 1000 }).Count
        WerReports1001       = $wer1001.Count
        LiveKernelEvents     = $lke.Count
        LiveKernelSignaturen = @($lke | Group-Object Signatur | Sort-Object Count -Descending | ForEach-Object {
                                   [pscustomobject]@{ Signatur = $_.Name; Anzahl = $_.Count }
                               })
        BlueScreens1001      = $bsod.Count
        BlueScreenSignaturen = @($bsod | Group-Object Signatur | Sort-Object Count -Descending | ForEach-Object {
                                   [pscustomobject]@{ Signatur = $_.Name; Anzahl = $_.Count }
                               })
        ServiceTimeouts7011  = @($sorted | Where-Object { $_.Id -eq 7011 }).Count
        StorageEvents129_153 = @($sorted | Where-Object { ($_.Id -eq 129 -or $_.Id -eq 153) -and $_.Log -eq 'System' }).Count
        KernelPower41        = @($sorted | Where-Object { $_.Id -eq 41 }).Count
        OAlerts              = @($sorted | Where-Object { $_.Log -eq 'OAlerts' }).Count
        UpmEvents            = @($sorted | Where-Object { $_.Quelle -eq 'Citrix Profile management' }).Count
        CrashSignaturen      = @($sorted | Where-Object { $_.Id -eq 1000 -and $_.Quelle -ne 'Citrix Profile management' } |
                                   Group-Object Signatur | Sort-Object Count -Descending | ForEach-Object {
                                   [pscustomobject]@{ Signatur = $_.Name; Anzahl = $_.Count }
                               })
        HangsProAnwendung    = @($hangs | Group-Object Prozess | Sort-Object Count -Descending | ForEach-Object {
                                   [pscustomobject]@{ Anwendung = $_.Name; Anzahl = $_.Count }
                               })
        EreignisseGruppiert  = $gruppen
        Ereignisse           = $sorted
    }
}

function Get-WerReports {
    param([int]$Hours = 72)
    Write-DiagLog 'M3a: WER ReportArchive (Metadaten)...'
    $cut   = (Get-Date).AddHours(-$Hours)
    $roots = @(
        (Join-Path $env:ProgramData  'Microsoft\Windows\WER\ReportArchive'),
        (Join-Path $env:LOCALAPPDATA 'Microsoft\Windows\WER\ReportArchive')
    )
    $items = New-Object System.Collections.Generic.List[object]
    foreach ($root in $roots) {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        $dirs = @()
        try { $dirs = @(Get-ChildItem -LiteralPath $root -Directory -ErrorAction Stop) }
        catch { Write-DiagLog "WER-Zugriff verweigert: $root" 'WARN'; continue }
        foreach ($d in $dirs) {
            if ($d.LastWriteTime -lt $cut) { continue }
            $werFile = Join-Path $d.FullName 'Report.wer'
            $app = $null; $etype = $null; $etime = $d.LastWriteTime
            $appPath = $null; $origName = $null; $targetId = $null
            if (Test-Path -LiteralPath $werFile) {
                foreach ($line in @(Get-Content -LiteralPath $werFile -TotalCount 250 -ErrorAction SilentlyContinue)) {
                    if ($line -like 'AppName=*')              { $app      = $line.Split('=', 2)[1] }
                    elseif ($line -like 'AppPath=*')          { $appPath  = $line.Split('=', 2)[1] }
                    elseif ($line -like 'OriginalFilename=*') { $origName = $line.Split('=', 2)[1] }
                    elseif ($line -like 'TargetAppId=*')      { $targetId = $line.Split('=', 2)[1] }
                    elseif ($line -like 'EventType=*')        { $etype    = $line.Split('=', 2)[1] }
                    elseif ($line -like 'EventTime=*') {
                        $t = 0L
                        if ([long]::TryParse($line.Split('=', 2)[1], [ref]$t)) {
                            try { $etime = [datetime]::FromFileTime($t) } catch { }
                        }
                    }
                }
            }
            # Fallback-Kette fuer MoApp*-/Store-Reports ohne AppName-Key
            if (-not $app -and $appPath)  { $app = Split-Path $appPath -Leaf }
            if (-not $app -and $origName) { $app = $origName }
            if (-not $app -and $targetId) {
                $app = $targetId
                if ($app.Length -gt 60) { $app = $app.Substring(0, 60) + '...' }
            }
            if (-not $etype) { $etype = ($d.Name -split '_')[0] }
            $items.Add([pscustomobject]@{
                Zeit      = (Get-Date $etime -Format s)
                Typ       = $etype
                Anwendung = $app
                Ordner    = $d.Name
            })
        }
    }
    @($items.ToArray() | Sort-Object Zeit -Descending)
}

function Get-ReliabilityInfo {
    param([int]$Hours = 72)
    Write-DiagLog 'M3b: Reliability-Records...'
    try {
        $cut  = (Get-Date).AddHours(-$Hours)
        $recs = @(Get-CimInstance Win32_ReliabilityRecords -ErrorAction Stop | Where-Object { $_.TimeGenerated -ge $cut })
        @($recs | ForEach-Object {
            $m = $_.Message
            if ($m -and $m.Length -gt 400) { $m = $m.Substring(0, 400) + ' ...' }
            [pscustomobject]@{
                Zeit    = (Get-Date $_.TimeGenerated -Format s)
                Quelle  = $_.SourceName
                EventId = $_.EventIdentifier
                Produkt = $_.ProductName
                Meldung = $m
            }
        } | Sort-Object Zeit -Descending)
    } catch {
        Write-DiagLog "Reliability-Records nicht verfuegbar: $($_.Exception.Message)" 'WARN'
        @()
    }
}

function Get-ProcessDetail {
    param([int]$TargetPid)
    Write-DiagLog "M4: Prozessdetails PID $TargetPid..."
    $p = $null
    try { $p = Get-Process -Id $TargetPid -ErrorAction Stop }
    catch { Write-DiagLog "Prozess $TargetPid nicht (mehr) vorhanden." 'WARN'; return $null }

    $cim = Get-CimInstance Win32_Process -Filter "ProcessId=$TargetPid" -ErrorAction SilentlyContinue
    $parent = $null
    if ($cim -and $cim.ParentProcessId) {
        try { $parent = "$((Get-Process -Id $cim.ParentProcessId -ErrorAction Stop).ProcessName) (PID $($cim.ParentProcessId))" }
        catch { $parent = "PID $($cim.ParentProcessId) (beendet)" }
    }
    $owner = $null
    if ($cim) {
        try {
            $o = Invoke-CimMethod -InputObject $cim -MethodName GetOwner -ErrorAction Stop
            if ($o.ReturnValue -eq 0) { $owner = "$($o.Domain)\$($o.User)" }
        } catch { }
    }

    $mods = @(); $modErr = $null
    try {
        $mods = @($p.Modules | ForEach-Object {
            $co = $null; $ver = $null
            try { $co  = $_.FileVersionInfo.CompanyName } catch { }
            try { $ver = $_.FileVersionInfo.FileVersion } catch { }
            [pscustomobject]@{
                Modul     = $_.ModuleName
                Pfad      = $_.FileName
                Version   = $ver
                Firma     = $co
                Microsoft = ($co -like '*Microsoft*')
            }
        })
    } catch {
        $modErr = $_.Exception.Message
        Write-DiagLog "Modulliste nicht lesbar (Rechte/Bitness): $modErr" 'WARN'
    }

    $threadStates = @($p.Threads | Group-Object ThreadState | ForEach-Object {
        [pscustomobject]@{ Status = "$($_.Name)"; Anzahl = $_.Count }
    })
    $waitReasons = @($p.Threads | Where-Object { "$($_.ThreadState)" -eq 'Wait' } | Group-Object WaitReason |
        Sort-Object Count -Descending | ForEach-Object {
            [pscustomobject]@{ Grund = "$($_.Name)"; Anzahl = $_.Count }
        })

    [pscustomobject]@{
        Name                 = $p.ProcessName
        PID                  = $p.Id
        Pfad                 = $(try { $p.Path } catch { $null })
        Version              = $(try { $p.FileVersionInfo.FileVersion } catch { $null })
        Produkt              = $(try { $p.FileVersionInfo.ProductName } catch { $null })
        Kommandozeile        = $(if ($cim) { $cim.CommandLine } else { $null })
        ElternProzess        = $parent
        Besitzer             = $owner
        SessionId            = $p.SessionId
        Start                = $(try { Get-Date $p.StartTime -Format s } catch { $null })
        CpuSekunden          = $(try { [math]::Round($p.TotalProcessorTime.TotalSeconds, 1) } catch { $null })
        RamMB                = [math]::Round($p.WorkingSet64 / 1MB, 1)
        PrivateMB            = [math]::Round($p.PrivateMemorySize64 / 1MB, 1)
        Handles              = $p.HandleCount
        Threads              = $p.Threads.Count
        Reagiert             = $p.Responding
        FensterTitel         = $p.MainWindowTitle
        ThreadStatus         = $threadStates
        WaitGruende          = $waitReasons
        ModuleGesamt         = $mods.Count
        ModuleNichtMicrosoft = @($mods | Where-Object { (-not $_.Microsoft) -and $_.Firma })
        ModuleOhneFirma      = @($mods | Where-Object { -not $_.Firma } | Select-Object -First 20)
        Module               = $mods
        ModulFehler          = $modErr
    }
}

function Get-TopProcesses {
    $cores = [Environment]::ProcessorCount
    $s1 = @{}
    foreach ($p in (Get-Process)) {
        $t = 0.0
        try { if ($p.TotalProcessorTime) { $t = $p.TotalProcessorTime.TotalMilliseconds } } catch { }
        $s1[$p.Id] = $t
    }
    Start-Sleep -Milliseconds 1000
    $list = foreach ($p in (Get-Process)) {
        $t2 = 0.0
        try { if ($p.TotalProcessorTime) { $t2 = $p.TotalProcessorTime.TotalMilliseconds } } catch { }
        $t1 = $t2
        if ($s1.ContainsKey($p.Id)) { $t1 = $s1[$p.Id] }
        [pscustomobject]@{
            PID        = $p.Id
            Name       = $p.ProcessName
            CpuProzent = [math]::Round((($t2 - $t1) / 1000) / $cores * 100, 1)
            RamMB      = [math]::Round($p.WorkingSet64 / 1MB, 0)
        }
    }
    [pscustomobject]@{
        TopCpu = @($list | Sort-Object CpuProzent -Descending | Select-Object -First 10)
        TopRam = @($list | Sort-Object RamMB -Descending | Select-Object -First 10)
    }
}

function Get-ResourceSnapshot {
    param([bool]$MultiSession = $false, [bool]$IncludeSessions = $false)
    Write-DiagLog 'M5: Ressourcen-Snapshot (Performance-Counter, ~3 s)...'
    $c = @{}
    # Sprachneutrale Counter-Aufloesung ueber Perflib-Indizes (deutsches OS-sicher)
    $defs = @(
        @{ Key = 'CpuGesamtProzent';       Obj = 238; Ctr = 6;    Inst = '_Total' },
        @{ Key = 'RamVerfuegbarMB';        Obj = 4;   Ctr = 1382; Inst = $null    },
        @{ Key = 'DiskAvgReadSec';         Obj = 234; Ctr = 208;  Inst = '_Total' },
        @{ Key = 'DiskAvgWriteSec';        Obj = 234; Ctr = 210;  Inst = '_Total' },
        @{ Key = 'DiskQueueLength';        Obj = 234; Ctr = 198;  Inst = '_Total' },
        @{ Key = 'PagefileNutzungProzent'; Obj = 700; Ctr = 702;  Inst = '_Total' }
    )
    $paths = @{}
    foreach ($d in $defs) {
        $on = Get-LocalizedCounterName -Index $d.Obj
        $cn = Get-LocalizedCounterName -Index $d.Ctr
        if ($on -and $cn) {
            $inst = ''
            if ($d.Inst) { $inst = "($($d.Inst))" }
            $paths[$d.Key] = "\$on$inst\$cn"
        }
    }
    if ($paths.Count -gt 0) {
        try {
            $samples = @(Get-Counter -Counter @($paths.Values) -SampleInterval 1 -MaxSamples 2 -ErrorAction Stop)
            $last = $samples[-1].CounterSamples
            foreach ($k in @($paths.Keys)) {
                $needle = $paths[$k].ToLower()
                $hit = $last | Where-Object { $_.Path.ToLower().EndsWith($needle) } | Select-Object -First 1
                if ($hit) { $c[$k] = [math]::Round($hit.CookedValue, 4) }
            }
        } catch {
            Write-DiagLog "Get-Counter fehlgeschlagen: $($_.Exception.Message)" 'WARN'
        }
    }
    $net = @()
    try {
        $net = @(Get-NetConnectionProfile -ErrorAction Stop | ForEach-Object {
            [pscustomobject]@{
                Netzwerk  = $_.Name
                Interface = $_.InterfaceAlias
                Kategorie = "$($_.NetworkCategory)"
                IPv4      = "$($_.IPv4Connectivity)"
            }
        })
    } catch { }
    $top = Get-TopProcesses
    $sessions = @()
    if ($MultiSession -and $IncludeSessions) { $sessions = @(Get-SessionResources) }
    elseif ($MultiSession) { Write-DiagLog 'Sitzungs-Aggregat uebersprungen (Adminrechte erforderlich fuer fremde Sessions).' 'WARN' }
    [pscustomobject]@{
        Zaehler         = [pscustomobject]$c
        TopProzesseCpu  = $top.TopCpu
        TopProzesseRam  = $top.TopRam
        Netzwerkprofile = $net
        Sessions        = $sessions
    }
}

function Get-SoftwareContext {
    param([int]$Days = 14)
    Write-DiagLog "M6: Software-Kontext (letzte $Days Tage)..."
    $cut = (Get-Date).AddDays(-$Days)
    $hotfixes = @()
    try {
        $hotfixes = @(Get-HotFix -ErrorAction Stop | Where-Object { $_.InstalledOn -and $_.InstalledOn -ge $cut } |
            Sort-Object InstalledOn -Descending | ForEach-Object {
                [pscustomobject]@{ KB = $_.HotFixID; Typ = $_.Description; Installiert = (Get-Date $_.InstalledOn -Format 'yyyy-MM-dd') }
            })
    } catch { }
    $sw = New-Object System.Collections.Generic.List[object]
    $citrix = $null
    $keys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    $all = @()
    foreach ($k in $keys) { $all += @(Get-ItemProperty $k -ErrorAction SilentlyContinue) }
    foreach ($e in $all) {
        $dn = $null
        try { $dn = $e.DisplayName } catch { }
        if (-not $dn) { continue }
        if ($dn -like 'Citrix Workspace*') { $citrix = "$dn $($e.DisplayVersion)".Trim() }
        $idate = $null
        try { $idate = $e.InstallDate } catch { }
        if ($idate -and "$idate" -match '^\d{8}$') {
            $d = $null
            try { $d = [datetime]::ParseExact("$idate", 'yyyyMMdd', $null) } catch { }
            if ($d -and $d -ge $cut) {
                $sw.Add([pscustomobject]@{ Name = $dn; Version = $e.DisplayVersion; Installiert = $d.ToString('yyyy-MM-dd') })
            }
        }
    }
    $av = @()
    try {
        $av = @(Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction Stop | ForEach-Object {
            $hex = '{0:X6}' -f $_.productState
            $aktiv = ($hex.Substring(2, 2) -eq '10' -or $hex.Substring(2, 2) -eq '11')
            [pscustomobject]@{ Produkt = $_.displayName; Aktiv = $aktiv; StatusHex = $hex }
        })
    } catch {
        Write-DiagLog 'SecurityCenter2 (AV-Status) nicht abfragbar.' 'WARN'
    }
    $edrServices = @('Sense','WinDefend','CSFalconService','SentinelAgent','CylanceSvc','ekrn','SepMasterService','TaniumClient','xagt')
    $edr = @()
    foreach ($s in $edrServices) {
        $svc = Get-Service -Name $s -ErrorAction SilentlyContinue
        if ($svc) { $edr += [pscustomobject]@{ Dienst = $s; Anzeigename = $svc.DisplayName; Status = "$($svc.Status)" } }
    }
    [pscustomobject]@{
        HotfixesNeu     = $hotfixes
        SoftwareNeu     = @($sw.ToArray() | Sort-Object Installiert -Descending)
        Antivirus       = $av
        SecurityDienste = $edr
        CitrixWorkspace = $citrix
    }
}

function Invoke-ProcDumpCapture {
    param([string]$ProcDumpExe, [int]$TargetPid, [string]$OutDir)
    Write-DiagLog "M7: ProcDump-Volldump (-ma) fuer PID $TargetPid..."
    $dmp = Join-Path $OutDir ('proc_{0}_{1:yyyyMMdd_HHmmss}.dmp' -f $TargetPid, (Get-Date))
    try {
        $psi = Start-Process -FilePath $ProcDumpExe -ArgumentList @('-accepteula', '-ma', "$TargetPid", "`"$dmp`"") -Wait -PassThru -WindowStyle Hidden
        if (Test-Path -LiteralPath $dmp) {
            $sz = [math]::Round((Get-Item -LiteralPath $dmp).Length / 1MB, 1)
            Write-DiagLog "Dump erstellt: $dmp ($sz MB)" 'OK'
            return [pscustomobject]@{ Datei = $dmp; GroesseMB = $sz; ExitCode = $psi.ExitCode }
        }
        Write-DiagLog "ProcDump ExitCode $($psi.ExitCode) - kein Dump erzeugt (Rechte? Bitness?)." 'WARN'
        return $null
    } catch {
        Write-DiagLog "ProcDump-Fehler: $($_.Exception.Message)" 'ERROR'
        return $null
    }
}

function Export-EvtxLogs {
    param([int]$Hours, [string]$OutDir)
    Write-DiagLog "EVTX-Rohexport (Application/System, $Hours h)..."
    $ms = [long]$Hours * 3600000
    $q  = "*[System[TimeCreated[timediff(@SystemTime) <= $ms]]]"
    $out = @()
    foreach ($log in @('Application', 'System')) {
        $f = Join-Path $OutDir "$log.evtx"
        $res = & wevtutil.exe epl $log "$f" "/q:$q" "/ow:true" 2>&1
        foreach ($r in @($res)) { if ($r) { Write-DiagLog "wevtutil: $r" 'WARN' } }
        if (Test-Path -LiteralPath $f) {
            $out += $f
            Write-DiagLog "EVTX exportiert: $f" 'OK'
        }
    }
    if ($out.Count -gt 0) {
        Write-DiagLog 'Hinweis: EVTX enthaelt Klartextdaten (Hostname/Benutzer).' 'WARN'
    }
    @($out)
}

function Get-ProcessTree {
    # M8a: Kindprozesse des Zielprozesses (rekursiv, max. Tiefe)
    param([int]$RootPid, [int]$MaxDepth = 3)
    Write-DiagLog "M8a: Prozessbaum ab PID $RootPid..."
    $all = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Select-Object ProcessId, ParentProcessId, Name)
    $items = New-Object System.Collections.Generic.List[object]
    $queue = New-Object System.Collections.Generic.Queue[object]
    $queue.Enqueue(@{ Id = $RootPid; Ebene = 0 })
    $seen = @{}
    $seen[$RootPid] = $true
    while ($queue.Count -gt 0) {
        $cur = $queue.Dequeue()
        if ($cur.Ebene -ge $MaxDepth) { continue }
        foreach ($c in @($all | Where-Object { $_.ParentProcessId -eq $cur.Id })) {
            $cpid = [int]$c.ProcessId
            if ($seen.ContainsKey($cpid)) { continue }
            $seen[$cpid] = $true
            $gp = $null
            try { $gp = Get-Process -Id $cpid -ErrorAction Stop } catch { }
            $reag = '-'; $cpu = $null; $ram = $null
            if ($gp) {
                if (-not [string]::IsNullOrEmpty($gp.MainWindowTitle)) {
                    $reag = 'NEIN'
                    if ($gp.Responding) { $reag = 'JA' }
                }
                $cpu = $(try { [math]::Round($gp.TotalProcessorTime.TotalSeconds, 1) } catch { $null })
                $ram = [math]::Round($gp.WorkingSet64 / 1MB, 0)
            }
            $items.Add([pscustomobject]@{ Ebene = ($cur.Ebene + 1); PID = $cpid; Name = $c.Name; Reagiert = $reag; CpuSekunden = $cpu; RamMB = $ram })
            $queue.Enqueue(@{ Id = $cpid; Ebene = ($cur.Ebene + 1) })
        }
    }
    Write-DiagLog "Prozessbaum: $($items.Count) Kindprozess(e)."
    @($items.ToArray())
}

function Get-ProcessNetwork {
    # M8b: TCP-Verbindungen des Zielprozesses inkl. Kinder, Status-/Remote-Verteilung, ICMP-Latenz Top-Ziele
    param([int[]]$Pids)
    Write-DiagLog "M8b: TCP-Verbindungen ($(@($Pids).Count) Prozess(e))..."
    $conns = @()
    try {
        $conns = @(Get-NetTCPConnection -ErrorAction Stop | Where-Object { $Pids -contains [int]$_.OwningProcess })
    } catch {
        Write-DiagLog "Get-NetTCPConnection fehlgeschlagen: $($_.Exception.Message)" 'WARN'
        return $null
    }
    $list = @($conns | ForEach-Object {
        [pscustomobject]@{
            LokalerPort = $_.LocalPort
            Remote      = "$($_.RemoteAddress):$($_.RemotePort)"
            RemoteIP    = "$($_.RemoteAddress)"
            Status      = "$($_.State)"
            PID         = [int]$_.OwningProcess
        }
    })
    $states  = @($list | Group-Object Status | Sort-Object Count -Descending | ForEach-Object {
        [pscustomobject]@{ Status = $_.Name; Anzahl = $_.Count }
    })
    $remotes = @($list | Where-Object { $_.RemoteIP -notin @('0.0.0.0', '::', '127.0.0.1', '::1') } |
        Group-Object Remote | Sort-Object Count -Descending | Select-Object -First 15 | ForEach-Object {
            [pscustomobject]@{ Remote = $_.Name; Anzahl = $_.Count; Status = (@($_.Group | Select-Object -ExpandProperty Status -Unique) -join ',') }
        })
    # Latenz zu Top-3 etablierten Remote-IPs (ICMP, Best Effort - kann durch Firewalls geblockt sein)
    $lat = @()
    $topIps = @($list | Where-Object { $_.Status -eq 'Established' -and $_.RemoteIP -notmatch '^(0\.0\.0\.0|127\.|::)' } |
        Group-Object RemoteIP | Sort-Object Count -Descending | Select-Object -First 3 | ForEach-Object { $_.Name })
    foreach ($ip in $topIps) {
        $ms = $null
        try {
            $pr = @(Test-Connection -ComputerName $ip -Count 2 -ErrorAction Stop)
            $ms = [math]::Round((($pr | Measure-Object -Property ResponseTime -Average).Average), 0)
        } catch { }
        $lat += [pscustomobject]@{ Ziel = $ip; LatenzMs = $ms }
    }
    [pscustomobject]@{
        VerbindungenGesamt = $list.Count
        NachStatus         = $states
        TopRemotes         = $remotes
        LatenzTopZiele     = @($lat)
        SynSent            = @($list | Where-Object { $_.Status -eq 'SynSent' }).Count
        CloseWait          = @($list | Where-Object { $_.Status -eq 'CloseWait' }).Count
    }
}

function Get-CitrixContext {
    # M8c: Sitzungskontext (ICA-Erkennung, VDA-Version, qwinsta-Uebersicht)
    param([int]$TargetSessionId = -1)
    Write-DiagLog 'M8c: Citrix-/Sitzungskontext...'
    $vda = $null
    foreach ($k in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')) {
        foreach ($e in @(Get-ItemProperty $k -ErrorAction SilentlyContinue)) {
            $dn = $null
            try { $dn = $e.DisplayName } catch { }
            if ($dn -like 'Citrix Virtual Delivery Agent*' -or $dn -like 'Citrix Virtual Apps*') { $vda = "$dn $($e.DisplayVersion)".Trim() }
        }
    }
    $qw = @()
    try { $qw = @((qwinsta.exe) 2>$null | Select-Object -First 15) } catch { }
    $sessName = $env:SESSIONNAME
    if (-not $sessName) {
        # Fallback: aktive Sitzung aus qwinsta ('>'-Markierung), falls SESSIONNAME im Startkontext fehlt
        $cur = @($qw | Where-Object { "$_" -match '^\s*>' } | Select-Object -First 1)
        if ($cur.Count -gt 0 -and "$($cur[0])" -match '^\s*>\s*(\S+)') { $sessName = $Matches[1] }
    }
    $hdx = $null
    if ($sessName -like 'ICA*') { $hdx = Get-IcaSessionMetrics }
    [pscustomobject]@{
        SkriptSitzung = $sessName
        IstIcaSitzung = ($sessName -like 'ICA*')
        ZielSessionId = $TargetSessionId
        VDA           = $vda
        HdxMetriken   = $hdx
        Sitzungen     = $qw
    }
}

function Get-OfficeContext {
    # M8d: Office C2R-Version/Kanal, COM-Add-ins (LoadBehavior), Resiliency (deaktivierte/crashende Add-ins), HW-Beschleunigung
    Write-DiagLog 'M8d: Office-Kontext (C2R, Add-ins, Resiliency)...'
    $c2r = $null
    try {
        $cfg = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration' -ErrorAction Stop
        $chMap = @{
            '492350f6-3a01-4f97-b9c0-c7c6ddf67d60' = 'Current Channel'
            '55336b82-a18d-4dd6-b5f6-9e5095c314a6' = 'Monthly Enterprise Channel'
            '7ffbc6bf-bc32-4f92-8982-f9dd17fd3114' = 'Semi-Annual Enterprise Channel'
            'b8f9b850-328d-4355-9145-c59439a0c4cf' = 'Semi-Annual Enterprise Preview'
            '64256afe-f5d9-4f86-8936-8840a6a4f5be' = 'Current Channel (Preview)'
            '5440fd1f-7ecb-4221-8110-145efaa6372f' = 'Beta Channel'
        }
        $ch = "$($cfg.UpdateChannel)"
        foreach ($key in @($chMap.Keys)) { if ($ch -match $key) { $ch = $chMap[$key]; break } }
        $c2r = [pscustomobject]@{ Version = $cfg.VersionToReport; Kanal = $ch; Plattform = $cfg.Platform }
    } catch {
        Write-DiagLog 'Kein Office Click-to-Run gefunden.' 'WARN'
    }
    $apps = @('Word', 'Excel', 'PowerPoint', 'Outlook')
    $addins = New-Object System.Collections.Generic.List[object]
    foreach ($root in @('HKCU:\SOFTWARE\Microsoft\Office', 'HKLM:\SOFTWARE\Microsoft\Office', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Office')) {
        foreach ($app in $apps) {
            $p = Join-Path $root "$app\Addins"
            if (-not (Test-Path $p)) { continue }
            foreach ($a in @(Get-ChildItem $p -ErrorAction SilentlyContinue)) {
                $v = Get-ItemProperty $a.PSPath -ErrorAction SilentlyContinue
                $lb = $null; $fn = $null
                try { $lb = $v.LoadBehavior } catch { }
                try { $fn = $v.FriendlyName } catch { }
                $src = 'HKLM'
                if ($root -like 'HKCU*') { $src = 'HKCU' }
                $addins.Add([pscustomobject]@{
                    App = $app; Addin = $a.PSChildName; Name = $fn
                    LoadBehavior = $lb; Aktiv = ($lb -eq 3); Quelle = $src
                })
            }
        }
    }
    # Resiliency: von Office selbst deaktivierte bzw. als crashend markierte Add-ins (starker Hang-Indikator)
    $resil = New-Object System.Collections.Generic.List[object]
    foreach ($app in $apps) {
        foreach ($sub in @('DisabledItems', 'CrashingAddinList')) {
            $p = "HKCU:\SOFTWARE\Microsoft\Office\16.0\$app\Resiliency\$sub"
            if (-not (Test-Path $p)) { continue }
            $key = Get-Item $p -ErrorAction SilentlyContinue
            if (-not $key) { continue }
            foreach ($vn in @($key.GetValueNames())) {
                $decoded = $null
                try {
                    $b = $key.GetValue($vn)
                    if ($b -is [byte[]]) {
                        $txt = [System.Text.Encoding]::Unicode.GetString($b)
                        # Nur druckbare Latin-Segmente (>= 4 Zeichen) - Binaerheader dekodiert sonst als CJK-Mojibake
                        $frag = @($txt -split "`0" | ForEach-Object {
                            @([regex]::Matches("$_", '[\u0020-\u007E\u00A0-\u00FF]{4,}') | ForEach-Object { $_.Value.Trim() })
                        } | Where-Object { $_ -match '[\\\w]{4,}' })
                        $decoded = ($frag -join ' | ')
                        if ($decoded.Length -gt 160) { $decoded = $decoded.Substring(0, 160) + '...' }
                    }
                } catch { }
                $resil.Add([pscustomobject]@{ App = $app; Liste = $sub; Wert = $vn; Inhalt = $decoded })
            }
        }
    }
    $hw = $null
    try { $hw = (Get-ItemProperty 'HKCU:\SOFTWARE\Microsoft\Office\16.0\Common\Graphics' -ErrorAction Stop).DisableHardwareAcceleration } catch { }
    [pscustomobject]@{
        ClickToRun          = $c2r
        ComAddins           = @($addins.ToArray())
        ResiliencyEintraege = @($resil.ToArray())
        HwBeschlDeaktiviert = $hw
    }
}

function Get-OutlookDataFiles {
    # M8e: OST/PST/NST-Inventar (Groesse, letzte Aenderung)
    Write-DiagLog 'M8e: Outlook-Datendateien (OST/PST)...'
    $dirs = @(
        (Join-Path $env:LOCALAPPDATA 'Microsoft\Outlook'),
        (Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'Outlook-Dateien'),
        (Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'Outlook Files')
    )
    $files = New-Object System.Collections.Generic.List[object]
    foreach ($dir in $dirs) {
        if (-not (Test-Path -LiteralPath $dir)) { continue }
        foreach ($f in @(Get-ChildItem -LiteralPath $dir -File -ErrorAction SilentlyContinue | Where-Object { $_.Extension -in '.ost', '.pst', '.nst' })) {
            $files.Add([pscustomobject]@{
                Datei = $f.Name
                Typ = $f.Extension.TrimStart('.').ToUpper()
                GroesseGB = [math]::Round($f.Length / 1GB, 2)
                Geaendert = (Get-Date $f.LastWriteTime -Format s)
                Pfad = $f.FullName
            })
        }
    }
    @($files.ToArray() | Sort-Object GroesseGB -Descending)
}

function Get-TeamsContext {
    # M8f: New-Teams-MSIX-Version + WebView2-Runtime-Version
    Write-DiagLog 'M8f: Teams-/WebView2-Kontext...'
    $teamsVer = $null
    try {
        $pkg = Get-AppxPackage -Name 'MSTeams' -ErrorAction Stop
        if ($pkg) { $teamsVer = "$($pkg.Version)" }
    } catch { }
    $wv2 = $null
    foreach ($k in @('HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}',
                     'HKCU:\SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}')) {
        try {
            $v = (Get-ItemProperty $k -ErrorAction Stop).pv
            if ($v) { $wv2 = $v; break }
        } catch { }
    }
    [pscustomobject]@{ TeamsMsix = $teamsVer; WebView2Runtime = $wv2 }
}

function Get-NexusContext {
    # M8g: Nexus-KIS-Produkte (Uninstall-Keys) und -Dienste
    Write-DiagLog 'M8g: Nexus-KIS-Kontext...'
    $prod = New-Object System.Collections.Generic.List[object]
    foreach ($k in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*')) {
        foreach ($e in @(Get-ItemProperty $k -ErrorAction SilentlyContinue)) {
            $dn = $null
            try { $dn = $e.DisplayName } catch { }
            if ($dn -and $dn -match '(?i)nexus') { $prod.Add([pscustomobject]@{ Produkt = $dn; Version = $e.DisplayVersion }) }
        }
    }
    $svcs = @(Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '(?i)nexus' -or $_.DisplayName -match '(?i)nexus' } | ForEach-Object {
        [pscustomobject]@{ Dienst = $_.Name; Anzeigename = $_.DisplayName; Status = "$($_.Status)" }
    })
    [pscustomobject]@{
        Produkte = @($prod.ToArray() | Sort-Object Produkt -Unique)
        Dienste  = $svcs
    }
}

function Copy-AppLogs {
    # M8h: App-Logdateien gemaess Profil einsammeln (opt-in, Limits: 5 Dateien/Pfad, 5 MB/Datei, 25 MB gesamt)
    param([string[]]$LogPaths, [string]$OutDir, [string]$ProfilName)
    $maxDateien = 5; $maxMB = 5; $gesamtMaxMB = 25
    $dest = Join-Path $OutDir ('AppLogs\{0}' -f $ProfilName)
    $collected = New-Object System.Collections.Generic.List[object]
    $sumMB = 0.0
    foreach ($lp in @($LogPaths)) {
        if (-not $lp) { continue }
        $expanded = [Environment]::ExpandEnvironmentVariables($lp)
        if (-not (Test-Path -LiteralPath $expanded)) { Write-DiagLog "App-Logpfad nicht gefunden: $expanded" 'WARN'; continue }
        $files = @(Get-ChildItem -LiteralPath $expanded -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First $maxDateien)
        foreach ($f in $files) {
            $szMB = [math]::Round($f.Length / 1MB, 2)
            if ($szMB -gt $maxMB) { Write-DiagLog "App-Log uebersprungen (> $maxMB MB): $($f.Name)" 'WARN'; continue }
            if (($sumMB + $szMB) -gt $gesamtMaxMB) { Write-DiagLog 'App-Log-Gesamtlimit erreicht - weitere Dateien uebersprungen.' 'WARN'; break }
            if (-not (Test-Path -LiteralPath $dest)) { New-Item -ItemType Directory -Path $dest -Force | Out-Null }
            try {
                Copy-Item -LiteralPath $f.FullName -Destination $dest -Force
                $sumMB += $szMB
                $collected.Add([pscustomobject]@{ Datei = $f.Name; GroesseMB = $szMB; Geaendert = (Get-Date $f.LastWriteTime -Format s); Profil = $ProfilName })
            } catch {
                Write-DiagLog "App-Log-Kopie fehlgeschlagen: $($f.Name)" 'WARN'
            }
        }
    }
    if ($collected.Count -gt 0) {
        Write-DiagLog "App-Logs gesammelt ($ProfilName): $($collected.Count) Datei(en), $([math]::Round($sumMB, 1)) MB - koennen personenbezogene Daten enthalten." 'WARN'
    }
    @($collected.ToArray())
}

function Initialize-NativeUi {
    # P/Invoke fuer SendMessageTimeout (UI-Latenzmessung); idempotent je Prozess
    if (-not ([System.Management.Automation.PSTypeName]'AppHangDiagNative').Type) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class AppHangDiagNative {
    [DllImport("user32.dll", SetLastError=true, CharSet=CharSet.Auto)]
    public static extern IntPtr SendMessageTimeout(IntPtr hWnd, uint Msg, UIntPtr wParam, IntPtr lParam, uint fuFlags, uint uTimeout, out UIntPtr lpdwResult);
}
'@
    }
}

function Get-UiLatencyMs {
    # Message-Loop-Antwortzeit in ms: $null = kein Fenster/Fehler, -1 = Timeout (haengt), sonst ms
    param([int]$TargetPid, [int]$TimeoutMs = 5000)
    try {
        Initialize-NativeUi
        $p = Get-Process -Id $TargetPid -ErrorAction Stop
        $h = $p.MainWindowHandle
        if ($h -eq [IntPtr]::Zero) { return $null }
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $res = [UIntPtr]::Zero
        # WM_NULL, SMTO_ABORTIFHUNG (0x2) + SMTO_NOTIMEOUTIFNOTHUNG (0x8)
        $ok = [AppHangDiagNative]::SendMessageTimeout($h, 0, [UIntPtr]::Zero, [IntPtr]::Zero, (0x0002 -bor 0x0008), [uint32]$TimeoutMs, [ref]$res)
        $sw.Stop()
        if ($ok -eq [IntPtr]::Zero) { return -1 }
        [int]$sw.ElapsedMilliseconds
    } catch { $null }
}

function Get-PlatformProfile {
    # M0: Plattform-Klassifikation Client / VDI / TerminalServer / Server
    $os = $null
    try { $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop } catch { }
    $productType = 1
    $caption = 'unbekannt'
    if ($os) { $productType = [int]$os.ProductType; $caption = "$($os.Caption)".Trim() }
    $edition = ''
    try { $edition = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop).EditionID } catch { }
    $tsAppCompat = 0
    try { $tsAppCompat = [int](Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -ErrorAction Stop).TSAppCompat } catch { }
    $hatVda = $false
    foreach ($svcName in @('BrokerAgent', 'picaSvc2', 'porticaservice')) {
        try { if (Get-Service -Name $svcName -ErrorAction Stop) { $hatVda = $true; break } } catch { }
    }
    $istServer = ($productType -ne 1)
    $istMulti  = ($tsAppCompat -eq 1) -or ($edition -eq 'ServerRdsh')
    $profil = 'Client'
    if ($hatVda -and $istMulti) { $profil = 'TerminalServer (Citrix Multi-Session-VDA)' }
    elseif ($hatVda)            { $profil = 'VDI (Citrix Single-Session-VDA)' }
    elseif ($istMulti)          { $profil = 'TerminalServer (RDSH)' }
    elseif ($istServer)         { $profil = 'Server' }
    [pscustomobject]@{
        PlatformProfil  = $profil
        IstServerOS     = $istServer
        IstMultiSession = $istMulti
        HatVda          = $hatVda
        EditionID       = $edition
        OSCaption       = $caption
    }
}

function Get-IcaSessionMetrics {
    # HDX-/ICA-Sitzungsmetriken (nur auf VDA vorhanden; Counter englisch registriert; tolerant, kein Warn-Rauschen)
    $own = "$env:SESSIONNAME".ToLower()
    $result = $null
    try {
        $cs = @((Get-Counter -Counter '\ICA Session(*)\Latency - Last Recorded', '\ICA Session(*)\Latency - Session Average', '\ICA Session(*)\Input Session Bandwidth', '\ICA Session(*)\Output Session Bandwidth' -ErrorAction Stop).CounterSamples)
        $mine = @($cs | Where-Object { $own -and $_.InstanceName -eq $own })
        if ($mine.Count -eq 0) { $mine = @($cs | Where-Object { $_.InstanceName -like 'ica*' }) }
        if ($mine.Count -gt 0) {
            $pick = {
                param($pat)
                $v = @($mine | Where-Object { $_.Path -match $pat } | Select-Object -First 1)
                if ($v.Count -gt 0) { [math]::Round($v[0].CookedValue, 0) } else { $null }
            }
            $result = [pscustomobject]@{
                Instanz        = $mine[0].InstanceName
                LatenzLetzteMs = (& $pick 'latency - last')
                LatenzMittelMs = (& $pick 'latency - session')
                InputBps       = (& $pick 'input session')
                OutputBps      = (& $pick 'output session')
            }
        }
    } catch { }
    $result
}

function Get-SessionResources {
    # M5b: CPU/RAM-Aggregat je Sitzung (Multi-Session; Kennzahlen, KEINE Prozesslisten fremder Sessions)
    Write-DiagLog 'M5b: Sitzungs-Ressourcenaggregat (Multi-Session)...'
    $cores = [Environment]::ProcessorCount
    $s1 = @{}
    foreach ($p in (Get-Process)) {
        $t = 0.0
        try { if ($p.TotalProcessorTime) { $t = $p.TotalProcessorTime.TotalMilliseconds } } catch { }
        $s1[$p.Id] = $t
    }
    Start-Sleep -Milliseconds 1000
    $agg = @{}
    foreach ($p in (Get-Process)) {
        $sid = [int]$p.SessionId
        if (-not $agg.ContainsKey($sid)) { $agg[$sid] = @{ Cpu = 0.0; Ram = 0.0; Anz = 0 } }
        $t2 = 0.0
        try { if ($p.TotalProcessorTime) { $t2 = $p.TotalProcessorTime.TotalMilliseconds } } catch { }
        $t1 = $t2
        if ($s1.ContainsKey($p.Id)) { $t1 = $s1[$p.Id] }
        $agg[$sid].Cpu = $agg[$sid].Cpu + ((($t2 - $t1) / 1000) / $cores * 100)
        $agg[$sid].Ram = $agg[$sid].Ram + ($p.WorkingSet64 / 1MB)
        $agg[$sid].Anz = $agg[$sid].Anz + 1
    }
    # Benutzer je Session via explorer.exe-Owner (fremde Sessions nur mit Adminrechten lesbar)
    $owners = @{}
    try {
        foreach ($e in @(Get-CimInstance Win32_Process -Filter "Name='explorer.exe'" -ErrorAction SilentlyContinue)) {
            $o = $null
            try {
                $oi = Invoke-CimMethod -InputObject $e -MethodName GetOwner -ErrorAction Stop
                if ($oi.User) { $o = $oi.User }
            } catch { }
            if ($null -ne $e.SessionId -and $o -and -not $owners.ContainsKey([int]$e.SessionId)) { $owners[[int]$e.SessionId] = $o }
        }
    } catch { }
    @($agg.Keys | ForEach-Object {
        $sid = [int]$_
        $usr = '-'
        if ($owners.ContainsKey($sid)) { $usr = $owners[$sid] }
        [pscustomobject]@{
            SessionId  = $sid
            Benutzer   = $usr
            Prozesse   = $agg[$sid].Anz
            CpuProzent = [math]::Round($agg[$sid].Cpu, 1)
            RamMB      = [math]::Round($agg[$sid].Ram, 0)
        }
    } | Sort-Object CpuProzent -Descending)
}

function Get-UpmContext {
    # M9: Citrix-UPM-/Profilcontainer-Diagnose (strikt read-only: kein Mount/Dismount, keine VHDX-Manipulation)
    $svc = $null
    try { $svc = Get-Service -Name 'ctxProfile' -ErrorAction Stop } catch { }
    if (-not $svc) { return $null }
    Write-DiagLog 'M9: Citrix-UPM-/Containerprofil-Diagnose...'
    $ver = $null
    try {
        $svcPath = (Get-CimInstance Win32_Service -Filter "Name='ctxProfile'" -ErrorAction Stop).PathName
        if ($svcPath -match '"?([^"]+\.exe)') { $ver = (Get-Item -LiteralPath $Matches[1] -ErrorAction Stop).VersionInfo.FileVersion }
    } catch { }
    # Policy-/Konfig-Auszug (Policies vor lokaler Konfiguration; Container-Wertnamen generisch)
    $cfg = @{}
    foreach ($k in @('HKLM:\SOFTWARE\Policies\Citrix\UserProfileManager', 'HKLM:\SOFTWARE\Citrix\UserProfileManager')) {
        if (-not (Test-Path $k)) { continue }
        $ip = Get-ItemProperty $k -ErrorAction SilentlyContinue
        foreach ($n in @('ServiceActive', 'PSEnabled', 'PathToUserStore', 'PSMidSessionWriteBack')) {
            if ($null -eq $cfg[$n]) {
                $v = $null
                try { $v = $ip.$n } catch { }
                if ($null -ne $v) { $cfg[$n] = $v }
            }
        }
        try {
            $key = Get-Item $k -ErrorAction Stop
            foreach ($vn in @($key.GetValueNames() | Where-Object { $_ -match '(?i)container' })) {
                if ($null -eq $cfg[$vn]) { $cfg[$vn] = (@($key.GetValue($vn)) -join '; ') }
            }
        } catch { }
    }
    # Gemountete Profilcontainer: File-Backed Virtual Disks -> VHDX-UNC-Pfad + freier Platz im Containervolume
    $disks = @()
    try {
        foreach ($d in @(Get-Disk -ErrorAction Stop | Where-Object { "$($_.BusType)" -eq 'FileBackedVirtual' })) {
            $freiGB = $null; $freiProzent = $null
            try {
                $vols = @(Get-Partition -DiskNumber $d.Number -ErrorAction Stop | Get-Volume -ErrorAction Stop)
                $v0 = $vols | Sort-Object Size -Descending | Select-Object -First 1
                if ($v0 -and $v0.Size -gt 0) {
                    $freiGB = [math]::Round($v0.SizeRemaining / 1GB, 2)
                    $freiProzent = [math]::Round($v0.SizeRemaining / $v0.Size * 100, 1)
                }
            } catch { }
            $disks += [pscustomobject]@{
                VhdxPfad    = "$($d.Location)"
                GroesseGB   = [math]::Round($d.Size / 1GB, 1)
                FreiGB      = $freiGB
                FreiProzent = $freiProzent
            }
        }
    } catch { }
    # Profil-Fileserver-Erreichbarkeit/Latenz (aus VHDX-UNC-Pfad abgeleitet; ICMP Best Effort)
    $fsHost = $null; $fsLatenz = $null; $fsErreichbar = $null
    $unc = @($disks | Where-Object { $_.VhdxPfad -like '\\*' } | Select-Object -First 1)
    if ($unc.Count -gt 0 -and $unc[0].VhdxPfad -match '^\\\\([^\\]+)\\') {
        $fsHost = $Matches[1]
        try {
            $pr = @(Test-Connection -ComputerName $fsHost -Count 2 -ErrorAction Stop)
            $fsLatenz = [math]::Round((($pr | Measure-Object -Property ResponseTime -Average).Average), 0)
            $fsErreichbar = $true
        } catch { $fsErreichbar = $false }
    }
    [pscustomobject]@{
        DienstStatus         = "$($svc.Status)"
        Version              = $ver
        Konfiguration        = [pscustomobject]$cfg
        ContainerAktiv       = (@($disks).Count -gt 0)
        ContainerDisks       = @($disks)
        ProfilFileserver     = $fsHost
        FileserverErreichbar = $fsErreichbar
        FileserverLatenzMs   = $fsLatenz
        GesammelteLogs       = @()
    }
}

function Get-PerfAggregate {
    # Verlaufsaggregat (min/Mittel/p95/max) ueber Monitor-Samples
    param([object[]]$Samples, [int]$LagMs = 500)
    if (-not $Samples -or @($Samples).Count -eq 0) { return $null }
    $s = @($Samples)
    $metrics = @('UiLatenzMs', 'CpuProzent', 'RamMB', 'PrivateMB', 'Handles', 'Threads')
    $agg = foreach ($mName in $metrics) {
        $vals = @($s | ForEach-Object { $_.$mName } | Where-Object { $null -ne $_ -and $_ -ge 0 } | Sort-Object)
        if ($vals.Count -eq 0) { continue }
        $p95i = [int][math]::Ceiling($vals.Count * 0.95) - 1
        if ($p95i -lt 0) { $p95i = 0 }
        if ($p95i -ge $vals.Count) { $p95i = $vals.Count - 1 }
        [pscustomobject]@{
            Metrik = $mName
            Min    = [math]::Round(($vals | Select-Object -First 1), 1)
            Mittel = [math]::Round((($vals | Measure-Object -Average).Average), 1)
            P95    = [math]::Round($vals[$p95i], 1)
            Max    = [math]::Round(($vals | Select-Object -Last 1), 1)
        }
    }
    [pscustomobject]@{
        AnzahlSamples = $s.Count
        VonZeit       = $s[0].Zeit
        BisZeit       = $s[$s.Count - 1].Zeit
        LagSchwelleMs = $LagMs
        Aggregate     = @($agg)
        Samples       = $s
    }
}

function ConvertTo-NtStatusText {
    # ExitCode-/NTSTATUS-Ersteinordnung fuer Crash-Diagnose
    param($ExitCode)
    if ($null -eq $ExitCode) { return 'unbekannt (ExitCode nicht lesbar - z.B. fremder/elevierter Prozess)' }
    $hex = ('0x{0:x8}' -f [int]$ExitCode)
    $map = @{
        '0x00000000' = 'normal beendet (0)'
        '0x00000001' = 'generischer Fehler (1)'
        '0xc0000005' = 'ACCESS_VIOLATION - Speicherzugriffsfehler (haeufig fehlerhaftes Modul/Add-in)'
        '0xc0000374' = 'HEAP_CORRUPTION - Heap-Beschaedigung'
        '0xc00000fd' = 'STACK_OVERFLOW - Stackueberlauf (Rekursion)'
        '0xe0434352' = 'CLR-Exception - unbehandelte .NET-Ausnahme'
        '0xc000041d' = 'unbehandelte Ausnahme in Callback'
        '0xc0000409' = 'STACK_BUFFER_OVERRUN / FailFast'
        '0xc0000142' = 'DLL_INIT_FAILED - DLL-Initialisierung fehlgeschlagen'
        '0xc06d007e' = 'Delay-Load-Modul nicht gefunden'
        '0x80000003' = 'BREAKPOINT - Debug-Break'
        '0x40010004' = 'DBG_TERMINATE_PROCESS - extern beendet (taskkill/Debugger)'
        '0xc000013a' = 'CTRL_C_EXIT - durch Benutzer/Konsole abgebrochen'
    }
    if ($map.ContainsKey($hex)) { return "$hex = $($map[$hex])" }
    if ($hex -like '0xc*') { return "$hex = NTSTATUS-Fehlercode (Absturzverdacht - Code nachschlagen)" }
    "$hex = anwendungsspezifischer ExitCode"
}

#endregion Bibliothek

#region Auswertung und Orchestrierung

function Get-DiagFindings {
    param($Report)
    $f = New-Object System.Collections.Generic.List[string]
    $ev = $Report.Events
    if ($ev) {
        if ($ev.AppHangs1002 -gt 0) {
            $apps = (@($ev.HangsProAnwendung | Select-Object -First 3 | ForEach-Object { "$($_.Anwendung) ($($_.Anzahl)x)" }) -join ', ')
            $f.Add("App-Hangs (Event 1002): $($ev.AppHangs1002) im Zeitfenster - betroffen: $apps")
        }
        if ($ev.AppCrashes1000 -gt 0)      { $f.Add("Anwendungsabstuerze (Event 1000): $($ev.AppCrashes1000)") }
        if ($ev.ServiceTimeouts7011 -gt 0) { $f.Add("Dienst-Timeouts (7011): $($ev.ServiceTimeouts7011) - Hinweis auf systemweite Blockade (IO/Storage/Anmeldedienste)") }
        if ($ev.StorageEvents129_153 -gt 0){ $f.Add("Storage-Events (129/153): $($ev.StorageEvents129_153) - Storage-/Treiberpfad pruefen (Resets, IO-Retries)") }
        if ($ev.KernelPower41 -gt 0)       { $f.Add("Kernel-Power 41: $($ev.KernelPower41) unerwartete(r) Neustart(s) im Zeitfenster") }
        if ($ev.PSObject.Properties['LiveKernelEvents'] -and $ev.LiveKernelEvents -gt 0) {
            $sigTxt = (@($ev.LiveKernelSignaturen | Select-Object -First 4 | ForEach-Object { "$($_.Signatur) ($($_.Anzahl)x)" }) -join ', ')
            $f.Add("LiveKernelEvents (WER 1001): $($ev.LiveKernelEvents) - Top-Signaturen: $sigTxt")
            $gpu = @($ev.LiveKernelSignaturen | Where-Object { $_.Signatur -match '(?i)P1:(0x)?(10e|116|117|141|193)$' })
            if ($gpu.Count -gt 0) {
                $f.Add('GPU-/Grafiktreiber-Verdacht: LiveKernelEvent-P1 10e/116/117/141/193 (TDR/Video-Engine-Timeout) - Grafiktreiber pruefen (Cleaninstall/Rollback, Overlays/Injection-Hooks deaktivieren)')
            }
        }
        if ($ev.PSObject.Properties['BlueScreens1001'] -and $ev.BlueScreens1001 -gt 0) {
            $bsTxt = (@($ev.BlueScreenSignaturen | Select-Object -First 3 | ForEach-Object { "$($_.Signatur) ($($_.Anzahl)x)" }) -join ', ')
            $f.Add("BlueScreen-WER-Reports: $($ev.BlueScreens1001) - $bsTxt - Minidumps unter C:\Windows\Minidump analysieren (WinDbg !analyze -v)")
        }
    }
    $sys = $Report.System
    if ($sys) {
        if ($sys.PendingReboot)            { $f.Add("Neustart ausstehend ($(@($sys.PendingRebootGruende) -join ', ')) - kann Instabilitaet verursachen") }
        if ($sys.RamFreiProzent -lt 10)    { $f.Add("Speicherdruck: nur $($sys.RamFreiProzent)% RAM frei") }
        if ($sys.UptimeStunden -gt 336)    { $f.Add("Hohe Uptime ($($sys.UptimeStunden) h) - lange kein echter Neustart (FastStartup?)") }
    }
    $res = $Report.Resources
    if ($res -and $res.Zaehler) {
        $z = $res.Zaehler
        $zHash = @{}
        foreach ($pr in $z.PSObject.Properties) { $zHash[$pr.Name] = $pr.Value }
        if ($zHash.ContainsKey('CpuGesamtProzent') -and $zHash['CpuGesamtProzent'] -gt 90) { $f.Add("CPU-Last hoch: $($zHash['CpuGesamtProzent'])%") }
        $rd = 0; $wr = 0
        if ($zHash.ContainsKey('DiskAvgReadSec'))  { $rd = $zHash['DiskAvgReadSec'] }
        if ($zHash.ContainsKey('DiskAvgWriteSec')) { $wr = $zHash['DiskAvgWriteSec'] }
        if ($rd -gt 0.025 -or $wr -gt 0.025) { $f.Add("Disk-Latenz auffaellig (Read $rd s / Write $wr s; Richtwert < 0.025 s)") }
        if ($zHash.ContainsKey('PagefileNutzungProzent') -and $zHash['PagefileNutzungProzent'] -gt 70) { $f.Add("Pagefile-Nutzung hoch: $($zHash['PagefileNutzungProzent'])%") }
    }
    $tp = $Report.TargetProcess
    if ($tp) {
        if ($tp.Reagiert -eq $false) { $f.Add("Zielprozess $($tp.Name) (PID $($tp.PID)) reagiert zum Capture-Zeitpunkt NICHT") }
        if (@($tp.ModuleNichtMicrosoft).Count -gt 0) {
            $firmen = (@($tp.ModuleNichtMicrosoft | Group-Object Firma | Sort-Object Count -Descending |
                Select-Object -First 5 | ForEach-Object { $_.Name }) -join ', ')
            $f.Add("Fremdmodule im Zielprozess ($(@($tp.ModuleNichtMicrosoft).Count)): u.a. $firmen - Hook-/Addin-Verdacht pruefen (AV/EDR, Citrix, Shell-Erweiterungen)")
        }
        if ($tp.ModulFehler) { $f.Add("Modulliste des Zielprozesses nicht lesbar ($($tp.ModulFehler)) - ggf. als Administrator wiederholen") }
    }
    $sw = $Report.Software
    if ($sw) {
        $hc = @($sw.HotfixesNeu).Count
        $sc = @($sw.SoftwareNeu).Count
        if ($hc -gt 0 -or $sc -gt 0) { $f.Add("Kuerzliche Aenderungen: $hc Hotfix(e), $sc Software-Installation(en) in 14 Tagen - zeitliche Korrelation mit Haengern pruefen") }
    }
    # M8: App-Kontext-Heuristiken
    $ac = $Report.AppContext
    if ($ac) {
        if ($ac.Office -and @($ac.Office.ResiliencyEintraege).Count -gt 0) {
            $rApps = (@($ac.Office.ResiliencyEintraege | Group-Object App | ForEach-Object { "$($_.Name) ($($_.Count))" }) -join ', ')
            $f.Add("Office-Resiliency: $(@($ac.Office.ResiliencyEintraege).Count) Eintrag/Eintraege (von Office deaktivierte/als crashend markierte Add-ins) - $rApps - Add-in-Verdacht ERHAERTET")
        }
        $bigOst = @($ac.OutlookDateien | Where-Object { $_.GroesseGB -ge 25 })
        if ($bigOst.Count -gt 0) {
            $ostTxt = (@($bigOst | ForEach-Object { "$($_.Datei) ($($_.GroesseGB) GB)" }) -join ', ')
            $f.Add("Outlook-Datendatei(en) >= 25 GB: $ostTxt - Performance-/Hang-Risiko (Cached-Mode-Umfang reduzieren, Archivierung pruefen)")
        }
        if ($ac.Teams -and -not $ac.Teams.WebView2Runtime) {
            $f.Add('WebView2-Runtime nicht gefunden - New Teams benoetigt WebView2 (Installation/Reparatur pruefen)')
        }
    }
    $netF = $Report.Network
    if ($netF) {
        if ($netF.SynSent -ge 1) { $f.Add("TCP: $($netF.SynSent) Verbindung(en) in SYN_SENT - Verbindungsaufbau haengt (Backend/Firewall/Routing pruefen)") }
        if ($netF.CloseWait -gt 5) { $f.Add("TCP: $($netF.CloseWait) Verbindungen in CLOSE_WAIT - Anwendung schliesst Sockets nicht (Backend-/App-Verdacht)") }
        $slow = @($netF.LatenzTopZiele | Where-Object { $null -ne $_.LatenzMs -and $_.LatenzMs -gt 50 })
        if ($slow.Count -gt 0) {
            $slowTxt = (@($slow | ForEach-Object { "$($_.Ziel)=$($_.LatenzMs)ms" }) -join ', ')
            $f.Add("Netzwerklatenz zu App-Backends erhoeht: $slowTxt (Richtwert < 50 ms, LAN/WAN-abhaengig)")
        }
    }
    $treeF = @($Report.ProcessTree)
    if ($treeF.Count -gt 0) {
        $hangKids = @($treeF | Where-Object { $_.Reagiert -eq 'NEIN' })
        if ($hangKids.Count -gt 0) {
            $kidTxt = (@($hangKids | ForEach-Object { "$($_.Name) (PID $($_.PID))" }) -join ', ')
            $f.Add("Kindprozess(e) reagieren NICHT: $kidTxt - Hang liegt ggf. im Kindprozess (z.B. WebView2/Renderer)")
        }
    }
    $cxF = $Report.CitrixContext
    if ($cxF -and $cxF.IstIcaSitzung) {
        $f.Add('Anwendung laeuft in einer Citrix-ICA-Sitzung - Session-/VDA-Perspektive (HDX-Latenz, VDA-Last) mitpruefen')
    }
    # Crash-Heuristiken (v1.3)
    $ciF = $Report.CrashInfo
    if ($ciF) {
        $f.Add("Prozess-Ende erfasst: $($ciF.ProzessName) - ExitCode $($ciF.Bedeutung)")
        if (@($ciF.WatchdogDumps).Count -gt 0) { $f.Add("Crash-Watchdog-Dump(s) vorhanden: $(@($ciF.WatchdogDumps) -join ', ') - WinDbg-Analyse (!analyze -v) empfohlen") }
    }
    if ($Report.Events -and $Report.Events.PSObject.Properties['CrashSignaturen']) {
        $repeated = @($Report.Events.CrashSignaturen | Where-Object { $_.Anzahl -ge 3 } | Select-Object -First 3)
        if ($repeated.Count -gt 0) {
            $rTxt = (@($repeated | ForEach-Object { "$($_.Signatur) ($($_.Anzahl)x)" }) -join ' | ')
            $f.Add("Wiederholte Crashes gleicher Signatur (>= 3x): $rTxt - reproduzierbares Modul-/Add-in-Problem wahrscheinlich")
        }
    }
    # Verlaufs-/Trend-Heuristiken (v1.3)
    $vf = $Report.Verlauf
    if ($vf -and @($vf.Samples).Count -ge 10) {
        $smp = @($vf.Samples)
        $t0 = Get-Date $smp[0].Zeit
        $t1 = Get-Date $smp[$smp.Count - 1].Zeit
        $minuten = [math]::Max(($t1 - $t0).TotalMinutes, 0.1)
        $privS = @($smp | Where-Object { $null -ne $_.PrivateMB })
        if ($privS.Count -ge 10 -and $minuten -ge 5) {
            $ramDelta = $privS[$privS.Count - 1].PrivateMB - $privS[0].PrivateMB
            $ramPro10 = [math]::Round($ramDelta / $minuten * 10, 0)
            if ($ramPro10 -ge 100) { $f.Add("Speicherwachstum des Zielprozesses: +$ramPro10 MB je 10 min ueber $([math]::Round($minuten,0)) min (Private Bytes) - Memory-Leak-Verdacht") }
        }
        $hS = @($smp | Where-Object { $null -ne $_.Handles })
        if ($hS.Count -ge 10) {
            $hDelta = $hS[$hS.Count - 1].Handles - $hS[0].Handles
            if ($hDelta -ge 500 -and $hS[0].Handles -gt 0 -and ($hDelta / $hS[0].Handles) -ge 0.3) {
                $f.Add("Handle-Wachstum des Zielprozesses: +$hDelta Handles im Beobachtungszeitraum - Handle-Leak-Verdacht")
            }
        }
        $lp = 0
        if ($Report.System) { $lp = [int]$Report.System.LogischeProzessoren }
        $cpuS = @($smp | ForEach-Object { $_.CpuProzent } | Where-Object { $null -ne $_ } | Sort-Object)
        if ($lp -gt 2 -and $cpuS.Count -ge 10) {
            $median = $cpuS[[int][math]::Floor($cpuS.Count / 2)]
            $oneCore = 100.0 / $lp
            if ($median -ge ($oneCore * 0.85) -and $median -le ($oneCore * 1.15)) {
                $f.Add("Zielprozess-CPU pendelt um $([math]::Round($oneCore,1))% (= 1 Kern von $lp) - Single-Thread-Bottleneck-Verdacht (App rechnet einkernig)")
            }
        }
        $latAgg = @($vf.Aggregate | Where-Object { $_.Metrik -eq 'UiLatenzMs' } | Select-Object -First 1)
        if ($latAgg.Count -gt 0 -and $latAgg[0].P95 -ge $vf.LagSchwelleMs) {
            $f.Add("UI-Latenz p95 = $($latAgg[0].P95) ms (Schwelle $($vf.LagSchwelleMs) ms, max $($latAgg[0].Max) ms) - spuerbare Anwendungs-Lags belegt")
        }
    }
    # UPM-/Containerprofil-Heuristiken (v1.3)
    $uf = $Report.UpmContext
    if ($uf) {
        if ($uf.DienstStatus -ne 'Running') { $f.Add("Citrix-UPM-Dienst (ctxProfile) nicht aktiv (Status: $($uf.DienstStatus)) - Profilverarbeitung gestoert") }
        foreach ($cd in @($uf.ContainerDisks)) {
            if (($null -ne $cd.FreiProzent -and $cd.FreiProzent -lt 5) -or ($null -ne $cd.FreiGB -and $cd.FreiGB -lt 1)) {
                $f.Add("Profilcontainer fast VOLL: $($cd.VhdxPfad) ($($cd.FreiGB) GB / $($cd.FreiProzent)% frei) - haeufige Ursache fuer Office-/Anmelde-Haenger (Container vergroessern/bereinigen)")
            }
        }
        if ($uf.FileserverErreichbar -eq $false) { $f.Add("Profil-Fileserver $($uf.ProfilFileserver) per ICMP nicht erreichbar - SMB-Pfad des Containerprofils pruefen") }
        elseif ($null -ne $uf.FileserverLatenzMs -and $uf.FileserverLatenzMs -gt 20) {
            $f.Add("Latenz zum Profil-Fileserver $($uf.ProfilFileserver): $($uf.FileserverLatenzMs) ms - Profil-I/O (VHDX ueber SMB) verlangsamt (Richtwert < 20 ms)")
        }
    }
    # HDX-/Sitzungs-Heuristiken (v1.3)
    $cxH = $Report.CitrixContext
    if ($cxH -and $cxH.PSObject.Properties['HdxMetriken'] -and $cxH.HdxMetriken) {
        $rtt = $cxH.HdxMetriken.LatenzLetzteMs
        if ($null -ne $rtt -and $rtt -gt 300) { $f.Add("HDX-/ICA-Sitzungslatenz KRITISCH: $rtt ms - Nutzerwahrnehmung 'App haengt' kann Session-Latenz sein (Netzpfad Client<->VDA pruefen)") }
        elseif ($null -ne $rtt -and $rtt -gt 150) { $f.Add("HDX-/ICA-Sitzungslatenz erhoeht: $rtt ms (Richtwert < 150 ms)") }
    }
    if ($Report.Resources -and $Report.Resources.PSObject.Properties['Sessions']) {
        $noisy = @($Report.Resources.Sessions | Where-Object { $_.CpuProzent -gt 40 } | Select-Object -First 3)
        if ($noisy.Count -gt 0) {
            $nTxt = (@($noisy | ForEach-Object { "Session $($_.SessionId) ($($_.Benutzer)): $($_.CpuProzent)% CPU" }) -join ' | ')
            $f.Add("Noisy-Neighbor-Verdacht (Multi-Session): $nTxt - Sitzungslast als Mitursache pruefen")
        }
    }
    if ($Report.Plattform -and $Report.Plattform.IstMultiSession) {
        $docs = [Environment]::GetFolderPath('MyDocuments')
        if ($docs -like '\\*') { $f.Add("Dokumente-Ordner ist auf UNC umgeleitet ($docs) - Datei-I/O der Anwendung geht ueber das Netz (Latenzpfad)") }
    }
    if ($f.Count -eq 0) { $f.Add('Keine offensichtlichen Auffaelligkeiten in der Heuristik - Detailanalyse des Reports (KI/manuell) empfohlen.') }
    @($f.ToArray())
}

function New-DiagSummary {
    param($Report)

    function ConvertTo-MdCell {
        param($Value, [int]$Max = 110)
        $s = "$Value"
        $s = $s -replace '\r?\n', ' '
        $s = $s -replace '\|', '/'
        $s = $s.Trim()
        if ($s.Length -gt $Max) { $s = $s.Substring(0, $Max) + ' ...' }
        if ($s -eq '') { $s = '-' }
        $s
    }

    $sb  = New-Object System.Text.StringBuilder
    $m   = $Report.Meta
    $sys = $Report.System
    $ev  = $Report.Events

    [void]$sb.AppendLine('# AppHangDiag Report')
    [void]$sb.AppendLine()
    $plat = ''
    if ($Report.PSObject.Properties['Plattform'] -and $Report.Plattform) { $plat = " Plattform: $($Report.Plattform.PlatformProfil)." }
    $fokus = ''
    if ($m.PSObject.Properties['TriggerTyp']) {
        if ($m.TriggerTyp -eq 'Crash') { $fokus = ' FOKUS: Absturzursache - ExitCode, korrelierte 1000er-Events/WER-Reports und ggf. Watchdog-Dump priorisieren.' }
        elseif ($m.TriggerTyp -eq 'Lag') { $fokus = ' FOKUS: Performance-/Latenzursache (kein kompletter Freeze) - Leistungsverlauf, Ressourcen, Backend-/Session-Latenz priorisieren.' }
        elseif ($m.TriggerTyp -eq 'Hang') { $fokus = ' FOKUS: Hang-Ursache - Zielprozess-Threads/Waits, Kindprozesse, Backend-Verbindungen priorisieren.' }
    }
    [void]$sb.AppendLine("> **KI-Analyseauftrag:** Analysiere den folgenden Diagnose-Report eines Windows-Systems (Client oder Citrix-Terminalserver) auf Ursachen fuer Anwendungshaenger/Einfrieren, Performance-Probleme (Lags) und Abstuerze.$plat Korreliere Events, Prozessdetails, Leistungsverlauf, Sitzungs-/Profilkontext, Ressourcenlage und kuerzliche Aenderungen. Nenne die wahrscheinlichsten Ursachen priorisiert mit Begruendung sowie konkrete naechste Diagnose- und Abhilfeschritte.$fokus Vollstaendige Rohdaten: ``report.json`` im selben Paket.")
    [void]$sb.AppendLine()

    [void]$sb.AppendLine('## Metadaten')
    [void]$sb.AppendLine("- Tool: $($m.Tool) v$($m.Version) | Zeitpunkt: $($m.Zeitpunkt) | Trigger: $($m.Trigger)")
    [void]$sb.AppendLine("- Host: $($m.Hostname) | Benutzer: $($m.Benutzer) | Administrator: $($m.Administrator)")
    $zp = '-'
    if ($m.ZielPid) { $zp = $m.ZielPid }
    [void]$sb.AppendLine("- Event-Zeitfenster: $($m.EventFensterStunden) h | Ziel-PID: $zp | Trigger-Typ: $($m.TriggerTyp)")
    if ($Report.PSObject.Properties['Plattform'] -and $Report.Plattform) {
        $pf = $Report.Plattform
        [void]$sb.AppendLine("- Plattform: $($pf.PlatformProfil) | Multi-Session: $($pf.IstMultiSession) | Citrix-VDA: $($pf.HatVda) | Edition: $($pf.EditionID)")
    }
    [void]$sb.AppendLine()

    [void]$sb.AppendLine('## Automatische Befunde (Heuristik)')
    foreach ($x in @($Report.Findings)) { [void]$sb.AppendLine("- $x") }
    [void]$sb.AppendLine()

    [void]$sb.AppendLine('## System')
    [void]$sb.AppendLine("- OS: $($sys.OS) $($sys.DisplayVersion) (Build $($sys.Build)) | Modell: $($sys.Modell)")
    [void]$sb.AppendLine("- CPU: $($sys.CPU) ($($sys.LogischeProzessoren) LP) | RAM: $($sys.RamGB) GB, frei $($sys.RamFreiProzent)% | CPU-Last (WMI): $($sys.CpuLastProzent)%")
    [void]$sb.AppendLine("- Letzter Start: $($sys.LetzterStart) | Uptime: $($sys.UptimeStunden) h | PendingReboot: $($sys.PendingReboot)")
    [void]$sb.AppendLine("- Energieplan: $(ConvertTo-MdCell $sys.Energieplan 140)")
    foreach ($g in @($sys.GPU)) {
        [void]$sb.AppendLine("- GPU: $($g.Name) | Treiber $($g.Treiber) vom $($g.TreiberDatum)")
    }
    [void]$sb.AppendLine()

    $ciS = $Report.CrashInfo
    if ($ciS) {
        [void]$sb.AppendLine('## Crash-Kontext (Prozess-Ende im Monitor)')
        [void]$sb.AppendLine("- Prozess: $($ciS.ProzessName) (letzte PID $($ciS.LetztePid)) | Exit-Zeit: $($ciS.ExitZeit)")
        [void]$sb.AppendLine("- ExitCode: $($ciS.Bedeutung)")
        if (@($ciS.WatchdogDumps).Count -gt 0) { [void]$sb.AppendLine("- Watchdog-Dump(s): $(@($ciS.WatchdogDumps) -join ', ') - WinDbg: !analyze -v") }
        if (@($ciS.KorrelierteEreignisse).Count -gt 0) {
            [void]$sb.AppendLine()
            [void]$sb.AppendLine('| Zeit | Log | ID | Signatur (korreliertes Ereignis, letzte 15 min) |')
            [void]$sb.AppendLine('|---|---|---|---|')
            foreach ($ce in @($ciS.KorrelierteEreignisse)) {
                [void]$sb.AppendLine("| $($ce.Zeit) | $($ce.Log) | $($ce.Id) | $(ConvertTo-MdCell $ce.Signatur 70) |")
            }
        }
        if (@($ciS.KorrelierteWerReports).Count -gt 0) {
            $cw = (@($ciS.KorrelierteWerReports | ForEach-Object { "$($_.Zeit) $($_.Typ)" }) -join ' | ')
            [void]$sb.AppendLine("- Korrelierte WER-Reports: $cw")
        }
        [void]$sb.AppendLine()
    }

    $tp = $Report.TargetProcess
    if ($tp) {
        [void]$sb.AppendLine('## Zielprozess')
        $reag = 'JA'
        if ($tp.Reagiert -eq $false) { $reag = 'NEIN' }
        [void]$sb.AppendLine("- $($tp.Name) (PID $($tp.PID)) | Reagiert: $reag | Start: $($tp.Start) | CPU: $($tp.CpuSekunden) s")
        [void]$sb.AppendLine("- RAM: $($tp.RamMB) MB (Privat $($tp.PrivateMB) MB) | Handles: $($tp.Handles) | Threads: $($tp.Threads) | Session: $($tp.SessionId)")
    [void]$sb.AppendLine("- Pfad: $(ConvertTo-MdCell $tp.Pfad 160)")
        [void]$sb.AppendLine("- Version: $($tp.Version) | Produkt: $(ConvertTo-MdCell $tp.Produkt 60)")
        [void]$sb.AppendLine("- Kommandozeile: $(ConvertTo-MdCell $tp.Kommandozeile 200)")
        [void]$sb.AppendLine("- Elternprozess: $($tp.ElternProzess) | Besitzer: $($tp.Besitzer) | Fenster: $(ConvertTo-MdCell $tp.FensterTitel 80)")
        $ts = (@($tp.ThreadStatus | ForEach-Object { "$($_.Status)=$($_.Anzahl)" }) -join ', ')
        $wg = (@($tp.WaitGruende | Select-Object -First 6 | ForEach-Object { "$($_.Grund)=$($_.Anzahl)" }) -join ', ')
        [void]$sb.AppendLine("- Thread-Status: $ts")
        [void]$sb.AppendLine("- Wait-Gruende: $wg")
        [void]$sb.AppendLine("- Module gesamt: $($tp.ModuleGesamt) | Nicht-Microsoft: $(@($tp.ModuleNichtMicrosoft).Count)")
        if (@($tp.ModuleNichtMicrosoft).Count -gt 0) {
            [void]$sb.AppendLine()
            [void]$sb.AppendLine('### Fremdmodule (Nicht-Microsoft, Top 15)')
            [void]$sb.AppendLine('| Modul | Firma | Version |')
            [void]$sb.AppendLine('|---|---|---|')
            foreach ($mo in @($tp.ModuleNichtMicrosoft | Select-Object -First 15)) {
                [void]$sb.AppendLine("| $(ConvertTo-MdCell $mo.Modul 40) | $(ConvertTo-MdCell $mo.Firma 40) | $(ConvertTo-MdCell $mo.Version 30) |")
            }
        }
        [void]$sb.AppendLine()
    }

    $treeS = @()
    if ($Report.PSObject.Properties['ProcessTree']) { $treeS = @($Report.ProcessTree) }
    if ($treeS.Count -gt 0) {
        [void]$sb.AppendLine('### Kindprozesse (Prozessbaum)')
        [void]$sb.AppendLine('| Ebene | PID | Name | Reagiert | CPU s | RAM MB |')
        [void]$sb.AppendLine('|---|---|---|---|---|---|')
        foreach ($k in @($treeS | Select-Object -First 20)) {
            [void]$sb.AppendLine("| $($k.Ebene) | $($k.PID) | $(ConvertTo-MdCell $k.Name 40) | $($k.Reagiert) | $($k.CpuSekunden) | $($k.RamMB) |")
        }
        [void]$sb.AppendLine()
    }
    $netS = $Report.Network
    if ($netS) {
        [void]$sb.AppendLine('### Netzwerk (Zielprozess + Kinder)')
        $stTxt = (@($netS.NachStatus | ForEach-Object { "$($_.Status)=$($_.Anzahl)" }) -join ', ')
        [void]$sb.AppendLine("- TCP-Verbindungen: $($netS.VerbindungenGesamt) | Status: $stTxt")
        if (@($netS.LatenzTopZiele).Count -gt 0) {
            $latTxt = (@($netS.LatenzTopZiele | ForEach-Object {
                $ms = 'n/a (ICMP geblockt?)'
                if ($null -ne $_.LatenzMs) { $ms = "$($_.LatenzMs) ms" }
                "$($_.Ziel): $ms"
            }) -join ' | ')
            [void]$sb.AppendLine("- Latenz Top-Ziele (ICMP): $latTxt")
        }
        if (@($netS.TopRemotes).Count -gt 0) {
            [void]$sb.AppendLine()
            [void]$sb.AppendLine('| Remote-Endpunkt | Verbindungen | Status |')
            [void]$sb.AppendLine('|---|---|---|')
            foreach ($r in @($netS.TopRemotes | Select-Object -First 12)) {
                [void]$sb.AppendLine("| $(ConvertTo-MdCell $r.Remote 45) | $($r.Anzahl) | $(ConvertTo-MdCell $r.Status 40) |")
            }
        }
        [void]$sb.AppendLine()
    }
    $cxS = $Report.CitrixContext
    if ($cxS) {
        [void]$sb.AppendLine('### Sitzungskontext')
        [void]$sb.AppendLine("- Skript-Sitzung: $($cxS.SkriptSitzung) | ICA-Sitzung: $($cxS.IstIcaSitzung) | Ziel-SessionId: $($cxS.ZielSessionId)")
        if ($cxS.VDA) { [void]$sb.AppendLine("- Citrix VDA: $($cxS.VDA)") }
        if ($cxS.PSObject.Properties['HdxMetriken'] -and $cxS.HdxMetriken) {
            $hm = $cxS.HdxMetriken
            [void]$sb.AppendLine("- HDX-Metriken ($($hm.Instanz)): RTT $($hm.LatenzLetzteMs) ms (Mittel $($hm.LatenzMittelMs) ms) | In $($hm.InputBps) Bps | Out $($hm.OutputBps) Bps")
        }
        [void]$sb.AppendLine()
    }
    $upmS = $Report.UpmContext
    if ($upmS) {
        [void]$sb.AppendLine('### Citrix UPM / Profilcontainer')
        [void]$sb.AppendLine("- UPM-Dienst: $($upmS.DienstStatus) | Version: $($upmS.Version) | Container aktiv: $($upmS.ContainerAktiv)")
        $upmCfg = $upmS.Konfiguration
        if ($upmCfg) {
            $cfgTxt = (@($upmCfg.PSObject.Properties | Select-Object -First 6 | ForEach-Object { "$($_.Name)=$(ConvertTo-MdCell $_.Value 60)" }) -join ' | ')
            if ($cfgTxt) { [void]$sb.AppendLine("- Konfiguration: $cfgTxt") }
        }
        if (@($upmS.ContainerDisks).Count -gt 0) {
            [void]$sb.AppendLine()
            [void]$sb.AppendLine('| Profilcontainer (VHDX) | Groesse GB | Frei GB | Frei % |')
            [void]$sb.AppendLine('|---|---|---|---|')
            foreach ($cd in @($upmS.ContainerDisks)) {
                [void]$sb.AppendLine("| $(ConvertTo-MdCell $cd.VhdxPfad 90) | $($cd.GroesseGB) | $($cd.FreiGB) | $($cd.FreiProzent) |")
            }
            [void]$sb.AppendLine()
        }
        if ($upmS.ProfilFileserver) { [void]$sb.AppendLine("- Profil-Fileserver: $($upmS.ProfilFileserver) | erreichbar: $($upmS.FileserverErreichbar) | Latenz: $($upmS.FileserverLatenzMs) ms") }
        if (@($upmS.GesammelteLogs).Count -gt 0) {
            $ulg = (@($upmS.GesammelteLogs | ForEach-Object { "$($_.Datei) ($($_.GroesseMB) MB)" }) -join ', ')
            [void]$sb.AppendLine("- UPM-Logs (AppLogs\CitrixUPM): $ulg")
        }
        [void]$sb.AppendLine()
    }
    $vfS = $Report.Verlauf
    if ($vfS) {
        [void]$sb.AppendLine("### Leistungsverlauf (Monitor: $($vfS.AnzahlSamples) Samples, $($vfS.VonZeit) bis $($vfS.BisZeit))")
        [void]$sb.AppendLine('| Metrik | Min | Mittel | P95 | Max |')
        [void]$sb.AppendLine('|---|---|---|---|---|')
        foreach ($ag in @($vfS.Aggregate)) {
            [void]$sb.AppendLine("| $($ag.Metrik) | $($ag.Min) | $($ag.Mittel) | $($ag.P95) | $($ag.Max) |")
        }
        [void]$sb.AppendLine("- Lag-Schwelle: $($vfS.LagSchwelleMs) ms | Rohdaten: ``report.json`` -> ``Verlauf.Samples``")
        [void]$sb.AppendLine()
    }
    $acS = $Report.AppContext
    if ($acS) {
        [void]$sb.AppendLine("## App-Kontext (Profil: $(@($acS.Profile) -join ', '))")
        if ($acS.Office) {
            $o = $acS.Office
            if ($o.ClickToRun) { [void]$sb.AppendLine("- Office C2R: $($o.ClickToRun.Version) | Kanal: $($o.ClickToRun.Kanal) | $($o.ClickToRun.Plattform)") }
            $hwTxt = 'Standard'
            if ($o.HwBeschlDeaktiviert -eq 1) { $hwTxt = 'deaktiviert' }
            [void]$sb.AppendLine("- HW-Beschleunigung: $hwTxt | COM-Add-ins: $(@($o.ComAddins).Count) | Resiliency-Eintraege: $(@($o.ResiliencyEintraege).Count)")
            if (@($o.ComAddins).Count -gt 0) {
                [void]$sb.AppendLine()
                [void]$sb.AppendLine('| App | Add-in | LoadBehavior | Aktiv | Quelle |')
                [void]$sb.AppendLine('|---|---|---|---|---|')
                foreach ($a in @($o.ComAddins | Sort-Object App, Addin | Select-Object -First 20)) {
                    [void]$sb.AppendLine("| $($a.App) | $(ConvertTo-MdCell $a.Addin 45) | $($a.LoadBehavior) | $($a.Aktiv) | $($a.Quelle) |")
                }
                [void]$sb.AppendLine()
            }
            if (@($o.ResiliencyEintraege).Count -gt 0) {
                [void]$sb.AppendLine('| App | Resiliency-Liste | Inhalt (dekodiert) |')
                [void]$sb.AppendLine('|---|---|---|')
                foreach ($r in @($o.ResiliencyEintraege | Select-Object -First 10)) {
                    [void]$sb.AppendLine("| $($r.App) | $($r.Liste) | $(ConvertTo-MdCell $r.Inhalt 90) |")
                }
                [void]$sb.AppendLine()
            }
        }
        if (@($acS.OutlookDateien).Count -gt 0) {
            [void]$sb.AppendLine('| Outlook-Datendatei | Typ | GB | Geaendert |')
            [void]$sb.AppendLine('|---|---|---|---|')
            foreach ($fd in @($acS.OutlookDateien | Select-Object -First 10)) {
                [void]$sb.AppendLine("| $(ConvertTo-MdCell $fd.Datei 45) | $($fd.Typ) | $($fd.GroesseGB) | $($fd.Geaendert) |")
            }
            [void]$sb.AppendLine()
        }
        if ($acS.Teams) { [void]$sb.AppendLine("- Teams (MSIX): $($acS.Teams.TeamsMsix) | WebView2-Runtime: $($acS.Teams.WebView2Runtime)") }
        if ($acS.Nexus) {
            $np = (@($acS.Nexus.Produkte | Select-Object -First 8 | ForEach-Object { "$($_.Produkt) $($_.Version)" }) -join ' | ')
            $ns = (@($acS.Nexus.Dienste | ForEach-Object { "$($_.Dienst)=$($_.Status)" }) -join ', ')
            if ($np) { [void]$sb.AppendLine("- Nexus-Produkte: $np") }
            if ($ns) { [void]$sb.AppendLine("- Nexus-Dienste: $ns") }
        }
        if (@($acS.GesammelteLogs).Count -gt 0) {
            $lgTxt = (@($acS.GesammelteLogs | ForEach-Object { "$($_.Datei) ($($_.GroesseMB) MB)" }) -join ', ')
            [void]$sb.AppendLine("- Gesammelte App-Logs (AppLogs\): $lgTxt")
        }
        [void]$sb.AppendLine()
    }

    [void]$sb.AppendLine("## Ereignisse (Application/System/OAlerts, letzte $($ev.FensterStunden) h)")
    [void]$sb.AppendLine("- Gesamt: $($ev.AnzahlGesamt) | App-Hangs 1002: $($ev.AppHangs1002) | App-Crashes 1000: $($ev.AppCrashes1000) | WER 1001: $($ev.WerReports1001)")
    [void]$sb.AppendLine("- Dienst-Timeouts 7011: $($ev.ServiceTimeouts7011) | Storage 129/153: $($ev.StorageEvents129_153) | Kernel-Power 41: $($ev.KernelPower41)")
    if ($ev.PSObject.Properties['OAlerts']) {
        $upmCount = 0
        if ($ev.PSObject.Properties['UpmEvents']) { $upmCount = $ev.UpmEvents }
        [void]$sb.AppendLine("- Office-Alerts (OAlerts-Log): $($ev.OAlerts) | UPM-Events (Warning/Error): $upmCount")
    }
    if ($ev.PSObject.Properties['LiveKernelEvents']) {
        [void]$sb.AppendLine("- LiveKernelEvents: $($ev.LiveKernelEvents) | BlueScreen-Reports: $($ev.BlueScreens1001)")
        if (@($ev.LiveKernelSignaturen).Count -gt 0) {
            $lkeTxt = (@($ev.LiveKernelSignaturen | Select-Object -First 6 | ForEach-Object { "$($_.Signatur): $($_.Anzahl)x" }) -join ' | ')
            [void]$sb.AppendLine("- LiveKernel-Signaturen: $lkeTxt")
        }
    }
    if (@($ev.HangsProAnwendung).Count -gt 0) {
        $hpa = (@($ev.HangsProAnwendung | ForEach-Object { "$($_.Anwendung): $($_.Anzahl)x" }) -join ' | ')
        [void]$sb.AppendLine("- Hangs pro Anwendung: $hpa")
    }
    $grp = @()
    if ($ev.PSObject.Properties['EreignisseGruppiert']) { $grp = @($ev.EreignisseGruppiert) }
    if ($grp.Count -gt 0) {
        [void]$sb.AppendLine()
        [void]$sb.AppendLine("### Ereignisgruppen (dedupliziert, Top 20 von $($grp.Count) Gruppen)")
        [void]$sb.AppendLine('| Anzahl | Zuletzt | Log | ID | Signatur | Meldung (Beispiel, gekuerzt) |')
        [void]$sb.AppendLine('|---|---|---|---|---|---|')
        foreach ($g in @($grp | Select-Object -First 20)) {
            [void]$sb.AppendLine("| $($g.Anzahl)x | $($g.Zuletzt) | $($g.Log) | $($g.Id) | $(ConvertTo-MdCell $g.Signatur 45) | $(ConvertTo-MdCell $g.Beispiel 100) |")
        }
    }
    [void]$sb.AppendLine()

    if (@($Report.WerReports).Count -gt 0) {
        [void]$sb.AppendLine('## WER-Reports (Top 15)')
        [void]$sb.AppendLine('| Zeit | Typ | Anwendung |')
        [void]$sb.AppendLine('|---|---|---|')
        foreach ($w in @($Report.WerReports | Select-Object -First 15)) {
            [void]$sb.AppendLine("| $($w.Zeit) | $(ConvertTo-MdCell $w.Typ 30) | $(ConvertTo-MdCell $w.Anwendung 60) |")
        }
        [void]$sb.AppendLine()
    }

    if (@($Report.Reliability).Count -gt 0) {
        [void]$sb.AppendLine('## Reliability-Records (Top 15)')
        [void]$sb.AppendLine('| Zeit | Quelle | EventId | Produkt |')
        [void]$sb.AppendLine('|---|---|---|---|')
        foreach ($r in @($Report.Reliability | Select-Object -First 15)) {
            [void]$sb.AppendLine("| $($r.Zeit) | $(ConvertTo-MdCell $r.Quelle 35) | $($r.EventId) | $(ConvertTo-MdCell $r.Produkt 50) |")
        }
        [void]$sb.AppendLine()
    }

    $res = $Report.Resources
    if ($res) {
        [void]$sb.AppendLine('## Ressourcen (Momentaufnahme)')
        $z = $res.Zaehler
        $zHash = @{}
        if ($z) { foreach ($pr in $z.PSObject.Properties) { $zHash[$pr.Name] = $pr.Value } }
        [void]$sb.AppendLine("- CPU gesamt: $($zHash['CpuGesamtProzent'])% | RAM verfuegbar: $($zHash['RamVerfuegbarMB']) MB | Pagefile: $($zHash['PagefileNutzungProzent'])%")
        [void]$sb.AppendLine("- Disk (_Total): AvgRead $($zHash['DiskAvgReadSec']) s | AvgWrite $($zHash['DiskAvgWriteSec']) s | Queue $($zHash['DiskQueueLength'])")
        if (@($res.Netzwerkprofile).Count -gt 0) {
            $np = (@($res.Netzwerkprofile | ForEach-Object { "$($_.Netzwerk) [$($_.Interface), $($_.Kategorie), IPv4=$($_.IPv4)]" }) -join ' | ')
            [void]$sb.AppendLine("- Netzwerk: $np")
        }
        [void]$sb.AppendLine()
        [void]$sb.AppendLine('### Top-Prozesse CPU (1-s-Delta)')
        [void]$sb.AppendLine('| PID | Prozess | CPU % | RAM MB |')
        [void]$sb.AppendLine('|---|---|---|---|')
        foreach ($t in @($res.TopProzesseCpu | Select-Object -First 8)) {
            [void]$sb.AppendLine("| $($t.PID) | $(ConvertTo-MdCell $t.Name 35) | $($t.CpuProzent) | $($t.RamMB) |")
        }
        [void]$sb.AppendLine()
        [void]$sb.AppendLine('### Top-Prozesse RAM')
        [void]$sb.AppendLine('| PID | Prozess | RAM MB | CPU % |')
        [void]$sb.AppendLine('|---|---|---|---|')
        foreach ($t in @($res.TopProzesseRam | Select-Object -First 8)) {
            [void]$sb.AppendLine("| $($t.PID) | $(ConvertTo-MdCell $t.Name 35) | $($t.RamMB) | $($t.CpuProzent) |")
        }
        [void]$sb.AppendLine()
        if ($res.PSObject.Properties['Sessions'] -and @($res.Sessions).Count -gt 0) {
            [void]$sb.AppendLine('### Sitzungen (Multi-Session-Aggregat, Top 10 nach CPU)')
            [void]$sb.AppendLine('| Session | Benutzer | Prozesse | CPU % | RAM MB |')
            [void]$sb.AppendLine('|---|---|---|---|---|')
            foreach ($ss in @($res.Sessions | Select-Object -First 10)) {
                [void]$sb.AppendLine("| $($ss.SessionId) | $(ConvertTo-MdCell $ss.Benutzer 25) | $($ss.Prozesse) | $($ss.CpuProzent) | $($ss.RamMB) |")
            }
            [void]$sb.AppendLine()
        }
    }

    $sw = $Report.Software
    if ($sw) {
        [void]$sb.AppendLine('## Software-Kontext (letzte 14 Tage)')
        if (@($sw.HotfixesNeu).Count -gt 0) {
            $hf = (@($sw.HotfixesNeu | ForEach-Object { "$($_.KB) ($($_.Installiert))" }) -join ', ')
            [void]$sb.AppendLine("- Hotfixes: $hf")
        } else {
            [void]$sb.AppendLine('- Hotfixes: keine im Zeitraum')
        }
        if (@($sw.SoftwareNeu).Count -gt 0) {
            [void]$sb.AppendLine()
            [void]$sb.AppendLine('| Software (neu/aktualisiert) | Version | Installiert |')
            [void]$sb.AppendLine('|---|---|---|')
            foreach ($s in @($sw.SoftwareNeu | Select-Object -First 15)) {
                [void]$sb.AppendLine("| $(ConvertTo-MdCell $s.Name 60) | $(ConvertTo-MdCell $s.Version 25) | $($s.Installiert) |")
            }
            [void]$sb.AppendLine()
        } else {
            [void]$sb.AppendLine('- Software-Installationen: keine im Zeitraum')
        }
        if (@($sw.Antivirus).Count -gt 0) {
            $avs = (@($sw.Antivirus | ForEach-Object { "$($_.Produkt) (aktiv: $($_.Aktiv))" }) -join ' | ')
            [void]$sb.AppendLine("- Antivirus: $avs")
        }
        if (@($sw.SecurityDienste).Count -gt 0) {
            $ed = (@($sw.SecurityDienste | ForEach-Object { "$($_.Dienst)=$($_.Status)" }) -join ', ')
            [void]$sb.AppendLine("- Security-Dienste: $ed")
        }
        if ($sw.CitrixWorkspace) { [void]$sb.AppendLine("- Citrix: $($sw.CitrixWorkspace)") }
        [void]$sb.AppendLine()
    }

    [void]$sb.AppendLine('## Artefakte im Paket')
    [void]$sb.AppendLine('- `report.json` - vollstaendige strukturierte Rohdaten (fuer KI-Tiefenanalyse)')
    if ($Report.Dump) {
        [void]$sb.AppendLine("- Prozess-Dump: $(Split-Path $Report.Dump.Datei -Leaf) ($($Report.Dump.GroesseMB) MB) - Analyse via WinDbg (!analyze -v -hang)")
    } else {
        [void]$sb.AppendLine('- Prozess-Dump: nicht erstellt')
    }
    if (@($Report.Evtx).Count -gt 0) {
        [void]$sb.AppendLine("- EVTX-Rohlogs: $(@($Report.Evtx) -join ', ') (Klartextdaten)")
    } else {
        [void]$sb.AppendLine('- EVTX-Rohlogs: nicht exportiert')
    }
    if ($Report.AppContext -and @($Report.AppContext.GesammelteLogs).Count -gt 0) {
        [void]$sb.AppendLine("- App-Logs: $(@($Report.AppContext.GesammelteLogs).Count) Datei(en) unter AppLogs\ (koennen personenbezogene Daten enthalten)")
    }

    $sb.ToString()
}

function Invoke-FullCapture {
    param([hashtable]$Options)
    if ($Options.LogQueue) { $script:DiagLogQueue = $Options.LogQueue }

    $ts    = Get-Date
    $stamp = $ts.ToString('yyyyMMdd_HHmmss')
    $dir   = Join-Path $Options.OutputRoot "Capture_$stamp"
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    Write-DiagLog "Capture gestartet -> $dir (Trigger: $($Options.Trigger))"

    $meta = [pscustomobject]@{
        Tool                = 'AppHangDiag'
        Version             = $Options.Version
        Zeitpunkt           = $ts.ToString('s')
        Trigger             = $Options.Trigger
        Hostname            = $env:COMPUTERNAME
        Benutzer            = "$env:USERDOMAIN\$env:USERNAME"
        Administrator       = [bool]$Options.IsAdmin
        ZielPid             = $Options.TargetPid
        EventFensterStunden = $Options.Hours
        TriggerTyp          = $(if ($Options.TriggerTyp) { $Options.TriggerTyp } else { 'Manuell' })
        PlattformProfil     = $(if ($Options.Platform) { $Options.Platform.PlatformProfil } else { 'unbekannt' })
    }

    # Multi-Session: Warnung, wenn das Ausgabeziel im Profil-/UNC-Pfad liegt (Containerprofil/SMB)
    if ($Options.Platform -and $Options.Platform.IstMultiSession) {
        $orLow = "$($Options.OutputRoot)".ToLower()
        $tempOk = (Join-Path $env:LOCALAPPDATA 'Temp').ToLower()
        if ($orLow.StartsWith('\\') -or ($orLow.StartsWith("$env:USERPROFILE".ToLower()) -and -not $orLow.StartsWith($tempOk))) {
            Write-DiagLog 'Ausgabeziel liegt auf UNC bzw. im Benutzerprofil - bei UPM-Containerprofilen VHDX-Wachstum/SMB-Last. Empfehlung: LOCALAPPDATA\Temp\AppHangDiag.' 'WARN'
        }
    }

    # 1) Dump ZUERST - solange der Prozess noch haengt (fluechtige Evidenz)
    $dump = $null
    if ($Options.DoDump -and $Options.ProcDumpExe -and $Options.TargetPid) {
        $dump = Invoke-ProcDumpCapture -ProcDumpExe $Options.ProcDumpExe -TargetPid $Options.TargetPid -OutDir $dir
    }

    # 2) Prozessdetails (ebenfalls fluechtig), Prozessbaum, TCP; Sitzungskontext laeuft IMMER (Systemebene)
    $tp = $null; $tree = @(); $net = $null
    $sid = -1
    if ($Options.TargetPid) {
        $tp = Get-ProcessDetail -TargetPid $Options.TargetPid
        $tree = @(Get-ProcessTree -RootPid $Options.TargetPid)
        $allPids = @([int]$Options.TargetPid) + @($tree | ForEach-Object { [int]$_.PID })
        $net = Get-ProcessNetwork -Pids $allPids
        if ($tp) { $sid = $tp.SessionId }
    }
    $citrix = Get-CitrixContext -TargetSessionId $sid
    $upm = Get-UpmContext
    if ($upm -and $Options.IncludeAppLogs) {
        $upmLogs = @(Copy-AppLogs -LogPaths @((Join-Path $env:SystemRoot 'System32\LogFiles\UserProfileManager')) -OutDir $dir -ProfilName 'CitrixUPM')
        $upm.GesammelteLogs = $upmLogs
    }

    # 2b) Leistungsverlauf aus Monitor-Ringpuffer (falls vorhanden)
    $verlauf = $null
    if ($Options.PerfHistory -and @($Options.PerfHistory).Count -gt 0) {
        $lagMs = 500
        if ($Options.LagMs) { $lagMs = [int]$Options.LagMs }
        $verlauf = Get-PerfAggregate -Samples @($Options.PerfHistory) -LagMs $lagMs
        Write-DiagLog "Leistungsverlauf: $($verlauf.AnzahlSamples) Sample(s) ($($verlauf.VonZeit) bis $($verlauf.BisZeit))."
    }

    # 3) M8: App-Profil-Kontext (Office/Outlook/Teams/Nexus)
    $appCtx = $null
    if ($Options.AppProfile) {
        $prof = $Options.AppProfile
        Write-DiagLog "M8: App-Profil aktiv: $(@($prof.Namen) -join ', ')"
        $office = $null; $olkFiles = @(); $teams = $null; $nexus = $null; $appLogs = @()
        if (@($prof.Collect) -contains 'Office')         { $office   = Get-OfficeContext }
        if (@($prof.Collect) -contains 'OutlookDateien') { $olkFiles = @(Get-OutlookDataFiles) }
        if (@($prof.Collect) -contains 'Teams')          { $teams    = Get-TeamsContext }
        if (@($prof.Collect) -contains 'Nexus')          { $nexus    = Get-NexusContext }
        if ($Options.IncludeAppLogs -and @($prof.LogPaths).Count -gt 0) {
            $appLogs = @(Copy-AppLogs -LogPaths @($prof.LogPaths) -OutDir $dir -ProfilName $prof.LogProfil)
        }
        $appCtx = [pscustomobject]@{
            Profile        = @($prof.Namen)
            Office         = $office
            OutlookDateien = $olkFiles
            Teams          = $teams
            Nexus          = $nexus
            GesammelteLogs = $appLogs
        }
    }

    $sys = Get-SystemInfo
    $ev  = Get-HangEvents -Hours $Options.Hours
    $wer = @(Get-WerReports -Hours $Options.Hours)
    $rel = @(Get-ReliabilityInfo -Hours $Options.Hours)
    $isMulti = $false
    if ($Options.Platform) { $isMulti = [bool]$Options.Platform.IstMultiSession }
    $res = Get-ResourceSnapshot -MultiSession $isMulti -IncludeSessions ([bool]$Options.IsAdmin)
    $sw  = Get-SoftwareContext

    # 3b) Crash-Kontext: ExitCode-Dekodierung + Korrelation (Events der exe, WER, frische Watchdog-Dumps)
    $crash = $null
    if ($Options.CrashInfo) {
        $ci = $Options.CrashInfo
        Write-DiagLog "Crash-Kontext: $($ci.ProzessName) (PID $($ci.LetztePid)) ExitCode $($ci.ExitCodeHex)"
        $decoded = ConvertTo-NtStatusText -ExitCode $ci.ExitCode
        $exePat  = "$($ci.ProzessName)*"
        $cutoff  = (Get-Date).AddMinutes(-15).ToString('s')
        $corrEv  = @($ev.Ereignisse | Where-Object {
            $_.Zeit -ge $cutoff -and ($_.Id -eq 1000 -or $_.Id -eq 1001 -or $_.Id -eq 1002) -and
            ($_.Prozess -like $exePat -or $_.Meldung -match [regex]::Escape($ci.ProzessName))
        } | Select-Object Zeit, Log, Id, Signatur -First 10)
        $corrWer = @($wer | Where-Object { $_.Anwendung -like $exePat } | Select-Object -First 3)
        $freshDumps = @()
        try {
            foreach ($fd in @(Get-ChildItem -LiteralPath $Options.OutputRoot -Filter '*.dmp' -File -ErrorAction SilentlyContinue |
                Where-Object { $_.LastWriteTime -ge (Get-Date).AddMinutes(-15) })) {
                $moved = $fd.FullName
                try { Move-Item -LiteralPath $fd.FullName -Destination $dir -Force; $moved = Join-Path $dir $fd.Name } catch { }
                $freshDumps += (Split-Path $moved -Leaf)
            }
        } catch { }
        if ($freshDumps.Count -gt 0) { Write-DiagLog "Watchdog-Dump(s) in Capture uebernommen: $($freshDumps -join ', ')" 'OK' }
        $crash = [pscustomobject]@{
            ProzessName           = $ci.ProzessName
            LetztePid             = $ci.LetztePid
            ExitZeit              = $ci.ExitZeit
            ExitCode              = $ci.ExitCode
            ExitCodeHex           = $ci.ExitCodeHex
            Bedeutung             = $decoded
            KorrelierteEreignisse = $corrEv
            KorrelierteWerReports = $corrWer
            WatchdogDumps         = @($freshDumps)
        }
    }

    $evtxNames = @()
    if ($Options.IncludeEvtx) {
        $evtxFiles = @(Export-EvtxLogs -Hours $Options.Hours -OutDir $dir)
        $evtxNames = @($evtxFiles | ForEach-Object { Split-Path $_ -Leaf })
    }

    $report = [ordered]@{
        Meta          = $meta
        Plattform     = $Options.Platform
        System        = $sys
        TargetProcess = $tp
        ProcessTree   = $tree
        Network       = $net
        CitrixContext = $citrix
        UpmContext    = $upm
        AppContext    = $appCtx
        Verlauf       = $verlauf
        CrashInfo     = $crash
        Events        = $ev
        WerReports    = $wer
        Reliability   = $rel
        Resources     = $res
        Software      = $sw
        Dump          = $dump
        Evtx          = $evtxNames
        Findings      = @()
    }
    $report.Findings = @(Get-DiagFindings -Report ([pscustomobject]$report))
    Write-DiagLog "Heuristik: $(@($report.Findings).Count) Befund(e)."

    $json = $report | ConvertTo-Json -Depth 8
    $md   = New-DiagSummary -Report ([pscustomobject]$report)

    $enc      = New-Object System.Text.UTF8Encoding($false)
    $jsonPath = Join-Path $dir 'report.json'
    $mdPath   = Join-Path $dir 'summary.md'
    [System.IO.File]::WriteAllText($jsonPath, $json, $enc)
    [System.IO.File]::WriteAllText($mdPath, $md, $enc)
    Write-DiagLog "report.json und summary.md geschrieben." 'OK'

    # ZIP: Dumps > 500 MB verbleiben nur im Capture-Ordner; AppLogs-Unterordner wird mitverpackt
    $zip     = Join-Path $Options.OutputRoot ('AppHangDiag_{0}_{1}.zip' -f $env:COMPUTERNAME, $stamp)
    $allF    = @(Get-ChildItem -LiteralPath $dir -File)
    $files   = @($allF | Where-Object { -not ($_.Extension -eq '.dmp' -and $_.Length -gt 500MB) })
    $skipped = @($allF | Where-Object { $_.Extension -eq '.dmp' -and $_.Length -gt 500MB })
    $zipItems = @($files.FullName)
    $appLogsDir = Join-Path $dir 'AppLogs'
    if (Test-Path -LiteralPath $appLogsDir) { $zipItems += $appLogsDir }
    try {
        Compress-Archive -Path $zipItems -DestinationPath $zip -Force
        Write-DiagLog "Export-ZIP: $zip" 'OK'
        if ($skipped.Count -gt 0) {
            Write-DiagLog 'Dump > 500 MB nicht ins ZIP uebernommen (verbleibt im Capture-Ordner).' 'WARN'
        }
    } catch {
        Write-DiagLog "ZIP-Fehler: $($_.Exception.Message)" 'ERROR'
        $zip = $null
    }

    Write-DiagLog 'Capture abgeschlossen.' 'OK'
    [pscustomobject]@{
        Ordner  = $dir
        Zip     = $zip
        Json    = $jsonPath
        Summary = $mdPath
        Befunde = @($report.Findings)
    }
}

#endregion Auswertung und Orchestrierung

# Funktionsliste fuer Runspace-Uebernahme (GUI-Hintergrund-Capture)
$Script:LibFunctions = @(
    'Write-DiagLog', 'Get-LocalizedCounterName', 'Get-PendingReboot', 'Get-SystemInfo',
    'Get-HangEvents', 'Get-WerReports', 'Get-ReliabilityInfo', 'Get-ProcessDetail',
    'Get-TopProcesses', 'Get-ResourceSnapshot', 'Get-SoftwareContext', 'Invoke-ProcDumpCapture',
    'Export-EvtxLogs', 'Get-ProcessTree', 'Get-ProcessNetwork', 'Get-CitrixContext',
    'Get-OfficeContext', 'Get-OutlookDataFiles', 'Get-TeamsContext', 'Get-NexusContext',
    'Copy-AppLogs', 'Initialize-NativeUi', 'Get-UiLatencyMs', 'Get-PlatformProfile',
    'Get-IcaSessionMetrics', 'Get-SessionResources', 'Get-UpmContext', 'Get-PerfAggregate',
    'ConvertTo-NtStatusText', 'Get-DiagFindings', 'New-DiagSummary', 'Invoke-FullCapture'
)

#region App-Profile (M8)
# Built-in-Profile; ueberschreibbar per AppHangDiag.profiles.json neben dem Skript (gleiche Struktur).
$Script:AppProfiles = @(
    [pscustomobject]@{ Name = 'Office';  Match = @('winword', 'excel', 'powerpnt', 'onenote', 'msaccess', 'visio', 'mspub'); Collect = @('Office');                  LogPaths = @() },
    [pscustomobject]@{ Name = 'Outlook'; Match = @('outlook', 'olk');                                                        Collect = @('Office', 'OutlookDateien'); LogPaths = @() },
    [pscustomobject]@{ Name = 'Teams';   Match = @('ms-teams', 'msteams', 'teams');                                          Collect = @('Teams');                    LogPaths = @('%LOCALAPPDATA%\Packages\MSTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams\Logs') },
    [pscustomobject]@{ Name = 'Nexus';   Match = @('nexus*', 'ngkis*', 'kisng*', 'medico*');                                 Collect = @('Nexus');                    LogPaths = @() }
)
$Script:ProfilesJsonPath = Join-Path $Script:ScriptDir 'AppHangDiag.profiles.json'
if (Test-Path -LiteralPath $Script:ProfilesJsonPath) {
    try {
        $Script:AppProfiles = @((Get-Content -LiteralPath $Script:ProfilesJsonPath -Raw) | ConvertFrom-Json)
        Write-DiagLog "App-Profile aus AppHangDiag.profiles.json geladen: $(@($Script:AppProfiles).Count) Profil(e)."
    } catch {
        Write-DiagLog "AppHangDiag.profiles.json fehlerhaft - Built-in-Profile bleiben aktiv: $($_.Exception.Message)" 'WARN'
    }
}

function Get-AppProfileForProcess {
    # Liefert das zusammengefuehrte Profil (Collect/LogPaths-Union) fuer einen Prozessnamen oder $null
    param([string]$ProcessName)
    if (-not $ProcessName) { return $null }
    $hits = New-Object System.Collections.Generic.List[object]
    foreach ($p in @($Script:AppProfiles)) {
        foreach ($m in @($p.Match)) {
            if ($ProcessName -like $m) { $hits.Add($p); break }
        }
    }
    if ($hits.Count -eq 0) { return $null }
    $namen   = @($hits | ForEach-Object { $_.Name })
    $collect = @($hits | ForEach-Object { @($_.Collect) } | Select-Object -Unique)
    $logs    = @($hits | ForEach-Object { @($_.LogPaths) } | Where-Object { $_ } | Select-Object -Unique)
    [pscustomobject]@{
        Namen     = $namen
        Collect   = $collect
        LogPaths  = $logs
        LogProfil = ($namen -join '_')
    }
}
#endregion App-Profile (M8)

#region Plattform (M0)
$Script:Platform = Get-PlatformProfile
Write-DiagLog "Plattform erkannt: $($Script:Platform.PlatformProfil) ($($Script:Platform.OSCaption))"
# Multi-Session: Default-Ausgabeziel nach LOCALAPPDATA\Temp (UPM-Standard-Exclusion) statt Dokumente,
# sofern -OutputRoot nicht explizit gesetzt wurde (vermeidet VHDX-Wachstum/SMB-Last im Containerprofil)
if ($Script:Platform.IstMultiSession -and -not $PSBoundParameters.ContainsKey('OutputRoot')) {
    $OutputRoot = Join-Path $env:LOCALAPPDATA 'Temp\AppHangDiag'
    Write-DiagLog "Multi-Session erkannt - Ausgabeziel: $OutputRoot"
}
#endregion Plattform (M0)

#region CLI-Modus
if ($Snapshot) {
    Write-DiagLog "AppHangDiag v$($Script:AppVersion) - CLI-Snapshot"
    $resolvedPid = $null
    if ($TargetPid -gt 0) {
        $resolvedPid = $TargetPid
    } elseif ($ProcessName) {
        $cand = @(Get-Process -Name $ProcessName -ErrorAction SilentlyContinue)
        if ($cand.Count -eq 0) {
            Write-DiagLog "Prozess '$ProcessName' nicht gefunden - System-Snapshot ohne Prozessbezug." 'WARN'
        } else {
            if ($cand.Count -gt 1) {
                Write-DiagLog "Mehrere Instanzen von '$ProcessName' - verwende PID $($cand[0].Id). Alternativ -TargetPid nutzen." 'WARN'
            }
            $resolvedPid = $cand[0].Id
        }
    }
    if (-not (Test-Path -LiteralPath $OutputRoot)) { New-Item -ItemType Directory -Path $OutputRoot -Force | Out-Null }
    if ($Dump -and -not $Script:ProcDumpExe) {
        Write-DiagLog 'ProcDump nicht gefunden (procdump64.exe neben das Skript legen) - Dump wird uebersprungen.' 'WARN'
    }
    $profProcName = $null
    if ($resolvedPid) { try { $profProcName = (Get-Process -Id $resolvedPid -ErrorAction Stop).ProcessName } catch { } }
    $appProfile = Get-AppProfileForProcess -ProcessName $profProcName
    if ($appProfile) { Write-DiagLog "App-Profil erkannt: $(@($appProfile.Namen) -join ', ')" }
    $opts = @{
        Version     = $Script:AppVersion
        Trigger     = 'CLI'
        IsAdmin     = $Script:IsAdmin
        TargetPid   = $resolvedPid
        Hours       = $EventWindowHours
        IncludeEvtx = [bool]$IncludeEvtx
        IncludeAppLogs = [bool]$IncludeAppLogs
        AppProfile  = $appProfile
        Platform    = $Script:Platform
        TriggerTyp  = 'Manuell'
        PerfHistory = @()
        LagMs       = 500
        CrashInfo   = $null
        DoDump      = ([bool]$Dump -and $null -ne $Script:ProcDumpExe -and $null -ne $resolvedPid)
        ProcDumpExe = $Script:ProcDumpExe
        OutputRoot  = $OutputRoot
        LogQueue    = $null
    }
    $res = Invoke-FullCapture -Options $opts
    Write-DiagLog '--- Ergebnis ---'
    Write-DiagLog "Ordner: $($res.Ordner)" 'OK'
    if ($res.Zip) { Write-DiagLog "ZIP:    $($res.Zip)" 'OK' }
    foreach ($b in @($res.Befunde)) { Write-DiagLog "Befund: $b" }
    return
}
#endregion CLI-Modus

#region GUI
if ([System.Threading.Thread]::CurrentThread.ApartmentState -ne 'STA') {
    Write-Warning 'Die GUI benoetigt STA. Bitte starten mit: powershell.exe -STA -File .\AppHangDiag.ps1'
    exit 1
}
Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Windows.Forms

$xamlText = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="AppHangDiag - Anwendungshaenger-Diagnose"
        Height="780" Width="1120" MinHeight="640" MinWidth="960"
        WindowStartupLocation="CenterScreen"
        FontFamily="Segoe UI" FontSize="12" Background="#F4F6F8">
  <Grid Margin="10">
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="*"/>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="170"/>
      <RowDefinition Height="Auto"/>
    </Grid.RowDefinitions>

    <GroupBox Grid.Row="0" Header="Optionen" Margin="0,0,0,6">
      <WrapPanel Margin="6">
        <CheckBox x:Name="chkAppLogs" Content="App-Logs sammeln (Profil)" Margin="0,4,18,4" VerticalAlignment="Center"/>
        <CheckBox x:Name="chkEvtx" Content="EVTX-Rohexport (Application/System)" Margin="0,4,18,4" VerticalAlignment="Center"/>
        <CheckBox x:Name="chkDump" Content="ProcDump-Dump (-ma)" Margin="0,4,18,4" VerticalAlignment="Center"/>
        <CheckBox x:Name="chkWatchdog" Content="Crash-Watchdog (ProcDump -e)" Margin="0,4,18,4" VerticalAlignment="Center"/>
        <TextBlock Text="Event-Zeitfenster (h):" VerticalAlignment="Center" Margin="0,0,4,0"/>
        <TextBox x:Name="txtHours" Width="44" Text="72" VerticalAlignment="Center" Margin="0,0,18,0"/>
        <TextBlock Text="Ausgabeordner:" VerticalAlignment="Center" Margin="0,0,4,0"/>
        <TextBox x:Name="txtOut" Width="300" VerticalAlignment="Center"/>
        <Button x:Name="btnBrowse" Content="..." Width="28" Margin="4,0,0,0"/>
      </WrapPanel>
    </GroupBox>

    <GroupBox Grid.Row="1" Header="Prozessauswahl (laufende Anwendungen)">
      <DockPanel Margin="6">
        <StackPanel DockPanel.Dock="Top" Orientation="Horizontal" Margin="0,0,0,6">
          <Button x:Name="btnRefresh" Content="Aktualisieren" Width="110" Margin="0,0,12,0"/>
          <CheckBox x:Name="chkAllProcs" Content="Alle Prozesse (auch ohne Fenster)" VerticalAlignment="Center" Margin="0,0,12,0"/>
          <CheckBox x:Name="chkAllSessions" Content="Alle Sitzungen" VerticalAlignment="Center" Margin="0,0,12,0"/>
          <TextBlock Text="Filter:" VerticalAlignment="Center" Margin="0,0,4,0"/>
          <TextBox x:Name="txtFilter" Width="220" VerticalAlignment="Center"/>
        </StackPanel>
        <DataGrid x:Name="dgProcs" AutoGenerateColumns="False" IsReadOnly="True" SelectionMode="Single"
                  HeadersVisibility="Column" GridLinesVisibility="Horizontal" RowHeaderWidth="0"
                  CanUserAddRows="False" Background="White">
          <DataGrid.Columns>
            <DataGridTextColumn Header="PID" Binding="{Binding PID}" Width="70"/>
            <DataGridTextColumn Header="Session" Binding="{Binding Session}" Width="60"/>
            <DataGridTextColumn Header="Prozess" Binding="{Binding Name}" Width="170"/>
            <DataGridTextColumn Header="Fenstertitel" Binding="{Binding Titel}" Width="*"/>
            <DataGridTextColumn Header="Reagiert" Binding="{Binding Reagiert}" Width="80">
              <DataGridTextColumn.CellStyle>
                <Style TargetType="DataGridCell">
                  <Style.Triggers>
                    <DataTrigger Binding="{Binding Reagiert}" Value="NEIN">
                      <Setter Property="Background" Value="#F6B0B0"/>
                      <Setter Property="FontWeight" Value="Bold"/>
                    </DataTrigger>
                  </Style.Triggers>
                </Style>
              </DataGridTextColumn.CellStyle>
            </DataGridTextColumn>
            <DataGridTextColumn Header="RAM (MB)" Binding="{Binding RamMB}" Width="80"/>
            <DataGridTextColumn Header="Start" Binding="{Binding Start}" Width="130"/>
          </DataGrid.Columns>
        </DataGrid>
      </DockPanel>
    </GroupBox>

    <Grid Grid.Row="2" Margin="0,6,0,6">
      <Grid.ColumnDefinitions>
        <ColumnDefinition Width="Auto"/>
        <ColumnDefinition Width="*"/>
      </Grid.ColumnDefinitions>
      <GroupBox Grid.Column="0" Header="Aktionen" Margin="0,0,6,0">
        <StackPanel Orientation="Horizontal" Margin="6">
          <Button x:Name="btnSysSnap" Content="System-Snapshot" Width="130" Margin="0,0,8,0"/>
          <Button x:Name="btnProcSnap" Content="Prozess-Snapshot" Width="130" Margin="0,0,8,0"/>
          <Button x:Name="btnOpenOut" Content="Ausgabeordner" Width="110"/>
        </StackPanel>
      </GroupBox>
      <GroupBox Grid.Column="1" Header="Monitor-Modus (Auto-Capture bei Hang/Lag/Crash)">
        <StackPanel Orientation="Horizontal" Margin="6">
          <TextBlock Text="Intervall (s):" VerticalAlignment="Center" Margin="0,0,4,0"/>
          <TextBox x:Name="txtPoll" Width="36" Text="2" VerticalAlignment="Center" Margin="0,0,12,0"/>
          <TextBlock Text="Hang-Schwelle (s):" VerticalAlignment="Center" Margin="0,0,4,0"/>
          <TextBox x:Name="txtThresh" Width="36" Text="10" VerticalAlignment="Center" Margin="0,0,12,0"/>
          <TextBlock Text="Lag-Schwelle (ms):" VerticalAlignment="Center" Margin="0,0,4,0"/>
          <TextBox x:Name="txtLagMs" Width="48" Text="500" VerticalAlignment="Center" Margin="0,0,12,0"/>
          <Button x:Name="btnMonStart" Content="Monitor starten" Width="120" Margin="0,0,8,0"/>
          <Button x:Name="btnMonStop" Content="Stopp" Width="70" IsEnabled="False" Margin="0,0,12,0"/>
          <TextBlock x:Name="lblMonStatus" Text="inaktiv" VerticalAlignment="Center" FontWeight="Bold"/>
        </StackPanel>
      </GroupBox>
    </Grid>

    <GroupBox Grid.Row="3" Header="Protokoll">
      <TextBox x:Name="txtLog" Margin="6" IsReadOnly="True" VerticalScrollBarVisibility="Auto"
               TextWrapping="Wrap" FontFamily="Consolas" FontSize="11"
               Background="#1E1E1E" Foreground="#DCDCDC" BorderThickness="0"/>
    </GroupBox>

    <StatusBar Grid.Row="4" Margin="0,6,0,0">
      <StatusBarItem><TextBlock x:Name="lblProcDump"/></StatusBarItem>
      <Separator/>
      <StatusBarItem><TextBlock x:Name="lblAdmin"/></StatusBarItem>
      <Separator/>
      <StatusBarItem><TextBlock x:Name="lblPlatform"/></StatusBarItem>
      <Separator/>
      <StatusBarItem><TextBlock x:Name="lblBusy" Text="Bereit"/></StatusBarItem>
    </StatusBar>
  </Grid>
</Window>
'@

$window = [System.Windows.Markup.XamlReader]::Parse($xamlText)
$window.Title = "AppHangDiag v$($Script:AppVersion) - Anwendungshaenger-Diagnose"
$C = @{}
foreach ($n in @('chkAppLogs','chkEvtx','chkDump','chkWatchdog','txtHours','txtOut','btnBrowse','btnRefresh','chkAllProcs',
                 'chkAllSessions','txtFilter','dgProcs','btnSysSnap','btnProcSnap','btnOpenOut','txtPoll','txtThresh',
                 'txtLagMs','btnMonStart','btnMonStop','lblMonStatus','txtLog','lblProcDump','lblAdmin','lblPlatform','lblBusy')) {
    $C[$n] = $window.FindName($n)
}

$Gui = @{
    Busy = $false; PS = $null; RS = $null; Handle = $null
    MonPid = 0; MonName = ''; MonProc = $null; MonStartZeit = $null; Threshold = 10; HangSec = 0.0; EpisodeCaptured = $false
    LagMs = 500; LagSec = 0.0; LagPolls = 0; LagCaptured = $false; LastCpuMs = -1.0
    PerfBuffer = (New-Object 'System.Collections.Generic.List[object]')
    Episodes   = (New-Object 'System.Collections.Generic.List[object]')
    Watchdog   = $null
}
$LogQueue = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))

function Add-GuiLog {
    param([string]$Message, [switch]$Raw)
    $line = $Message
    if (-not $Raw) { $line = '{0:HH:mm:ss} [GUI  ] {1}' -f (Get-Date), $Message }
    if ($C.txtLog.Text.Length -gt 400000) { $C.txtLog.Text = $C.txtLog.Text.Substring(200000) }
    $C.txtLog.AppendText($line + [Environment]::NewLine)
    $C.txtLog.ScrollToEnd()
}

function Set-ActionButtons {
    param([bool]$Enabled)
    $C.btnSysSnap.IsEnabled  = $Enabled
    $C.btnProcSnap.IsEnabled = $Enabled
}

function Update-ProcessList {
    $flt = $C.txtFilter.Text
    $all = [bool]$C.chkAllProcs.IsChecked
    $ownSid  = [System.Diagnostics.Process]::GetCurrentProcess().SessionId
    $allSess = [bool]$C.chkAllSessions.IsChecked
    $rows = foreach ($p in (Get-Process | Sort-Object ProcessName)) {
        if ($Script:Platform.IstMultiSession -and (-not $allSess) -and $p.SessionId -ne $ownSid) { continue }
        if ((-not $all) -and [string]::IsNullOrEmpty($p.MainWindowTitle)) { continue }
        if ($flt -and ($p.ProcessName -notlike "*$flt*") -and ($p.MainWindowTitle -notlike "*$flt*")) { continue }
        $reag = '-'
        if (-not [string]::IsNullOrEmpty($p.MainWindowTitle)) {
            $reag = 'NEIN'
            if ($p.Responding) { $reag = 'JA' }
        }
        [pscustomobject]@{
            PID      = $p.Id
            Session  = $p.SessionId
            Name     = $p.ProcessName
            Titel    = $p.MainWindowTitle
            Reagiert = $reag
            RamMB    = [math]::Round($p.WorkingSet64 / 1MB, 0)
            Start    = $(try { $p.StartTime.ToString('dd.MM. HH:mm:ss') } catch { '' })
        }
    }
    $C.dgProcs.ItemsSource = @($rows)
}

function Start-DiagCaptureGui {
    param([int]$CapturePid = 0, [string]$Trigger = 'Manuell', [string]$CaptureProcName = '',
          [string]$TriggerTyp = 'Manuell', [hashtable]$CrashInfo = $null)
    if ($Gui.Busy) { Add-GuiLog 'Capture laeuft bereits - Anforderung verworfen.'; return }
    $hours = 72
    [void][int]::TryParse($C.txtHours.Text, [ref]$hours)
    if ($hours -lt 1 -or $hours -gt 720) { $hours = 72; $C.txtHours.Text = '72' }
    $outRoot = $C.txtOut.Text
    if ([string]::IsNullOrWhiteSpace($outRoot)) { $outRoot = Join-Path $env:USERPROFILE 'Documents\AppHangDiag'; $C.txtOut.Text = $outRoot }
    if (-not (Test-Path -LiteralPath $outRoot)) { New-Item -ItemType Directory -Path $outRoot -Force | Out-Null }

    $tpid = $null
    if ($CapturePid -gt 0) { $tpid = $CapturePid }
    $opts = @{
        Version     = $Script:AppVersion
        Trigger     = $Trigger
        IsAdmin     = $Script:IsAdmin
        TargetPid   = $tpid
        Hours       = $hours
        IncludeEvtx = [bool]$C.chkEvtx.IsChecked
        IncludeAppLogs = [bool]$C.chkAppLogs.IsChecked
        AppProfile  = $(if ($CaptureProcName) { Get-AppProfileForProcess -ProcessName $CaptureProcName } else { $null })
        Platform    = $Script:Platform
        TriggerTyp  = $TriggerTyp
        PerfHistory = @($Gui.PerfBuffer.ToArray())
        LagMs       = $Gui.LagMs
        CrashInfo   = $CrashInfo
        DoDump      = ([bool]$C.chkDump.IsChecked -and $null -ne $Script:ProcDumpExe -and $null -ne $tpid)
        ProcDumpExe = $Script:ProcDumpExe
        OutputRoot  = $outRoot
        LogQueue    = $LogQueue
    }

    $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    foreach ($fn in $Script:LibFunctions) {
        $def = (Get-Content -Path "function:\$fn" -ErrorAction Stop).ToString()
        $entry = New-Object System.Management.Automation.Runspaces.SessionStateFunctionEntry($fn, $def)
        $iss.Commands.Add($entry)
    }
    $rs = [runspacefactory]::CreateRunspace($iss)
    $rs.Open()
    $ps = [powershell]::Create()
    $ps.Runspace = $rs
    [void]$ps.AddScript({ param($o) Invoke-FullCapture -Options $o }).AddArgument($opts)

    $Gui.PS = $ps; $Gui.RS = $rs
    $Gui.Handle = $ps.BeginInvoke()
    $Gui.Busy = $true
    $C.lblBusy.Text = "Capture laeuft... ($Trigger)"
    Set-ActionButtons $false
    $pidTxt = '-'
    if ($tpid) { $pidTxt = $tpid }
    if ($opts.AppProfile) { Add-GuiLog "App-Profil erkannt: $(@($opts.AppProfile.Namen) -join ', ')" }
    Add-GuiLog "Capture gestartet (Trigger: $Trigger, PID: $pidTxt)."
}

function Stop-Monitor {
    $monTimer.Stop()
    if ($Gui.Watchdog) {
        try { if (-not $Gui.Watchdog.HasExited) { $Gui.Watchdog.Kill() } } catch { }
        $Gui.Watchdog = $null
        Add-GuiLog 'Crash-Watchdog (ProcDump) beendet.'
    }
    if ($Gui.Episodes.Count -gt 0) {
        try {
            $sess = [pscustomobject]@{
                Tool     = 'AppHangDiag'
                Version  = $Script:AppVersion
                Prozess  = $Gui.MonName
                PID      = $Gui.MonPid
                Beginn   = $Gui.MonStartZeit
                Ende     = (Get-Date).ToString('s')
                Episoden = @($Gui.Episodes.ToArray())
            }
            $sessDir = $C.txtOut.Text
            if (-not (Test-Path -LiteralPath $sessDir)) { New-Item -ItemType Directory -Path $sessDir -Force | Out-Null }
            $sp = Join-Path $sessDir ('session_{0}.json' -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
            [System.IO.File]::WriteAllText($sp, ($sess | ConvertTo-Json -Depth 5), (New-Object System.Text.UTF8Encoding($false)))
            Add-GuiLog "Sitzungsprotokoll geschrieben: $sp ($($Gui.Episodes.Count) Episode(n))."
        } catch { Add-GuiLog "Sitzungsprotokoll konnte nicht geschrieben werden: $($_.Exception.Message)" }
        $Gui.Episodes.Clear()
    }
    $Gui.MonPid = 0; $Gui.MonProc = $null; $Gui.HangSec = 0; $Gui.EpisodeCaptured = $false
    $Gui.LagSec = 0; $Gui.LagPolls = 0; $Gui.LagCaptured = $false; $Gui.LastCpuMs = -1.0
    $C.btnMonStart.IsEnabled = $true
    $C.btnMonStop.IsEnabled  = $false
    $C.lblMonStatus.Text = 'inaktiv'
    $C.lblMonStatus.Foreground = [System.Windows.Media.Brushes]::Black
}

# --- Timer: GUI-Log-Drain + Capture-Abschluss ---
$uiTimer = New-Object System.Windows.Threading.DispatcherTimer
$uiTimer.Interval = [TimeSpan]::FromMilliseconds(400)
$uiTimer.Add_Tick({
    while ($LogQueue.Count -gt 0) {
        $line = $LogQueue[0]
        $LogQueue.RemoveAt(0)
        Add-GuiLog $line -Raw
    }
    if ($Gui.Busy -and $Gui.Handle -and $Gui.Handle.IsCompleted) {
        try {
            $out = $Gui.PS.EndInvoke($Gui.Handle)
            foreach ($r in @($out)) {
                Add-GuiLog "Ergebnis-Ordner: $($r.Ordner)"
                if ($r.Zip) { Add-GuiLog "Export-ZIP:      $($r.Zip)" }
                foreach ($b in @($r.Befunde)) { Add-GuiLog "  Befund: $b" }
            }
            foreach ($e in @($Gui.PS.Streams.Error)) { Add-GuiLog "FEHLER: $e" }
        } catch {
            Add-GuiLog "FEHLER im Capture: $($_.Exception.Message)"
        } finally {
            try { $Gui.PS.Dispose() } catch { }
            try { if ($Gui.RS) { $Gui.RS.Dispose() } } catch { }
            $Gui.PS = $null; $Gui.RS = $null; $Gui.Handle = $null; $Gui.Busy = $false
            $C.lblBusy.Text = 'Bereit'
            Set-ActionButtons $true
        }
    }
})

# --- Timer: Monitor-Modus ---
$monTimer = New-Object System.Windows.Threading.DispatcherTimer
$monTimer.Interval = [TimeSpan]::FromSeconds(2)
$monTimer.Add_Tick({
    $mpid = $Gui.MonPid
    if (-not $mpid) { return }
    $ivl = $monTimer.Interval.TotalSeconds
    $p = $null
    try { $p = Get-Process -Id $mpid -ErrorAction Stop } catch { }
    if (-not $p) {
        # Prozess-Ende: ExitCode/ExitZeit vom gehaltenen Prozessobjekt lesen (Crash-Erkennung)
        $exitCode = $null; $exitZeit = $null
        if ($Gui.MonProc) {
            try { $Gui.MonProc.Refresh() } catch { }
            try {
                if ($Gui.MonProc.HasExited) {
                    $exitCode = $Gui.MonProc.ExitCode
                    $exitZeit = $Gui.MonProc.ExitTime.ToString('s')
                }
            } catch { }
        }
        $hexTxt = 'nicht lesbar'
        if ($null -ne $exitCode) { $hexTxt = ('0x{0:x8}' -f $exitCode) }
        Add-GuiLog "Monitor: Prozess $($Gui.MonName) (PID $mpid) wurde beendet. ExitCode: $hexTxt"
        [void]$Gui.Episodes.Add([pscustomobject]@{
            Typ = 'Crash/ProzessEnde'; Zeit = (Get-Date).ToString('s'); DauerS = $null; Detail = "ExitCode $hexTxt"
        })
        $ci = @{ ProzessName = $Gui.MonName; LetztePid = $mpid; ExitCode = $exitCode; ExitCodeHex = $hexTxt; ExitZeit = $exitZeit }
        Add-GuiLog 'Monitor: Erfasse Crash-Capture (ExitCode-Dekodierung, Event-/WER-/Dump-Korrelation).'
        Start-DiagCaptureGui -CaptureProcName $Gui.MonName -Trigger 'Monitor (Crash/Prozess-Ende)' -TriggerTyp 'Crash' -CrashInfo $ci
        Stop-Monitor
        $C.lblMonStatus.Text = 'Prozess beendet'
        return
    }
    $p.Refresh()

    # Perf-Sample je Tick (Ringpuffer, max. 1800 Eintraege = 1 h bei 2-s-Intervall)
    $lat = Get-UiLatencyMs -TargetPid $mpid
    $cpuMs = 0.0
    try { if ($p.TotalProcessorTime) { $cpuMs = $p.TotalProcessorTime.TotalMilliseconds } } catch { }
    $cpuPct = $null
    if ($Gui.LastCpuMs -ge 0 -and $ivl -gt 0) {
        $cpuPct = [math]::Round((($cpuMs - $Gui.LastCpuMs) / 1000.0) / [Environment]::ProcessorCount * 100.0 / $ivl, 1)
        if ($cpuPct -lt 0) { $cpuPct = 0 }
    }
    $Gui.LastCpuMs = $cpuMs
    [void]$Gui.PerfBuffer.Add([pscustomobject]@{
        Zeit       = (Get-Date).ToString('s')
        UiLatenzMs = $lat
        CpuProzent = $cpuPct
        RamMB      = [math]::Round($p.WorkingSet64 / 1MB, 0)
        PrivateMB  = [math]::Round($p.PrivateMemorySize64 / 1MB, 0)
        Handles    = $p.HandleCount
        Threads    = $p.Threads.Count
    })
    if ($Gui.PerfBuffer.Count -gt 1800) { $Gui.PerfBuffer.RemoveAt(0) }

    if (-not $p.Responding) {
        $Gui.HangSec = $Gui.HangSec + $ivl
        $Gui.LagSec = 0; $Gui.LagPolls = 0
        $C.lblMonStatus.Text = ('HAENGT seit {0:0} s - {1} (PID {2})' -f $Gui.HangSec, $Gui.MonName, $mpid)
        $C.lblMonStatus.Foreground = [System.Windows.Media.Brushes]::Red
        if ($Gui.HangSec -ge $Gui.Threshold -and -not $Gui.EpisodeCaptured) {
            $Gui.EpisodeCaptured = $true
            [void]$Gui.Episodes.Add([pscustomobject]@{
                Typ = 'Hang'; Zeit = (Get-Date).ToString('s'); DauerS = [math]::Round($Gui.HangSec, 0); Detail = 'Responding=false'
            })
            Add-GuiLog ('Monitor: Hang-Schwelle erreicht ({0} s) - Auto-Capture wird ausgeloest.' -f $Gui.Threshold)
            Start-DiagCaptureGui -CapturePid $mpid -CaptureProcName $Gui.MonName -Trigger 'Monitor (Hang)' -TriggerTyp 'Hang'
        }
    } else {
        if ($Gui.HangSec -gt 0) {
            Add-GuiLog ('Monitor: {0} wieder reaktionsfaehig (Hang-Dauer ~{1:0} s).' -f $Gui.MonName, $Gui.HangSec)
        }
        $Gui.HangSec = 0
        $Gui.EpisodeCaptured = $false
        # Lag-Pruefung: UI-Latenz >= Schwelle (oder Timeout -1) ueber 3 aufeinanderfolgende Polls
        if ($null -ne $lat -and ($lat -lt 0 -or $lat -ge $Gui.LagMs)) {
            $Gui.LagSec = $Gui.LagSec + $ivl
            $Gui.LagPolls = $Gui.LagPolls + 1
            $latTxt = 'Timeout'
            if ($lat -ge 0) { $latTxt = "$lat ms" }
            $C.lblMonStatus.Text = ('LAG {0} - {1} (PID {2})' -f $latTxt, $Gui.MonName, $mpid)
            $C.lblMonStatus.Foreground = [System.Windows.Media.Brushes]::DarkOrange
            if ($Gui.LagPolls -ge 3 -and -not $Gui.LagCaptured) {
                $Gui.LagCaptured = $true
                [void]$Gui.Episodes.Add([pscustomobject]@{
                    Typ = 'Lag'; Zeit = (Get-Date).ToString('s'); DauerS = [math]::Round($Gui.LagSec, 0); Detail = "UI-Latenz $latTxt (Schwelle $($Gui.LagMs) ms)"
                })
                Add-GuiLog ('Monitor: UI-Latenz {0} >= Schwelle {1} ms ueber {2} Polls - Lag-Capture wird ausgeloest.' -f $latTxt, $Gui.LagMs, $Gui.LagPolls)
                Start-DiagCaptureGui -CapturePid $mpid -CaptureProcName $Gui.MonName -Trigger 'Monitor (Lag)' -TriggerTyp 'Lag'
            }
        } else {
            if ($Gui.LagSec -gt 0) {
                Add-GuiLog ('Monitor: {0} UI-Latenz wieder normal (Lag-Dauer ~{1:0} s).' -f $Gui.MonName, $Gui.LagSec)
            }
            $Gui.LagSec = 0; $Gui.LagPolls = 0; $Gui.LagCaptured = $false
            $C.lblMonStatus.Text = ('ueberwacht {0} (PID {1}) - OK' -f $Gui.MonName, $mpid)
            $C.lblMonStatus.Foreground = [System.Windows.Media.Brushes]::DarkGreen
        }
    }
})

# --- Event-Verdrahtung ---
$C.btnRefresh.Add_Click({ Update-ProcessList })
$C.chkAllProcs.Add_Click({ Update-ProcessList })
$C.txtFilter.Add_TextChanged({ Update-ProcessList })

$C.btnBrowse.Add_Click({
    $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
    $dlg.Description = 'Ausgabeordner fuer AppHangDiag waehlen'
    if (Test-Path -LiteralPath $C.txtOut.Text) { $dlg.SelectedPath = $C.txtOut.Text }
    if ($dlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { $C.txtOut.Text = $dlg.SelectedPath }
})

$C.btnOpenOut.Add_Click({
    $o = $C.txtOut.Text
    if (-not (Test-Path -LiteralPath $o)) { New-Item -ItemType Directory -Path $o -Force | Out-Null }
    Start-Process explorer.exe $o
})

$C.btnSysSnap.Add_Click({ Start-DiagCaptureGui -Trigger 'Manuell (System)' })

$C.btnProcSnap.Add_Click({
    $sel = $C.dgProcs.SelectedItem
    if (-not $sel) { Add-GuiLog 'Bitte zuerst einen Prozess in der Liste auswaehlen.'; return }
    Start-DiagCaptureGui -CapturePid ([int]$sel.PID) -CaptureProcName $sel.Name -Trigger "Manuell (Prozess $($sel.Name))"
})

$C.btnMonStart.Add_Click({
    $sel = $C.dgProcs.SelectedItem
    if (-not $sel) { Add-GuiLog 'Monitor: Bitte zuerst einen Prozess in der Liste auswaehlen.'; return }
    $poll = 2
    [void][int]::TryParse($C.txtPoll.Text, [ref]$poll)
    if ($poll -lt 1) { $poll = 2; $C.txtPoll.Text = '2' }
    $th = 10
    [void][int]::TryParse($C.txtThresh.Text, [ref]$th)
    if ($th -lt $poll) { $th = $poll; $C.txtThresh.Text = "$th" }
    $lagMs = 500
    [void][int]::TryParse($C.txtLagMs.Text, [ref]$lagMs)
    if ($lagMs -lt 100) { $lagMs = 500; $C.txtLagMs.Text = '500' }
    $Gui.MonPid = [int]$sel.PID
    $Gui.MonName = $sel.Name
    $Gui.MonProc = $null
    try { $Gui.MonProc = Get-Process -Id $Gui.MonPid -ErrorAction Stop } catch { }
    $Gui.MonStartZeit = (Get-Date).ToString('s')
    $Gui.Threshold = $th
    $Gui.LagMs = $lagMs
    $Gui.HangSec = 0
    $Gui.EpisodeCaptured = $false
    $Gui.LagSec = 0; $Gui.LagPolls = 0; $Gui.LagCaptured = $false; $Gui.LastCpuMs = -1.0
    $Gui.PerfBuffer.Clear()
    $Gui.Episodes.Clear()
    # Crash-Watchdog (opt-in): ProcDump haengt sich als Debugger an und schreibt bei unbehandelter
    # Second-Chance-Exception (-e) bzw. Fenster-Hang (-h) automatisch einen Dump ins Ausgabeziel
    if ([bool]$C.chkWatchdog.IsChecked -and $Script:ProcDumpExe) {
        try {
            $wdDir = $C.txtOut.Text
            if (-not (Test-Path -LiteralPath $wdDir)) { New-Item -ItemType Directory -Path $wdDir -Force | Out-Null }
            $wdArgs = @('-accepteula', '-ma', '-e', '-h', '-t', "$($Gui.MonPid)", $wdDir)
            $Gui.Watchdog = Start-Process -FilePath $Script:ProcDumpExe -ArgumentList $wdArgs -WindowStyle Hidden -PassThru
            Add-GuiLog ('Crash-Watchdog: ProcDump als Debugger an PID {0} angehaengt (EDR-sichtbar; belegt den Debugger-Slot). Dumps -> {1}' -f $Gui.MonPid, $wdDir)
        } catch {
            $Gui.Watchdog = $null
            Add-GuiLog "Crash-Watchdog konnte nicht gestartet werden: $($_.Exception.Message)"
        }
    }
    $monTimer.Interval = [TimeSpan]::FromSeconds($poll)
    $monTimer.Start()
    $C.btnMonStart.IsEnabled = $false
    $C.btnMonStop.IsEnabled  = $true
    $C.lblMonStatus.Text = ('ueberwacht {0} (PID {1})' -f $Gui.MonName, $Gui.MonPid)
    $C.lblMonStatus.Foreground = [System.Windows.Media.Brushes]::DarkGreen
    Add-GuiLog ('Monitor gestartet: {0} (PID {1}), Intervall {2} s, Hang-Schwelle {3} s, Lag-Schwelle {4} ms.' -f $Gui.MonName, $Gui.MonPid, $poll, $th, $lagMs)
})

$C.btnMonStop.Add_Click({
    Stop-Monitor
    Add-GuiLog 'Monitor gestoppt.'
})

$window.Add_Closing({
    try { $monTimer.Stop() } catch { }
    try { $uiTimer.Stop() } catch { }
    if ($Gui.Busy -and $Gui.PS) { try { $Gui.PS.Stop() } catch { } }
})

# --- Initialisierung ---
$C.txtOut.Text = $OutputRoot
if ($Script:ProcDumpExe) {
    $C.lblProcDump.Text = "ProcDump: $(Split-Path $Script:ProcDumpExe -Leaf) gefunden"
    $C.chkDump.IsChecked = $true
} else {
    $C.lblProcDump.Text = 'ProcDump: nicht gefunden (procdump64.exe neben das Skript legen)'
    $C.chkDump.IsEnabled = $false
    $C.chkDump.Content = 'ProcDump-Dump (procdump fehlt)'
}
if ($Script:IsAdmin) {
    $C.lblAdmin.Text = 'Administrator: ja'
} else {
    $C.lblAdmin.Text = 'Administrator: nein (Modul-/Dump-Zugriff ggf. eingeschraenkt)'
}
$C.lblPlatform.Text = "Plattform: $($Script:Platform.PlatformProfil)"
$window.Title = $window.Title + " [$($Script:Platform.PlatformProfil)]"
if (-not $Script:ProcDumpExe) {
    $C.chkWatchdog.IsEnabled = $false
    $C.chkWatchdog.Content = 'Crash-Watchdog (procdump fehlt)'
}
if ($Script:Platform.IstMultiSession) {
    $C.chkAllSessions.IsEnabled = $Script:IsAdmin
    if (-not $Script:IsAdmin) { $C.chkAllSessions.Content = 'Alle Sitzungen (Admin erforderlich)' }
    $C.chkAllSessions.Add_Click({ Update-ProcessList })
} else {
    $C.chkAllSessions.Visibility = [System.Windows.Visibility]::Collapsed
}

Add-GuiLog "AppHangDiag v$($Script:AppVersion) gestartet. Ausgabe: $OutputRoot"
Add-GuiLog "Plattform: $($Script:Platform.PlatformProfil) | $($Script:Platform.OSCaption)"
if ($Script:Platform.IstMultiSession) { Add-GuiLog 'Multi-Session: Prozessliste zeigt nur die eigene Sitzung (Checkbox "Alle Sitzungen" fuer Gesamtsicht, Admin).' }
if (-not $Script:IsAdmin) { Add-GuiLog 'Hinweis: Ohne Adminrechte sind Modul-Listen/Dumps fremder Prozesse ggf. nicht lesbar.' }
Add-GuiLog 'Prozess auswaehlen und Snapshot ausloesen - oder Monitor-Modus fuer Auto-Capture bei Hang/Lag/Crash starten.'

Update-ProcessList
$uiTimer.Start()
[void]$window.ShowDialog()
#endregion GUI
