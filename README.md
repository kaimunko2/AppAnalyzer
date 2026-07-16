# AppHangDiag – Dokumentation

| | |
|---|---|
| **Anwendung** | AppHangDiag.ps1 |
| **Version** | 1.3.2 |
| **Doku-Stand** | 2026-07-16 (synchron zu Skript v1.3.2) |
| **Zweck** | Diagnose-Sammlung bei Anwendungshängern, Lags und Abstürzen – zur direkten Analyse und nachgelagerten KI-Analyse per Exportpaket |
| **Zielplattform** | Windows 11 Enterprise (22H2–24H2) **und** Citrix-Terminalserver / RDSH auf Windows Server (plattform-adaptiv, M0); Windows PowerShell 5.1 (WPF), kompatibel zu PowerShell 7 |
| **Abhängigkeiten** | Keine Pflicht-Abhängigkeiten. Optional: Sysinternals ProcDump im Skriptverzeichnis (Dump + Crash-Watchdog), `AppHangDiag.profiles.json` für eigene App-Profile |

---

## 1. Überblick

AppHangDiag erfasst bei einem Anwendungshänger (App-Freeze), bei spürbaren Lags oder bei einem Absturz in einem Durchlauf alle relevanten Diagnosedaten: Systemzustand, Eventlogs, WER-/Reliability-Historie, Prozessdetails inkl. Modulliste, Prozessbaum, TCP-Verbindungen mit Latenzmessung, Sitzungskontext (Citrix/ICA inkl. HDX-Metriken), Ressourcen-Momentaufnahme, Software-Änderungshistorie sowie optional einen Prozess-Volldump, EVTX-Rohlogs und App-Logdateien.

Neu in v1.3:

- **Plattform-adaptiv (M0):** Das Skript erkennt beim Start, ob es auf einem **Client**, einer **VDI** (Single-Session-VDA), einem **Citrix-Terminalserver** (Multi-Session-VDA), einem **RDSH** oder einem generischen **Server** läuft, und passt Prozessliste, Ressourcenerfassung, Ausgabeziel und KI-Analyseauftrag entsprechend an.
- **Lag-Erfassung:** UI-Latenzmessung per `SendMessageTimeout` (Message-Loop-Antwortzeit), Lag-Episoden mit eigener Schwelle und Auto-Capture – erfasst das reale Feldproblem „App ruckelt/verzögert, hängt aber nicht komplett".
- **Crash-Erfassung:** Endet der überwachte Prozess, wird der ExitCode vom gehaltenen Prozessobjekt gelesen, als NTSTATUS dekodiert und ein Capture mit Ereignis-/WER-/Dump-Korrelation ausgelöst. Optionaler **ProcDump-Crash-Watchdog** (opt-in) liefert dabei den vollwertigen Crash-Dump.
- **Leistungsverlauf:** Der Monitor sammelt je Poll ein Perf-Sample (UI-Latenz, CPU %, RAM, Private Bytes, Handles, Threads) in einen Ringpuffer; jedes Capture erhält den Verlauf inkl. Aggregat (min/Mittel/p95/max) und Trend-Heuristiken (Memory-/Handle-Leak, Single-Thread-Bottleneck).
- **Citrix-UPM-/Profilcontainer-Diagnose (M9):** UPM-Dienst/Konfiguration, gemountete Container-VHDX (Pfad, Größe, **freier Platz**), Profil-Fileserver-Latenz, UPM-Events und UPM-Logs – read-only.

Für die Anwendungsfamilien **Office/Outlook, Teams (new) und Nexus KIS** aktiviert das Profil-Framework (M8) automatisch anwendungsspezifische Zusatzerfassung. Das Ergebnis wird als strukturiertes JSON, als KI-lesbare Markdown-Zusammenfassung mit vorangestelltem, trigger- und plattformadaptivem Analyseauftrag und als ZIP-Paket abgelegt.

## 2. Betriebsmodi

| Modus | Start | Beschreibung |
|---|---|---|
| **GUI** (Standard) | `.\AppHangDiag.ps1` | WPF-Oberfläche mit Prozessauswahl, System-/Prozess-Snapshot, Monitor-Modus (Hang/Lag/Crash), Optionen und Live-Protokoll. Capture läuft in separatem Runspace – GUI bleibt bedienbar. |
| **CLI** | `.\AppHangDiag.ps1 -Snapshot [...]` | Headless-Erfassung für Automation/Remote (Intune, ServiceNow, PSRemoting). Ausgabe ins Konsolen-Log. Lag-/Crash-Monitor und Watchdog sind GUI-Funktionen. |

### CLI-Parameter

| Parameter | Typ | Default | Beschreibung |
|---|---|---|---|
| `-Snapshot` | Switch | – | Aktiviert den CLI-Modus (ohne GUI) |
| `-ProcessName` | String | – | Prozessname ohne `.exe`; bei Mehrfachinstanzen wird die erste PID verwendet (Warnung im Log) |
| `-TargetPid` | Int | 0 | Prozess-ID; hat Vorrang vor `-ProcessName` |
| `-IncludeEvtx` | Switch | aus | EVTX-Rohexport (Application/System) ins Paket aufnehmen |
| `-IncludeAppLogs` | Switch | aus | App-Logdateien gemäß App-Profil einsammeln; auf UPM-Systemen zusätzlich UPM-Logs. Limits: max. 5 Dateien je Pfad, 5 MB je Datei, 25 MB gesamt; Ablage unter `AppLogs\` |
| `-Dump` | Switch | aus | ProcDump-Volldump (`-ma`), sofern ProcDump vorhanden und Zielprozess gesetzt |
| `-EventWindowHours` | Int (1–720) | 72 | Zeitfenster für Event-/WER-/Reliability-Auswertung |
| `-OutputRoot` | String | plattformabhängig | Ausgabeverzeichnis. **Client:** `Dokumente\AppHangDiag`. **Multi-Session** (Terminalserver/RDSH): automatisch `%LOCALAPPDATA%\Temp\AppHangDiag` (UPM-Standard-Exclusion – vermeidet VHDX-Wachstum und SMB-Last im Containerprofil), sofern nicht explizit gesetzt. Bei UNC-/Profilpfaden auf Multi-Session erfolgt eine Warnung. |

### Beispiele

```powershell
.\AppHangDiag.ps1                                                  # GUI
.\AppHangDiag.ps1 -Snapshot -ProcessName outlook -IncludeEvtx -IncludeAppLogs
.\AppHangDiag.ps1 -Snapshot -TargetPid 4711 -Dump -EventWindowHours 24
powershell.exe -ExecutionPolicy Bypass -File .\AppHangDiag.ps1 -Snapshot
```

## 3. GUI

| Bereich | Funktion |
|---|---|
| **Optionen** | App-Logs sammeln (Profil), EVTX-Rohexport, ProcDump-Dump, **Crash-Watchdog (ProcDump -e)** (opt-in, Default AUS), Event-Zeitfenster (h), Ausgabeordner inkl. Ordnerauswahl |
| **Prozessauswahl** | DataGrid mit PID, **Session**, Prozess, Fenstertitel, Reagiert (JA/NEIN, rot bei NEIN), RAM, Startzeit. Default: nur Prozesse mit Fenster; Checkbox „Alle Prozesse"; Live-Filter auf Name/Titel. **Multi-Session:** Liste zeigt per Default nur die **eigene Sitzung**; Checkbox „Alle Sitzungen" (nur mit Adminrechten aktiv) für die Gesamtsicht – verhindert Fremd-User-Einsicht und versehentliche Fremd-Session-Dumps. |
| **Aktionen** | System-Snapshot (ohne Prozessbezug), Prozess-Snapshot (ausgewählte Zeile), Ausgabeordner öffnen |
| **Monitor-Modus** | Intervall (s), Hang-Schwelle (s), **Lag-Schwelle (ms, Default 500)**, Start/Stopp, Statusanzeige (grün OK / orange LAG / rot HÄNGT) |
| **Protokoll** | Live-Log (dunkel, Consolas), Längenbegrenzung 400.000 Zeichen |
| **Statusbar** | ProcDump-Erkennungsstatus, Administrator-Status, **Plattformprofil**, Capture-Status; Plattformprofil zusätzlich im Fenstertitel |

Beim Prozess-Snapshot und im Monitor-Modus wird der Prozessname gegen die App-Profile aufgelöst; ein Treffer wird im Protokoll gemeldet. Während eines laufenden Captures sind die Snapshot-Buttons gesperrt (Busy-Guard); parallele Captures werden verworfen und protokolliert.

## 4. Monitor-Modus (Hang / Lag / Crash)

Pollt den ausgewählten Prozess im konfigurierten Intervall (Default 2 s) und erfasst dabei je Tick ein **Perf-Sample** (UI-Latenz via `SendMessageTimeout`, CPU %-Delta, RAM, Private Bytes, Handles, Threads) in einen Ringpuffer (max. 1800 Samples ≈ 1 h bei 2 s). Das Sampling ist an das Monitor-Intervall gekoppelt; die Eigenlast ist minimal (nur Zielprozess-Metriken, keine Get-Counter-Aufrufe je Tick).

**Zustandslogik (Priorität Hang > Lag):**

1. **Hang:** `Responding = false` → Hang-Sekunden akkumulieren, Status rot. Hang-Dauer ≥ Schwelle (Default 10 s) → **einmaliges** Auto-Capture (`TriggerTyp = Hang`; Dump zuerst, solange der Prozess hängt). Prozess reagiert wieder → Log mit Hang-Dauer, Re-Arm.
2. **Lag:** Prozess reagiert, aber UI-Latenz ≥ Lag-Schwelle (oder Timeout) über **3 aufeinanderfolgende Polls** → einmaliges Auto-Capture (`TriggerTyp = Lag`), Status orange. Latenz wieder normal → Log mit Lag-Dauer, Re-Arm.
3. **Crash/Prozess-Ende:** Prozess verschwindet → **ExitCode/ExitZeit** werden vom beim Monitor-Start gehaltenen Prozessobjekt gelesen, NTSTATUS-dekodiert und ein Capture mit `TriggerTyp = Crash` inkl. Korrelation ausgelöst (1000/1001/1002-Events der exe aus den letzten 15 min, WER-Reports, frische Watchdog-Dumps aus dem Ausgabeziel werden in den Capture-Ordner übernommen). Monitor stoppt.
4. **Sitzungs-/Episodenprotokoll:** Jede Episode (Hang/Lag/Crash) wird mit Zeit, Dauer und Detail protokolliert; beim Monitor-Stopp wird `session_<ts>.json` in das Ausgabeziel geschrieben (Prozess, PID, Zeitraum, Episodenliste) – belegt Häufung und zeitliche Muster über die gesamte Beobachtung.

**Crash-Watchdog (opt-in):** Bei aktivierter Checkbox und vorhandenem ProcDump wird beim Monitor-Start `procdump -accepteula -ma -e -h -t <PID> <Ausgabeziel>` gestartet: ProcDump hängt sich als **Debugger** an und schreibt bei unbehandelter Second-Chance-Exception (`-e`), Fenster-Hang (`-h`) oder Prozessende (`-t`) automatisch einen Volldump. Beim Monitor-Stopp wird der Watchdog beendet. Hinweise: Debugger-Attach ist **EDR-sichtbar** und belegt den (einzigen) Debugger-Slot des Prozesses – kein paralleler Visual-Studio-/WinDbg-Attach möglich. Default AUS; Klartext-Hinweis im Protokoll.

Hinweis: `Responding` und UI-Latenz sind nur für Prozesse mit Message-Loop (Fenster) aussagekräftig; ohne Fenster liefert die Latenzmessung `null` (kein Lag-Trigger).

## 5. Erfassungsmodule

| Modul | Inhalt | Quelle |
|---|---|---|
| **M0 Plattform** *(neu)* | Klassifikation **Client / VDI (Citrix Single-Session-VDA) / TerminalServer (Citrix Multi-Session-VDA) / TerminalServer (RDSH) / Server** aus `ProductType`, `EditionID` (`ServerRdsh` = Win 10/11 multi-session), `TSAppCompat` und VDA-Diensten (`BrokerAgent`, `picaSvc2`, `porticaservice`). Läuft einmalig beim Start in der Hauptsession; Ergebnis in Statusbar/Fenstertitel, `Meta.PlattformProfil`, Knoten `Plattform` und im KI-Analyseauftrag | CIM, Registry, `Get-Service` |
| **M1 System** | OS/Build/DisplayVersion, Modell, CPU/RAM inkl. freiem RAM %, Uptime/letzter Start, PendingReboot (CBS/WU/PFRO), Energieplan, GPU-Treiber | CIM, Registry, powercfg |
| **M2 Eventlogs** | Application 1000/1001/1002; System 41/129/153/7011; **OAlerts**; **UPM-Events** (Provider „Citrix Profile management", Warning/Error – Mount-/Sync-/Backoff-Probleme) im Zeitfenster. Signatur je Event: **1000er neu als `exe | fehlerhaftes Modul | Ausnahmecode`** (geparst über die Textvarianten „Name des fehlerhaften Moduls" (ältere Builds) / „Fehlerhafter Modulname" (Win 11 24H2/25H2) / „Faulting module name" (en); Basis der Crash-Gruppierung `CrashSignaturen`); WER-1001: Ereignisname + P1; OAlerts/UPM: erste Meldungszeile. Deduplizierte Ereignisgruppen; LiveKernelEvent-/BlueScreen-Zähler mit Signaturverteilung | `Get-WinEvent` FilterHashtable |
| **M3 WER/Reliability** | ReportArchive-Metadaten (ProgramData + LOCALAPPDATA, `Report.wer`-Parsing, Fallback-Kette für Store-Reports), Win32_ReliabilityRecords | Dateisystem, CIM |
| **M4 Prozess-Detail** | Pfad/Version/Produkt, Kommandozeile, Eltern/Besitzer/Session, CPU/RAM/Handles/Threads, Responding, Thread-Status + Wait-Gründe, Modulliste mit Nicht-Microsoft-Flag | `Get-Process`, Win32_Process |
| **M5 Ressourcen** | CPU gesamt, RAM verfügbar, Disk-Latenz Read/Write, Disk-Queue, Pagefile % (sprachneutral via Perflib-Indizes); Top-10 CPU (1-s-Delta) und RAM; Netzwerkprofile. **Multi-Session zusätzlich (M5b, Admin):** CPU/RAM/Prozessanzahl **aggregiert je Sitzung** (1-s-Delta, Benutzer via explorer.exe-Owner) – **nur Kennzahlen, keine Prozesslisten fremder Sessions** (Datenschutz-Entscheid) | `Get-Counter`, `Get-Process`, CIM |
| **M6 Software-Kontext** | Hotfixes + Software-Installationen der letzten 14 Tage, AV-Status, Security-/EDR-Dienste, Citrix-Workspace-Version | `Get-HotFix`, Uninstall-Keys, CIM, `Get-Service` |
| **M7 Dump** (optional) | ProcDump-Volldump `-ma` des Zielprozesses; zusätzlich Crash-Watchdog-Dumps (siehe §4/§10) | Sysinternals ProcDump |
| **M8a–M8h App-Profile** | Prozessbaum, TCP/Latenz, Office-C2R/Add-ins/Resiliency, OST/PST, Teams/WebView2, Nexus, App-Logs – unverändert zu v1.2 (siehe §6) | diverse |
| **M8c Sitzungskontext** *(erweitert)* | ICA-Sitzungserkennung (`SESSIONNAME`, Fallback: aktive `>`-Zeile aus qwinsta, falls die Variable im Startkontext fehlt), Citrix-VDA-Version, qwinsta-Übersicht, Ziel-SessionId; **neu: HDX-/ICA-Sitzungsmetriken** der eigenen Sitzung (Latency Last/Average, Input/Output Bandwidth aus dem Counter-Set „ICA Session"; nur auf VDA vorhanden, englisch registriert, tolerant ohne Warn-Rauschen). Läuft ab v1.3 **immer** (auch ohne Ziel-PID, z. B. beim Crash-Capture) | Umgebung, Registry, qwinsta, `Get-Counter` |
| **M9 Citrix UPM / Profilcontainer** *(neu)* | `ctxProfile`-Dienststatus + Version; UPM-Policy-/Konfig-Auszug (ServiceActive, PathToUserStore, Active Write Back, alle `*Container*`-Werte aus Policies- und lokalem Key); **gemountete Profilcontainer** (File-Backed Virtual Disks → VHDX-UNC-Pfad, Größe, **freier Platz GB/%** im Containervolume); Profil-Fileserver aus dem VHDX-Pfad abgeleitet mit Erreichbarkeit + ICMP-Latenz; UPM-Logs (`%SystemRoot%\System32\LogFiles\UserProfileManager`) via `-IncludeAppLogs` nach `AppLogs\CitrixUPM`. **Strikt read-only** – kein Mount/Dismount, keine VHDX-Manipulation. Läuft immer, wenn der UPM-Dienst existiert | `Get-Service`, Registry, `Get-Disk`/`Get-Volume`, `Test-Connection` |
| **Verlauf** *(neu)* | Leistungsverlauf aus dem Monitor-Ringpuffer: Rohsamples + Aggregat (min/Mittel/p95/max je Metrik), Zeitraum, Lag-Schwelle | Monitor-Sampling |
| **CrashInfo** *(neu)* | ExitCode (dezimal/hex/dekodiert), Exit-Zeit, korrelierte Events/WER-Reports (letzte 15 min), übernommene Watchdog-Dumps | Monitor + M2/M3 |

## 6. App-Profile und profiles.json

Unverändert zu v1.2: Das Profil-Framework ordnet Prozessnamen (Wildcard-Match, ohne `.exe`) einer Zusatzerfassung zu; mehrere Treffer werden vereinigt.

**Built-in-Profile:**

| Profil | Match | Collect | LogPaths |
|---|---|---|---|
| Office | winword, excel, powerpnt, onenote, msaccess, visio, mspub | Office | – |
| Outlook | outlook, olk | Office, OutlookDateien | – |
| Teams | ms-teams, msteams, teams | Teams | `%LOCALAPPDATA%\Packages\MSTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams\Logs` |
| Nexus | nexus\*, ngkis\*, kisng\*, medico\* | Nexus | – (installationsspezifisch per JSON ergänzen) |

**Überschreiben ohne Codeänderung:** Liegt eine `AppHangDiag.profiles.json` neben dem Skript, **ersetzt** sie die Built-in-Profile vollständig (Log-Hinweis; bei JSON-Fehler bleiben die Built-ins aktiv). Gültige `Collect`-Werte: `Office`, `OutlookDateien`, `Teams`, `Nexus`. Umgebungsvariablen in `LogPaths` werden expandiert.

```json
[
  { "Name": "Office",  "Match": ["winword","excel","powerpnt"], "Collect": ["Office"], "LogPaths": [] },
  { "Name": "Outlook", "Match": ["outlook","olk"], "Collect": ["Office","OutlookDateien"], "LogPaths": [] },
  { "Name": "Teams",   "Match": ["ms-teams"], "Collect": ["Teams"],
    "LogPaths": ["%LOCALAPPDATA%\\Packages\\MSTeams_8wekyb3d8bbwe\\LocalCache\\Microsoft\\MSTeams\\Logs"] },
  { "Name": "Nexus",   "Match": ["nexus*","ngkis*"], "Collect": ["Nexus"],
    "LogPaths": ["C:\\ProgramData\\Nexus\\Logs"] }
]
```

Die UPM-Log-Sammlung (M9) nutzt denselben Mechanismus intern mit dem festen Profilnamen `CitrixUPM` und ist nicht JSON-konfigurationspflichtig.

## 7. Ausgabeartefakte

```
<OutputRoot>\
├── Capture_<yyyyMMdd_HHmmss>\
│   ├── report.json          # vollständige strukturierte Rohdaten (UTF-8 ohne BOM, Depth 8)
│   ├── summary.md           # KI-lesbare Zusammenfassung mit adaptivem Analyseauftrag
│   ├── proc_<pid>_<ts>.dmp  # optional (ProcDump -ma)
│   ├── <proc>_<ts>.dmp      # optional (vom Crash-Watchdog übernommener Dump)
│   ├── Application.evtx     # optional (EVTX-Rohexport, zeitgefiltert)
│   ├── System.evtx          # optional
│   └── AppLogs\<Profil>\    # optional (App-Logs; auf UPM-Systemen zusätzlich AppLogs\CitrixUPM\)
├── session_<yyyyMMdd_HHmmss>.json             # Sitzungs-/Episodenprotokoll je Monitor-Lauf
└── AppHangDiag_<Host>_<yyyyMMdd_HHmmss>.zip   # Exportpaket
```

- **summary.md** beginnt mit einem Blockquote-KI-Analyseauftrag, der **Plattformprofil und Trigger-Typ-Fokus** enthält (Crash → ExitCode/Korrelation/Dump priorisieren; Lag → Leistungsverlauf/Ressourcen/Session-Latenz; Hang → Threads/Waits/Backend). Neue Sektionen: **Crash-Kontext** (ExitCode dekodiert, Korrelationstabelle, Watchdog-Dumps), **Citrix UPM / Profilcontainer** (Dienst, Konfig, Container-Tabelle mit freiem Platz, Fileserver-Latenz), **Leistungsverlauf** (Aggregat-Tabelle), **Sitzungen** (Multi-Session-Aggregat), HDX-Zeile im Sitzungskontext, UPM-Zähler in der Ereignisübersicht.
- **report.json** – neue Knoten: `Plattform`, `UpmContext`, `Verlauf` (inkl. `Samples`-Rohliste), `CrashInfo`; neue `Events`-Felder: `UpmEvents`, `CrashSignaturen`. `Meta` erhält `TriggerTyp` (Hang/Lag/Crash/Manuell) und `PlattformProfil`.
- **session_<ts>.json** – Prozess, PID, Beobachtungszeitraum und Episodenliste (Typ, Zeit, Dauer, Detail) eines Monitor-Laufs; wird beim Monitor-Stopp geschrieben, sobald mindestens eine Episode auftrat.
- **ZIP-Regel:** Dumps > 500 MB verbleiben nur im Capture-Ordner (Log-Hinweis); `AppLogs\` wird mit Struktur ins ZIP übernommen.
- **Datenschutz-Hinweis:** EVTX, Dumps und App-Logs enthalten Klartextdaten; App-Logs (insbesondere Nexus) können personenbezogene bzw. Patientendaten enthalten. Sammlung strikt opt-in. Session-Aggregate enthalten Benutzernamen fremder Sitzungen nur als Kennzahl und nur mit Adminrechten.

## 8. Heuristik (automatische Befunde)

Bestand aus v1.0–v1.2 unverändert (Events/System/Ressourcen/Zielprozess/Module/Änderungen/M8-Befunde). **Neu in v1.3:**

| Befund | Schwellwert/Bedingung |
|---|---|
| **Prozess-Ende/Crash** | CrashInfo vorhanden → ExitCode-Dekodierung als Befund; Hinweis auf Watchdog-Dumps mit WinDbg-Empfehlung |
| **Wiederholte Crash-Signatur** | Gleiche 1000er-Signatur (`exe | Modul | Ausnahmecode`) ≥ 3× im Zeitfenster → reproduzierbares Modul-/Add-in-Problem |
| **Memory-Leak-Verdacht** | Private Bytes des Zielprozesses wachsen ≥ 100 MB je 10 min über ≥ 5 min Beobachtung (≥ 10 Samples) |
| **Handle-Leak-Verdacht** | Handle-Zuwachs ≥ 500 **und** ≥ 30 % im Beobachtungszeitraum |
| **Single-Thread-Bottleneck** | Median der Zielprozess-CPU ≈ 100 %/LP (± 15 %) bei > 2 logischen Prozessoren |
| **UI-Latenz belegt** | p95 der UI-Latenz ≥ Lag-Schwelle |
| **Profilcontainer fast voll** | Containervolume < 5 % oder < 1 GB frei → häufige Ursache für Office-/Anmelde-Hänger |
| **UPM-Dienst gestört** | `ctxProfile` existiert, aber Status ≠ Running |
| **Profil-Fileserver** | ICMP nicht erreichbar bzw. Latenz > 20 ms (Profil-I/O über SMB verlangsamt) |
| **HDX-Latenz** | ICA-RTT > 150 ms (WARN) bzw. > 300 ms (KRITISCH) – „App hängt" kann Session-Latenz sein |
| **Noisy Neighbor** | Multi-Session: fremde Sitzung > 40 % CPU |
| **Dokumente umgeleitet** | Multi-Session und Dokumente-Ordner auf UNC → Datei-I/O über das Netz |

Ohne Treffer: expliziter Hinweis auf KI-/Detailanalyse.

## 9. ProcDump-Integration

- Erkennung ausschließlich im Skriptverzeichnis: `procdump64.exe` bevorzugt, sonst `procdump.exe`.
- **Snapshot-Dump:** `procdump -accepteula -ma <PID> <Datei>` (Volldump für Hang-Analyse, WinDbg `!analyze -v -hang`). Gefunden → GUI-Checkbox aktiv und vorausgewählt; nicht gefunden → Checkbox deaktiviert.
- **Crash-Watchdog (neu, opt-in):** `procdump -accepteula -ma -e -h -t <PID> <OutputRoot>` beim Monitor-Start; Dump bei unbehandelter Exception, Fenster-Hang oder Prozessende. Wird beim Monitor-Stopp beendet; frische Dumps werden beim Crash-Capture in den Capture-Ordner übernommen. **Governance:** Debugger-Attach ist EDR-sichtbar (ggf. mit SecOps abstimmen), belegt den Debugger-Slot des Prozesses, Default AUS.
- Bewusst **kein** comsvcs.dll-MiniDump-Fallback (EDR-Alarm-Vermeidung). ProcDump ist MS-signiert; je nach EDR-Policy dennoch Telemetrie möglich.

## 10. WER LocalDumps (manuelles Verfahren, ohne Skriptfunktion)

Für Crash-Dumps **ohne** laufenden Monitor/Watchdog (z. B. sporadische Abstürze über Nacht) bietet Windows Error Reporting persistente LocalDumps. **Bewusste Entscheidung v1.3:** Das Skript nimmt diese HKLM-Änderung **nicht** selbst vor (persistenter, systemweiter Eingriff → Change-/Governance-Prozess); das Verfahren ist hier als manuelle Anleitung dokumentiert.

Aktivieren (Beispiel Outlook, als Administrator):

```bat
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps\OUTLOOK.EXE" /v DumpFolder /t REG_EXPAND_SZ /d "C:\Dumps" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps\OUTLOOK.EXE" /v DumpType   /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps\OUTLOOK.EXE" /v DumpCount  /t REG_DWORD /d 5 /f
```

`DumpType 2` = Volldump; `DumpCount` begrenzt die Anzahl (Rotation). Deaktivieren nach Abschluss der Analyse:

```bat
reg delete "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps\OUTLOOK.EXE" /f
```

Hinweise: Wirkt für alle Benutzer des Systems (auf Terminalservern entsprechend viele potenzielle Dumps – `DumpFolder` mit ausreichend Platz außerhalb des Profils wählen); Volldumps enthalten Speicherinhalte inkl. möglicher personenbezogener Daten → Ablage und Löschung gemäß DSGVO-Prozess; Verteilung idealerweise per Intune/GPO mit befristetem Rückbau.

## 11. Architektur-Hinweise

- **Runspace-Capture (GUI):** Bibliotheksfunktionen werden per `InitialSessionState`/`SessionStateFunctionEntry` in einen Hintergrund-Runspace übernommen; Log-Rückkanal über synchronisierte ArrayList-Queue; DispatcherTimer (400 ms) drainiert das Log und schließt den Capture ab.
- **Plattform-Auflösung:** `Get-PlatformProfile` läuft einmalig in der Hauptsession (`$Script:Platform`); der Runspace erhält das Ergebnis über die Options (analog App-Profil-Auflösung).
- **UI-Latenzmessung:** P/Invoke `SendMessageTimeout` (WM_NULL, `SMTO_ABORTIFHUNG | SMTO_NOTIMEOUTIFNOTHUNG`, 5 s Timeout) via `Add-Type`, idempotent je Prozess (`PSTypeName`-Check). Rückgabe: ms, `-1` = Timeout (hängt), `null` = kein Fenster.
- **Ringpuffer:** `List[object]` mit max. 1800 Einträgen (`RemoveAt(0)` beim Überlauf); jedes Capture erhält eine **Snapshot-Kopie** (`ToArray()`) – Puffer läuft während des Captures weiter.
- **ExitCode-Lesen:** Beim Monitor-Start wird am gehaltenen `Process`-Objekt (`$Gui.MonProc`) einmalig `.Handle` berührt – .NET cached das Prozess-Handle nur dann, und nur mit gecachtem Handle sind `ExitCode`/`ExitTime` **nach** dem Prozessende lesbar (`Get-Process` hält von sich aus kein persistentes Handle; Feldfund v1.3.1). Fremde/elevierte Prozesse bleiben rechteabhängig → toleriert, Korrelation über 1000er-Events greift trotzdem.
- **Sprachneutrale Counter:** Performance-Counter-Pfade über Perflib-Indizes; Ausnahme ICA-Counter (von Citrix englisch registriert, ohne Perflib-Lokalisierung → direkte englische Pfade, tolerant).
- **Encoding:** Skript UTF-8 **mit** BOM (PS-5.1-Pflicht); Exportdateien UTF-8 ohne BOM.
- **PS-5.1-Kompatibilität:** kein Ternary/Null-Coalescing, `$TargetPid` statt reserviertem `$PID`, try/catch nur als `$()`-Subexpression.
- Dump wird **vor** allen anderen Modulen gezogen; Citrix-/UPM-Kontext läuft ab v1.3 immer (Systemebene, auch beim Crash-Capture ohne Ziel-PID).

## 12. Rechte und Einschränkungen

| Aspekt | Verhalten |
|---|---|
| Ohne Adminrechte | Modullisten/Dumps fremder Prozesse ggf. nicht lesbar; **Multi-Session:** kein Sitzungs-Aggregat (Kennzahlen fremder Sessions), Checkbox „Alle Sitzungen" deaktiviert. Statusbar-/Log-Hinweis. |
| ExitCode | Bei fremden/elevierten Prozessen ggf. nicht lesbar (`nicht lesbar` im Log/Report); Event-Korrelation liefert den Ausnahmecode dann über die 1000er-Signatur. |
| ICA-Counter | Nur auf VDA vorhanden; Fehlen wird still toleriert (`HdxMetriken = null`, kein Warn-Rauschen). |
| Get-Disk/Volume | Benötigt das Storage-Modul (auf Server-OS Standard); Fehler werden toleriert → `ContainerDisks` leer. |
| Crash-Watchdog | Belegt den Debugger-Slot (kein paralleler Debugger-Attach); EDR-sichtbar; GUI-only (kein CLI-Watchdog). |
| UI-Latenz/Lag | Nur für Fensterprozesse; Prozesse ohne Fenster liefern `null` → kein Lag-Trigger, Hang-Erkennung via `Responding` ebenfalls fensterabhängig. |
| Reliability-Records | Abhängig vom RAC-Task; kann leer sein (Warnung, kein Abbruch). |
| ICMP-Latenz | Kann durch Firewalls geblockt sein → `n/a`, kein Fehler (gilt auch für Profil-Fileserver-Latenz). |
| OAlerts-/UPM-Log | Existieren nur mit Office bzw. Citrix UPM; Fehlen wird toleriert. |
| Teams-MSIX / Resiliency | Per-User-Quellen → unter fremdem Konto (SYSTEM/Remote) ggf. leer. |
| STA | GUI erfordert STA; andernfalls Abbruch mit Hinweis `powershell.exe -STA`. |
| ExecutionPolicy | Ggf. `-ExecutionPolicy Bypass -File` bzw. Signierung gemäß Unternehmensrichtlinie. |

## 13. Changelog

| Version | Datum | Änderungen |
|---|---|---|
| 1.3.2 | 2026-07-16 | Patch nach Feldtest v1.3.1 (Crash-Pfad olk): **F4** Handle-Caching beim Monitor-Start (`$null = $Gui.MonProc.Handle`) – ohne gecachtes Handle liefert .NET `ExitCode`/`ExitTime` nach Prozessende nicht („ExitCode nicht lesbar" im Feld). Verifiziert per Vergleichstest (mit Cache: ExitCode lesbar, ohne: leer). Feldtest bestätigte im Übrigen den kompletten v1.3-Kern mit Echtdaten: Verlauf-Ringpuffer (71/93 Samples, Aggregat + Summary-Tabelle, erste UI-Latenz-Messungen 0–9 ms), Crash-Episode → `session_<ts>.json` → Crash-Capture mit TriggerTyp/FOKUS-Blockquote/Crash-Kontext-Sektion, Korrelation korrekt leer bei regulärem Prozessende. |
| 1.3.1 | 2026-07-16 | Patch nach Feldtest v1.3.0 (Win 11 Pro 25H2, Client): **F1** 1000er-Modul-Regex um Build-Variante „Fehlerhafter Modulname" (Win 11 24H2/25H2) erweitert – Crash-Signaturen enthalten wieder das fehlerhafte Modul (exe / Modul / Code). **F2** `SESSIONNAME`-Fallback in `Get-CitrixContext` über die aktive `>`-Zeile der qwinsta-Ausgabe. **F3** Resiliency-`Inhalt`-Dekodierung bereinigt auf druckbare Latin-Segmente ≥ 4 Zeichen (UTF-16-Binärheader dekodierte zuvor als CJK-Mojibake-Präfix). Feldtest bestätigte im Übrigen: Plattform-Erkennung (Client/Professional), TriggerTyp, CrashSignaturen, korrektes Null-Verhalten von UPM/HDX/Sessions auf Client, M8-Outlook-Profil inkl. Dump-Handling (293 MB < 500-MB-ZIP-Grenze). Regressionstest: Modul-Regex 3 Varianten, Mojibake-Bereinigung mit Felddaten, qwinsta-Fallback. |
| 1.3.0 | 2026-07-16 | **Plattform-Erkennung M0** (Client / VDI / TerminalServer Citrix/RDSH / Server aus ProductType, EditionID `ServerRdsh`, TSAppCompat, VDA-Diensten) mit Anzeige in Statusbar/Fenstertitel/Meta/KI-Auftrag; **Multi-Session-Anpassungen:** sitzungsgefilterte Prozessliste (Session-Spalte, eigene Sitzung als Default, „Alle Sitzungen" nur mit Admin), Sitzungs-Ressourcenaggregat M5b (CPU/RAM/Prozesse je Session, nur Kennzahlen), OutputRoot-Default `%LOCALAPPDATA%\Temp\AppHangDiag` (UPM-Exclusion) + UNC-/Profilpfad-Warnung. **Lag-Erfassung:** UI-Latenz via SendMessageTimeout (P/Invoke), Lag-Schwelle (ms) in GUI, Lag-Episoden (3 Polls, Re-Arm), Status orange. **Leistungsverlauf:** Perf-Sample je Monitor-Tick (UI-Latenz/CPU/RAM/Private/Handles/Threads), Ringpuffer 1800, `Verlauf`-Knoten mit Aggregat (min/Mittel/p95/max) + Trend-Heuristiken (RAM ≥ 100 MB/10 min, Handles ≥ 500 & ≥ 30 %, Single-Thread-Median, UI-p95). **Crash-Erfassung:** ExitCode/ExitTime vom gehaltenen Prozessobjekt, NTSTATUS-Dekodierung (`ConvertTo-NtStatusText`), Crash-Capture mit Korrelation (exe-Events 15 min, WER, Watchdog-Dump-Übernahme), `CrashInfo`-Knoten + Summary-Sektion; **1000er-Signatur** neu `exe | Modul | Ausnahmecode` (de/en) mit `CrashSignaturen`-Gruppierung + Wiederholungs-Heuristik ≥ 3×. **ProcDump-Crash-Watchdog** opt-in (`-ma -e -h -t`, GUI-Checkbox Default AUS, EDR-/Debugger-Slot-Hinweis, Kill bei Stopp). **Sitzungs-/Episodenprotokoll** `session_<ts>.json` (Hang/Lag/Crash-Episoden) + `Meta.TriggerTyp` + trigger-/plattformadaptiver KI-Analyseauftrag. **M8c:** HDX-/ICA-Sitzungsmetriken (Latency/Bandwidth, tolerant); Citrix-Kontext läuft immer. **M9 Citrix UPM/Profilcontainer** (read-only): Dienst/Version, Policy-Auszug, gemountete Container-VHDX mit freiem Platz, Fileserver-Latenz, UPM-Events in M2, UPM-Logs via `-IncludeAppLogs`. **12 neue Heuristiken** (Crash/Signatur/Leaks/Single-Thread/UI-p95/Container voll/UPM-Dienst/Fileserver/HDX/Noisy-Neighbor/Dokumente-UNC). **Entscheid:** WER-LocalDumps bewusst nur als manuelles Doku-Verfahren (§10), keine persistente HKLM-Änderung durch das Skript. Parse- (2597 Zeilen, 39 Funktionen) und Funktionstest (NTSTATUS-Decoder, Signatur-Regex de/en, PerfAggregate, 14 Mock-Befunde, alle neuen Summary-Sektionen) bestanden. |
| 1.2.0 | 2026-07-16 | M8 App-Profil-Framework (Office/Outlook/Teams/Nexus, `AppHangDiag.profiles.json`), Prozessbaum/TCP/Sitzungskontext bei Ziel-PID, OAlerts, App-Log-Sammlung opt-in, 8 neue Heuristiken, Anonymisierungsfunktion vollständig entfernt. |
| 1.1.0 | 2026-07-16 | Ereignis-Dedup mit Signaturen, WER-Parser-Fallback-Kette, LiveKernelEvent-/GPU-TDR-/BlueScreen-Heuristiken. Validiert gegen Feldtestdaten. |
| 1.0.0 | 2026-07-15 | Initialrelease: WPF-GUI, Monitor-Modus (Hang), Module M1–M7, ProcDump-Dump, EVTX-Export, Heuristik, report.json/summary.md/ZIP, CLI-Modus. |

---

*Diese Dokumentation wird bei jeder Skriptänderung mitgeführt; Versionsstand und Changelog sind synchron zum Skript zu halten.*
