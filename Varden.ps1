<#
    ===========================================================================
     Varden  -  malware scanner for Windows 10 / 11   (open, readable script)
    ===========================================================================
     This is a plain PowerShell script - you can read every line. There is no
     hidden program. It scans the places malware uses to start, hide and spy,
     and (with your permission) moves anything bad into a quarantine folder you
     can undo. Nothing is deleted permanently.

     RUN IT (pick one):
       * right-click Run-Varden.bat  ->  Run as administrator
       * or:  powershell -ExecutionPolicy Bypass -File Varden.ps1
       * or (if the owner has published it):  irm <their-link> | iex

     Removed items go to  C:\ProgramData\Varden\Quarantine  and can be
     restored from the menu. Every change is written to a log you can read.
    ===========================================================================
#>
param(
    [ValidateSet('Quick', 'Full', 'Custom', 'Menu')]
    [string]$Scan = 'Menu',
    [string]$Scope = 'Quick',
    [int]   $Minutes = 10,
    [switch]$NoUsb,
    [switch]$NoUpdate,
    [switch]$NoElevate
)

$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference    = 'SilentlyContinue'
try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch {}

# ---- make sure we are running as administrator (works for a file OR for  irm|iex ) ----
$isAdmin = $false
try { $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) } catch {}
if (-not $isAdmin -and -not $NoElevate) {
    try {
        # find my own source: a real file, or the text that was piped into iex
        $body = $null
        if ($PSCommandPath -and (Test-Path -LiteralPath $PSCommandPath)) { $body = Get-Content -LiteralPath $PSCommandPath -Raw }
        elseif ($MyInvocation.MyCommand.ScriptBlock) { $body = $MyInvocation.MyCommand.ScriptBlock.Ast.Extent.Text }
        $tmp = Join-Path $env:TEMP 'Varden.ps1'
        if ($body) { Set-Content -LiteralPath $tmp -Value $body -Encoding UTF8 }
        $target = if ($body) { $tmp } else { $PSCommandPath }
        Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList (
            "-NoProfile -ExecutionPolicy Bypass -File `"$target`" -Scan $Scan") -ErrorAction Stop
        return
    } catch {
        Write-Host "  Please allow it to run as administrator (click Yes on the prompt)." -ForegroundColor Yellow
        Start-Sleep 2
    }
}

try { $Host.UI.RawUI.WindowTitle = 'Varden' } catch {}

$SelfPath  = $PSCommandPath
$Root      = Join-Path $env:ProgramData 'Varden'
$QDir      = Join-Path $Root 'Quarantine'
$QLog      = Join-Path $Root 'quarantine-log.txt'
$ChangeLog = Join-Path $Root 'changes-log.txt'
New-Item -ItemType Directory -Force -Path $QDir | Out-Null

$Exclusions = @(@($Root, "$env:SystemDrive\SimpleMalwareScanner") | ForEach-Object { "$_".Trim().TrimEnd('\') } | Where-Object { $_ })
$script:NThreat = 0
$script:NSus    = 0
$script:FileCount = 0
$script:UseNative = $false      # pure PowerShell only - no runtime compiling
$script:ScanStart = Get-Date
$script:CurName = ''

$LogFile = Join-Path $Root 'scan-log.txt'
function Log([string]$s) { try { Add-Content -LiteralPath $LogFile -Value ("{0}  {1}" -f (Get-Date -Format 'HH:mm:ss.fff'), $s) -Encoding UTF8 } catch {} }
function B64([string]$s) { if (-not $s) { return '' }; return [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($s)) }
function Dec([string]$e){ [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($e)) }

# ---- colours ----
$script:C = @{ Dim='DarkGray'; Ok='Green'; Warn='Yellow'; Bad='Red'; Head='Cyan'; Txt='Gray'; White='White' }

# ---- live feedback while a check runs (the current line keeps updating) ----
function Emit([string]$s) { }
function Emit-Progress([int]$Pct, [string]$Text) { }
function Emit-Count {
    try {
        Write-Host ("`r   ~  {0,-34} {1,11:N0} files " -f $script:CurName, $script:FileCount) -NoNewline -ForegroundColor DarkGray
    } catch {}
}


# Folders any program can write to - where malware likes to live
$UserWritable = '(?i)\\AppData\\|\\Temp\\|\\Users\\Public\\|\\ProgramData\\|\\Downloads\\|\\Desktop\\|\\Documents\\|\\Windows\\Tasks\\|\$Recycle\.Bin'
# Command tricks used by malware (hidden window, encoded or downloaded code)
$BadCmd = (Dec 'KD9pKShccy1lKG5jfG5jb2RlZGNvbW1hbmQpP1xzK1tBLVphLXowLTkrLz1dezIwLH18ZnJvbWJhc2U2NHN0cmluZ3xcYmlleFxifGludm9rZS1leHByZXNzaW9ufGRvd25sb2Fkc3RyaW5nfGRvd25sb2FkZmlsZXxpbnZva2Utd2VicmVxdWVzdHxcYml3clxifG5ldFwud2ViY2xpZW50fFxzLXcoaW5kb3dzdHlsZSk/XHMraChpZGRlbik/XGJ8bXNodGEoXC5leGUpP1xzK1siXT8oaHR0cHxqYXZhc2NyaXB0fHZic2NyaXB0KXxyZWdzdnIzMi4rL2k6XHMqaHR0cHM/fHJ1bmRsbDMyLitqYXZhc2NyaXB0OnxiaXRzYWRtaW4uKy90cmFuc2ZlcnxjZXJ0dXRpbC4rLXVybGNhY2hlKQ==')
# File paths inside a command line
$FileInCmd = '(?i)[a-z]:\\[^"<>|*?\r\n]+?\.(exe|dll|sys|scr|pif|com|ps1|vbs|vbe|js|jse|wsf|hta|bat|cmd)(?=$|[\s",])'
# Folders not worth walking (huge caches, developer libraries)
$SkipDirs = '(?i)^(cache|code cache|gpucache|cache_data|node_modules|site-packages|__pycache__|\.git|winsxs|webcache|inetcache)$'
# Security websites malware likes to block
$SecuritySites = '(?i)(microsoft|windowsupdate|virustotal|malwarebytes|kaspersky|eset|avast|avg\.com|norton|bitdefender|mcafee|sophos|trendmicro|f-secure|hitmanpro|emsisoft)'

$StatusMap = @{ 0='Unknown'; 1='Detected'; 2='Cleaned'; 3='Quarantined'; 4='Removed'; 5='Allowed'; 6='Blocked';
                102='Quarantine failed'; 103='Remove failed'; 104='Allow failed'; 105='Abandoned'; 107='Block failed' }

# =====================================================================
#  Helpers
# =====================================================================
function Write-Log([string]$Text) { Add-Content -Path $ChangeLog -Value ("{0}  {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Text) }

function Add-Finding($Level, $Area, $Text, $Fix) {
    if ($Fix -and $Fix.Files) {
        foreach ($f in @($Fix.Files)) {
            if (-not $f) { continue }
            if ($SelfPath -and $f -eq $SelfPath) { return }                       # never report Varden itself
            foreach ($e in $Exclusions) { if ($e -and $f.StartsWith($e, [StringComparison]::OrdinalIgnoreCase)) { return } }
        }
    }
    [void]$script:Findings.Add([pscustomobject]@{ Level = $Level; Area = $Area; Text = $Text; Fix = $Fix; Result = ''; Hashes = @() })
    if ($Fix -and $Fix.Files) { foreach ($f in $Fix.Files) { if ($f) { [void]$script:Flagged.Add($f) } } }
    if ($Level -eq 'THREAT') { $script:NThreat++ } elseif ($Level -eq 'SUSPICIOUS') { $script:NSus++ }
    Emit-Count
}

function Test-Signed([string]$Path) {
    if ($script:SigCache.ContainsKey($Path)) { return $script:SigCache[$Path] }
    $ok = $false
    if ($script:UseNative -and $Path -notlike "$env:windir\*") {
        try { $ok = [MwNative]::IsSigned($Path) } catch {}
    }
    if (-not $ok) { try { $ok = ((Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop).Status -eq 'Valid') } catch {} }
    $script:SigCache[$Path] = $ok
    return $ok
}

# Looks at a command line and says why it is suspicious (if it is)
function Test-Command([string]$Cmd) {
    $res = [pscustomobject]@{ Reasons = @(); Files = @() }
    if ([string]::IsNullOrWhiteSpace($Cmd)) { return $res }
    $Cmd = [Environment]::ExpandEnvironmentVariables($Cmd)
    if ($Cmd -match $BadCmd) { $res.Reasons += 'uses a hidden, encoded or download command (common malware trick)' }
    foreach ($m in [regex]::Matches($Cmd, $FileInCmd)) {
        $f = $m.Value.Trim()
        if ($res.Files -contains $f) { continue }
        if ($f -match $UserWritable -and (Test-Path -LiteralPath $f) -and -not (Test-Signed $f)) {
            $res.Reasons += 'starts an unsigned file from a user folder'
            $res.Files   += $f
        }
    }
    $res.Reasons = @($res.Reasons | Select-Object -Unique)
    return $res
}

function Join-Why($r) { return ($r.Reasons -join '; ') }

function Get-Profiles {
    Get-ChildItem -LiteralPath "$env:SystemDrive\Users" -Directory -Force | Where-Object {
        $_.Name -notin @('Default', 'Default User', 'All Users', 'Public') -and (Test-Path -LiteralPath "$($_.FullName)\AppData")
    } | ForEach-Object { $_.FullName }
}

# HKLM + every logged-in user's registry
function Get-Hives {
    'Registry::HKEY_LOCAL_MACHINE'
    Get-ChildItem 'Registry::HKEY_USERS' | Where-Object { $_.PSChildName -match '^S-1-5-21-[\d-]+$' } |
        ForEach-Object { "Registry::HKEY_USERS\$($_.PSChildName)" }
}
function Get-UserHives { Get-Hives | Where-Object { $_ -like '*HKEY_USERS*' } }

function Get-RegValues([string]$Key) {
    $item = Get-Item -LiteralPath $Key
    if (-not $item) { return }
    foreach ($n in $item.GetValueNames()) {
        if ($n -eq '') { continue }
        [pscustomobject]@{ Key = $Key; Name = $n; Value = [string]$item.GetValue($n) }
    }
}

# (fast-engine removed - pure PowerShell only)

# Pure-PowerShell folder walker (used when the native helper is unavailable)
function Find-FilesPS([string]$Dir, [int]$Depth, [string]$Pattern) {
    $out = New-Object System.Collections.Generic.List[string]
    if ([string]::IsNullOrEmpty($Dir) -or -not (Test-Path -LiteralPath $Dir)) { return $out }
    $rx = New-Object System.Text.RegularExpressions.Regex($Pattern, 'IgnoreCase')
    $skip = New-Object System.Text.RegularExpressions.Regex($SkipDirs, 'IgnoreCase')
    $stack = New-Object System.Collections.Generic.Stack[object]
    $stack.Push(@($Dir, 0))
    while ($stack.Count -gt 0) {
        $cur = $stack.Pop(); $d = $cur[0]; $lvl = $cur[1]
        try { foreach ($f in [IO.Directory]::EnumerateFiles($d)) { $script:FileCount++; if ($rx.IsMatch($f)) { $out.Add($f) } } } catch {}
        if ($lvl -lt $Depth) {
            try {
                foreach ($s in [IO.Directory]::EnumerateDirectories($d)) {
                    if ($skip.IsMatch([IO.Path]::GetFileName($s))) { continue }
                    try { if (([IO.File]::GetAttributes($s) -band [IO.FileAttributes]::ReparsePoint) -ne 0) { continue } } catch { continue }
                    $ex = $false
                    foreach ($e in $Exclusions) { if ($e -and $s.StartsWith($e, [StringComparison]::OrdinalIgnoreCase)) { $ex = $true; break } }
                    if (-not $ex) { $stack.Push(@($s, ($lvl + 1))) }
                }
            } catch {}
        }
    }
    return $out
}

function Get-FilesFast([string]$Dir, [int]$Depth, [string]$Pattern) {
    if ($script:UseNative) {
        try { return [MwNative]::Find($Dir, $Depth, $Pattern, $SkipDirs) }
        catch { $script:UseNative = $false; Log "Native Find failed, switching to PowerShell: $($_.Exception.Message)" }
    }
    return Find-FilesPS $Dir $Depth $Pattern
}

# Checks the signatures of many files at once (parallel when native is available)
function Update-SigCache([string[]]$Paths) {
    $todo = @($Paths | Where-Object { $_ -and -not $script:SigCache.ContainsKey($_) -and $_ -notlike "$env:windir\*" } | Select-Object -Unique)
    if (-not $todo.Count) { return }
    if ($script:UseNative) {
        try {
            $res = [MwNative]::SignedMany([string[]]$todo)
            for ($i = 0; $i -lt $todo.Count; $i++) { $script:SigCache[$todo[$i]] = $res[$i] }
            return
        } catch { Log "Parallel signature check failed: $($_.Exception.Message)" }
    }
    foreach ($f in $todo) { [void](Test-Signed $f) }
}

# True if $File has an NTFS data stream called $Name (e.g. Zone.Identifier = came from the internet)
function Has-Stream([string]$File, [string]$Name) {
    if ($script:UseNative) { try { return [MwNative]::HasStream($File, $Name) } catch {} }
    try { return [bool](Get-Item -LiteralPath $File -Stream $Name -ErrorAction Stop) } catch { return $false }
}

function Resolve-Dll([string]$Name) {
    if (-not $Name) { return $null }
    try {
        $n = [Environment]::ExpandEnvironmentVariables($Name.Trim().Trim('"'))
        if ($n -notmatch '(?i)\.(dll|exe|sys)$') { $n += '.dll' }
        if ([IO.Path]::IsPathRooted($n)) { return $n }
        return (Join-Path "$env:windir\System32" $n)
    } catch { return $null }
}
function Test-BadFile([string]$Path) { return ($Path -and (Test-Path -LiteralPath $Path) -and -not (Test-Signed $Path)) }


# =====================================================================
#  Checks - startup & persistence
# =====================================================================
function Check-Autoruns {
    $runKeys = 'Software\Microsoft\Windows\CurrentVersion\Run',
               'Software\Microsoft\Windows\CurrentVersion\RunOnce',
               'Software\Microsoft\Windows\CurrentVersion\RunOnceEx',
               'Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run',
               'Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
               'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
               'Software\Microsoft\Windows\CurrentVersion\RunServices',
               'Software\Microsoft\Windows\CurrentVersion\RunServicesOnce'
    foreach ($h in Get-Hives) {
        foreach ($k in $runKeys) {
            foreach ($v in Get-RegValues "$h\$k") {
                $r = Test-Command $v.Value
                if ($r.Reasons.Count) {
                    Add-Finding 'SUSPICIOUS' 'Startup entry' ("'{0}' starts with Windows: {1}`n       Why: {2}" -f $v.Name, $v.Value, (Join-Why $r)) `
                        @{ Type = 'RegRemove'; Key = $v.Key; Name = $v.Name; Old = $v.Value; Files = $r.Files; Desc = 'Remove from startup + quarantine its file' }
                }
            }
        }
        $load = (Get-ItemProperty -LiteralPath "$h\Software\Microsoft\Windows NT\CurrentVersion\Windows").Load
        if ($load) {
            Add-Finding 'SUSPICIOUS' 'Startup entry' "Hidden 'Load' entry starts: $load" `
                @{ Type = 'RegRemove'; Key = "$h\Software\Microsoft\Windows NT\CurrentVersion\Windows"; Name = 'Load'; Old = $load; Files = (Test-Command $load).Files; Desc = 'Remove the Load entry' }
        }
    }

    # Startup folders
    $folders = @("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp")
    $folders += Get-Profiles | ForEach-Object { "$_\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup" }
    $wsh = New-Object -ComObject WScript.Shell
    foreach ($d in $folders) {
        foreach ($file in Get-ChildItem -LiteralPath $d -File -Force | Where-Object { $_.Name -ne 'desktop.ini' }) {
            if ($file.Extension -eq '.lnk') {
                $l = $wsh.CreateShortcut($file.FullName)
                $cmd = "`"$($l.TargetPath)`" $($l.Arguments)"
            } else { $cmd = "`"$($file.FullName)`"" }
            $r = Test-Command $cmd
            if ($r.Reasons.Count) {
                Add-Finding 'SUSPICIOUS' 'Startup folder' ("{0} runs: {1}`n       Why: {2}" -f $file.FullName, $cmd, (Join-Why $r)) `
                    @{ Type = 'None'; Files = @(@($file.FullName) + $r.Files | Select-Object -Unique); Desc = 'Quarantine the startup item and its file' }
            }
        }
    }

    # Winlogon hijack
    $wl  = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    $wlp = Get-ItemProperty -LiteralPath $wl
    if ($wlp.Shell -and $wlp.Shell.Trim() -notmatch '^(?i)explorer\.exe,?$') {
        Add-Finding 'THREAT' 'Windows logon' "Windows starts '$($wlp.Shell)' instead of only explorer.exe" `
            @{ Type = 'RegSet'; Key = $wl; Name = 'Shell'; Value = 'explorer.exe'; Old = $wlp.Shell; Files = (Test-Command $wlp.Shell).Files; Desc = 'Reset to explorer.exe' }
    }
    if ($wlp.Userinit -and $wlp.Userinit.Trim() -notmatch '^(?i)[a-z]:\\windows\\system32\\userinit\.exe,?$') {
        Add-Finding 'THREAT' 'Windows logon' "Logon runs extra programs: $($wlp.Userinit)" `
            @{ Type = 'RegSet'; Key = $wl; Name = 'Userinit'; Value = "$env:windir\system32\userinit.exe,"; Old = $wlp.Userinit; Files = (Test-Command $wlp.Userinit).Files; Desc = 'Reset to the Windows default' }
    }
    foreach ($h in Get-UserHives) {
        $us = (Get-ItemProperty -LiteralPath "$h\Software\Microsoft\Windows NT\CurrentVersion\Winlogon").Shell
        if ($us) {
            Add-Finding 'THREAT' 'Windows logon' "A user's logon starts '$us' as the desktop" `
                @{ Type = 'RegRemove'; Key = "$h\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"; Name = 'Shell'; Old = $us; Files = (Test-Command $us).Files; Desc = 'Remove it' }
        }
    }

    # Program hijack (IFEO debugger) + SilentProcessExit
    foreach ($base in 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options',
                      'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options') {
        foreach ($k in Get-ChildItem -LiteralPath $base) {
            $dbg = $k.GetValue('Debugger')
            if ($dbg) {
                Add-Finding 'SUSPICIOUS' 'Program hijack' "When '$($k.PSChildName)' is opened, Windows runs '$dbg' instead" `
                    @{ Type = 'RegRemove'; Key = $k.PSPath; Name = 'Debugger'; Old = $dbg; Files = (Test-Command $dbg).Files; Desc = 'Remove the hijack' }
            }
        }
    }
    foreach ($k in Get-ChildItem -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit') {
        $m = $k.GetValue('MonitorProcess')
        if ($m) {
            Add-Finding 'SUSPICIOUS' 'Program hijack' "When '$($k.PSChildName)' closes, Windows secretly runs '$m'" `
                @{ Type = 'RegRemove'; Key = $k.PSPath; Name = 'MonitorProcess'; Old = $m; Files = (Test-Command $m).Files; Desc = 'Remove the hijack' }
        }
    }
}

function Check-Tasks {
    foreach ($t in Get-ScheduledTask) {
        foreach ($a in @($t.Actions)) {
            if (-not $a.Execute) { continue }
            $cmd = '"' + $a.Execute.Trim('"') + '" ' + $a.Arguments
            $r = Test-Command $cmd
            if ($r.Reasons.Count) {
                Add-Finding 'SUSPICIOUS' 'Scheduled task' ("Task '{0}{1}' runs: {2}`n       Why: {3}" -f $t.TaskPath, $t.TaskName, $cmd, (Join-Why $r)) `
                    @{ Type = 'Task'; Name = $t.TaskName; Path = $t.TaskPath; Files = $r.Files; Desc = 'Disable the task + quarantine its file' }
                break
            }
        }
    }
}

function Check-Services {
    foreach ($s in Get-CimInstance Win32_Service) {
        $r = Test-Command $s.PathName
        if ($r.Reasons.Count) {
            Add-Finding 'SUSPICIOUS' 'Service' ("'{0}' ({1}) runs: {2}`n       Why: {3}" -f $s.Name, $s.DisplayName, $s.PathName, (Join-Why $r)) `
                @{ Type = 'Service'; Name = $s.Name; Files = $r.Files; Desc = 'Stop + disable it, quarantine its file' }
        }
    }
}

function Check-Drivers {
    foreach ($d in Get-CimInstance Win32_SystemDriver) {
        $p = [string]$d.PathName
        if (-not $p) { continue }
        $p = $p.Trim('"') -replace '^\\\?\?\\', ''
        $p = $p -replace '^(?i)\\SystemRoot', $env:windir
        $p = $p -replace '^(?i)System32\\', "$env:windir\System32\"
        $p = [Environment]::ExpandEnvironmentVariables($p)
        if ($p -match $UserWritable -and (Test-Path -LiteralPath $p)) {
            Add-Finding 'THREAT' 'Driver' "Driver '$($d.Name)' lives in a user folder: $p" `
                @{ Type = 'Service'; Name = $d.Name; Files = @(); Desc = 'Disable the driver (takes effect after restart)' }
        }
        elseif ($d.State -eq 'Running' -and (Test-Path -LiteralPath $p) -and -not (Test-Signed $p)) {
            Add-Finding 'SUSPICIOUS' 'Driver' "Unsigned driver is loaded: '$($d.Name)' ($($d.DisplayName)) $p" `
                @{ Type = 'Service'; Name = $d.Name; Files = @(); Desc = 'Disable the driver (takes effect after restart)' }
        }
    }
}

function Check-Wmi {
    foreach ($cls in 'CommandLineEventConsumer', 'ActiveScriptEventConsumer') {
        foreach ($c in Get-WmiObject -Namespace 'root\subscription' -Class $cls) {
            if ($cls -eq 'CommandLineEventConsumer') { $what = $c.CommandLineTemplate }
            else { $s = [string]$c.ScriptText; $what = 'script: ' + $s.Substring(0, [Math]::Min(150, $s.Length)) }
            Add-Finding 'SUSPICIOUS' 'Hidden WMI trigger' "'$($c.Name)' secretly runs: $what" `
                @{ Type = 'Wmi'; Class = $cls; Name = $c.Name; Files = (Test-Command $what).Files; Desc = 'Delete the hidden trigger' }
        }
    }
}

function Check-Bits {
    $guid = $null; $name = ''
    foreach ($line in @(& bitsadmin.exe /list /allusers /verbose 2>$null)) {
        if ($line -match '^GUID:\s*(\{[0-9A-Fa-f-]+\})\s*DISPLAY:\s*(.*)$') { $guid = $Matches[1]; $name = $Matches[2].Trim("'") }
        elseif ($guid -and $line -match '^NOTIFICATION COMMAND LINE:\s*(.+)$' -and $Matches[1].Trim() -notmatch '^(?i)none') {
            $cmd = $Matches[1].Trim()
            Add-Finding 'SUSPICIOUS' 'Hidden download job' "Background download job '$name' runs a program when done: $cmd" `
                @{ Type = 'Bits'; Guid = $guid; Files = (Test-Command $cmd).Files; Desc = 'Cancel the job + quarantine its file' }
        }
    }
}

# DLLs that Windows loads into its own core parts
function Check-Hooks {
    $lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    foreach ($key in $lsa, "$lsa\OSConfig") {
        foreach ($name in 'Authentication Packages', 'Notification Packages', 'Security Packages') {
            foreach ($item in @((Get-ItemProperty -LiteralPath $key).$name)) {
                if (-not $item -or $item -eq '""') { continue }
                $path = Resolve-Dll $item
                if (Test-BadFile $path) {
                    Add-Finding 'THREAT' 'Password hook' "The Windows login system loads an unsigned DLL ($name): $path" `
                        @{ Type = 'RegMultiRemove'; Key = $key; Name = $name; Entry = $item; Files = @($path); Desc = 'Unhook it + quarantine (restart needed)' }
                }
            }
        }
    }
    foreach ($v in Get-RegValues 'HKLM:\SOFTWARE\Microsoft\NetSh') {
        $path = Resolve-Dll $v.Value
        if (Test-BadFile $path) {
            Add-Finding 'SUSPICIOUS' 'DLL hook' "Network tool (netsh) loads an unsigned DLL: $path" `
                @{ Type = 'RegRemove'; Key = $v.Key; Name = $v.Name; Old = $v.Value; Files = @($path); Desc = 'Remove the hook + quarantine' }
        }
    }
    foreach ($k in Get-ChildItem -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors') {
        $path = Resolve-Dll ([string]$k.GetValue('Driver'))
        if (Test-BadFile $path) {
            Add-Finding 'SUSPICIOUS' 'DLL hook' "Printer system loads an unsigned DLL: $path (monitor '$($k.PSChildName)')" $null
        }
    }
    foreach ($k in Get-ChildItem -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify') {
        $path = Resolve-Dll ([string]$k.GetValue('DllName'))
        if (Test-BadFile $path) {
            Add-Finding 'SUSPICIOUS' 'DLL hook' "Logon loads an unsigned DLL: $path" `
                @{ Type = 'RegKeyRemove'; Key = $k.PSPath; Files = @($path); Desc = 'Remove the hook + quarantine' }
        }
    }
    foreach ($v in Get-RegValues 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls') {
        $path = Resolve-Dll $v.Value
        Add-Finding 'SUSPICIOUS' 'DLL injection' "AppCertDlls loads into every program: $($v.Value)" `
            @{ Type = 'RegRemove'; Key = $v.Key; Name = $v.Name; Old = $v.Value; Files = @(@($path) | Where-Object { Test-BadFile $_ }); Desc = 'Remove the injection' }
    }
    foreach ($k in 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows',
                   'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows') {
        $v = (Get-ItemProperty -LiteralPath $k).AppInit_DLLs
        if ($v -and $v.Trim()) {
            Add-Finding 'SUSPICIOUS' 'DLL injection' "AppInit_DLLs loads into every program: $v" `
                @{ Type = 'RegSet'; Key = $k; Name = 'AppInit_DLLs'; Value = ''; Old = $v; Files = (Test-Command $v).Files; Desc = 'Clear AppInit_DLLs' }
        }
    }
    # COM hijack: a user's registry overrides a Windows component with a file from a user folder
    foreach ($h in Get-UserHives) {
        $clsid = Get-Item -LiteralPath "$($h)_Classes\CLSID"
        if (-not $clsid) { continue }
        foreach ($sub in $clsid.GetSubKeyNames()) {
            foreach ($srv in 'InprocServer32', 'LocalServer32') {
                $k = $clsid.OpenSubKey("$sub\$srv")
                if (-not $k) { continue }
                $val = [string]$k.GetValue('')
                $k.Close()
                if (-not $val) { continue }
                $r = Test-Command $val
                if ($r.Reasons.Count) {
                    Add-Finding 'SUSPICIOUS' 'COM hijack' "Windows component $sub is redirected to: $val" `
                        @{ Type = 'RegKeyRemove'; Key = "$($h)_Classes\CLSID\$sub"; Files = $r.Files; Desc = 'Remove the hijack + quarantine its file' }
                }
            }
        }
    }
}

function Check-ScriptAutoload {
    # PowerShell profiles run every time PowerShell starts
    $ps = @("$env:windir\System32\WindowsPowerShell\v1.0\profile.ps1", "$env:windir\System32\WindowsPowerShell\v1.0\Microsoft.PowerShell_profile.ps1")
    foreach ($p in Get-Profiles) {
        $ps += Get-ChildItem -LiteralPath "$p\Documents\WindowsPowerShell", "$p\Documents\PowerShell" -Filter '*profile.ps1' -File -Force | ForEach-Object { $_.FullName }
    }
    foreach ($f in $ps | Select-Object -Unique) {
        if ((Test-Path -LiteralPath $f) -and ((Get-Content -LiteralPath $f -Raw) -match $BadCmd)) {
            Add-Finding 'SUSPICIOUS' 'Script autoload' "PowerShell startup script contains a hidden/download command: $f" `
                @{ Type = 'None'; Files = @($f); Desc = 'Quarantine the script' }
        }
    }
    # Office opens these automatically
    foreach ($p in Get-Profiles) {
        foreach ($d in "$p\AppData\Roaming\Microsoft\Word\STARTUP", "$p\AppData\Roaming\Microsoft\Excel\XLSTART") {
            foreach ($f in Get-ChildItem -LiteralPath $d -File -Force | Where-Object { $_.Extension -match '(?i)^\.(dotm|docm|xlsm|xlam|xla|xlsb|xll|wll)$' }) {
                Add-Finding 'SUSPICIOUS' 'Office macro' "Office opens this macro file automatically: $($f.FullName) (fine if you installed an add-in)" `
                    @{ Type = 'None'; Files = @($f.FullName); Desc = 'Quarantine the file' }
            }
        }
    }
}

# =====================================================================
#  Checks - running programs, files, system
# =====================================================================
function Check-Processes {
    $net = @{}
    foreach ($c in Get-NetTCPConnection) {
        $key = [int]$c.OwningProcess
        $txt = $null
        if ("$($c.State)" -eq 'Established' -and $c.RemoteAddress -notmatch '^(127\.|::1$|0\.0\.0\.0)') { $txt = "$($c.RemoteAddress):$($c.RemotePort)" }
        elseif ("$($c.State)" -eq 'Listen') { $txt = "listening on port $($c.LocalPort)" }
        if ($txt) {
            if (-not $net.ContainsKey($key)) { $net[$key] = New-Object System.Collections.Generic.List[string] }
            $net[$key].Add($txt)
        }
    }
    $procs = @(Get-CimInstance Win32_Process)
    $byPid = @{}
    foreach ($p in $procs) { $byPid[[int]$p.ProcessId] = $p }
    Update-SigCache @($procs | ForEach-Object { $_.ExecutablePath } | Where-Object { $_ -and $_ -match $UserWritable })

    $sysNames = 'svchost.exe',(Dec 'bHNhc3MuZXhl'),'csrss.exe','winlogon.exe','services.exe','smss.exe','wininit.exe',
                'spoolsv.exe','taskhostw.exe','dllhost.exe','conhost.exe','rundll32.exe','explorer.exe','dwm.exe','lsm.exe','sihost.exe','ctfmon.exe'
    $docApps  = 'winword.exe','excel.exe','powerpnt.exe','outlook.exe','msaccess.exe','mspub.exe','onenote.exe','acrord32.exe','acrobat.exe','wordpad.exe','hwp.exe'
    $tools    = 'powershell.exe','pwsh.exe','cmd.exe','wscript.exe','cscript.exe','mshta.exe','rundll32.exe','regsvr32.exe','certutil.exe','bitsadmin.exe','msbuild.exe','installutil.exe'

    foreach ($p in $procs) {
        if ($p.ProcessId -eq $PID -or ($SelfPath -and $p.ExecutablePath -eq $SelfPath)) { continue }
        $path  = $p.ExecutablePath
        $pname = ([string]$p.Name).ToLower()
        $nt = ''
        if ($net.ContainsKey([int]$p.ProcessId)) { $nt = "`n       Network: " + ((@($net[[int]$p.ProcessId]) | Select-Object -Unique -First 5) -join ', ') }
        $parent = $byPid[[int]$p.ParentProcessId]
        $c = [string]$p.CommandLine
        $short = $c.Substring(0, [Math]::Min(200, $c.Length))

        if ($parent -and ($docApps -contains ([string]$parent.Name).ToLower()) -and ($tools -contains $pname)) {
            Add-Finding 'THREAT' 'Malicious document' ("'{0}' (a document program) started '{1}' - this is how malicious documents attack:`n       {2}" -f $parent.Name, $p.Name, $short) `
                @{ Type = 'Process'; ProcId = $p.ProcessId; Files = @(); Desc = 'Stop the started program' }
        }
        elseif ($path -and ($sysNames -contains $pname) -and ($path -notlike "$env:windir\*")) {
            Add-Finding 'THREAT' 'Fake system program' "'$($p.Name)' pretends to be part of Windows but runs from: $path (PID $($p.ProcessId))$nt" `
                @{ Type = 'Process'; ProcId = $p.ProcessId; Files = @($path); Desc = 'Stop it + quarantine the file' }
        }
        elseif ($path -and $path -notlike "$env:windir\*" -and -not (Test-Path -LiteralPath $path)) {
            Add-Finding 'SUSPICIOUS' 'Running program' "'$($p.Name)' is running but its file was deleted from disk (a malware trick): $path (PID $($p.ProcessId))$nt" `
                @{ Type = 'Process'; ProcId = $p.ProcessId; Files = @(); Desc = 'Stop the program' }
        }
        elseif ($path -and $path -match $UserWritable -and -not (Test-Signed $path)) {
            Add-Finding 'SUSPICIOUS' 'Running program' "Unsigned program running from a user folder: $path (PID $($p.ProcessId))$nt" `
                @{ Type = 'Process'; ProcId = $p.ProcessId; Files = @($path); Desc = 'Stop it + quarantine the file' }
        }
        elseif ($c -and $c -match $BadCmd) {
            Add-Finding 'SUSPICIOUS' 'Running program' ("'{0}' (PID {1}) runs a hidden/encoded/download command:`n       {2}{3}" -f $p.Name, $p.ProcessId, $short, $nt) `
                @{ Type = 'Process'; ProcId = $p.ProcessId; Files = @(); Desc = 'Stop the program' }
        }
    }
}

function Check-SystemFiles {
    # Classic backdoor: replace Sticky Keys / Ease of Access with cmd.exe to get in without a password
    $names = 'sethc.exe','utilman.exe','osk.exe','Magnify.exe','Narrator.exe','DisplaySwitch.exe','AtBroker.exe',
             'svchost.exe',(Dec 'bHNhc3MuZXhl'),'winlogon.exe','services.exe','csrss.exe','smss.exe','wininit.exe','userinit.exe',
             'taskmgr.exe','cmd.exe','conhost.exe','rundll32.exe','regsvr32.exe'
    $files = @("$env:windir\explorer.exe") + ($names | ForEach-Object { "$env:windir\System32\$_" })
    foreach ($p in $files) {
        if (-not (Test-Path -LiteralPath $p)) { continue }
        $sig = Get-AuthenticodeSignature -LiteralPath $p
        if ($sig.Status -ne 'Valid' -or [string]$sig.SignerCertificate.Subject -notmatch 'Microsoft') {
            Add-Finding 'THREAT' 'Replaced Windows file' "This Windows file is not the real Microsoft one: $p" `
                @{ Type = 'Sfc'; Path = $p; Desc = 'Let Windows repair the file (sfc)' }
        }
    }
}

function Check-Files {
    $exe       = '\.(exe|dll|scr|pif|com|ps1|vbs|vbe|js|jse|wsf|hta|bat|cmd)$'
    $scriptExt = '\.(scr|pif|com|ps1|vbs|vbe|js|jse|wsf|hta|bat|cmd)$'
    $double    = '(?i)\.(pdf|docx?|xlsx?|pptx?|txt|rtf|jpe?g|png|gif|mp3|mp4|avi|mov|zip|rar|7z|csv|html?)\s*\.(exe|scr|pif|com|bat|cmd|vbs|js|hta|lnk)$'
    $noise     = '(?i)\\Python\d*\\|\\Programs\\Python\\|\\\.vscode\\|\\JetBrains\\|\\Temp\\.*\.(tmp|cvr)\\|\\Microsoft\\WindowsApps\\'

    $places = @()   # folder, depth, pattern
    foreach ($p in Get-Profiles) {
        $places += , @("$p\AppData\Roaming", 0, $exe)
        $places += , @("$p\AppData\Local", 0, $exe)
        $places += , @("$p\AppData\LocalLow", 1, $exe)
        $places += , @("$p\AppData\Local\Temp", 3, $scriptExt)
    }
    $places += , @($env:ProgramData, 0, $exe)
    $places += , @("$env:SystemDrive\Users\Public", 4, $exe)
    $places += , @("$env:windir\Temp", 3, $scriptExt)
    $places += , @("$env:windir\Tasks", 1, $exe)
    $places += , @("$env:windir\Fonts", 0, $exe)
    foreach ($d in Get-FixedDrives) { $places += , @("$d`$Recycle.Bin", 3, $exe) }

    $cands = New-Object System.Collections.Generic.List[string]
    foreach ($pl in $places) { foreach ($f in Get-FilesFast $pl[0] $pl[1] $pl[2]) { if ($f -notmatch $noise) { $cands.Add($f) } }; Emit-Count }

    # New programs anywhere in AppData (droppers usually land here)
    $cut = (Get-Date).AddDays(-30)
    $recent = New-Object System.Collections.Generic.List[string]
    foreach ($p in Get-Profiles) {
        Emit-Count
        foreach ($f in Get-FilesFast "$p\AppData" 12 '\.(exe|scr|pif|com)$') {
            if ($f -match $noise) { continue }
            $fi = New-Object IO.FileInfo($f)
            if ($fi.CreationTime -ge $cut -or $fi.LastWriteTime -ge $cut) { $recent.Add($f) }
        }
    }
    Update-SigCache (@($cands) + @($recent))

    foreach ($f in $cands) {
        if ($script:Flagged.Contains($f)) { continue }
        if (-not (Test-Signed $f)) {
            Add-Finding 'SUSPICIOUS' 'Hiding place' "Unsigned program/script in a spot malware likes: $f" `
                @{ Type = 'None'; Files = @($f); Desc = 'Quarantine the file' }
        }
    }
    foreach ($f in $recent) {
        if ($script:Flagged.Contains($f)) { continue }
        if (-not (Test-Signed $f)) {
            $fi = New-Object IO.FileInfo($f)
            Add-Finding 'SUSPICIOUS' 'New program' ("Unsigned program added in the last 30 days: {0} ({1:yyyy-MM-dd})" -f $f, $fi.CreationTime) `
                @{ Type = 'None'; Files = @($f); Desc = 'Quarantine the file' }
        }
    }

    # Programs disguised as documents (invoice.pdf.exe) - every drive in a Complete scan
    $roots = @()
    if ($Scope -eq 'Complete') { foreach ($d in Get-FixedDrives) { $roots += , @($d, 60) } }
    else { foreach ($p in Get-Profiles) { foreach ($d in 'Downloads', 'Desktop', 'Documents', 'Pictures', 'Videos', 'Music', 'OneDrive', 'AppData\Local\Temp') { $roots += , @("$p\$d", 8) } } }
    foreach ($r in $roots) {
        foreach ($f in Get-FilesFast $r[0] $r[1] '\.(exe|scr|pif|com|bat|cmd|vbs|js|hta|lnk)$') {
            if ([IO.Path]::GetFileName($f) -match $double -and -not $script:Flagged.Contains($f) -and $f -notlike "$env:windir\*") {
                Add-Finding 'THREAT' 'Fake document' "Program disguised as a document: $f" `
                    @{ Type = 'None'; Files = @($f); Desc = 'Quarantine the file' }
            }
        }
    }
}

function Check-Network {
    $hosts = "$env:windir\System32\drivers\etc\hosts"
    $lines = @(Get-Content -LiteralPath $hosts | Where-Object { $_ -match '^\s*[^#\s]' })
    $redirect = @($lines | Where-Object { $_ -notmatch '^\s*(0\.0\.0\.0|127\.0\.0\.1|::1|::)\s' })
    $blockSec = @($lines | Where-Object { $_ -match '^\s*(0\.0\.0\.0|127\.0\.0\.1|::1|::)\s' -and $_ -match $SecuritySites })
    if ($redirect.Count) {
        Add-Finding 'SUSPICIOUS' 'Hosts file' ("Websites are being redirected:`n       " + (($redirect | Select-Object -First 15) -join "`n       ")) `
            @{ Type = 'Hosts'; Lines = $redirect; Desc = 'Back up the hosts file and remove these lines' }
    }
    if ($blockSec.Count) {
        Add-Finding 'THREAT' 'Hosts file' ("Security/update websites are blocked:`n       " + (($blockSec | Select-Object -First 15) -join "`n       ")) `
            @{ Type = 'Hosts'; Lines = $blockSec; Desc = 'Back up the hosts file and remove these lines' }
    }
    foreach ($h in Get-UserHives) {
        $k = "$h\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        $ip = Get-ItemProperty -LiteralPath $k
        if ($ip.ProxyEnable -eq 1 -and $ip.ProxyServer) {
            Add-Finding 'SUSPICIOUS' 'Proxy' "Web traffic goes through proxy '$($ip.ProxyServer)' (fine if you or your work set this up)" `
                @{ Type = 'RegSet'; Key = $k; Name = 'ProxyEnable'; Value = 0; Old = 1; Desc = 'Turn the proxy off' }
        }
        if ($ip.AutoConfigURL) {
            Add-Finding 'SUSPICIOUS' 'Proxy' "Web traffic uses a proxy script: $($ip.AutoConfigURL) (fine if your work set this up)" `
                @{ Type = 'RegRemove'; Key = $k; Name = 'AutoConfigURL'; Old = $ip.AutoConfigURL; Desc = 'Remove the proxy script' }
        }
    }
    # DNS servers (malware changes them to send you to fake websites)
    $knownDns = '^(8\.8\.8\.8|8\.8\.4\.4|1\.1\.1\.1|1\.0\.0\.1|1\.1\.1\.[23]|1\.0\.0\.[23]|9\.9\.9\.\d+|149\.112\.112\.\d+|208\.67\.22[02]\.22[02]|94\.140\.1[45]\.\d+|76\.76\.(2|10)\.\d+|185\.228\.16[89]\.\d+|2001:4860:4860::88(88|44)|2606:4700:4700::1(111|001|112|002|113|003)|2620:fe::.*|2620:119:3[05]::3[05])$'
    $privateIp = '^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|fe80:|fec0:|fd|fc|::1$)'
    $seen = @{}
    foreach ($d in Get-DnsClientServerAddress | Where-Object { $_.ServerAddresses }) {
        $odd = @($d.ServerAddresses | Where-Object { $_ -notmatch $knownDns -and $_ -notmatch $privateIp })
        if (-not $odd.Count -or $seen.ContainsKey($d.InterfaceIndex)) { continue }
        $seen[$d.InterfaceIndex] = 1
        Add-Finding 'WARNING' 'DNS' ("Network '{0}' uses DNS server {1}. This is usually your internet provider, but malware changes DNS to send you to fake websites." -f $d.InterfaceAlias, ($odd -join ', ')) `
            @{ Type = 'DnsReset'; Index = $d.InterfaceIndex; Desc = 'Reset this network to automatic DNS' }
    }
}

function Check-Browsers {
    $bases = 'Software\Policies\Google\Chrome', 'Software\Policies\Microsoft\Edge', 'Software\Policies\BraveSoftware\Brave', 'Software\Policies\Mozilla\Firefox'
    foreach ($h in Get-Hives) {
        foreach ($b in $bases) {
            foreach ($v in Get-RegValues "$h\$b\ExtensionInstallForcelist") {
                Add-Finding 'SUSPICIOUS' 'Browser' "Extension forced into the browser: $($v.Value) (normal on work PCs, adware on home PCs)" `
                    @{ Type = 'RegRemove'; Key = $v.Key; Name = $v.Name; Old = $v.Value; Desc = 'Remove the forced extension' }
            }
            foreach ($n in 'DefaultSearchProviderSearchURL', 'HomepageLocation', 'RestoreOnStartupURLs', 'NewTabPageLocation') {
                $val = (Get-ItemProperty -LiteralPath "$h\$b").$n
                if ($val) {
                    Add-Finding 'SUSPICIOUS' 'Browser' "Browser $n is locked to: $val" `
                        @{ Type = 'RegRemove'; Key = "$h\$b"; Name = $n; Old = $val; Desc = 'Unlock this browser setting' }
                }
            }
        }
    }
    # Browser shortcuts that open a website by force (hijacked shortcut)
    $wsh = New-Object -ComObject WScript.Shell
    $lnkDirs = @("$env:SystemDrive\Users\Public\Desktop", "$env:ProgramData\Microsoft\Windows\Start Menu\Programs")
    foreach ($p in Get-Profiles) { $lnkDirs += "$p\Desktop", "$p\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch", "$p\AppData\Roaming\Microsoft\Windows\Start Menu\Programs" }
    foreach ($d in $lnkDirs) {
        foreach ($f in Get-FilesFast $d 2 '\.lnk$') {
            $l = $wsh.CreateShortcut($f)
            if ($l.TargetPath -match '(?i)\\(chrome|msedge|firefox|brave|opera|iexplore)\.exe$' -and $l.Arguments -match '(?i)https?://') {
                Add-Finding 'SUSPICIOUS' 'Browser' "Browser shortcut forces a website: $f -> $($l.Arguments)" `
                    @{ Type = 'LnkArgs'; Path = $f; Old = $l.Arguments; Desc = 'Remove the website from the shortcut' }
            }
        }
    }
    # Extensions that were sideloaded instead of installed from the store
    $chromium = [ordered]@{ 'Chrome' = 'Google\Chrome\User Data'; 'Edge' = 'Microsoft\Edge\User Data'; 'Brave' = 'BraveSoftware\Brave-Browser\User Data'; 'Vivaldi' = 'Vivaldi\User Data'; 'Chromium' = 'Chromium\User Data' }
    foreach ($p in Get-Profiles) {
        foreach ($b in $chromium.Keys) {
            $ud = "$p\AppData\Local\$($chromium[$b])"
            if (-not (Test-Path -LiteralPath $ud)) { continue }
            foreach ($prof in Get-ChildItem -LiteralPath $ud -Directory | Where-Object { $_.Name -eq 'Default' -or $_.Name -like 'Profile *' }) {
                $seen = @{}
                foreach ($pf in 'Secure Preferences', 'Preferences') {
                    $file = Join-Path $prof.FullName $pf
                    if (-not (Test-Path -LiteralPath $file)) { continue }
                    $json = $null
                    try { $json = Get-Content -LiteralPath $file -Raw -Encoding UTF8 | ConvertFrom-Json } catch { continue }
                    $settings = $json.extensions.settings
                    if (-not $settings) { continue }
                    foreach ($e in $settings.PSObject.Properties) {
                        $id = $e.Name; $s = $e.Value
                        if ($seen.ContainsKey($id)) { continue }
                        $seen[$id] = 1
                        $loc = 0; [void][int]::TryParse([string]$s.location, [ref]$loc)
                        $fromStore = [bool]$s.from_webstore
                        $side = ($loc -eq 4 -or $loc -eq 8)
                        $external = (($loc -eq 2 -or $loc -eq 3 -or $loc -eq 6) -and -not $fromStore)
                        if (-not ($side -or $external)) { continue }
                        if ($s.state -eq 0 -and $s.disable_reasons) { continue }
                        $dir = if ($side) { [string]$s.path } else { Join-Path $prof.FullName "Extensions\$id" }
                        $name = [string]$s.manifest.name
                        if (-not $name -or $name -like '__MSG_*') { $name = Get-ExtName $dir }
                        $how = if ($loc -eq 4) { 'loaded from a folder (developer mode)' } elseif ($loc -eq 8) { 'forced in on the command line' } else { 'installed by another program, not from the store' }
                        $keys = @("HKLM:\SOFTWARE\Google\Chrome\Extensions\$id", "HKLM:\SOFTWARE\WOW6432Node\Google\Chrome\Extensions\$id",
                                  "HKLM:\SOFTWARE\Microsoft\Edge\Extensions\$id", "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Edge\Extensions\$id")
                        Add-Finding 'SUSPICIOUS' 'Browser extension' "$b extension '$name' ($id) was $how. Adware and spy extensions get in this way." `
                            @{ Type = 'RegKeysRemove'; RegKeys = $keys; Files = @(@($dir) | Where-Object { $_ -and (Test-Path -LiteralPath $_) }); Desc = 'Remove the extension (close the browser first)' }
                    }
                }
            }
        }
        foreach ($fx in Get-ChildItem -LiteralPath "$p\AppData\Roaming\Mozilla\Firefox\Profiles" -Directory) {
            $file = Join-Path $fx.FullName 'extensions.json'
            if (-not (Test-Path -LiteralPath $file)) { continue }
            $j = $null
            try { $j = Get-Content -LiteralPath $file -Raw -Encoding UTF8 | ConvertFrom-Json } catch { continue }
            foreach ($a in @($j.addons)) {
                if ($a.type -ne 'extension' -or -not $a.active) { continue }
                if (@('app-profile', 'app-builtin', 'app-system-defaults', 'app-system-addons', 'app-temporary') -contains [string]$a.location) { continue }
                $nm = [string]$a.defaultLocale.name
                if (-not $nm) { $nm = [string]$a.id }
                Add-Finding 'SUSPICIOUS' 'Browser extension' "Firefox extension '$nm' was installed from outside Firefox ($($a.location))." `
                    @{ Type = 'None'; Files = @(@([string]$a.path) | Where-Object { $_ -and (Test-Path -LiteralPath $_) }); Desc = 'Remove the extension file (close Firefox first)' }
            }
        }
    }
}

function Check-Security {
    $st = Get-MpComputerStatus
    if ($st -and $st.AntivirusEnabled -and -not $st.RealTimeProtectionEnabled) {
        Add-Finding 'SUSPICIOUS' 'Antivirus' 'Defender real-time protection is OFF. Malware often turns it off.' @{ Type = 'DefenderOn'; Desc = 'Turn real-time protection back on' }
    }
    $mp = Get-MpPreference
    if ($mp) {
        foreach ($kind in 'ExclusionPath', 'ExclusionProcess', 'ExclusionExtension') {
            foreach ($v in @($mp.$kind)) {
                if ($v -and $v -notmatch '^N/A') {
                    Add-Finding 'SUSPICIOUS' 'Antivirus' "Defender is told to ignore ($kind): $v  - malware adds these to hide" `
                        @{ Type = 'Exclusion'; Kind = $kind; Value = $v; Desc = 'Remove this exclusion' }
                }
            }
        }
    }
    $pk = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
    foreach ($n in 'DisableAntiSpyware', 'DisableAntiVirus') {
        if ((Get-ItemProperty -LiteralPath $pk).$n -eq 1) {
            Add-Finding 'SUSPICIOUS' 'Antivirus' "A policy switches Defender off ($n)" @{ Type = 'RegRemove'; Key = $pk; Name = $n; Old = 1; Desc = 'Remove the policy' }
        }
    }
    foreach ($n in (Dec 'RGlzYWJsZVJlYWx0aW1lTW9uaXRvcmluZw=='), 'DisableBehaviorMonitoring', 'DisableOnAccessProtection', 'DisableIOAVProtection') {
        if ((Get-ItemProperty -LiteralPath "$pk\Real-Time Protection").$n -eq 1) {
            Add-Finding 'SUSPICIOUS' 'Antivirus' "A policy switches part of Defender off ($n)" @{ Type = 'RegRemove'; Key = "$pk\Real-Time Protection"; Name = $n; Old = 1; Desc = 'Remove the policy' }
        }
    }
    foreach ($fp in Get-NetFirewallProfile) {
        if ("$($fp.Enabled)" -eq 'False') {
            Add-Finding 'SUSPICIOUS' 'Firewall' "The Windows firewall is OFF for $($fp.Name) networks" @{ Type = 'Firewall'; Name = $fp.Name; Desc = 'Turn the firewall back on' }
        }
    }
    $sys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    $sp = Get-ItemProperty -LiteralPath $sys
    if ($sp.EnableLUA -eq 0) {
        Add-Finding 'SUSPICIOUS' 'Security setting' 'User Account Control (UAC) is switched off' @{ Type = 'RegSet'; Key = $sys; Name = 'EnableLUA'; Value = 1; Old = 0; Desc = 'Turn UAC back on (restart needed)' }
    }
    elseif ($sp.ConsentPromptBehaviorAdmin -eq 0) {
        Add-Finding 'SUSPICIOUS' 'Security setting' 'Programs get admin rights without asking you' @{ Type = 'RegSet'; Key = $sys; Name = 'ConsentPromptBehaviorAdmin'; Value = 5; Old = 0; Desc = 'Make Windows ask again' }
    }
    if ($sp.DisableTaskMgr -eq 1 -or $sp.DisableRegistryTools -eq 1) {
        Add-Finding 'THREAT' 'Security setting' 'Task Manager or Registry Editor is blocked (malware does this to stop you)' `
            @{ Type = 'RegMultiProp'; Key = $sys; Names = @('DisableTaskMgr', 'DisableRegistryTools'); Desc = 'Unblock them' }
    }
    foreach ($h in Get-UserHives) {
        $uk = "$h\Software\Microsoft\Windows\CurrentVersion\Policies\System"
        $up = Get-ItemProperty -LiteralPath $uk
        if ($up.DisableTaskMgr -eq 1 -or $up.DisableRegistryTools -eq 1) {
            Add-Finding 'THREAT' 'Security setting' 'Task Manager or Registry Editor is blocked for a user (malware does this to stop you)' `
                @{ Type = 'RegMultiProp'; Key = $uk; Names = @('DisableTaskMgr', 'DisableRegistryTools'); Desc = 'Unblock them' }
        }
    }
    $ss = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
    if ((Get-ItemProperty -LiteralPath $ss).EnableSmartScreen -eq 0) {
        Add-Finding 'SUSPICIOUS' 'Security setting' 'SmartScreen (download protection) is switched off by a policy' @{ Type = 'RegRemove'; Key = $ss; Name = 'EnableSmartScreen'; Old = 0; Desc = 'Remove the policy' }
    }
    $wu = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
    if ((Get-ItemProperty -LiteralPath $wu).NoAutoUpdate -eq 1) {
        Add-Finding 'SUSPICIOUS' 'Security setting' 'Windows Update is switched off by a policy' @{ Type = 'RegRemove'; Key = $wu; Name = 'NoAutoUpdate'; Old = 1; Desc = 'Remove the policy' }
    }
    foreach ($u in Get-LocalUser) {
        if ($u.Enabled -and $u.Name.EndsWith('$')) {
            Add-Finding 'THREAT' 'Hidden account' "Hidden user account '$($u.Name)' exists (backdoor trick)" @{ Type = 'DisableUser'; Name = $u.Name; Desc = 'Disable the account' }
        }
        elseif ($u.Enabled -and $u.SID.Value -like '*-501') {
            Add-Finding 'SUSPICIOUS' 'Accounts' "The Guest account '$($u.Name)' is turned on" @{ Type = 'DisableUser'; Name = $u.Name; Desc = 'Disable the Guest account' }
        }
    }
    if ($st -and $st.AntivirusEnabled -and $st.AntivirusSignatureAge -gt 7) {
        Add-Finding 'SUSPICIOUS' 'Antivirus' "Virus definitions are $($st.AntivirusSignatureAge) days old, so new malware can be missed" @{ Type = 'DefUpdate'; Desc = 'Update the virus definitions now' }
    }
    if ($mp -and $st -and $st.AntivirusEnabled) {
        if ($mp.PUAProtection -eq 0) {
            Add-Finding 'WARNING' 'Antivirus' 'Protection against adware and unwanted programs (PUA) is off' @{ Type = 'DefSet'; Name = 'PUAProtection'; Value = 1; Desc = 'Turn PUA protection on' }
        }
        if ($mp.MAPSReporting -eq 0) {
            Add-Finding 'WARNING' 'Antivirus' 'Cloud protection is off, so Defender reacts slower to brand-new malware' @{ Type = 'DefSet'; Name = 'MAPSReporting'; Value = 2; Desc = 'Turn cloud protection on' }
        }
    }
}

# =====================================================================
#  Microsoft Defender (runs in the background)
# =====================================================================
function Get-HotFolders {
    $profiles = @(Get-Profiles)
    $l = New-Object System.Collections.Generic.List[string]
    foreach ($p in $profiles) { $l.Add("$p\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup") }
    $l.Add("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp")
    foreach ($p in $profiles) { $l.Add("$p\AppData\Local\Temp") }
    $l.Add("$env:windir\Temp")
    foreach ($p in $profiles) { $l.Add("$p\Downloads"); $l.Add("$p\Desktop") }
    $l.Add("$env:SystemDrive\Users\Public")
    foreach ($p in $profiles) { $l.Add("$p\AppData\Roaming"); $l.Add("$p\AppData\LocalLow") }
    $l.Add($env:ProgramData)
    foreach ($p in $profiles) { $l.Add("$p\AppData\Local") }
    foreach ($p in $profiles) { $l.Add("$p\Documents") }
    if (-not $NoUsb) { foreach ($drv in Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=2') { $l.Add("$($drv.DeviceID)\") } }
    $l | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -Unique
}

function Start-DefenderJob([string]$Mode, [string[]]$Folders, [bool]$SkipUpdate) {
    Start-Job -ArgumentList $Mode, (, $Folders), $SkipUpdate -ScriptBlock {
        param($Mode, $Folders, $SkipUpdate)
        if (-not $SkipUpdate) {
            'STEP:updating virus definitions'
            try { Update-MpSignature -ErrorAction Stop } catch {}
        }
        if ($Mode -eq 'Full') {
            'STEP:every file on every drive'
            Start-MpScan -ScanType FullScan
            'DONE:full'
            return
        }
        'STEP:memory, boot and system areas'
        Start-MpScan -ScanType QuickScan
        'DONE:quick'
        foreach ($f in $Folders) {
            "STEP:$f"
            Start-MpScan -ScanType CustomScan -ScanPath $f
            "DONE:$f"
        }
    }
}

function Wait-Defender($Job, [datetime]$Until, [int]$PctFrom) {
    $done = New-Object System.Collections.Generic.List[string]
    $current = 'starting'
    $t0 = Get-Date
    $span = ($Until - $t0).TotalSeconds
    while ($true) {
        foreach ($line in @(Receive-Job $Job)) {
            if ($line -like 'STEP:*') { $current = $line.Substring(5) }
            elseif ($line -like 'DONE:*') { $done.Add($line.Substring(5)) }
        }
        if ($Job.State -ne 'Running') { break }
        if ($Until -ne [datetime]::MaxValue -and (Get-Date) -ge $Until) {
            $mp = Join-Path $env:ProgramFiles 'Windows Defender\MpCmdRun.exe'
            if (Test-Path -LiteralPath $mp) { & $mp -Scan -Cancel | Out-Null }
            Stop-Job $Job
            break
        }
        if ($Until -eq [datetime]::MaxValue) {
            Emit-Progress -1 ("Virus scan: {0}  ({1} elapsed)" -f $current, ((Get-Date) - $t0).ToString('hh\:mm\:ss'))
        } else {
            $pct = $PctFrom + [int]((100 - $PctFrom - 2) * [Math]::Min(1, ((Get-Date) - $t0).TotalSeconds / [Math]::Max(1, $span)))
            Emit-Progress $pct ("Virus scan: {0}  ({1} left)" -f $current, ($Until - (Get-Date)).ToString('mm\:ss'))
        }
        Emit-Count
        Start-Sleep -Seconds 1
    }
    foreach ($line in @(Receive-Job $Job)) { if ($line -like 'DONE:*') { $done.Add($line.Substring(5)) } }
    Remove-Job $Job -Force
    return , $done
}

function Get-DefenderDetections([datetime]$Since) {
    $threats = @{}
    foreach ($t in @(Get-MpThreat)) { $threats[[string]$t.ThreatID] = $t }
    foreach ($d in @(Get-MpThreatDetection)) {
        if (-not $d) { continue }
        $t = $threats[[string]$d.ThreatID]
        $active = ($t -and $t.IsActive)
        if ($d.InitialDetectionTime -lt $Since -and -not $active) { continue }   # old, already handled
        $name   = if ($t) { $t.ThreatName } else { "Threat ID $($d.ThreatID)" }
        $status = $StatusMap[[int]$d.ThreatStatusID]
        $where  = (@($d.Resources) -join "`n       ")
        if ($active -or $status -match 'failed|Detected|Allowed|Unknown') {
            Add-Finding 'THREAT' 'Virus (Defender)' ("{0}  [status: {1}]`n       {2}" -f $name, $status, $where) `
                @{ Type = 'DefenderRemove'; Desc = 'Let Defender remove it' }
        } else {
            Add-Finding 'THREAT' 'Virus (Defender)' ("{0}  [already {1} by Defender]`n       {2}" -f $name, "$status".ToLower(), $where) $null
        }
    }
}

# =====================================================================
#  Fixing
# =====================================================================
function Move-ToQuarantine([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return }
    Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -eq $Path } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
    Start-Sleep -Milliseconds 300
    $id = [guid]::NewGuid().ToString('N')
    Move-Item -LiteralPath $Path -Destination (Join-Path $QDir "$id.quarantined") -Force -ErrorAction Stop
    Add-Content -Path $QLog -Value ("{0}`t{1}`t{2}" -f $id, (Get-Date -Format 'yyyy-MM-dd HH:mm'), $Path)
    Write-Log "Quarantined $Path (id $id)"
}

function Invoke-Fix($F) {
    $x = $F.Fix
    switch ($x.Type) {
        'RegRemove' {
            Write-Log "Removed registry value [$($x.Key)] '$($x.Name)' = $($x.Old)"
            Remove-ItemProperty -LiteralPath $x.Key -Name $x.Name -ErrorAction Stop
        }
        'RegSet' {
            Write-Log "Changed registry value [$($x.Key)] '$($x.Name)' from '$($x.Old)' to '$($x.Value)'"
            Set-ItemProperty -LiteralPath $x.Key -Name $x.Name -Value $x.Value -ErrorAction Stop
        }
        'RegMultiProp' {
            foreach ($n in $x.Names) { Remove-ItemProperty -LiteralPath $x.Key -Name $n }
            Write-Log "Removed [$($x.Key)] $($x.Names -join ', ')"
        }
        'RegMultiRemove' {
            $cur = @((Get-ItemProperty -LiteralPath $x.Key).($x.Name))
            $new = [string[]]@($cur | Where-Object { $_ -ne $x.Entry })
            Set-ItemProperty -LiteralPath $x.Key -Name $x.Name -Value $new -Type MultiString -ErrorAction Stop
            Write-Log "Removed '$($x.Entry)' from [$($x.Key)] '$($x.Name)'"
        }
        'RegKeyRemove' {
            $bk = Join-Path $Root ("regkey-backup-{0}.reg" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
            $native = ($x.Key -replace '^.*Registry::', '' -replace '^HKLM:', 'HKEY_LOCAL_MACHINE')
            & reg.exe export "$native" "$bk" /y | Out-Null
            Remove-Item -LiteralPath $x.Key -Recurse -Force -ErrorAction Stop
            Write-Log "Removed registry key [$($x.Key)] (backup: $bk)"
        }
        'Task' {
            Write-Log "Disabled scheduled task $($x.Path)$($x.Name)"
            Disable-ScheduledTask -TaskName $x.Name -TaskPath $x.Path -ErrorAction Stop | Out-Null
        }
        'Service' {
            Write-Log "Stopped and disabled service/driver $($x.Name)"
            & sc.exe stop "$($x.Name)" | Out-Null
            & sc.exe config "$($x.Name)" start= disabled | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "could not disable (sc.exe error $LASTEXITCODE)" }
        }
        'Wmi' {
            Write-Log "Deleted WMI trigger $($x.Class) '$($x.Name)'"
            Get-WmiObject -Namespace 'root\subscription' -Class '__FilterToConsumerBinding' |
                Where-Object { $_.Consumer -like "*$($x.Class)*" -and $_.Consumer -like "*`"$($x.Name)`"*" } | Remove-WmiObject
            Get-WmiObject -Namespace 'root\subscription' -Class $x.Class | Where-Object { $_.Name -eq $x.Name } | Remove-WmiObject -ErrorAction Stop
        }
        'Bits' {
            Get-BitsTransfer -AllUsers | Where-Object { "{$($_.JobId)}" -eq $x.Guid } | Remove-BitsTransfer -ErrorAction Stop
            Write-Log "Cancelled background download job $($x.Guid)"
        }
        'Process' {
            Write-Log "Stopped process PID $($x.ProcId)"
            Stop-Process -Id $x.ProcId -Force
        }
        'Hosts' {
            $h = "$env:windir\System32\drivers\etc\hosts"
            $backup = Join-Path $Root ("hosts-backup-{0}.txt" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
            Copy-Item -LiteralPath $h -Destination $backup -ErrorAction Stop
            $lines = $x.Lines
            $keep = @(Get-Content -LiteralPath $h | Where-Object { $lines -notcontains $_ })
            Set-Content -LiteralPath $h -Value $keep -Encoding ASCII -ErrorAction Stop
            & ipconfig.exe /flushdns | Out-Null
            Write-Log "Cleaned hosts file (backup: $backup)"
        }
        'LnkArgs' {
            $wsh = New-Object -ComObject WScript.Shell
            $l = $wsh.CreateShortcut($x.Path)
            $l.Arguments = ($l.Arguments -replace '(?i)"?https?://\S+"?', '').Trim()
            $l.Save()
            Write-Log "Removed website '$($x.Old)' from shortcut $($x.Path)"
        }
        'Exclusion' {
            $p = @{}; $p[$x.Kind] = $x.Value
            Remove-MpPreference @p -ErrorAction Stop
            Write-Log "Removed Defender $($x.Kind) '$($x.Value)'"
        }
        'DefenderOn' {
            Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop
            Write-Log 'Turned Defender real-time protection on'
        }
        'DefenderRemove' {
            Remove-MpThreat -ErrorAction Stop
            Write-Log 'Asked Defender to remove all active threats'
        }
        'Firewall' {
            Set-NetFirewallProfile -Name $x.Name -Enabled True -ErrorAction Stop
            Write-Log "Turned firewall on for $($x.Name)"
        }
        'DisableUser' {
            Disable-LocalUser -Name $x.Name -ErrorAction Stop
            Write-Log "Disabled account $($x.Name)"
        }
        'DnsReset' {
            Set-DnsClientServerAddress -InterfaceIndex $x.Index -ResetServerAddresses -ErrorAction Stop
            Clear-DnsClientCache
            Write-Log "Reset DNS to automatic on interface $($x.Index)"
        }
        'RegKeysRemove' {
            foreach ($k in @($x.RegKeys)) { if ($k -and (Test-Path -LiteralPath $k)) { Remove-Item -LiteralPath $k -Recurse -Force; Write-Log "Removed registry key $k" } }
        }
        'DefUpdate' {
            Update-MpSignature -ErrorAction Stop
            Write-Log 'Updated Defender virus definitions'
        }
        'DefSet' {
            $p = @{}; $p[$x.Name] = $x.Value
            Set-MpPreference @p -ErrorAction Stop
            Write-Log "Set Defender $($x.Name) = $($x.Value)"
        }
        'Uninstall' {
            Start-Process -FilePath "$env:windir\System32\cmd.exe" -ArgumentList ('/c "' + $x.Cmd + '"') -WindowStyle Hidden -ErrorAction Stop
            Write-Log "Started uninstaller: $($x.Cmd)"
        }
        'Cert' {
            $cp = "$($x.Store)\$($x.Thumb)"
            $c = Get-Item -LiteralPath $cp -ErrorAction Stop
            [IO.File]::WriteAllBytes((Join-Path $Root "cert-backup-$($x.Thumb).cer"), $c.Export([Security.Cryptography.X509Certificates.X509ContentType]::Cert))
            Remove-Item -LiteralPath $cp -ErrorAction Stop
            Write-Log "Removed certificate $($c.Subject) from $($x.Store) (backup kept)"
        }
        'Bcd' {
            & bcdedit.exe /set '{current}' $x.Opt off | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "bcdedit failed ($LASTEXITCODE)" }
            Write-Log "Turned boot option $($x.Opt) off"
        }
        'FwRule' {
            try { Remove-NetFirewallRule -Name $x.Id -ErrorAction Stop }
            catch { Remove-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules' -Name $x.Id -ErrorAction Stop }
            Write-Log "Deleted firewall rule $($x.Id)"
        }
        'Stream' {
            $q = Join-Path $QDir ("stream-{0}.quarantined" -f [guid]::NewGuid().ToString('N'))
            $bytes = Get-Content -LiteralPath $x.Path -Stream $x.Stream -Encoding Byte -ReadCount 0
            if ($bytes) { [IO.File]::WriteAllBytes($q, [byte[]]$bytes) }
            Remove-Item -LiteralPath $x.Path -Stream $x.Stream -ErrorAction Stop
            Write-Log "Removed hidden stream '$($x.Stream)' from $($x.Path) (copy kept in $q)"
        }
        'Unhide' {
            $i = Get-Item -LiteralPath $x.Path -Force -ErrorAction Stop
            $i.Attributes = $i.Attributes -band (-bnot ([IO.FileAttributes]::Hidden -bor [IO.FileAttributes]::System))
            Write-Log "Made $($x.Path) visible"
        }
        'Sfc' {
            & sfc.exe "/scanfile=$($x.Path)" | Out-Null
            Write-Log "Ran sfc on $($x.Path)"
        }
    }
    foreach ($file in @($x.Files)) { if ($file) { Move-ToQuarantine $file } }
}


# =====================================================================
#  More helpers
# =====================================================================
function Get-FixedDrives {
    Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object { "$($_.DeviceID)\" }
}

function Get-ExtName([string]$Dir) {
    if (-not $Dir -or -not (Test-Path -LiteralPath $Dir)) { return '(unknown name)' }
    $m = Get-ChildItem -LiteralPath $Dir -Filter 'manifest.json' -Recurse -Depth 2 -File | Select-Object -First 1
    if ($m) {
        try {
            $n = [string](Get-Content -LiteralPath $m.FullName -Raw -Encoding UTF8 | ConvertFrom-Json).name
            if ($n -and $n -notlike '__MSG_*') { return $n }
        } catch {}
    }
    return '(unknown name)'
}

function Emit-Count {
    $files = $script:FileCount
    if ($script:UseNative) { try { $files = [MwNative]::Count } catch {} }
    Emit ("C|{0}|{1}|{2}" -f $files, $script:NThreat, $script:NSus)
}

# Reads inside scripts and returns "path|score|reasons" for ones scoring high enough.
# Uses the fast native scanner when available, otherwise the same rules in pure PowerShell.
$script:ScriptRules = @(
    @('downloads from the internet', 2, (Dec 'KERvd25sb2FkU3RyaW5nfERvd25sb2FkRmlsZXxEb3dubG9hZERhdGF8TmV0XC5XZWJDbGllbnR8SW52b2tlLVdlYlJlcXVlc3R8XGJpd3JcYnxJbnZva2UtUmVzdE1ldGhvZHxTdGFydC1CaXRzVHJhbnNmZXJ8Yml0c2FkbWluW15cbl17MCw4MH0vdHJhbnNmZXJ8Y2VydHV0aWxbXlxuXXswLDgwfS11cmxjYWNoZXxNU1hNTDJcLihTZXJ2ZXIpP1hNTEhUVFB8V2luSHR0cFwuV2luSHR0cFJlcXVlc3R8VVJMRG93bmxvYWRUb0ZpbGUp')),
    @('runs commands', 1, (Dec 'KEludm9rZS1FeHByZXNzaW9ufFxiaWV4XGJ8V1NjcmlwdFwuU2hlbGx8U2hlbGxcLkFwcGxpY2F0aW9ufFNoZWxsRXhlY3V0ZXxcLkV4ZWNccypcKHxcLlJ1blxzKlwofFN0YXJ0LVByb2Nlc3N8Y21kKFwuZXhlKT9ccysvYyk=')),
    @('hides encoded code', 2, (Dec 'KEZyb21CYXNlNjRTdHJpbmd8XHMtZShuY3xuY29kZWRjb21tYW5kKT9ccytbQS1aYS16MC05Ky89XXs0MCx9fFtBLVphLXowLTkrL117NDAwLH09ezAsMn18KFxbY2hhclxdXHMqXGR7MiwzfVxzKlsrLF0/XHMqKXs4LH18KGNoclx3P1woXGR7MiwzfVwpXHMqJlxzKil7OCx9fFN0cmluZ1wuRnJvbUNoYXJDb2RlXCgoXGR7MiwzfSxccyopezgsfSk=')),
    @('runs hidden', 1, '(\s-w(indowstyle)?\s+h(idden)?\b|WindowStyle\s*=?\s*[''"]?Hidden|\.Run\s*\([^,\n]+,\s*0\b)'),
    @('switches security off', 3, (Dec 'KEFtc2lVdGlsc3xhbXNpSW5pdEZhaWxlZHxBbXNpU2NhbkJ1ZmZlcnxTZXQtTXBQcmVmZXJlbmNlfEFkZC1NcFByZWZlcmVuY2V8RGlzYWJsZVJlYWx0aW1lTW9uaXRvcmluZ3xuZXRzaFxzKyhhZHYpP2ZpcmV3YWxsXHMrc2V0W15cbl17MCw0MH1cYm9mZlxiKQ==')),
    @('makes itself start automatically', 1, '(CurrentVersion\\Run|schtasks(\.exe)?\s+/create|Register-ScheduledTask|Start Menu\\Programs\\Startup|__EventFilter|CommandLineEventConsumer)'),
    @('deletes backups (ransomware)', 6, (Dec 'KHZzc2FkbWluKFwuZXhlKT9ccytkZWxldGVccytzaGFkb3dzfHNoYWRvd2NvcHlccytkZWxldGV8d2JhZG1pbihcLmV4ZSk/XHMrZGVsZXRlfHJlY292ZXJ5ZW5hYmxlZFxzK25vfFdpbjMyX1NoYWRvd0NvcHlbXlxuXXswLDYwfURlbGV0ZSk=')),
    @('steals passwords or wallets', 3, (Dec 'KG1pbWlrYXR6fHNla3VybHNhfGNvbXN2Y3MoXC5kbGwpP1teXG5dezAsNDB9TWluaUR1bXB8cHJvY2R1bXBbXlxuXXswLDQwfWxzYXNzfFxcTG9naW4gRGF0YXxcXExvY2FsIFN0YXRlfHdhbGxldFwuZGF0fFxcRXhvZHVzXFx8XFxFbGVjdHJ1bVxcfFxcRXRoZXJldW1cXGtleXN0b3JlKQ==')),
    @('injects code into memory', 2, (Dec 'KFZpcnR1YWxBbGxvY3xXcml0ZVByb2Nlc3NNZW1vcnl8Q3JlYXRlUmVtb3RlVGhyZWFkfFJlZmxlY3Rpb25cLkFzc2VtYmx5XF06OkxvYWR8R2V0RGVsZWdhdGVGb3JGdW5jdGlvblBvaW50ZXIp')),
    @('crypto mining', 3, (Dec 'KHN0cmF0dW1cKyh0Y3B8c3NsKTovL3x4bXJpZ3wtLWRvbmF0ZS1sZXZlbHxjcnlwdG9uaWdodCk=')),
    @('sends data to Telegram or Discord', 2, '(api\.telegram\.org/bot|discord(app)?\.com/api/webhooks)')
)

function Scan-Scripts([string[]]$Files, [long]$MaxBytes) {
    if ($script:UseNative) {
        try { return [MwNative]::ScanScripts($Files, $MaxBytes) }
        catch { Log "Native script scan failed, using PowerShell: $($_.Exception.Message)" }
    }
    $out = New-Object System.Collections.Generic.List[string]
    $rx = @($script:ScriptRules | ForEach-Object { , @($_[0], $_[1], (New-Object System.Text.RegularExpressions.Regex($_[2], 'IgnoreCase'))) })
    foreach ($f in $Files) {
        try {
            $fi = New-Object IO.FileInfo($f)
            if ($fi.Length -eq 0 -or $fi.Length -gt $MaxBytes) { continue }
            $t = [IO.File]::ReadAllText($f)
            $score = 0; $why = New-Object System.Collections.Generic.List[string]
            foreach ($r in $rx) { if ($r[2].IsMatch($t)) { $score += $r[1]; $why.Add($r[0]) } }
            if ($score -ge 4) { $out.Add(("{0}|{1}|{2}" -f $f, $score, ($why -join ', '))) }
        } catch {}
    }
    return $out
}

# =====================================================================
#  Ransomware
# =====================================================================
function Check-Ransomware {
    $noteWords = 'how[_ -]?to[_ -]?(decrypt|recover|restore|back[_ -]?files)|decrypt[_ -]?(instruction|my[_ -]?files|files|info)|read[_ -]?me[_ -]?(for|to)[_ -]?decrypt|restore[_ -]?(my[_ -]?)?files|recover[_ -]?(my[_ -]?)?files|your[_ -]?files[_ -]?(are|were|is)?[_ -]?(encrypted|locked)|files[_ -]?(are[_ -]?)?encrypted|help[_ -]?(decrypt|recover|restore|your[_ -]?files)|readme-warning|ransom[_ -]?note|!!!.*read.*!!!'
    $encExt = 'locky|zepto|odin|thor|aesir|osiris|cerber[0-9]?|wncry|wnry|wcry|wncryt|crypted|encrypted|locked|lockbit|ryk|djvu|makop|phobos|dharma|xtbl|crysis|crinf|kraken|ecc|exx|ezz|zzzzz|crypz|cryp1|vvv|ccc|crab|gdcb|krab|sage|nemty|sodinokibi|maze|egregor|conti|hive|blackcat|akira|harma|heets|onion|basta|royal|medusa|8base|rhysida|cuba|babuk|clop|cl0p|ragnar|avaddon|lockfile|enc_robbinhood'
    $pattern = '(?i)(\\[^\\]*(' + $noteWords + ')[^\\]*\.(txt|html?|hta|url|rtf)$)|(\\_readme\.txt$)|(\.(' + $encExt + ')$)|(\.id[-_][0-9A-F]{8}\.\[[^\]]+@[^\]]+\])'

    $roots = @()
    foreach ($p in Get-Profiles) { foreach ($d in 'Desktop', 'Documents', 'Pictures', 'Downloads', 'Videos', 'Music', 'OneDrive') { $roots += "$p\$d" } }
    $roots += "$env:SystemDrive\Users\Public"
    if ($Scope -eq 'Complete') { foreach ($d in Get-FixedDrives) { if ($d -ne "$env:SystemDrive\") { $roots += $d } } }

    $notes = New-Object System.Collections.Generic.List[string]
    $byExt = @{}
    foreach ($r in $roots) {
        Emit-Count
        foreach ($f in Get-FilesFast $r 12 $pattern) {
            $name = [IO.Path]::GetFileName($f)
            if ($name -match ('(?i)(' + $noteWords + ')') -or $name -ieq '_readme.txt') {
                if ($name -match '(?i)\.(txt|html?|hta|url|rtf)$') { $notes.Add($f); continue }
            }
            $ext = if ($f -match '(?i)\.id[-_][0-9A-F]{8}\.\[') { 'dharma-style .id-XXXX.[email]' } else { [IO.Path]::GetExtension($f).ToLower() }
            if (-not $byExt.ContainsKey($ext)) { $byExt[$ext] = New-Object System.Collections.Generic.List[string] }
            $byExt[$ext].Add($f)
        }
    }
    foreach ($n in ($notes | Select-Object -First 10)) {
        Add-Finding 'THREAT' 'Ransomware' "Ransom note found: $n`n       Do not pay. Check nomoreransom.org for a free decryptor and restore files from a backup." $null
    }
    foreach ($ext in $byExt.Keys) {
        $list = $byExt[$ext]
        if ($list.Count -lt 10) { continue }
        Add-Finding 'THREAT' 'Ransomware' ("{0} files look encrypted by ransomware (ending in {1}), for example:`n       {2}`n       Disconnect from the internet, do not pay, and restore from a backup." -f $list.Count, $ext, (($list | Select-Object -First 3) -join "`n       ")) $null
    }
}

# =====================================================================
#  Crypto miners
# =====================================================================
function Check-Miners {
    $minerNames = (Dec 'KD9pKV4oeG1yaWcuKnx4bXItc3Rhay4qfG1pbmVyZHxjcHVtaW5lci4qfG5ibWluZXJ8dC1yZXh8dHJleHxwaG9lbml4bWluZXJ8bG9sbWluZXJ8Z21pbmVyfG1pbmVyfGV0aG1pbmVyfGNsYXltb3JlLip8Y2dtaW5lcnxiZmdtaW5lcnxjY21pbmVyfHNyYm1pbmVyLip8dGVhbXJlZG1pbmVyfGV4Y2F2YXRvcnxuYW5vbWluZXJ8d2lsZHJpZy4qfHJpZ2VsfGJ6bWluZXJ8b25lemVyb21pbmVyKVwuZXhlJA==')
    $minerArgs  = (Dec 'KD9pKShzdHJhdHVtXCsodGNwfHNzbHx0bHMpOi8vfC0tZG9uYXRlLWxldmVsfC0tY3B1LW1heC10aHJlYWRzLWhpbnR8LS1jb2luWz0gXShtb25lcm98eG1yfHJ2bnxldGMpfC0tYWxnb1s9IF0/KHJ4fGNufHJhbmRvbXh8a2F3cG93fGV0aGFzaHxldGNoYXNofGF1dG9seWtvc3xnaG9zdHJpZGVyKXxccy1hXHMrKHJ4LzB8Y24vcnxyYW5kb214fGthd3Bvdyl8KG1pbmV4bXJ8c3VwcG9ydHhtcnxuYW5vcG9vbHwybWluZXJzfGYycG9vbHxoYXNodmF1bHR8bW9uZXJvb2NlYW58aGVyb21pbmVyc3x1bm1pbmVhYmxlfGMzcG9vbHxuaWNlaGFzaClcLihjb218b3JnfG5ldHxwcm98aW8pKQ==')
    $ports = 3333, 4444, 5555, 7777, 14433, 14444, 45560, 45700, 10128, 20128, 10001, 13333
    $seen = @{}
    foreach ($p in Get-CimInstance Win32_Process) {
        if ($p.ProcessId -eq $PID) { continue }
        $isName = ([string]$p.Name) -match $minerNames
        $isArgs = ([string]$p.CommandLine) -match $minerArgs
        if (-not ($isName -or $isArgs)) { continue }
        $seen[[int]$p.ProcessId] = 1
        $path = [string]$p.ExecutablePath
        $c = [string]$p.CommandLine
        if ($isArgs -and -not $isName) {
            Add-Finding 'THREAT' 'Crypto miner' ("'{0}' is secretly mining cryptocurrency (a disguised miner):`n       {1}" -f $p.Name, $c.Substring(0, [Math]::Min(200, $c.Length))) `
                @{ Type = 'Process'; ProcId = $p.ProcessId; Files = @(@($path) | Where-Object { $_ -and $_ -notlike "$env:windir\*" }); Desc = 'Stop it + quarantine the file' }
        } else {
            Add-Finding 'SUSPICIOUS' 'Crypto miner' "Mining program '$($p.Name)' is running from $path - fine only if you mine on purpose" `
                @{ Type = 'Process'; ProcId = $p.ProcessId; Files = @(@($path) | Where-Object { $_ }); Desc = 'Stop it + quarantine the file' }
        }
    }
    foreach ($c in Get-NetTCPConnection -State Established | Where-Object { $ports -contains [int]$_.RemotePort }) {
        if ($seen.ContainsKey([int]$c.OwningProcess)) { continue }
        $proc = Get-CimInstance Win32_Process -Filter "ProcessId=$([int]$c.OwningProcess)"
        if (-not $proc -or -not $proc.ExecutablePath -or $proc.ExecutablePath -notmatch $UserWritable) { continue }
        if (Test-Signed $proc.ExecutablePath) { continue }
        $seen[[int]$c.OwningProcess] = 1
        Add-Finding 'SUSPICIOUS' 'Crypto miner' "'$($proc.Name)' ($($proc.ExecutablePath)) talks to $($c.RemoteAddress):$($c.RemotePort), a port used by mining pools" `
            @{ Type = 'Process'; ProcId = $proc.ProcessId; Files = @($proc.ExecutablePath); Desc = 'Stop it + quarantine the file' }
    }
    $fileRx = (Dec 'XFwoeG1yaWdbXlxcXSp8eG1yLXN0YWtbXlxcXSp8bWluZXJkfGNwdW1pbmVyW15cXF0qfG5ibWluZXJ8dC1yZXh8cGhvZW5peG1pbmVyfGxvbG1pbmVyfGdtaW5lcnxldGhtaW5lcnxzcmJtaW5lclteXFxdKnx0ZWFtcmVkbWluZXJ8bmFub21pbmVyfHdpbGRyaWdbXlxcXSopXC5leGUk')
    $roots = @(); foreach ($p in Get-Profiles) { $roots += "$p\AppData", "$p\Downloads", "$p\Desktop" }
    $roots += $env:ProgramData, "$env:windir\Temp", "$env:SystemDrive\Users\Public"
    foreach ($r in $roots) {
        foreach ($f in Get-FilesFast $r 8 $fileRx) {
            if ($script:Flagged.Contains($f)) { continue }
            Add-Finding 'SUSPICIOUS' 'Crypto miner' "Mining program found: $f (fine only if you mine on purpose)" @{ Type = 'None'; Files = @($f); Desc = 'Quarantine the file' }
        }
    }
}

# =====================================================================
#  Remote access tools and RATs
# =====================================================================
function Check-RemoteAccess {
    $tools = [ordered]@{
        'anydesk' = 'AnyDesk'; 'teamviewer' = 'TeamViewer'; 'teamviewer_service' = 'TeamViewer'; 'tv_w32' = 'TeamViewer'; 'tv_x64' = 'TeamViewer'
        'ultraviewer_desktop' = 'UltraViewer'; 'ultraviewer_service' = 'UltraViewer'; 'rustdesk' = 'RustDesk'
        'screenconnect.clientservice' = 'ScreenConnect'; 'screenconnect.windowsclient' = 'ScreenConnect'
        'srservice' = 'Splashtop'; 'strwinclt' = 'Splashtop'; 'rutserv' = 'Remote Utilities'; 'rfusclient' = 'Remote Utilities'
        'remotepcservice' = 'RemotePC'; 'ateraagent' = 'Atera'; 'client32' = 'NetSupport Manager'; 'aa_v3' = 'Ammyy Admin'; 'ammyy_admin' = 'Ammyy Admin'
        'logmein' = 'LogMeIn'; 'lmiguardiansvc' = 'LogMeIn'; 'supremo' = 'Supremo'; 'supremoservice' = 'Supremo'; 'aeroadmin' = 'AeroAdmin'
        'dwagent' = 'DWService'; 'dwagsvc' = 'DWService'; 'action1_agent' = 'Action1'; 'radmin' = 'Radmin'; 'rserver3' = 'Radmin'
        'winvnc' = 'VNC'; 'tvnserver' = 'TightVNC'; 'vncserver' = 'VNC'; 'meshagent' = 'MeshCentral'; 'getscreen' = 'Getscreen'
        'ngrok' = 'ngrok tunnel'; 'cloudflared' = 'Cloudflare tunnel'; 'chisel' = 'Chisel tunnel'; 'plink' = 'PuTTY tunnel'
    }
    $risky = 'client32', 'aa_v3', 'ammyy_admin', 'ngrok', 'meshagent', 'chisel', 'plink', 'rutserv', 'rfusclient'
    $reported = @{}
    foreach ($p in Get-CimInstance Win32_Process) {
        $n = ([IO.Path]::GetFileNameWithoutExtension([string]$p.Name)).ToLower()
        if (-not $tools.Contains($n)) { continue }
        $tool = $tools[$n]
        if ($reported.ContainsKey($tool)) { continue }
        $reported[$tool] = 1
        $path = [string]$p.ExecutablePath
        $hidden = ($path -and $path -match $UserWritable -and (($risky -contains $n) -or -not (Test-Signed $path)))
        if ($hidden) {
            Add-Finding 'SUSPICIOUS' 'Remote access' "$tool is running from a hidden user folder ($path). Hackers and 'tech support' scammers use it to control PCs." `
                @{ Type = 'Process'; ProcId = $p.ProcessId; Files = @($path); Desc = 'Close it + quarantine the file' }
        } else {
            Add-Finding 'WARNING' 'Remote access' "$tool is running ($path). It lets someone control this PC - fine if you installed it yourself, dangerous if a 'support' caller asked you to." `
                @{ Type = 'Process'; ProcId = $p.ProcessId; Files = @(); Desc = 'Close it now' }
        }
    }
    $ts = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
    if ((Get-ItemProperty -LiteralPath $ts).fDenyTSConnections -eq 0) {
        Add-Finding 'WARNING' 'Remote access' 'Remote Desktop is turned on: people on your network or the internet can try to log in to this PC' `
            @{ Type = 'RegSet'; Key = $ts; Name = 'fDenyTSConnections'; Value = 1; Old = 0; Desc = 'Turn Remote Desktop off' }
    }
}

# =====================================================================
#  Adware and unwanted programs (PUPs)
# =====================================================================
function Check-Pups {
    $pup = '(?i)(web ?companion|segurazo|saferweb|bytefence|wave ?browser|wavesor|onelaunch|onestart|pc ?accelerate|pc ?app ?store|reimage|restoro|fortect|mycleanpc|advanced ?system ?(care|repair)|driver ?support|driver ?updater|systweak|search ?(baron|marquis|protect|manager)|mindspark|myway|conduit|ask ?toolbar|babylon|delta ?search|shopper ?pro|pdf ?(power|super|pro) ?tool|easy ?pdf ?combine|manual ?finder|webdiscover|dragon ?boost|zip ?on|cleanmy ?pc|total ?av|shield ?apps|smart ?pc ?fixer|pc ?optimizer ?pro|speedup ?my ?pc|hola ?(vpn|unblocker)|yontoo|crossrider|superfish|visual ?discovery|wajam|browsefox|eorezo|sweet ?(page|im)|nationzoom|trovi|vosteran|price ?(meter|gong)|savings ?bull|relevant ?knowledge|opencandy|installcore|outbrowse|amonetize|chromium ?(pdf|player)|mysearchdial|1 ?click ?download|cool ?web ?search|mail ?checker ?pro|weather ?app ?tab|coupon ?(server|printer ?for ?windows))'
    $crack = '(?i)(kms ?pico|kms ?auto|kms ?tools|kms ?matrix|kmspico|microsoft ?toolkit|re-?loader ?activator|windows ?loader|aact)'
    $keys = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')
    foreach ($h in Get-UserHives) { $keys += "$h\Software\Microsoft\Windows\CurrentVersion\Uninstall" }
    $seen = @{}
    foreach ($k in $keys) {
        foreach ($app in Get-ChildItem -LiteralPath $k) {
            $name = [string]$app.GetValue('DisplayName')
            if (-not $name -or $seen.ContainsKey($name)) { continue }
            $isPup = $name -match $pup
            $isCrack = $name -match $crack
            if (-not ($isPup -or $isCrack)) { continue }
            $seen[$name] = 1
            $cmd = [string]$app.GetValue('QuietUninstallString')
            if (-not $cmd) { $cmd = [string]$app.GetValue('UninstallString') }
            $text = if ($isCrack) { "'$name' is installed - a piracy activator. These are very often bundled with trojans and miners." }
                    else { "'$name' is installed - known adware / potentially unwanted program (PUP)." }
            $fix = if ($cmd) { @{ Type = 'Uninstall'; Cmd = $cmd; Desc = 'Open its uninstaller' } } else { $null }
            Add-Finding 'SUSPICIOUS' 'Unwanted program' $text $fix
        }
    }
}

# =====================================================================
#  Fake root certificates (let programs spy on https)
# =====================================================================
function Check-Certs {
    $bad   = '(?i)(superfish|edellroot|dsdtestprovider|privdog|komodia|sendori|wajam|nethelper|ad-?aware ?web|kurupira)'
    $devOk = '(?i)(CN=localhost|IIS Express|ASP\.NET Core HTTPS development|mkcert|Fiddler|DO_NOT_TRUST|Charles Proxy|PortSwigger|mitmproxy|Docker|Hyper-V|Windows Azure|Microsoft)'
    $seen = @{}
    foreach ($store in 'Cert:\LocalMachine\Root', 'Cert:\CurrentUser\Root') {
        foreach ($c in Get-ChildItem -LiteralPath $store) {
            if ($seen.ContainsKey($c.Thumbprint + $store)) { continue }
            $seen[$c.Thumbprint + $store] = 1
            $fix = @{ Type = 'Cert'; Store = $store; Thumb = $c.Thumbprint; Desc = 'Remove the certificate (a backup is kept)' }
            if ($c.Subject -match $bad -or $c.Issuer -match $bad) {
                Add-Finding 'THREAT' 'Fake certificate' "A known malicious root certificate is trusted: $($c.Subject). It lets a program read your secure (https) traffic." $fix
            } elseif ($c.HasPrivateKey -and $c.Subject -notmatch $devOk) {
                Add-Finding 'SUSPICIOUS' 'Fake certificate' "A root certificate whose private key is on this PC is trusted: $($c.Subject). Programs use this trick to read your secure (https) traffic." $fix
            } elseif ($c.HasPrivateKey -and $c.Subject -match '(?i)(Fiddler|DO_NOT_TRUST|Charles|PortSwigger|mitmproxy)') {
                Add-Finding 'WARNING' 'Certificate' "A traffic-inspection certificate is trusted: $($c.Subject) (fine if you use that tool)" $fix
            }
        }
    }
}

# =====================================================================
#  Bootkits and rootkit-friendly boot settings
# =====================================================================
function Check-Boot {
    $no = '(?i)^(no|non|nein|nu|nee|nej|ei|nie|nao|0|false|off)$'
    foreach ($line in @(& bcdedit.exe /enum '{current}' 2>$null)) {
        if ($line -match '^(testsigning|nointegritychecks|debug|bootdebug)\s+(\S+)\s*$' -and $Matches[2] -notmatch $no) {
            $opt = $Matches[1]
            Add-Finding 'SUSPICIOUS' 'Boot settings' "Windows starts with '$opt' switched on. This lets unsigned drivers (rootkits) load." `
                @{ Type = 'Bcd'; Opt = $opt; Desc = 'Switch it off (restart needed)' }
        }
    }
    try {
        if (-not (Confirm-SecureBootUEFI -ErrorAction Stop)) {
            Add-Finding 'WARNING' 'Boot settings' 'Secure Boot is off. It blocks boot-level malware (bootkits); you can turn it on in the PC firmware (BIOS/UEFI) settings.' $null
        }
    } catch {}
    $sm = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
    foreach ($item in @((Get-ItemProperty -LiteralPath $sm).BootExecute)) {
        if (-not $item -or $item -match '(?i)^autocheck\s+autochk\b') { continue }
        Add-Finding 'SUSPICIOUS' 'Boot settings' "A program runs before Windows starts (BootExecute): $item" `
            @{ Type = 'RegMultiRemove'; Key = $sm; Name = 'BootExecute'; Entry = $item; Desc = 'Remove it from the boot sequence' }
    }
}

# =====================================================================
#  Firewall rules that open the PC for unsigned programs
# =====================================================================
function Check-FirewallRules {
    $item = Get-Item -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules'
    if (-not $item) { return }
    $cands = @()
    foreach ($n in $item.GetValueNames()) {
        $v = [string]$item.GetValue($n)
        if (-not ($v -match '(?i)\|Action=Allow\|') -or -not ($v -match '(?i)\|Active=TRUE\|') -or -not ($v -match '(?i)\|Dir=In\|')) { continue }
        if (-not ($v -match '(?i)\|App=([^|]+)\|')) { continue }
        $app = [Environment]::ExpandEnvironmentVariables($Matches[1])
        if ($app -notmatch $UserWritable -or -not (Test-Path -LiteralPath $app)) { continue }
        $rname = if ($v -match '(?i)\|Name=([^|]+)\|') { $Matches[1] } else { $n }
        $cands += , @($n, $app, $rname)
    }
    Update-SigCache @($cands | ForEach-Object { $_[1] })
    foreach ($c in $cands) {
        if (Test-Signed $c[1]) { continue }
        Add-Finding 'SUSPICIOUS' 'Firewall rule' "The firewall lets the network reach '$($c[2])': $($c[1]) (an unsigned program in a user folder)" `
            @{ Type = 'FwRule'; Id = $c[0]; Files = @($c[1]); Desc = 'Delete the rule + quarantine the program' }
    }
}

# =====================================================================
#  Dangerous downloads (files that came from the internet or email)
# =====================================================================
function Check-Downloads {
    $rx = '\.(js|jse|vbs|vbe|wsf|wsh|hta|ps1|bat|cmd|scr|pif|cpl|chm|lnk|iso|img|vhd|vhdx|docm|xlsm|pptm|dotm|xlam|one)$'
    $cut = (Get-Date).AddDays(-60)
    $wsh = New-Object -ComObject WScript.Shell
    foreach ($p in Get-Profiles) {
        foreach ($d in 'Downloads', 'Desktop', 'Documents', 'AppData\Local\Temp', 'AppData\Local\Microsoft\Windows\INetCache\Content.Outlook', 'AppData\Local\Packages\Microsoft.Office.Desktop_8wekyb3d8bbwe') {
            foreach ($f in Get-FilesFast "$p\$d" 5 $rx) {
                if ($script:Flagged.Contains($f)) { continue }
                if (-not (Has-Stream $f 'Zone.Identifier')) { continue }   # only files from the internet / email
                $fi = New-Object IO.FileInfo($f)
                $ext = $fi.Extension.ToLower()
                $q = @{ Type = 'None'; Files = @($f); Desc = 'Quarantine the file' }
                if ($ext -match '^\.(js|jse|vbs|vbe|wsf|wsh|hta|scr|pif|cpl|chm)$') {
                    Add-Finding 'SUSPICIOUS' 'Dangerous download' "Script or program file downloaded from the internet: $f. Normal downloads almost never use this file type." $q
                } elseif ($ext -match '^\.(ps1|bat|cmd)$') {
                    Add-Finding 'WARNING' 'Dangerous download' "Script downloaded from the internet: $f (only keep it if you know what it does)" $q
                } elseif ($ext -eq '.lnk') {
                    $l = $wsh.CreateShortcut($f)
                    $t = "$($l.TargetPath) $($l.Arguments)"
                    if ($t -match '(?i)(powershell|cmd\.exe|mshta|wscript|cscript|rundll32|regsvr32|conhost|curl\.exe|bitsadmin|certutil)') {
                        Add-Finding 'THREAT' 'Malicious shortcut' "Downloaded shortcut runs a hidden command: $f`n       -> $($t.Substring(0, [Math]::Min(200, $t.Length)))" $q
                    }
                } elseif ($ext -match '^\.(iso|img|vhd|vhdx)$') {
                    if ($fi.Length -lt 200MB -and $fi.CreationTime -gt $cut) {
                        Add-Finding 'WARNING' 'Dangerous download' ("Small disk image downloaded: {0} ({1:N0} MB). Malware is often hidden inside disk images." -f $f, ($fi.Length / 1MB)) $q
                    }
                } elseif ($ext -match '^\.(docm|xlsm|pptm|dotm|xlam)$') {
                    Add-Finding 'SUSPICIOUS' 'Macro document' "Office file with macros downloaded from the internet: $f. Do not enable macros unless you trust the sender." $q
                } elseif ($ext -eq '.one') {
                    Add-Finding 'WARNING' 'Dangerous download' "OneNote file downloaded from the internet: $f (used in phishing attacks)" $q
                }
            }
        }
    }
}

# =====================================================================
#  Malicious scripts (looks inside every script)
# =====================================================================
function Check-ScriptContent {
    $ext = '\.(ps1|psm1|vbs|vbe|js|jse|wsf|wsh|hta|bat|cmd|py)$'
    $roots = @()
    if ($Scope -eq 'Complete') {
        foreach ($d in Get-FixedDrives) { $roots += , @($d, 60) }
    } else {
        foreach ($p in Get-Profiles) {
            $roots += , @("$p\Desktop", 6); $roots += , @("$p\Downloads", 6); $roots += , @("$p\Documents", 6)
            $roots += , @("$p\AppData\Roaming", 10); $roots += , @("$p\AppData\Local\Temp", 6); $roots += , @("$p\AppData\Local", 3)
        }
        $roots += , @("$env:SystemDrive\Users\Public", 6); $roots += , @($env:ProgramData, 6)
        $roots += , @("$env:windir\Temp", 4); $roots += , @("$env:windir\Tasks", 2)
    }
    $files = New-Object System.Collections.Generic.List[string]
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($r in $roots) {
        foreach ($f in Get-FilesFast $r[0] $r[1] $ext) {
            if ($f -like "$env:windir\*" -and $f -notlike "$env:windir\Temp\*" -and $f -notlike "$env:windir\Tasks\*") { continue }
            if ($seen.Add($f)) { $files.Add($f) }
        }
    }
    foreach ($hit in (Scan-Scripts $files.ToArray() 2MB)) {
        $a = $hit.Split('|')
        $score = [int]$a[1]
        $lvl = if ($score -ge 6) { 'THREAT' } else { 'SUSPICIOUS' }
        Add-Finding $lvl 'Malicious script' ("Script: {0}`n       What it does: {1} (risk score {2})" -f $a[0], $a[2], $score) `
            @{ Type = 'None'; Files = @($a[0]); Desc = 'Quarantine the script' }
    }
}

# =====================================================================
#  Hidden data streams (NTFS) - a place to hide malware inside a normal file
# =====================================================================
function Check-Ads {
    $ok = '^(Zone\.Identifier|SmartScreen|com\.dropbox\..*|encryptable|favicon|OECustomProperty|AFP_AfpInfo|AFP_Resource|ms-properties|Win32App_1|.*SummaryInformation|.*Q30lsldxJoudresxAaaqpcawXc|\{4c8cc155-6c1e-11d1-8e41-00c04fb9386d\}|KAVICHS|OneDrive.*|\$KERNEL\..*|CA_INOC_.*|SEP_.*|WofCompressedData|AVG.*|avast.*|ESET.*|Bitdefender.*|ms-.*|.*\.mrk|Thumbs\.db.*|apple.*|com\.apple\..*)$'
    $okRx = New-Object System.Text.RegularExpressions.Regex($ok, 'IgnoreCase')
    $roots = @()
    if ($Scope -eq 'Complete') {
        foreach ($d in Get-FixedDrives) { $roots += , @($d, 40) }
    } else {
        foreach ($p in Get-Profiles) {
            $roots += , @("$p\Desktop", 6); $roots += , @("$p\Downloads", 6); $roots += , @("$p\Documents", 6)
            $roots += , @("$p\AppData\Roaming", 6); $roots += , @("$p\AppData\Local\Temp", 4)
        }
        $roots += , @("$env:SystemDrive\Users\Public", 6); $roots += , @($env:ProgramData, 4); $roots += , @("$env:windir\Temp", 4)
    }
    $n = 0
    foreach ($r in $roots) {
        $hits = $null
        if ($script:UseNative) {
            try { $hits = [MwNative]::FindStreams($r[0], $r[1], $SkipDirs, $ok, 2048) } catch { $hits = $null }
        }
        if ($null -eq $hits) {
            # PowerShell fallback: walk the files, read their streams with Get-Item -Stream *
            $hits = New-Object System.Collections.Generic.List[string]
            foreach ($f in (Find-FilesPS $r[0] $r[1] '.')) {
                try {
                    foreach ($st in @(Get-Item -LiteralPath $f -Stream * -ErrorAction Stop)) {
                        $sn = $st.Stream
                        if ($sn -eq ':$DATA' -or $sn -eq '' -or $st.Length -lt 2048 -or $okRx.IsMatch($sn)) { continue }
                        $hits.Add(("{0}|{1}|{2}" -f $f, $sn, $st.Length))
                    }
                } catch {}
            }
        }
        foreach ($hit in $hits) {
            $a = $hit.Split('|')
            $path = $a[0]; $stream = $a[1]; $size = [long]$a[2]
            $lvl = 'SUSPICIOUS'; $extra = ''
            try {
                $b = @(Get-Content -LiteralPath $path -Stream $stream -Encoding Byte -TotalCount 2 -ErrorAction Stop)
                if ($b.Count -ge 2 -and $b[0] -eq 77 -and $b[1] -eq 90) { $lvl = 'THREAT'; $extra = ' It contains a hidden program.' }
            } catch {}
            Add-Finding $lvl 'Hidden data' ("A hidden data stream '{0}' ({1:N0} KB) is attached to {2}.{3}" -f $stream, ($size / 1KB), $path, $extra) `
                @{ Type = 'Stream'; Path = $path; Stream = $stream; Desc = 'Delete the hidden stream (the file itself stays)' }
            $n++
            if ($n -ge 50) { return }
        }
    }
}

# =====================================================================
#  USB worms (shortcut viruses, autorun)
# =====================================================================
function Check-Usb {
    if ($NoUsb) { return }
    $wsh = New-Object -ComObject WScript.Shell
    foreach ($drv in Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=2') {
        $root = "$($drv.DeviceID)\"
        $ar = Join-Path $root 'autorun.inf'
        if (Test-Path -LiteralPath $ar) {
            Add-Finding 'SUSPICIOUS' 'USB worm' "USB drive $($drv.DeviceID) has an autorun file (old USB-worm trick): $ar" @{ Type = 'None'; Files = @($ar); Desc = 'Quarantine the autorun file' }
        }
        foreach ($l in Get-ChildItem -LiteralPath $root -Filter '*.lnk' -File -Force) {
            $s = $wsh.CreateShortcut($l.FullName)
            $t = "$($s.TargetPath) $($s.Arguments)"
            if ($t -match '(?i)(cmd\.exe|powershell|wscript|cscript|rundll32|mshta|\.vbs\b|\.js\b|\.wsf\b)') {
                Add-Finding 'THREAT' 'USB worm' "Shortcut on the USB drive runs a hidden command (shortcut virus): $($l.FullName)`n       -> $($t.Substring(0, [Math]::Min(200, $t.Length)))" `
                    @{ Type = 'None'; Files = @($l.FullName); Desc = 'Quarantine the shortcut' }
            }
        }
        foreach ($s in Get-ChildItem -LiteralPath $root -File -Force | Where-Object { $_.Extension -match '(?i)^\.(vbs|vbe|js|jse|wsf|bat|cmd|scr|pif)$' }) {
            Add-Finding 'SUSPICIOUS' 'USB worm' "Script on the root of the USB drive: $($s.FullName)" @{ Type = 'None'; Files = @($s.FullName); Desc = 'Quarantine the script' }
        }
        foreach ($d in Get-ChildItem -LiteralPath $root -Directory -Force) {
            if ($d.Name -in @('System Volume Information', '$RECYCLE.BIN', 'RECYCLER')) { continue }
            if (($d.Attributes -band [IO.FileAttributes]::Hidden) -and ($d.Attributes -band [IO.FileAttributes]::System)) {
                Add-Finding 'WARNING' 'USB worm' "Folder '$($d.FullName)' is hidden as a system folder. Shortcut viruses hide your files like this." `
                    @{ Type = 'Unhide'; Path = $d.FullName; Desc = 'Make the folder visible again' }
            }
        }
    }
}

# =====================================================================
#  Traces of recent attacks (event logs, earlier detections)
# =====================================================================
function Check-History {
    $threats = @{}
    foreach ($t in @(Get-MpThreat)) { $threats[[string]$t.ThreatID] = $t }
    $since = (Get-Date).AddDays(-30)
    $n = 0
    foreach ($d in @(Get-MpThreatDetection | Where-Object { $_ -and $_.InitialDetectionTime -ge $since -and $_.InitialDetectionTime -lt $script:ScanStart } | Sort-Object InitialDetectionTime -Descending)) {
        $t = $threats[[string]$d.ThreatID]
        if ($t -and $t.IsActive) { continue }    # still active ones are reported by the virus scan
        $n++; if ($n -gt 10) { break }
        $name = if ($t) { $t.ThreatName } else { "Threat ID $($d.ThreatID)" }
        Add-Finding 'WARNING' 'Past detection' ("{0:yyyy-MM-dd}: Microsoft Defender found {1} ({2})`n       {3}" -f $d.InitialDetectionTime, $name, "$($StatusMap[[int]$d.ThreatStatusID])".ToLower(), (@($d.Resources) -join "`n       ")) $null
    }
    try {
        $ev = Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-PowerShell/Operational'; Id = 4104; Level = 3; StartTime = (Get-Date).AddDays(-7) } -MaxEvents 300 -ErrorAction Stop
        $n = 0
        foreach ($e in $ev) {
            $text = [string]$e.Properties[2].Value
            $spath = [string]$e.Properties[4].Value
            if ($spath -and ($spath -like "$Root*" -or $spath -like '*SimpleMalwareScanner*')) { continue }
            if ($text -match 'MwNative|Varden|MALWAREA|SimpleMalwareScanner|Check-Autoruns') { continue }
            $n++; if ($n -gt 5) { break }
            $one = ($text -replace '\s+', ' ').Trim()
            $one = $one.Substring(0, [Math]::Min(180, $one.Length))
            $from = if ($spath) { " ($spath)" } else { '' }
            $files = @(@($spath) | Where-Object { $_ -and (Test-Path -LiteralPath $_) -and $_ -notlike "$env:windir\*" })
            $fix = if ($files.Count) { @{ Type = 'None'; Files = $files; Desc = 'Quarantine the script' } } else { $null }
            Add-Finding 'SUSPICIOUS' 'Script activity' ("{0:yyyy-MM-dd HH:mm}: Windows flagged a suspicious PowerShell script{1}:`n       {2}" -f $e.TimeCreated, $from, $one) $fix
        }
    } catch {}
    try {
        foreach ($e in Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 7045; StartTime = (Get-Date).AddDays(-14) } -MaxEvents 200 -ErrorAction Stop) {
            $svc = [string]$e.Properties[0].Value
            $img = [string]$e.Properties[1].Value
            if ($img -notmatch $UserWritable -and $img -notmatch $BadCmd) { continue }
            Add-Finding 'SUSPICIOUS' 'New service' ("{0:yyyy-MM-dd HH:mm}: service '{1}' was installed and runs: {2}" -f $e.TimeCreated, $svc, $img) `
                @{ Type = 'Service'; Name = $svc; Files = (Test-Command $img).Files; Desc = 'Stop + disable it, quarantine its file' }
        }
    } catch {}
    try {
        $c = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 104; StartTime = (Get-Date).AddDays(-30) } -MaxEvents 3 -ErrorAction Stop)
        if ($c.Count) {
            Add-Finding 'WARNING' 'Event log' ("A Windows event log was cleared on {0:yyyy-MM-dd}. Attackers do this to hide their tracks (cleanup tools do it too)." -f $c[0].TimeCreated) $null
        }
    } catch {}
}

# =====================================================================
#  Console front-end  (minimalist, shows everything it does)
# =====================================================================
function Emit-Count { try { Write-Host ("`r   ~  {0,-34} {1,11:N0} files " -f $script:CurName, $script:FileCount) -NoNewline -ForegroundColor DarkGray } catch {} }
function Emit-Progress([int]$Pct, [string]$Text) { }

$AllChecks = [ordered]@{
    startup    = @('Programs that start with Windows',  { Check-Autoruns })
    tasks      = @('Scheduled tasks',                   { Check-Tasks })
    services   = @('Services and drivers',              { Check-Services; Check-Drivers })
    processes  = @('Running programs',                  { Check-Processes })
    files      = @('Places malware hides',              { Check-Files })
    scriptscan = @('Malicious scripts',                 { Check-ScriptContent })
    downloads  = @('Dangerous downloads',               { Check-Downloads })
    ransomware = @('Ransomware',                         { Check-Ransomware })
    miners     = @('Crypto miners',                     { Check-Miners })
    remote     = @('Remote-access tools',               { Check-RemoteAccess })
    browser    = @('Browser hijackers',                 { Check-Browsers })
    pups       = @('Adware and unwanted programs',      { Check-Pups })
    network    = @('Hosts file, proxy and DNS',         { Check-Network })
    certs      = @('Fake security certificates',        { Check-Certs })
    boot       = @('Start-up / boot settings',          { Check-Boot })
    hooks      = @('DLL hooks and hijacks',             { Check-Hooks })
    hidden     = @('Hidden triggers',                   { Check-Wmi; Check-Bits })
    scripts    = @('Auto-loading scripts and macros',   { Check-ScriptAutoload })
    sysfiles   = @('Replaced Windows files',            { Check-SystemFiles })
    usb        = @('USB worms',                         { Check-Usb })
    firewall   = @('Firewall rules',                    { Check-FirewallRules })
    security   = @('Security settings (AV, firewall)',  { Check-Security })
    history    = @('Recent attack traces',              { Check-History })
}

function Line([string]$ch) { Write-Host ("   " + ($ch * 60)) -ForegroundColor DarkGray }

function Banner {
    Clear-Host
    Write-Host ''
    Write-Host '    V A R D E N' -ForegroundColor Cyan
    Write-Host '    malware scanner  .  reads every hiding place on your PC' -ForegroundColor DarkGray
    Write-Host ''
}

function Run-Check([string]$name, [scriptblock]$block) {
    $script:CurName = $name
    $before = $script:Findings.Count
    Write-Host ("`r   .  {0,-34} {1,16}" -f $name, 'scanning...') -NoNewline -ForegroundColor DarkGray
    try { & $block | Out-Null } catch { Log "Check '$name' ERROR: $($_.Exception.Message)" }
    $found = $script:Findings.Count - $before
    if ($found -gt 0) {
        Write-Host ("`r   !  {0,-34} {1,16}" -f $name, ("$found found")) -ForegroundColor Yellow
    } else {
        Write-Host ("`r   +  {0,-34} {1,16}" -f $name, 'clean') -ForegroundColor Green
    }
}

function Run-Scan([string]$Mode) {
    $script:Findings = New-Object System.Collections.ArrayList
    $script:Flagged  = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $script:SigCache = @{}
    $script:NThreat = 0; $script:NSus = 0; $script:FileCount = 0
    $script:Scope = if ($Mode -eq 'Full') { 'Complete' } else { 'Quick' }
    $started = Get-Date; $script:ScanStart = $started
    try { Set-Content -LiteralPath $LogFile -Value ("==== Varden $Mode scan {0} ====" -f (Get-Date)) -Encoding UTF8 } catch {}
    Log ("PowerShell=$($PSVersionTable.PSVersion) 64bit=$([Environment]::Is64BitProcess) Scope=$($script:Scope)")

    Banner
    Write-Host ("   $Mode scan  .  started $($started.ToString('HH:mm'))") -ForegroundColor White
    $profs = @(Get-Profiles)
    if ($profs.Count -eq 0) { Write-Host '   NOTE: no user folders readable - are you running as administrator?' -ForegroundColor Yellow }
    Write-Host ''

    # Microsoft Defender virus scan in the background
    $defJob = $null; $defState = 'not available'
    if (-not $NoUpdate) { try { Update-MpSignature -ErrorAction Stop } catch {} }
    try {
        $st = Get-MpComputerStatus -ErrorAction Stop
        if ($st -and $st.AntivirusEnabled) {
            $type = if ($Mode -eq 'Full') { 'FullScan' } else { 'QuickScan' }
            $defJob = Start-Job { param($t) Start-MpScan -ScanType $t } -ArgumentList $type
            $defState = "running ($type) in the background"
        }
    } catch {}
    Write-Host ("   Microsoft Defender virus scan: {0}" -f $defState) -ForegroundColor DarkGray
    Write-Host ''
    Write-Host '   Checking:' -ForegroundColor White

    $keys = @($AllChecks.Keys)
    foreach ($k in $keys) { Run-Check $AllChecks[$k][0] $AllChecks[$k][1] }

    if ($defJob) {
        $script:CurName = 'Microsoft Defender virus scan'
        Write-Host ("`r   .  {0,-34} {1,16}" -f $script:CurName, 'finishing...') -NoNewline -ForegroundColor DarkGray
        Wait-Job $defJob -Timeout ([int]($Minutes * 60)) | Out-Null
        Remove-Job $defJob -Force
        Get-DefenderDetections $started.AddMinutes(-1)
        Write-Host ("`r   +  {0,-34} {1,16}" -f $script:CurName, 'done') -ForegroundColor Green
    }

    foreach ($f in $script:Findings) {
        if (-not $f.Fix) { continue }
        $f.Hashes = @(@($f.Fix.Files) | Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Leaf) } | ForEach-Object {
            $h = (Get-FileHash -LiteralPath $_ -Algorithm SHA256).Hash; if ($h) { "$h  $_" } })
    }
    foreach ($f in $script:Findings) { $f | Add-Member -NotePropertyName Group -NotePropertyValue (Get-Group $f) -Force }
    $script:List = @($script:Findings | Sort-Object Group, Area)
    $g1 = @($script:List | Where-Object { $_.Group -eq 1 }).Count
    $g2 = @($script:List | Where-Object { $_.Group -eq 2 }).Count
    $g3 = @($script:List | Where-Object { $_.Group -eq 3 }).Count
    $took = (Get-Date) - $started
    Log ("DONE files=$($script:FileCount) remove=$g1 check=$g2 note=$g3 total=$($script:List.Count)")

    # ---- verdict ----
    Write-Host ''
    Line '='
    if ($g1 -gt 0) {
        Write-Host ("   [!]  ACTION NEEDED  -  {0} real threat(s) you should remove" -f $g1) -ForegroundColor Red
    } elseif ($g2 -gt 0) {
        Write-Host ("   [~]  no confirmed threats  -  {0} item(s) worth a quick look" -f $g2) -ForegroundColor Yellow
    } else {
        Write-Host '   [OK]  YOUR COMPUTER LOOKS SAFE  -  nothing dangerous was found' -ForegroundColor Green
    }
    Line '='
    Write-Host ("   {0} to remove   .   {1} to check   .   {2} notes   .   {3:N0} files checked   .   {4:mm\:ss}" -f $g1, $g2, $g3, $script:FileCount, $took) -ForegroundColor DarkGray

    Show-Results
    try { if ($script:NThreat -gt 0) { [Media.SystemSounds]::Exclamation.Play() } else { [Media.SystemSounds]::Asterisk.Play() } } catch {}
    Ask-And-Fix
    Save-Report $Mode $started
}

# How sure are we?  1 = real threat (remove)   2 = check it (could be your own program)   3 = info / settings
function Get-Group($f) {
    if ($f.Area -eq 'Virus (Defender)') { return 1 }
    switch ($f.Level) { 'THREAT' { 1 } 'SUSPICIOUS' { 2 } default { 3 } }
}
$script:GroupInfo = @{
    1 = @{ Tag = 'REMOVE'; Color = 'Red'; Head = 'REAL THREATS  -  you should remove these';
           Advice = 'Almost certainly malicious. Removing them is safe and recommended.' }
    2 = @{ Tag = 'CHECK '; Color = 'Yellow'; Head = 'CHECK THESE  -  malware, OR a program you installed yourself';
           Advice = 'Look at each file name. If you RECOGNISE it (a game, an app, a driver you installed) KEEP it. If you do NOT recognise it, remove it. Most of these are simply programs that are not digitally signed - not always malware.' }
    3 = @{ Tag = 'NOTE  '; Color = 'DarkYellow'; Head = 'GOOD TO KNOW  -  settings and history (usually NOT malware)';
           Advice = 'These are settings or past events, not files to delete. Only change one if it does not match how you use your PC.' }
}

function Show-Results {
    if ($script:List.Count -eq 0) { return }
    $num = 0
    foreach ($g in 1, 2, 3) {
        $items = @($script:List | Where-Object { $_.Group -eq $g })
        if (-not $items.Count) { continue }
        $gi = $script:GroupInfo[$g]
        Write-Host ''
        Line '-'
        Write-Host ("   {0}" -f $gi.Head) -ForegroundColor $gi.Color
        Write-Host ("   {0}" -f $gi.Advice) -ForegroundColor DarkGray
        Line '-'
        foreach ($f in $items) {
            $num++
            Write-Host ("   {0,2}. [{1}]  {2}" -f $num, $gi.Tag.Trim(), $f.Area) -ForegroundColor $gi.Color
            foreach ($ln in ($f.Text -split "`n")) { if ($ln.Trim()) { Write-Host ('        ' + $ln.Trim()) -ForegroundColor Gray } }
            foreach ($h in $f.Hashes) { Write-Host ('        check this file online:  https://www.virustotal.com/gui/file/' + ($h.Split(' ')[0])) -ForegroundColor DarkGray }
            if ($f.Fix) { Write-Host ('        if removed: ' + $f.Fix.Desc) -ForegroundColor DarkGray } else { Write-Host '        (nothing to remove - information only)' -ForegroundColor DarkGray }
            Write-Host ''
        }
    }
}

function Ask-And-Fix {
    $fixable = @(); for ($i = 0; $i -lt $script:List.Count; $i++) { if ($script:List[$i].Fix) { $fixable += ($i + 1) } }
    if (-not $fixable.Count) { return }
    $threats = @($fixable | Where-Object { $script:List[$_ - 1].Group -eq 1 })
    Write-Host ''
    Write-Host '   WHAT TO DO:' -ForegroundColor White
    Write-Host '     REMOVE items  ->  delete them (recommended).' -ForegroundColor DarkGray
    Write-Host '     CHECK items   ->  keep what you recognise, remove what you do not.' -ForegroundColor DarkGray
    Write-Host '     NOTE items    ->  usually leave alone.' -ForegroundColor DarkGray
    Write-Host '   Everything removed goes to quarantine and can be restored later.' -ForegroundColor DarkGray
    Write-Host ''
    $prompt = if ($threats.Count) { "   Remove what?  [R] the $($threats.Count) real threat(s) (recommended)   [A]ll   numbers (e.g. 2,5)   Enter = skip" }
              else { "   Remove what?  [A]ll flagged   numbers (e.g. 2,5)   Enter = skip" }
    $ans = Read-Host $prompt
    $pick = @()
    if ($ans -match '^\s*[rR]\s*$') { $pick = $threats }
    elseif ($ans -match '^\s*[aA]\s*$') { $pick = $fixable }
    elseif ($ans) { foreach ($s in ($ans -split '[,\s]+')) { $n = 0; if ([int]::TryParse($s, [ref]$n) -and $fixable -contains $n) { $pick += $n } } }
    foreach ($n in ($pick | Select-Object -Unique)) {
        $f = $script:List[$n - 1]
        try { Invoke-Fix $f; $f.Result = 'FIXED'; Write-Host "   [$n] removed and quarantined" -ForegroundColor Green }
        catch { $f.Result = "FAILED: $($_.Exception.Message)"; Write-Host "   [$n] could not remove: $($_.Exception.Message)" -ForegroundColor Red }
    }
    if ($pick.Count) { Write-Host '   Done. Please restart your PC to finish the cleanup.' -ForegroundColor White }
}

function Save-Report([string]$Mode, [datetime]$Started) {
    $r1 = @($script:List | Where-Object { $_.Group -eq 1 }).Count
    $r2 = @($script:List | Where-Object { $_.Group -eq 2 }).Count
    $r3 = @($script:List | Where-Object { $_.Group -eq 3 }).Count
    $lines = @("Varden - $Mode scan report", ('=' * 48), "Computer : $env:COMPUTERNAME",
               "When     : $($Started.ToString('yyyy-MM-dd HH:mm'))", "Files    : $($script:FileCount)",
               "Result   : $r1 to REMOVE (real threats), $r2 to CHECK, $r3 notes", '',
               "Legend   : REMOVE = delete it.  CHECK = keep if you recognise it, else remove.  NOTE = usually leave alone.", '')
    $lastG = 0; $i = 0
    foreach ($f in $script:List) { $i++
        if ($f.Group -ne $lastG) { $lastG = $f.Group; $lines += ''; $lines += ('=== ' + $script:GroupInfo[$f.Group].Head + ' ===') }
        $tag = $script:GroupInfo[$f.Group].Tag.Trim()
        $lines += "[$i] $tag - $($f.Area)"
        foreach ($ln in ($f.Text -split "`n")) { if ($ln.Trim()) { $lines += '      ' + $ln.Trim() } }
        foreach ($h in $f.Hashes) { $lines += "      SHA256 $h" }
        if ($f.Result) { $lines += "      Result: $($f.Result)" }
        $lines += '' }
    $lines += "Quarantine: $QDir"
    $name = 'Varden-Report_{0}.txt' -f (Get-Date -Format 'yyyy-MM-dd_HH-mm')
    $out = Join-Path ([Environment]::GetFolderPath('Desktop')) $name
    try {
        Set-Content -LiteralPath $out -Value $lines -Encoding UTF8
        Write-Host ''
        Write-Host "   A full report was saved to your Desktop:" -ForegroundColor Green
        Write-Host "   $name" -ForegroundColor White
        Start-Process notepad.exe -ArgumentList "`"$out`"" -ErrorAction SilentlyContinue
    } catch {}
}

function Restore-Menu {
    $items = @()
    if (Test-Path -LiteralPath $QLog) {
        $items = @(Get-Content -LiteralPath $QLog | ForEach-Object { $a = $_ -split "`t"; if ($a.Count -ge 3) { [pscustomobject]@{ Id = $a[0]; Date = $a[1]; Path = $a[2] } } } |
            Where-Object { Test-Path -LiteralPath (Join-Path $QDir "$($_.Id).quarantined") })
    }
    if (-not $items.Count) { Write-Host '   The quarantine is empty.' -ForegroundColor Green; return }
    for ($i = 0; $i -lt $items.Count; $i++) { Write-Host ("   [{0}] {1}  {2}" -f ($i + 1), $items[$i].Date, $items[$i].Path) }
    $ans = Read-Host '   Number to restore (Enter to cancel)'
    $n = 0; if (-not [int]::TryParse($ans, [ref]$n) -or $n -lt 1 -or $n -gt $items.Count) { return }
    $it = $items[$n - 1]
    try {
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $it.Path) | Out-Null
        Move-Item -LiteralPath (Join-Path $QDir "$($it.Id).quarantined") -Destination $it.Path -ErrorAction Stop
        Write-Log "Restored $($it.Path)"; Write-Host "   Restored: $($it.Path)" -ForegroundColor Green
    } catch { Write-Host "   Could not restore: $($_.Exception.Message)" -ForegroundColor Red }
}

# ---- entry point ----
if ($Scan -eq 'Quick') { Run-Scan 'Quick'; Write-Host ''; Read-Host '   Press Enter to close' | Out-Null; return }
if ($Scan -eq 'Full')  { Run-Scan 'Full';  Write-Host ''; Read-Host '   Press Enter to close' | Out-Null; return }

while ($true) {
    Banner
    Write-Host '    1    Quick scan    the places malware hides  (a few minutes)' -ForegroundColor White
    Write-Host '    2    Full scan     every file + full virus scan  (longer)' -ForegroundColor White
    Write-Host '    3    Quarantine    restore something you removed' -ForegroundColor White
    Write-Host '    4    Exit' -ForegroundColor White
    Write-Host ''
    switch (Read-Host '    Choose 1-4') {
        '1' { Run-Scan 'Quick'; Write-Host ''; Read-Host '    Press Enter for the menu' | Out-Null }
        '2' { Run-Scan 'Full';  Write-Host ''; Read-Host '    Press Enter for the menu' | Out-Null }
        '3' { Banner; Restore-Menu; Write-Host ''; Read-Host '    Press Enter for the menu' | Out-Null }
        '4' { return }
        default { }
    }
}
