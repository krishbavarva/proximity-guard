# guard.ps1 - Proximity Guard v3 (push approval + anti-theft location alerts)
#
# 1) Unlock approval: every time the laptop is unlocked (or the guard starts at
#    sign-in), your iPhone gets a one-time 6-digit code. Type it on the laptop to
#    continue. Wrong code 3 times / no answer in time -> the laptop locks again.
#    Your backup code also works (phone dead / no internet).
# 2) Anti-theft (v3): while the laptop is LOCKED you get an urgent alert with its
#    location (map link, Wi-Fi name, IP city, battery) when:
#      - the charger is unplugged
#      - the laptop wakes up from sleep
#      - it joins a different Wi-Fi network (it is being moved)
#      - someone fails the unlock code
#    After an alert, location updates keep coming every few minutes until you
#    unlock with your code. Alerts that cannot be sent (no internet) are queued
#    and sent, with the new location, as soon as the laptop is online again.
# 3) Library mode: run with -Library before you walk away. It locks the screen
#    and keeps the laptop awake (no idle sleep) so an unplug is caught at once.
#
# Usage (from the proximity-guard folder):
#   powershell -ExecutionPolicy Bypass -File .\guard.ps1 -Setup         # secret topic + backup code
#   powershell -ExecutionPolicy Bypass -File .\guard.ps1 -TestAlert     # check notifications reach the iPhone
#   powershell -ExecutionPolicy Bypass -File .\guard.ps1 -TestApprove   # try one approval without locking
#   powershell -ExecutionPolicy Bypass -File .\guard.ps1 -TestLocation  # send your current location to the iPhone
#   powershell -ExecutionPolicy Bypass -File .\guard.ps1 -Library       # library mode: lock + stay awake
#   powershell -ExecutionPolicy Bypass -File .\guard.ps1 -BootAlert     # (startup task) alert when Windows starts
#   powershell -ExecutionPolicy Bypass -File .\guard.ps1 -BarkKey <key> # also send alerts through the Bark iPhone app
#   powershell -ExecutionPolicy Bypass -File .\guard.ps1                # run the guard

param(
  [switch]$Setup,
  [switch]$TestAlert,
  [switch]$TestApprove,
  [switch]$TestLocation,
  [switch]$Library,
  [switch]$BootAlert,
  [string]$BarkKey = ''
)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$configPath = Join-Path $here 'config.json'
$logFile = Join-Path $here 'guard.log'
$pendingFile = Join-Path $here 'pending.txt'     # alerts waiting for internet
$libraryFlag = Join-Path $here 'library.flag'    # library mode is on until this time
$server = 'https://ntfy.sh'
$inv = [Globalization.CultureInfo]::InvariantCulture

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

if (-not (Test-Path $configPath)) {
  Copy-Item (Join-Path $here 'config.example.json') $configPath
}
$cfg = Get-Content $configPath -Raw | ConvertFrom-Json

# Fill in any setting missing from an older config.json.
$defaults = @{ alertTopic = ''; approvalSeconds = 90; maxAttempts = 3; maxPushPer10Min = 3;
               checkEverySeconds = 2; backupCodeSalt = ''; backupCodeHash = '';
               theftAlerts = $true; trackEveryMinutes = 3; libraryHours = 4; barkKey = '' }
foreach ($k in $defaults.Keys) {
  if (-not ($cfg.PSObject.Properties.Name -contains $k)) {
    $cfg | Add-Member -NotePropertyName $k -NotePropertyValue $defaults[$k]
  }
}

# ---------------------------------------------------------------- helpers

function Write-Log([string]$msg) {
  $line = '{0}  {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $msg
  try { Add-Content -Path $logFile -Value $line } catch {}
  Write-Host $line
}

function Save-Config {
  $cfg | ConvertTo-Json -Depth 5 | Set-Content -Path $configPath -Encoding UTF8
}

function New-RandomString([int]$length) {
  $chars = 'abcdefghijkmnopqrstuvwxyz23456789'
  $bytes = New-Object byte[] $length
  [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
  return -join ($bytes | ForEach-Object { $chars[$_ % $chars.Length] })
}

function Get-RandomInt([int]$min, [int]$max) {
  $bytes = New-Object byte[] 4
  [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
  return [int]($min + ([BitConverter]::ToUInt32($bytes, 0) % ($max - $min + 1)))
}

# Backup code is never stored in clear text: random salt + PBKDF2 (100 000 x SHA-256).
function Get-CodeHash([string]$code, [byte[]]$salt) {
  $kdf = New-Object System.Security.Cryptography.Rfc2898DeriveBytes(
    $code, $salt, 100000, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
  return [Convert]::ToBase64String($kdf.GetBytes(32))
}

# Constant-time comparison: timing cannot reveal how many characters were right.
function Test-SameString([string]$a, [string]$b) {
  if ($a.Length -ne $b.Length) { return $false }
  $diff = 0
  for ($i = 0; $i -lt $a.Length; $i++) { $diff = $diff -bor ([int][char]$a[$i] -bxor [int][char]$b[$i]) }
  return ($diff -eq 0)
}

function Test-BackupCode([string]$code) {
  if (-not $cfg.backupCodeHash -or -not $code) { return $false }
  $salt = [Convert]::FromBase64String($cfg.backupCodeSalt)
  return (Test-SameString (Get-CodeHash $code $salt) $cfg.backupCodeHash)
}

# LogonUI.exe runs while the Windows lock screen is shown.
function Test-ScreenLocked {
  return [bool](Get-Process -Name 'LogonUI' -ErrorAction SilentlyContinue)
}

function Lock-Screen {
  Start-Process -FilePath 'rundll32.exe' -ArgumentList 'user32.dll,LockWorkStation'
}

# Bark (iPhone app, Apple push): reliable on the lock screen.
# urgent -> critical alert (rings even in silent / Do Not Disturb, repeats 30 s)
# high -> time-sensitive (shows through Focus), default -> normal, low -> quiet.
function Send-Bark([string]$title, [string]$message, [string]$priority, [string]$click) {
  if (-not $cfg.barkKey) { return $false }
  $level = @{ urgent = 'critical'; high = 'timeSensitive'; default = 'active'; low = 'passive' }[$priority]
  if (-not $level) { $level = 'active' }
  $payload = @{ title = $title; body = $message; level = $level; group = 'Proximity Guard' }
  if ($click) { $payload['url'] = $click }
  if ($level -eq 'critical') { $payload['volume'] = 10; $payload['call'] = '1'; $payload['sound'] = 'alarm' }
  try {
    $json = [Text.Encoding]::UTF8.GetBytes(($payload | ConvertTo-Json -Compress))
    $r = Invoke-RestMethod -Method Post -Uri "https://api.day.app/$($cfg.barkKey)" -Body $json `
           -ContentType 'application/json; charset=utf-8' -TimeoutSec 8
    return ($r.code -eq 200)
  } catch {
    Write-Log ('Bark notification could not be sent: ' + $_.Exception.Message)
    return $false
  }
}

# Notification to your iPhone: Bark (if set up) + ntfy app subscribed to alertTopic.
# $click: link opened when you tap the notification (the map).
# Returns $true if at least one of them got it.
function Send-Alert([string]$title, [string]$message, [string]$priority = 'high',
                    [string]$actions = '', [string]$click = '', [string]$tags = 'lock') {
  $okBark = Send-Bark $title $message $priority $click
  $okNtfy = $false
  if ($cfg.alertTopic) {
    $headers = @{ Title = $title; Priority = $priority; Tags = $tags }
    if ($actions) { $headers['Actions'] = $actions }
    if ($click) { $headers['Click'] = $click }
    try {
      $body = [Text.Encoding]::UTF8.GetBytes($message)
      Invoke-RestMethod -Method Post -Uri "$server/$($cfg.alertTopic)" -Body $body -Headers $headers -TimeoutSec 8 | Out-Null
      $okNtfy = $true
    } catch {
      Write-Log ('ntfy notification could not be sent: ' + $_.Exception.Message)
    }
  }
  return ($okBark -or $okNtfy)
}

function Test-Online {
  try {
    Invoke-WebRequest -Uri "$server/v1/health" -UseBasicParsing -TimeoutSec 4 | Out-Null
    return $true
  } catch { return $false }
}

# ---------------------------------------------------------------- location

# Windows Location service (Wi-Fi positioning: often street-level in a city).
# Needs: Settings > Privacy & security > Location > ON, and
#        "Let desktop apps access your location" > ON.
function Get-WinLocation {
  try {
    Add-Type -AssemblyName System.Device
    $w = New-Object System.Device.Location.GeoCoordinateWatcher([System.Device.Location.GeoPositionAccuracy]::High)
    $w.Start()
    $deadline = (Get-Date).AddSeconds(15)
    while ((Get-Date) -lt $deadline) {
      if ($w.Permission -eq 'Denied') { break }
      if (-not $w.Position.Location.IsUnknown) { break }
      Start-Sleep -Milliseconds 500
    }
    $loc = $w.Position.Location
    $perm = $w.Permission
    $w.Stop(); $w.Dispose()
    if ($loc -and -not $loc.IsUnknown) {
      return @{ lat = $loc.Latitude.ToString('0.000000', $inv); lon = $loc.Longitude.ToString('0.000000', $inv);
                acc = [int]$loc.HorizontalAccuracy }
    }
    if ($perm -eq 'Denied') { Write-Log 'Windows location denied: turn on location for desktop apps' }
  } catch { Write-Log ('Windows location failed: ' + $_.Exception.Message) }
  return $null
}

# Public IP -> approximate city (works without the Windows Location service).
function Get-IpLocation {
  try { return (Invoke-RestMethod -Uri 'https://ipinfo.io/json' -TimeoutSec 6) } catch { return $null }
}

function Get-WifiName {
  try {
    $line = netsh wlan show interfaces | Where-Object { $_ -match '^\s+SSID\s+:' } | Select-Object -First 1
    if ($line) { return ($line -split ':', 2)[1].Trim() }
  } catch {}
  return ''
}

function Test-OnCharger {
  return ([System.Windows.Forms.SystemInformation]::PowerStatus.PowerLineStatus -eq 'Online')
}

function Get-PowerText {
  $p = [System.Windows.Forms.SystemInformation]::PowerStatus
  $pct = [int]($p.BatteryLifePercent * 100)
  if ($p.PowerLineStatus -eq 'Online') { return "Battery $pct% (charger plugged in)" }
  return "Battery $pct% (on battery, charger unplugged)"
}

# Everything we know about where the laptop is right now.
function Get-LocationReport([switch]$NoWindowsLocation) {
  $lines = @()
  $click = ''
  if (-not $NoWindowsLocation) {
    $w = Get-WinLocation
    if ($w) {
      $click = "https://maps.google.com/?q=$($w.lat),$($w.lon)"
      $lines += "Map (Windows location, ~$($w.acc) m): $click"
    }
  }
  $ip = Get-IpLocation
  if ($ip) {
    $lines += "IP $($ip.ip): $($ip.city), $($ip.region), $($ip.country) - $($ip.org)"
    if (-not $click -and $ip.loc) {
      $click = "https://maps.google.com/?q=$($ip.loc)"
      $lines += "Map (IP only, city level): $click"
    }
  }
  $ssid = Get-WifiName
  if ($ssid) { $lines += "Wi-Fi: $ssid" } else { $lines += 'Wi-Fi: not connected' }
  $lines += Get-PowerText
  return @{ text = ($lines -join "`n"); click = $click }
}

# ---------------------------------------------------------------- alarm state

# Keep the laptop awake (no idle sleep) during an alarm or in library mode,
# so it can keep reporting. Does not keep the screen on.
Add-Type -Namespace PG -Name Power -MemberDefinition '[DllImport("kernel32.dll")] public static extern uint SetThreadExecutionState(uint esFlags);'
$ES_CONTINUOUS = [uint32]2147483648
$ES_AWAKE = [uint32]2147483649   # ES_CONTINUOUS | ES_SYSTEM_REQUIRED
$script:awake = $false
function Set-KeepAwake([bool]$on) {
  if ($on -eq $script:awake) { return }
  if ($on) { [void][PG.Power]::SetThreadExecutionState($ES_AWAKE) }
  else { [void][PG.Power]::SetThreadExecutionState($ES_CONTINUOUS) }
  $script:awake = $on
}

function Test-LibraryMode {
  if (-not (Test-Path $libraryFlag)) { return $false }
  try {
    $until = [DateTime]::Parse((Get-Content $libraryFlag -Raw).Trim(), $inv)
    if ((Get-Date) -lt $until) { return $true }
  } catch {}
  Remove-Item $libraryFlag -ErrorAction SilentlyContinue
  return $false
}

$script:alarm = $false
$script:lastTrack = Get-Date

# Urgent alert with location. Starts the alarm (location updates until unlock).
# No internet: queued and sent as soon as the laptop is online again.
function Send-TheftAlert([string]$title, [string]$what, [string]$priority = 'urgent') {
  $script:alarm = $true
  Set-KeepAwake $true
  Write-Log "ALERT: $title"
  $stamp = Get-Date -Format 'HH:mm:ss'
  if (-not (Test-Online)) {
    Add-Content -Path $pendingFile -Value "$stamp  $title"
    Write-Log 'no internet: alert queued'
    $script:lastTrack = Get-Date
    return
  }
  $rep = Get-LocationReport
  $msg = "$what ($stamp)`n$($rep.text)"
  if (-not (Send-Alert $title $msg $priority '' $rep.click 'rotating_light')) {
    Add-Content -Path $pendingFile -Value "$stamp  $title"
  }
  $script:lastTrack = Get-Date
}

# Send queued alerts once the laptop is back online, with the NEW location.
function Send-Pending {
  if (-not (Test-Path $pendingFile)) { return }
  if (-not (Test-Online)) { return }
  $events = (Get-Content $pendingFile -Raw).Trim()
  $rep = Get-LocationReport
  $msg = "Laptop is online again. While offline:`n$events`n`nLocation now:`n$($rep.text)"
  if (Send-Alert 'Laptop back ONLINE' $msg 'urgent' '' $rep.click 'rotating_light') {
    Remove-Item $pendingFile -ErrorAction SilentlyContinue
    Write-Log 'queued alerts sent'
    $script:lastTrack = Get-Date
  }
}

function Clear-Alarm {
  if ($script:alarm) { Write-Log 'alarm cleared (owner unlocked with code)' }
  $script:alarm = $false
  Remove-Item $libraryFlag -ErrorAction SilentlyContinue
  Set-KeepAwake $false
}

# ---------------------------------------------------------------- approval

# Rate limit: max N codes sent per 10 minutes (stops someone from spamming
# your phone with unlock codes).
$script:pushTimes = @()

function Request-Approval([string]$reason, [switch]$NoLock) {
  # One-time 6-digit code, sent to your iPhone, valid only for this request.
  $script:otp = '{0:D6}' -f (Get-RandomInt 0 999999)

  $now = Get-Date
  $script:pushTimes = @($script:pushTimes | Where-Object { ($now - $_).TotalMinutes -lt 10 })
  $script:pushSent = $false
  if ($script:pushTimes.Count -lt $cfg.maxPushPer10Min) {
    $script:pushTimes += $now
    $script:pushSent = Send-Alert ("Laptop unlock code: " + $script:otp) ("$reason at $(Get-Date -Format 'HH:mm'). Type this code on the laptop. If this was not you, do nothing: the laptop will lock again.") 'high'
  } else {
    Write-Log 'too many unlock codes requested: phone code disabled for now, backup code only'
  }

  $script:result = 'timeout'
  $script:remaining = [int]$cfg.approvalSeconds
  $script:attempts = 0

  # Full-screen dark overlay over ALL monitors: nothing else can be clicked
  # until the code is entered or the laptop locks.
  $script:allowClose = $false
  $vs = [System.Windows.Forms.SystemInformation]::VirtualScreen
  $script:form = New-Object System.Windows.Forms.Form
  $script:form.Text = 'Proximity Guard'
  $script:form.FormBorderStyle = 'None'
  $script:form.StartPosition = 'Manual'
  $script:form.Bounds = $vs
  $script:form.TopMost = $true
  $script:form.ShowInTaskbar = $false
  $script:form.BackColor = [System.Drawing.Color]::FromArgb(8, 12, 20)
  $script:form.KeyPreview = $true

  # Panel in the middle of the primary screen.
  $ps = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
  $panel = New-Object System.Windows.Forms.Panel
  $panel.Size = New-Object System.Drawing.Size(520, 260)
  $panel.Location = New-Object System.Drawing.Point([int]($ps.X - $vs.X + ($ps.Width - 520) / 2), [int]($ps.Y - $vs.Y + ($ps.Height - 260) / 2))
  $panel.BackColor = [System.Drawing.Color]::FromArgb(18, 28, 44)
  $script:form.Controls.Add($panel)

  $title = New-Object System.Windows.Forms.Label
  $title.Location = New-Object System.Drawing.Point(24, 18)
  $title.Size = New-Object System.Drawing.Size(470, 34)
  $title.Font = New-Object System.Drawing.Font('Segoe UI', 16, [System.Drawing.FontStyle]::Bold)
  $title.ForeColor = [System.Drawing.Color]::FromArgb(0, 220, 240)
  $title.Text = 'Proximity Guard'
  $panel.Controls.Add($title)

  $info = New-Object System.Windows.Forms.Label
  $info.Location = New-Object System.Drawing.Point(24, 58)
  $info.Size = New-Object System.Drawing.Size(470, 44)
  $info.Font = New-Object System.Drawing.Font('Segoe UI', 11)
  $info.ForeColor = [System.Drawing.Color]::White
  if ($script:pushSent) { $info.Text = 'Enter the 6-digit code sent to your iPhone (or your backup code).' }
  else { $info.Text = 'Phone code unavailable. Enter your backup code.' }
  $panel.Controls.Add($info)

  $script:box = New-Object System.Windows.Forms.TextBox
  $script:box.Location = New-Object System.Drawing.Point(24, 112)
  $script:box.Size = New-Object System.Drawing.Size(330, 36)
  $script:box.Font = New-Object System.Drawing.Font('Segoe UI', 16)
  $script:box.UseSystemPasswordChar = $true
  $panel.Controls.Add($script:box)

  $ok = New-Object System.Windows.Forms.Button
  $ok.Text = 'Unlock'
  $ok.Location = New-Object System.Drawing.Point(368, 111)
  $ok.Size = New-Object System.Drawing.Size(126, 38)
  $ok.Font = New-Object System.Drawing.Font('Segoe UI', 11)
  $ok.ForeColor = [System.Drawing.Color]::White
  $ok.FlatStyle = 'Flat'
  $panel.Controls.Add($ok)
  $script:form.AcceptButton = $ok

  $script:countdown = New-Object System.Windows.Forms.Label
  $script:countdown.Location = New-Object System.Drawing.Point(24, 168)
  $script:countdown.Size = New-Object System.Drawing.Size(470, 60)
  $script:countdown.Font = New-Object System.Drawing.Font('Segoe UI', 11)
  $script:countdown.ForeColor = [System.Drawing.Color]::FromArgb(255, 120, 140)
  $script:countdown.Text = "Locks in $($script:remaining) s"
  $panel.Controls.Add($script:countdown)

  # Block Alt+F4 and any close attempt that does not come from the guard itself.
  $script:form.Add_FormClosing({ param($s, $e) if (-not $script:allowClose) { $e.Cancel = $true } })
  # If another window gets focus (Alt+Tab, Start menu), take focus back.
  $script:form.Add_Deactivate({
    if (-not $script:allowClose) { $script:form.TopMost = $true; $script:form.Activate(); $script:box.Focus() }
  })

  $ok.Add_Click({
    $typed = $script:box.Text.Trim()
    if ($script:pushSent -and (Test-SameString $typed $script:otp)) {
      $script:result = 'approved'
    } elseif (Test-BackupCode $typed) {
      $script:result = 'backup'
    } else {
      $script:attempts++
      $script:box.Text = ''
      if ($script:attempts -lt [int]$cfg.maxAttempts) {
        $script:countdown.Text = "Wrong code ($($script:attempts)/$($cfg.maxAttempts)). Locks in $($script:remaining) s"
        return
      }
      $script:result = 'wrongcode'
    }
    $script:timer.Stop()
    $script:allowClose = $true
    $script:form.Close()
  })

  $script:timer = New-Object System.Windows.Forms.Timer
  $script:timer.Interval = 1000
  $script:timer.Add_Tick({
    $script:remaining--
    $script:countdown.Text = "Locks in $($script:remaining) s"
    if ($script:remaining -le 0) { $script:timer.Stop(); $script:allowClose = $true; $script:form.Close() }
  })
  $script:form.Add_Shown({ $script:form.Activate(); $script:box.Focus(); $script:timer.Start() })
  [void]$script:form.ShowDialog()
  $script:timer.Stop()
  $script:form.Dispose()
  $script:otp = $null   # the code can never be used again

  $result = $script:result
  if ($result -eq 'approved') {
    Write-Log 'approved with the code from the iPhone'
  } elseif ($result -eq 'backup') {
    Write-Log 'unlocked with backup code'
    [void](Send-Alert 'Backup code used' ("Your laptop was unlocked with the backup code at $(Get-Date -Format 'HH:mm').") 'default')
  } else {
    $why = 'no code entered in time'
    if ($result -eq 'wrongcode') { $why = "wrong code $($cfg.maxAttempts) times" }
    if ($NoLock) {
      Write-Log "TEST: would lock now ($why)"
    } else {
      Lock-Screen
      Write-Log "LOCKED: $reason not approved ($why)"
      Send-TheftAlert 'Laptop locked: unlock NOT approved' "$reason was not approved ($why). The laptop was locked again."
    }
  }
  return $result
}

# ---------------------------------------------------------------- modes

if ($Setup) {
  if (-not $cfg.alertTopic) { $cfg.alertTopic = 'pg-' + (New-RandomString 24) }
  $a = Read-Host 'New backup code (at least 6 characters)' -AsSecureString
  $b = Read-Host 'Repeat the backup code' -AsSecureString
  $pa = [Runtime.InteropServices.Marshal]::PtrToStringBSTR([Runtime.InteropServices.Marshal]::SecureStringToBSTR($a))
  $pb = [Runtime.InteropServices.Marshal]::PtrToStringBSTR([Runtime.InteropServices.Marshal]::SecureStringToBSTR($b))
  if ($pa -ne $pb) { Write-Host 'The two codes are different. Nothing saved.' -ForegroundColor Red; exit 1 }
  if ($pa.Length -lt 6) { Write-Host 'Too short: use at least 6 characters.' -ForegroundColor Red; exit 1 }
  $salt = New-Object byte[] 16
  [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($salt)
  $cfg.backupCodeSalt = [Convert]::ToBase64String($salt)
  $cfg.backupCodeHash = Get-CodeHash $pa $salt
  Save-Config
  Write-Host ''
  Write-Host 'Setup saved.' -ForegroundColor Green
  Write-Host 'In the ntfy app on your iPhone, tap + and subscribe to this topic:' -ForegroundColor Cyan
  Write-Host "    $($cfg.alertTopic)" -ForegroundColor Yellow
  Write-Host 'Keep it secret: anyone who knows it can read your alerts.'
  exit 0
}

if ($BarkKey) {
  # Accepts the key alone or the full https://api.day.app/<key>/ URL from the Bark app.
  $k = $BarkKey.Trim() -replace '^https?://api\.day\.app/', ''
  $k = ($k -split '/')[0]
  $cfg.barkKey = $k
  Save-Config
  if (Send-Bark 'Proximity Guard + Bark' 'Bark works. Lock your iPhone and run -TestAlert to check the lock screen.' 'high' '') {
    Write-Host 'Bark key saved. Test notification sent: check your iPhone.' -ForegroundColor Green
  } else {
    Write-Host 'Bark key saved, but the test failed. Check the key in the Bark app.' -ForegroundColor Red
  }
  exit 0
}

if (-not $cfg.alertTopic -or -not $cfg.backupCodeHash) {
  Write-Host 'Run setup first: powershell -ExecutionPolicy Bypass -File .\guard.ps1 -Setup' -ForegroundColor Red
  exit 1
}

if ($TestAlert) {
  if (Send-Alert 'Proximity Guard test' 'If you see this on your iPhone, alerts work.' 'default') {
    Write-Host 'Test alert sent. Check your iPhone.' -ForegroundColor Green
  }
  exit 0
}

if ($TestApprove) {
  $r = Request-Approval 'Test approval' -NoLock
  Write-Host "Result: $r" -ForegroundColor Cyan
  exit 0
}

if ($TestLocation) {
  Write-Host 'Finding location (up to 15 s)...' -ForegroundColor Cyan
  $rep = Get-LocationReport
  Write-Host $rep.text
  if (Send-Alert 'Location test' ("This is what a theft alert looks like. Tap to open the map.`n" + $rep.text) 'default' '' $rep.click 'round_pushpin') {
    Write-Host 'Sent to your iPhone.' -ForegroundColor Green
  }
  exit 0
}

if ($Library) {
  # Tell the running guard: stay awake while locked for the next N hours. Then lock.
  $until = (Get-Date).AddHours([double]$cfg.libraryHours)
  Set-Content -Path $libraryFlag -Value $until.ToString('yyyy-MM-ddTHH:mm:ss', $inv)
  [void](Send-Alert 'Library mode ON' ("Laptop locked and watching until $($until.ToString('HH:mm')). Unplug, wake-up, Wi-Fi change or a wrong code will alert you with its location.") 'low' '' '' 'shield')
  Lock-Screen
  exit 0
}

if ($BootAlert) {
  # Run by a startup task: works even before anyone signs in, e.g. after the
  # laptop was forced off with the power button and switched on again.
  # Waits up to 10 minutes for internet. (IP + Wi-Fi only: Windows location is
  # not available before sign-in.)
  for ($i = 0; $i -lt 60; $i++) { if (Test-Online) { break }; Start-Sleep -Seconds 10 }
  $rep = Get-LocationReport -NoWindowsLocation
  [void](Send-Alert 'Laptop switched ON' ("Windows started at $(Get-Date -Format 'HH:mm'). If this was not you, it may be stolen.`n" + $rep.text) 'high' '' $rep.click 'computer')
  exit 0
}

# ---------------------------------------------------------------- guard loop

Write-Log 'Proximity Guard v3 started'
# Starting at sign-in counts as an unlock: approve it too.
if (-not (Test-ScreenLocked)) {
  $r = Request-Approval 'Sign-in'
  if ($r -eq 'approved' -or $r -eq 'backup') { Clear-Alarm }
}

$wasLocked = Test-ScreenLocked
$wasCharging = Test-OnCharger
$lastSsid = Get-WifiName
$lastTick = Get-Date
$lastSlowCheck = Get-Date

while ($true) {
 try {
  Start-Sleep -Seconds $cfg.checkEverySeconds
  $now = Get-Date
  $gap = ($now - $lastTick).TotalSeconds
  $lastTick = $now
  $locked = Test-ScreenLocked
  $charging = Test-OnCharger

  if ($cfg.theftAlerts) {
    # Library mode or alarm: no idle sleep while locked.
    Set-KeepAwake ($script:alarm -or ($locked -and (Test-LibraryMode)))

    # 1) The loop was paused much longer than usual: the laptop was asleep.
    if ($gap -gt ($cfg.checkEverySeconds + 30)) {
      Write-Log "woke up from sleep (asleep about $([int]$gap) s)"
      Start-Sleep -Seconds 10   # give Wi-Fi time to reconnect
      $locked = Test-ScreenLocked
      Send-TheftAlert 'Laptop woke up from sleep' 'Your laptop just woke up from sleep.' 'high'
      $lastSsid = Get-WifiName
      $charging = Test-OnCharger
      $lastTick = Get-Date
    }

    if ($locked) {
      # 2) Charger pulled out while locked.
      if ($wasCharging -and -not $charging) {
        Send-TheftAlert 'CHARGER UNPLUGGED while locked' 'Someone unplugged your laptop while it was locked.'
        $lastTick = Get-Date
      }

      # Slower checks every 15 s.
      if (($now - $lastSlowCheck).TotalSeconds -ge 15) {
        $lastSlowCheck = $now
        # 3) Different Wi-Fi while locked: the laptop is being moved.
        $ssid = Get-WifiName
        if ($ssid -ne $lastSsid) {
          if ($ssid) {
            Send-TheftAlert 'Laptop on a NEW Wi-Fi network' "Locked laptop moved from '$lastSsid' to '$ssid'."
          } elseif ($script:alarm -or (Test-LibraryMode)) {
            Add-Content -Path $pendingFile -Value "$(Get-Date -Format 'HH:mm:ss')  Wi-Fi '$lastSsid' disconnected while locked"
            Write-Log "Wi-Fi '$lastSsid' disconnected while locked"
          }
          $lastSsid = $ssid
        }
        # 4) Queued alerts: send as soon as there is internet again.
        if (Test-Path $pendingFile) { Send-Pending }
        # 5) During an alarm: location update every few minutes.
        if ($script:alarm -and (((Get-Date) - $script:lastTrack).TotalMinutes -ge $cfg.trackEveryMinutes)) {
          Send-TheftAlert 'Laptop location update' 'Still locked, still not unlocked by you.' 'high'
        }
        $lastTick = Get-Date   # location lookups take time: not a sleep
      }
    }
  }

  if ($wasLocked -and -not $locked) {
    Write-Log 'laptop unlocked: asking for approval'
    $r = Request-Approval 'Laptop unlocked'
    if ($r -eq 'approved' -or $r -eq 'backup') {
      Clear-Alarm
      if (Test-Path $pendingFile) { Remove-Item $pendingFile -ErrorAction SilentlyContinue }
    }
    Start-Sleep -Seconds 2
    $locked = Test-ScreenLocked
    $lastSsid = Get-WifiName
    $lastTick = Get-Date
    $charging = Test-OnCharger
  }
  $wasLocked = $locked
  $wasCharging = $charging
 } catch {
  # Never let one error stop the guard: log it and keep watching.
  Write-Log ('error in guard loop (still running): ' + $_.Exception.Message)
  Start-Sleep -Seconds 5
 }
}
