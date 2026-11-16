# Proximity Guard (v3: push one-time code + anti-theft location alerts)

Makes a known Windows password useless on its own. Every time the laptop is unlocked
(or the guard starts at sign-in), the owner's iPhone gets a one-time 6-digit code by
push notification. Type it on the laptop to continue. Wrong code 3 times or no answer
in time: the laptop locks again and an urgent alert is sent. A backup code works offline.

Two factors: something you know (Windows password) + something you have (your phone).

## v1 → v2: why the design changed

v1 detected the iPhone over Bluetooth and locked when it was away. Testing showed the
iPhone did not reliably reconnect to Windows after being away, which would lock the owner
out at random. v2 uses push approval over the internet instead (same model as
Microsoft Authenticator / Duo), which does not depend on Bluetooth.

## How it works

1. Unlock detected: `LogonUI.exe` (lock screen) disappears.
2. The guard creates a random one-time 6-digit code and sends it through ntfy to a secret `alertTopic`.
3. A window on the laptop asks for that code (or the backup code), with a countdown.
4. The code is valid for this request only and is erased afterwards (no replay).

v2.0 used number-matching buttons in the notification; ntfy action buttons were not
reliable on iPhone, so v2.1 switched to a typed one-time code (like bank SMS codes).

## v3: anti-theft location alerts

While the laptop is **locked**, an urgent ntfy alert with its location is sent when:

| Trigger | Why it matters |
|---|---|
| Charger unplugged | First thing someone does before walking away with it |
| Woke up from sleep | Someone opened the lid / pressed a key |
| New Wi-Fi network | The laptop is being moved |
| Unlock code failed | Someone knows the password but not the code |

Each alert has: a Google Maps link (Windows Location, Wi-Fi positioning), the public IP
city as a fallback, the Wi-Fi name and the battery level. Tapping the notification opens
the map. After an alert, location updates follow every `trackEveryMinutes` until the owner
unlocks with the code. If there is no internet, alerts are queued in `pending.txt` and sent
with the new location as soon as the laptop is online again.

**Library mode** (`library-lock.bat` or `-Library`): locks the screen and keeps the laptop
awake (no idle sleep) for `libraryHours`, so an unplug is noticed immediately.

**Boot alert** (`-BootAlert`, startup task as SYSTEM): alert with IP location when Windows
starts, even before anyone signs in (after a forced power-off).

Limits: a script cannot run while the laptop is asleep or off; holding the power button
always forces it off; a thief who keeps it offline or reinstalls Windows sends nothing.

## Setup

1. Install **ntfy** on the iPhone (App Store).
2. `powershell -ExecutionPolicy Bypass -File .\guard.ps1 -Setup` (creates topics + backup code)
3. In ntfy: **+** → subscribe to the printed `alertTopic`.
4. `-TestAlert`, then `-TestApprove` (never locks), then `-TestLocation`.
5. Run the guard: `powershell -ExecutionPolicy Bypass -File .\guard.ps1`

## Security notes

- One-time code: random, single use, erased after each request (no **replay**).
- Max 3 wrong attempts, max 3 codes per 10 minutes: limits **guessing** and notification spam.
- Backup code: salted PBKDF2-SHA256 (100 000 rounds), constant-time comparison.
- Topics are 24 random characters and act like passwords; `config.json` is git-ignored.
- ntfy.sh is a third-party relay: notifications contain no sensitive data.
- Limits: a person with admin rights could stop the script during the 30-second window;
  this is a deterrent and alarm, not a replacement for a secret password.
