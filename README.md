# WakeMenu

A tiny macOS **menu bar app** for waking PCs on your local network via **Wake-on-LAN**, with live on/off status and zero-config IP discovery.

No Dock icon, no dependencies, no Electron — just a single native Swift binary that lives in your menu bar.

```
⏻  ● Office PC          ← click to wake (green = online, red = offline)
   ● Gaming PC
   ─────────────
   Manage PCs…          ⌘M
   ─────────────
   Quit                 ⌘Q
```

## Features

- **One-click Wake-on-LAN** — sends the magic packet to any saved PC from the menu bar.
- **Live on/off status** — a subtle colored dot per PC (● online / ● offline / ● unknown), refreshed every 30s and whenever you open the menu.
- **Automatic IP discovery** — you only ever enter a **MAC address**. WakeMenu finds the PC's current IP itself by matching the MAC in the ARP table, so it keeps working even when DHCP reassigns the address.
- **Firewall-proof status** — detects "online" via ARP, so a PC shows as up even when its firewall blocks ping (Windows' default).
- **Network scanner** — scan the LAN and pick a device from a list (with reverse-DNS / NetBIOS name resolution) to auto-fill the add form.
- **Management window** — add / edit / remove / wake PCs from a proper UI, with a saved-PCs table and a discovery table.
- **Self-contained** — one `.app`, ad-hoc signed, ~no runtime dependencies.

## How Wake-on-LAN works here

A PC that is off has **no IP address**, so you can't send a packet *to* it directly. Instead WakeMenu broadcasts a **magic packet** (6×`0xFF` followed by the target MAC repeated 16×) over UDP to the subnet broadcast address (e.g. `192.168.10.255`, auto-detected). Every network card on the LAN sees it, and only the card whose **MAC** matches wakes the machine. That's why the **MAC is the only required field**.

## Requirements

- macOS 13 (Ventura) or later
- The Mac and the target PC on the **same LAN** (same subnet)
- Wake-on-LAN enabled on the target PC (see below)

## Install

### Option A — download a release

Grab `WakeMenu.app.zip` from the [Releases](../../releases) page, unzip, and move `WakeMenu.app` to `/Applications`.

> The app is **ad-hoc signed** (not notarized), so the first launch needs Gatekeeper approval:
> right-click the app → **Open** → **Open**, or run:
> ```sh
> xattr -dr com.apple.quarantine /Applications/WakeMenu.app
> ```

### Option B — build from source

```sh
git clone https://github.com/alexcding/WakeMenu.git
cd WakeMenu
./build.sh
open WakeMenu.app
```

Requires the Xcode command-line tools (`xcode-select --install`).

## Usage

1. Click the **⏻** icon in the menu bar → **Manage PCs…** (`⌘M`).
2. Either **Scan** the network and click your PC (auto-fills MAC + broadcast), or type the **Name** and **MAC** manually.
3. Click **Add PC**.
4. Back in the menu bar, click the PC's name to wake it. The status dot shows whether it's currently on.

### Finding a PC's MAC address

- **Windows:** `ipconfig /all` → the Ethernet adapter's *Physical Address*
- **Linux:** `ip link` → the `link/ether` value
- **macOS:** System Settings → Network → (interface) → Details → Hardware

Use the **wired Ethernet** MAC — Wi-Fi usually can't wake a powered-off machine.

## Enabling Wake-on-LAN on the target PC

- **BIOS/UEFI:** enable *Wake on LAN* / *Power On by PCIe*.
- **Windows:** Device Manager → network adapter → *Power Management* → check *Allow this device to wake the computer* and *Only allow a magic packet…*. Disable **Fast Startup** (Control Panel → Power Options), which blocks WoL.
- Keep the PC on **wired Ethernet**.

## Launch at login (optional)

A LaunchAgent plist is the simplest way:

```sh
cat > ~/Library/LaunchAgents/local.wakemenu.plist <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>local.wakemenu</string>
  <key>ProgramArguments</key><array><string>/Applications/WakeMenu.app/Contents/MacOS/WakeMenu</string></array>
  <key>RunAtLoad</key><true/>
  <key>LimitLoadToSessionType</key><string>Aqua</string>
</dict></plist>
PLIST
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/local.wakemenu.plist
```

Undo: `launchctl bootout gui/$(id -u)/local.wakemenu && rm ~/Library/LaunchAgents/local.wakemenu.plist`

## How status detection works

WakeMenu treats the **MAC as the source of truth**:

1. It pokes the last-known IP (one ping) to refresh the ARP cache.
2. It reads the ARP table and looks up your PC's MAC → that row's IP is the *current* IP.
3. If the MAC isn't found, it does one throttled subnet sweep to relocate it.

A host present in the ARP table is online — and ARP works below the firewall layer, so this is reliable even when ICMP (ping) is blocked.

## License

[MIT](LICENSE) © Alex Ding
