#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"

APP="WakeMenu.app"
BIN="$APP/Contents/MacOS/WakeMenu"

echo "Building WakeMenu.app…"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"

# Info.plist — LSUIElement=true => menu bar agent, no Dock icon
cat > "$APP/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key><string>WakeMenu</string>
    <key>CFBundleDisplayName</key><string>WakeMenu</string>
    <key>CFBundleIdentifier</key><string>local.wakemenu.app</string>
    <key>CFBundleVersion</key><string>1.1.0</string>
    <key>CFBundleShortVersionString</key><string>1.1.0</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleExecutable</key><string>WakeMenu</string>
    <key>LSMinimumSystemVersion</key><string>13.0</string>
    <key>LSUIElement</key><true/>
    <key>NSHumanReadableCopyright</key><string>WakeMenu</string>
</dict>
</plist>
PLIST

swiftc -O -o "$BIN" src/main.swift -framework AppKit
chmod +x "$BIN"

# Ad-hoc codesign so it runs without "damaged" warnings
codesign --force --deep --sign - "$APP" 2>/dev/null || true

echo "Done -> $(pwd)/$APP"
echo "Launch with: open \"$(pwd)/$APP\""
