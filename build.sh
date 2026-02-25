#!/bin/bash
# Build TabPilot.app bundle
set -euo pipefail

APP_NAME="TabPilot"

echo "Compiling ${APP_NAME}..."
swiftc -parse-as-library -o "${APP_NAME}" "${APP_NAME}.swift"

echo "Creating .app bundle..."
rm -rf "${APP_NAME}.app"
mkdir -p "${APP_NAME}.app/Contents/MacOS"
mv "${APP_NAME}" "${APP_NAME}.app/Contents/MacOS/"

cat > "${APP_NAME}.app/Contents/Info.plist" << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>TabPilot</string>
    <key>CFBundleIdentifier</key>
    <string>com.dailytools.tabpilot</string>
    <key>CFBundleName</key>
    <string>TabPilot</string>
    <key>CFBundleVersion</key>
    <string>0.1.0</string>
    <key>CFBundleShortVersionString</key>
    <string>0.1.0</string>
    <key>LSMinimumSystemVersion</key>
    <string>14.0</string>
    <key>LSUIElement</key>
    <true/>
    <key>NSAppleEventsUsageDescription</key>
    <string>TabPilot needs to communicate with Safari to read and manage your tabs.</string>
</dict>
</plist>
EOF

echo "Built ${APP_NAME}.app successfully!"
echo "Run: open ${APP_NAME}.app"
