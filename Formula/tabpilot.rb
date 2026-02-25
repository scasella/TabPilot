class Tabpilot < Formula
  desc "AI-powered Safari tab command center for your macOS menu bar"
  homepage "https://github.com/scasella/TabPilot"
  url "https://github.com/scasella/TabPilot/archive/refs/tags/v0.1.0.tar.gz"
  sha256 "72f3483d02e1f8561a1e3bfafe94838fcd557e66b09fc3dbb705beb070503422"
  license "MIT"

  depends_on :macos
  depends_on xcode: ["15.0", :build]

  def install
    system "swiftc", "-parse-as-library", "-O", "-o", "TabPilot", "TabPilot.swift"

    # Create .app bundle
    app_dir = prefix/"TabPilot.app/Contents"
    (app_dir/"MacOS").mkpath
    cp "TabPilot", app_dir/"MacOS/TabPilot"

    (app_dir/"Info.plist").write <<~XML
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
          <string>#{version}</string>
          <key>CFBundleShortVersionString</key>
          <string>#{version}</string>
          <key>LSMinimumSystemVersion</key>
          <string>14.0</string>
          <key>LSUIElement</key>
          <true/>
          <key>NSAppleEventsUsageDescription</key>
          <string>TabPilot needs to communicate with Safari to read and manage your tabs.</string>
      </dict>
      </plist>
    XML
  end

  def caveats
    <<~EOS
      TabPilot has been installed as an app bundle at:
        #{prefix}/TabPilot.app

      To launch:
        open #{prefix}/TabPilot.app

      To link to /Applications (optional):
        ln -sf #{prefix}/TabPilot.app /Applications/TabPilot.app

      On first launch, grant automation permission:
        System Settings > Privacy & Security > Automation > TabPilot > Safari
    EOS
  end

  test do
    assert_predicate prefix/"TabPilot.app/Contents/MacOS/TabPilot", :exist?
    assert_predicate prefix/"TabPilot.app/Contents/Info.plist", :exist?
  end
end
