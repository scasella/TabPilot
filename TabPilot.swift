// TabPilot — AI-Powered Safari Tab Command Center
// Day 11 · daily-macwidgets · 2026-02-25

import SwiftUI
import Network
import Security

// MARK: - Theme (from SafariMarkdown)

enum TPTheme {
    static let bg = Color(red: 0.11, green: 0.11, blue: 0.13)
    static let surface = Color(red: 0.16, green: 0.16, blue: 0.19)
    static let surfaceHover = Color(red: 0.20, green: 0.20, blue: 0.24)
    static let border = Color.white.opacity(0.08)
    static let textPrimary = Color.white.opacity(0.92)
    static let textSecondary = Color.white.opacity(0.55)
    static let accent = Color(red: 0.40, green: 0.65, blue: 1.0)
    static let success = Color(red: 0.30, green: 0.78, blue: 0.50)
    static let warning = Color(red: 1.0, green: 0.60, blue: 0.25)
    static let error = Color(red: 0.95, green: 0.35, blue: 0.35)
    static let fresh = Color(red: 0.30, green: 0.78, blue: 0.50)
    static let warm = Color(red: 0.40, green: 0.65, blue: 1.0)
    static let cooling = Color(red: 1.0, green: 0.60, blue: 0.25)
    static let stale = Color(red: 0.95, green: 0.35, blue: 0.35)
}

// MARK: - RawWebSocket (from CodexPilot/SafariMarkdown)

class RawWebSocket {
    private var connection: NWConnection?
    private let host: String
    private let port: UInt16
    private let queue = DispatchQueue(label: "ws", qos: .userInitiated)

    var onMessage: ((String) -> Void)?
    var onConnect: (() -> Void)?
    var onDisconnect: ((String) -> Void)?

    private var handshakeComplete = false
    private var receiveBuffer = Data()

    init(host: String, port: UInt16) {
        self.host = host
        self.port = port
    }

    func connect() {
        connection = NWConnection(
            host: NWEndpoint.Host(host),
            port: NWEndpoint.Port(rawValue: port)!,
            using: .tcp
        )
        connection?.stateUpdateHandler = { [weak self] state in
            switch state {
            case .ready: self?.performHandshake()
            case .failed(let err):
                DispatchQueue.main.async { self?.onDisconnect?("Failed: \(err)") }
            case .cancelled:
                DispatchQueue.main.async { self?.onDisconnect?("Cancelled") }
            default: break
            }
        }
        connection?.start(queue: queue)
    }

    func disconnect() {
        connection?.cancel()
        connection = nil
        handshakeComplete = false
        receiveBuffer = Data()
    }

    func send(_ text: String) {
        guard handshakeComplete else { return }
        let frame = encodeTextFrame(text)
        connection?.send(content: frame, completion: .contentProcessed({ _ in }))
    }

    private func performHandshake() {
        var keyBytes = [UInt8](repeating: 0, count: 16)
        _ = SecRandomCopyBytes(kSecRandomDefault, 16, &keyBytes)
        let key = Data(keyBytes).base64EncodedString()
        let request = "GET / HTTP/1.1\r\nHost: \(host):\(port)\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: \(key)\r\nSec-WebSocket-Version: 13\r\n\r\n"
        connection?.send(content: request.data(using: .utf8)!, completion: .contentProcessed({ [weak self] err in
            if let err {
                DispatchQueue.main.async { self?.onDisconnect?("Handshake send failed: \(err)") }
                return
            }
            self?.readHandshakeResponse()
        }))
    }

    private func readHandshakeResponse() {
        connection?.receive(minimumIncompleteLength: 1, maximumLength: 4096) { [weak self] data, _, _, err in
            guard let self else { return }
            if let err {
                DispatchQueue.main.async { self.onDisconnect?("Handshake read failed: \(err)") }
                return
            }
            guard let data else { return }
            let text = String(data: data, encoding: .utf8) ?? ""
            if text.contains("101") && text.lowercased().contains("upgrade") {
                self.handshakeComplete = true
                DispatchQueue.main.async { self.onConnect?() }
                self.startReading()
            } else {
                DispatchQueue.main.async { self.onDisconnect?("Handshake rejected: \(text.prefix(100))") }
            }
        }
    }

    private func encodeTextFrame(_ text: String) -> Data {
        let payload = Array(text.utf8)
        var frame = Data()
        frame.append(0x81)
        let len = payload.count
        if len < 126 {
            frame.append(UInt8(len) | 0x80)
        } else if len < 65536 {
            frame.append(126 | 0x80)
            frame.append(UInt8((len >> 8) & 0xFF))
            frame.append(UInt8(len & 0xFF))
        } else {
            frame.append(127 | 0x80)
            for i in (0..<8).reversed() { frame.append(UInt8((len >> (i * 8)) & 0xFF)) }
        }
        var mask = [UInt8](repeating: 0, count: 4)
        _ = SecRandomCopyBytes(kSecRandomDefault, 4, &mask)
        frame.append(contentsOf: mask)
        for (i, byte) in payload.enumerated() { frame.append(byte ^ mask[i % 4]) }
        return frame
    }

    private func startReading() {
        connection?.receive(minimumIncompleteLength: 2, maximumLength: 65536) { [weak self] data, _, _, err in
            guard let self else { return }
            if let err {
                DispatchQueue.main.async { self.onDisconnect?("Read error: \(err)") }
                return
            }
            if let data {
                self.receiveBuffer.append(data)
                self.processFrames()
            }
            self.startReading()
        }
    }

    private func processFrames() {
        while receiveBuffer.count >= 2 {
            let b0 = receiveBuffer[0]
            let b1 = receiveBuffer[1]
            let opcode = b0 & 0x0F
            let masked = (b1 & 0x80) != 0
            var payloadLen = Int(b1 & 0x7F)
            var offset = 2
            if payloadLen == 126 {
                guard receiveBuffer.count >= 4 else { return }
                payloadLen = Int(receiveBuffer[2]) << 8 | Int(receiveBuffer[3])
                offset = 4
            } else if payloadLen == 127 {
                guard receiveBuffer.count >= 10 else { return }
                payloadLen = 0
                for i in 0..<8 { payloadLen = (payloadLen << 8) | Int(receiveBuffer[2 + i]) }
                offset = 10
            }
            var maskKey: [UInt8] = []
            if masked {
                guard receiveBuffer.count >= offset + 4 else { return }
                maskKey = Array(receiveBuffer[offset..<offset+4])
                offset += 4
            }
            guard receiveBuffer.count >= offset + payloadLen else { return }
            var payload = Array(receiveBuffer[offset..<offset+payloadLen])
            if masked { for i in 0..<payload.count { payload[i] ^= maskKey[i % 4] } }
            receiveBuffer = Data(receiveBuffer[(offset + payloadLen)...])
            switch opcode {
            case 0x1:
                if let text = String(bytes: payload, encoding: .utf8) {
                    DispatchQueue.main.async { self.onMessage?(text) }
                }
            case 0x8:
                DispatchQueue.main.async { self.onDisconnect?("Server closed connection") }
                return
            case 0x9:
                var pong = Data([0x8A])
                pong.append(UInt8(payload.count) | 0x80)
                var mask = [UInt8](repeating: 0, count: 4)
                _ = SecRandomCopyBytes(kSecRandomDefault, 4, &mask)
                pong.append(contentsOf: mask)
                for (i, byte) in payload.enumerated() { pong.append(byte ^ mask[i % 4]) }
                connection?.send(content: pong, completion: .contentProcessed({ _ in }))
            default: break
            }
        }
    }
}

// MARK: - Models

struct SafariTab: Identifiable, Hashable {
    let id: String  // "\(windowIndex)-\(tabIndex)"
    let url: String
    let title: String
    let windowIndex: Int
    let tabIndex: Int
    var firstSeen: Date
    var clusterId: String?

    var domain: String {
        guard let comps = URLComponents(string: url) else { return url }
        return comps.host ?? url
    }

    var shortDomain: String {
        let d = domain
        if d.hasPrefix("www.") { return String(d.dropFirst(4)) }
        return d
    }

    var domainInitial: String {
        let d = shortDomain
        return d.isEmpty ? "?" : String(d.prefix(1)).uppercased()
    }

    var age: TimeInterval { Date().timeIntervalSince(firstSeen) }

    var ageCategory: AgeCategory {
        let hours = age / 3600
        if hours < 1 { return .fresh }
        if hours < 24 { return .warm }
        if hours < 24 * 7 { return .cooling }
        return .stale
    }

    var ageText: String {
        let mins = Int(age / 60)
        if mins < 1 { return "now" }
        if mins < 60 { return "\(mins)m" }
        let hours = mins / 60
        if hours < 24 { return "\(hours)h" }
        let days = hours / 24
        return "\(days)d"
    }

    func hash(into hasher: inout Hasher) { hasher.combine(id) }
    static func == (lhs: SafariTab, rhs: SafariTab) -> Bool { lhs.id == rhs.id }
}

enum AgeCategory: String, CaseIterable {
    case fresh, warm, cooling, stale

    var color: Color {
        switch self {
        case .fresh: return TPTheme.fresh
        case .warm: return TPTheme.warm
        case .cooling: return TPTheme.cooling
        case .stale: return TPTheme.stale
        }
    }

    var label: String {
        switch self {
        case .fresh: return "< 1h"
        case .warm: return "Today"
        case .cooling: return "This week"
        case .stale: return "7+ days"
        }
    }
}

struct TabCluster: Identifiable {
    let id: String
    let name: String
    let description: String
    var tabIndices: [Int]
    let color: Color

    static let clusterColors: [Color] = [
        Color(red: 0.40, green: 0.65, blue: 1.0),
        Color(red: 0.65, green: 0.45, blue: 1.0),
        Color(red: 0.30, green: 0.78, blue: 0.50),
        Color(red: 1.0, green: 0.60, blue: 0.25),
        Color(red: 0.95, green: 0.45, blue: 0.55),
        Color(red: 0.50, green: 0.80, blue: 0.85),
        Color(red: 0.85, green: 0.75, blue: 0.35),
        Color(red: 0.70, green: 0.55, blue: 0.40),
    ]
}

enum FilterMode: String, CaseIterable {
    case all = "All"
    case fresh = "Fresh"
    case stale = "Stale"
    case duplicates = "Dupes"
}

enum ViewMode: String, CaseIterable {
    case domain = "By Domain"
    case cluster = "AI Clusters"
}

// MARK: - Tab History Persistence

struct TabHistory: Codable {
    var firstSeen: [String: Date]  // URL → first seen
    var lastSeen: [String: Date]   // URL → last seen
}

enum TabHistoryStore {
    static let dir = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".tabpilot")
    static let file = dir.appendingPathComponent("tab_history.json")

    static func load() -> TabHistory {
        guard let data = try? Data(contentsOf: file),
              let history = try? JSONDecoder.iso8601.decode(TabHistory.self, from: data) else {
            return TabHistory(firstSeen: [:], lastSeen: [:])
        }
        return history
    }

    static func save(_ history: TabHistory) {
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        if let data = try? JSONEncoder.iso8601.encode(history) {
            try? data.write(to: file, options: .atomic)
        }
    }
}

extension JSONDecoder {
    static let iso8601: JSONDecoder = {
        let d = JSONDecoder()
        d.dateDecodingStrategy = .iso8601
        return d
    }()
}

extension JSONEncoder {
    static let iso8601: JSONEncoder = {
        let e = JSONEncoder()
        e.dateEncodingStrategy = .iso8601
        e.outputFormatting = [.prettyPrinted, .sortedKeys]
        return e
    }()
}

// MARK: - Safari Scanner

@Observable
class SafariScanner {
    var tabs: [SafariTab] = []
    var isScanning = false
    var lastScanError: String?
    var history: TabHistory

    private var timer: Timer?

    var tabCount: Int { tabs.count }

    var duplicateURLs: Set<String> {
        var seen = Set<String>()
        var dupes = Set<String>()
        for tab in tabs {
            if seen.contains(tab.url) { dupes.insert(tab.url) }
            seen.insert(tab.url)
        }
        return dupes
    }

    var duplicateCount: Int {
        let dupeURLs = duplicateURLs
        return tabs.filter { dupeURLs.contains($0.url) }.count
    }

    var domainGroups: [(String, [SafariTab])] {
        let grouped = Dictionary(grouping: tabs, by: { $0.shortDomain })
        return grouped.sorted { $0.value.count > $1.value.count }
    }

    init() {
        self.history = TabHistoryStore.load()
        scanAllTabs()
        startPolling()
    }

    deinit {
        timer?.invalidate()
    }

    func startPolling() {
        timer?.invalidate()
        timer = Timer.scheduledTimer(withTimeInterval: 5.0, repeats: true) { [weak self] _ in
            self?.scanAllTabs()
        }
    }

    func scanAllTabs() {
        isScanning = true
        lastScanError = nil

        // Bulk read all tab URLs and titles via AppleScript
        let script = NSAppleScript(source: """
            tell application "Safari"
                set tabData to {}
                set winCount to count of windows
                repeat with w from 1 to winCount
                    set tabCount to count of tabs of window w
                    repeat with t from 1 to tabCount
                        set tabURL to URL of tab t of window w
                        set tabName to name of tab t of window w
                        set end of tabData to (w as text) & "\\t" & (t as text) & "\\t" & tabURL & "\\t" & tabName
                    end repeat
                end repeat
                set AppleScript's text item delimiters to "\\n"
                return tabData as text
            end tell
        """)

        var errorInfo: NSDictionary?
        guard let result = script?.executeAndReturnError(&errorInfo) else {
            let errMsg = (errorInfo?[NSAppleScript.errorMessage] as? String) ?? "Unknown error"
            isScanning = false
            if errMsg.contains("not allowed") || errMsg.contains("permission") {
                lastScanError = "Automation permission denied. Go to System Settings > Privacy & Security > Automation and enable Safari for this app."
            } else {
                lastScanError = "Safari scan failed: \(errMsg)"
            }
            return
        }

        let raw = result.stringValue ?? ""
        let now = Date()
        var newTabs: [SafariTab] = []

        for line in raw.split(separator: "\n") {
            let parts = line.split(separator: "\t", maxSplits: 3)
            guard parts.count >= 4 else { continue }
            let winIdx = Int(parts[0]) ?? 0
            let tabIdx = Int(parts[1]) ?? 0
            let url = String(parts[2])
            let title = String(parts[3])

            // Track first-seen
            if history.firstSeen[url] == nil {
                history.firstSeen[url] = now
            }
            history.lastSeen[url] = now

            let firstSeen = history.firstSeen[url] ?? now

            let tab = SafariTab(
                id: "\(winIdx)-\(tabIdx)",
                url: url,
                title: title,
                windowIndex: winIdx,
                tabIndex: tabIdx,
                firstSeen: firstSeen
            )
            newTabs.append(tab)
        }

        tabs = newTabs
        isScanning = false
        TabHistoryStore.save(history)
    }

    func switchToTab(_ tab: SafariTab) {
        let script = NSAppleScript(source: """
            tell application "Safari"
                set current tab of window \(tab.windowIndex) to tab \(tab.tabIndex) of window \(tab.windowIndex)
                set index of window \(tab.windowIndex) to 1
                activate
            end tell
        """)
        var errorInfo: NSDictionary?
        script?.executeAndReturnError(&errorInfo)
    }

    func closeTab(_ tab: SafariTab) {
        let script = NSAppleScript(source: """
            tell application "Safari"
                close tab \(tab.tabIndex) of window \(tab.windowIndex)
            end tell
        """)
        var errorInfo: NSDictionary?
        script?.executeAndReturnError(&errorInfo)

        // Remove from list immediately
        tabs.removeAll { $0.id == tab.id }
    }

    func closeTabs(_ tabsToClose: [SafariTab]) {
        // Close in reverse order to avoid index shifting
        let sorted = tabsToClose.sorted {
            if $0.windowIndex != $1.windowIndex { return $0.windowIndex > $1.windowIndex }
            return $0.tabIndex > $1.tabIndex
        }
        for tab in sorted {
            closeTab(tab)
        }
    }

    func closeDuplicates() {
        let dupeURLs = duplicateURLs
        var seenURLs = Set<String>()
        var toClose: [SafariTab] = []

        for tab in tabs {
            if dupeURLs.contains(tab.url) {
                if seenURLs.contains(tab.url) {
                    toClose.append(tab)
                } else {
                    seenURLs.insert(tab.url)
                }
            }
        }
        closeTabs(toClose)
    }

    func closeStaleTabs() {
        let stale = tabs.filter { $0.ageCategory == .stale }
        closeTabs(stale)
    }
}

// MARK: - Tab Clusterer (Codex Integration)

enum ClusterState: Equatable {
    case idle
    case connecting
    case clustering
    case done
    case error(String)
}

@Observable
class TabClusterer {
    var state: ClusterState = .idle
    var clusters: [TabCluster] = []
    var nlResponse = ""
    var isNLQuery = false

    private var ws: RawWebSocket?
    private var nextId = 1
    private var threadId: String?
    private var pendingRequests: [Int: String] = [:]
    private var accumulatedResponse = ""
    private var pendingTabs: [SafariTab] = []
    private var nlCallback: ((String) -> Void)?

    var isConnected: Bool {
        if case .done = state { return true }
        if case .clustering = state { return true }
        return false
    }

    func clusterTabs(_ tabs: [SafariTab]) {
        guard !tabs.isEmpty else {
            state = .error("No tabs to cluster")
            return
        }

        pendingTabs = tabs
        isNLQuery = false
        accumulatedResponse = ""
        clusters = []
        nextId = 1
        threadId = nil
        pendingRequests = [:]

        state = .connecting
        connectToCodex()
    }

    func cancel() {
        ws?.disconnect()
        ws = nil
        state = .idle
    }

    // MARK: - Codex Protocol

    private var currentQuery: String = ""

    func askAboutTabs(query: String, tabs: [SafariTab], callback: ((String) -> Void)? = nil) {
        guard !tabs.isEmpty else { return }

        pendingTabs = tabs
        isNLQuery = true
        currentQuery = query
        accumulatedResponse = ""
        nlResponse = ""
        nlCallback = callback
        nextId = 1
        threadId = nil
        pendingRequests = [:]

        state = .connecting
        connectToCodex()
    }

    private func connectToCodex() {
        let socket = RawWebSocket(host: "127.0.0.1", port: 8080)

        socket.onConnect = { [weak self] in
            self?.sendInitialize()
        }

        socket.onMessage = { [weak self] msg in
            self?.handleMessage(msg)
        }

        socket.onDisconnect = { [weak self] reason in
            guard let self else { return }
            if case .connecting = self.state {
                self.state = .error("Cannot connect to Codex. Run: codex app-server --listen ws://127.0.0.1:8080")
            } else if case .clustering = self.state {
                self.state = .error("Disconnected: \(reason)")
            }
        }

        ws = socket
        socket.connect()
    }

    private func rpcSend(method: String, params: Any) -> Int {
        let id = nextId
        nextId += 1
        pendingRequests[id] = method

        let msg: [String: Any] = [
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params
        ]

        if let data = try? JSONSerialization.data(withJSONObject: msg),
           let text = String(data: data, encoding: .utf8) {
            ws?.send(text)
        }
        return id
    }

    private func rpcRespond(id: Any, result: Any) {
        let msg: [String: Any] = [
            "jsonrpc": "2.0",
            "id": id,
            "result": result
        ]
        if let data = try? JSONSerialization.data(withJSONObject: msg),
           let text = String(data: data, encoding: .utf8) {
            ws?.send(text)
        }
    }

    private func sendInitialize() {
        _ = rpcSend(method: "initialize", params: [
            "clientInfo": ["name": "TabPilot", "version": "0.1.0"]
        ])
    }

    private func sendThreadStart() {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        _ = rpcSend(method: "thread/start", params: [
            "ephemeral": true,
            "cwd": home
        ])
    }

    private func sendClusterTurn() {
        guard let tid = threadId else { return }

        let tabList = pendingTabs.enumerated().map { (i, tab) in
            "[\(i)] \(tab.title) — \(tab.url)"
        }.joined(separator: "\n")

        let prompt = """
        You are a tab organizer. Given a list of Safari browser tabs, group them into 3-8 semantic clusters based on topic similarity. Each tab belongs to exactly one cluster.

        Return ONLY valid JSON in this exact format:
        {"clusters": [{"name": "short cluster name", "description": "1-sentence description", "tabIndices": [0, 3, 7]}]}

        Rules:
        - Cluster names should be 2-4 words, descriptive (e.g., "React Development", "Apartment Search")
        - Every tab index must appear in exactly one cluster
        - If a tab doesn't fit any cluster, put it in a "Miscellaneous" cluster
        - Order clusters by size (largest first)
        - Tab indices are 0-based and correspond to the numbers in brackets below

        Tabs:
        \(tabList)
        """

        _ = rpcSend(method: "turn/start", params: [
            "threadId": tid,
            "effort": "medium",
            "input": [["type": "text", "text": prompt, "textElements": [] as [Any]]]
        ])
    }

    private func sendNLTurn() {
        guard let tid = threadId else { return }

        let tabList = pendingTabs.enumerated().map { (i, tab) in
            "[\(i)] \(tab.title) — \(tab.url)"
        }.joined(separator: "\n")

        let prompt = """
        You are a Safari tab assistant. The user has these open tabs:

        \(tabList)

        The user asks: "\(currentQuery)"

        Respond helpfully. If the user wants to close, find, or act on specific tabs, mention them by their index number in brackets. If the user wants a summary, provide a concise overview. Keep your response brief and actionable.
        """

        _ = rpcSend(method: "turn/start", params: [
            "threadId": tid,
            "effort": "medium",
            "input": [["type": "text", "text": prompt, "textElements": [] as [Any]]]
        ])
    }

    private func handleMessage(_ text: String) {
        guard let data = text.data(using: .utf8),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return }

        // Response to our requests
        if let id = json["id"] as? Int, let method = pendingRequests[id] {
            pendingRequests.removeValue(forKey: id)

            if let error = json["error"] as? [String: Any] {
                let msg = error["message"] as? String ?? "Unknown error"
                state = .error("Codex error (\(method)): \(msg)")
                return
            }

            let result = json["result"] as? [String: Any] ?? [:]

            switch method {
            case "initialize":
                sendThreadStart()
            case "thread/start":
                if let thread = result["thread"] as? [String: Any],
                   let tid = thread["id"] as? String {
                    threadId = tid
                    state = .clustering
                    if isNLQuery {
                        sendNLTurn()
                    } else {
                        sendClusterTurn()
                    }
                } else {
                    state = .error("Failed to create thread")
                }
            default:
                break
            }
            return
        }

        // Server requests (approvals) — auto-accept
        if let id = json["id"], json["method"] is String {
            rpcRespond(id: id, result: ["decision": "accept"])
            return
        }

        // Notifications
        if let method = json["method"] as? String {
            let params = json["params"] as? [String: Any] ?? [:]

            switch method {
            case "item/agentMessage/delta":
                if let delta = params["delta"] as? String {
                    accumulatedResponse += delta
                    if isNLQuery {
                        nlResponse = accumulatedResponse
                    }
                }

            case "turn/completed":
                if isNLQuery {
                    nlResponse = accumulatedResponse
                    nlCallback?(accumulatedResponse)
                    state = .done
                } else {
                    parseClusterResponse()
                }
                ws?.disconnect()
                ws = nil

            case "turn/error":
                let msg = params["error"] as? String ?? "Turn failed"
                state = .error(msg)
                ws?.disconnect()
                ws = nil

            default:
                break
            }
        }
    }

    private func parseClusterResponse() {
        // Try to extract JSON from the response
        var jsonStr = accumulatedResponse

        // Find JSON object in response (may be wrapped in markdown code block)
        if let range = jsonStr.range(of: "\\{[\\s\\S]*\"clusters\"[\\s\\S]*\\}", options: .regularExpression) {
            jsonStr = String(jsonStr[range])
        }

        guard let data = jsonStr.data(using: .utf8),
              let parsed = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let rawClusters = parsed["clusters"] as? [[String: Any]] else {
            state = .error("Could not parse AI cluster response. Try again.")
            return
        }

        var newClusters: [TabCluster] = []
        for (i, raw) in rawClusters.enumerated() {
            let name = raw["name"] as? String ?? "Cluster \(i + 1)"
            let desc = raw["description"] as? String ?? ""
            let indices: [Int]
            if let arr = raw["tabIndices"] as? [Int] {
                indices = arr
            } else if let arr = raw["tabIndices"] as? [NSNumber] {
                indices = arr.map { $0.intValue }
            } else {
                indices = []
            }

            let color = TabCluster.clusterColors[i % TabCluster.clusterColors.count]
            newClusters.append(TabCluster(
                id: "cluster-\(i)",
                name: name,
                description: desc,
                tabIndices: indices,
                color: color
            ))
        }

        clusters = newClusters
        state = .done
    }
}

// MARK: - Views

struct TabCountBadge: View {
    let count: Int

    var badgeColor: Color {
        if count < 20 { return TPTheme.fresh }
        if count < 40 { return TPTheme.warm }
        if count < 60 { return TPTheme.cooling }
        return TPTheme.stale
    }

    var body: some View {
        Text("\(count)")
            .font(.system(size: 10, weight: .bold, design: .rounded))
            .foregroundStyle(.white)
            .padding(.horizontal, 5)
            .padding(.vertical, 1)
            .background(badgeColor)
            .clipShape(Capsule())
    }
}

struct FilterChips: View {
    @Binding var selected: FilterMode
    let duplicateCount: Int

    var body: some View {
        HStack(spacing: 4) {
            ForEach(FilterMode.allCases, id: \.self) { mode in
                let isActive = selected == mode
                Button(action: { selected = mode }) {
                    HStack(spacing: 3) {
                        Text(mode.rawValue)
                            .font(.system(size: 10, weight: isActive ? .semibold : .regular))
                        if mode == .duplicates && duplicateCount > 0 {
                            Text("\(duplicateCount)")
                                .font(.system(size: 9, weight: .bold))
                                .foregroundStyle(.white)
                                .padding(.horizontal, 4)
                                .padding(.vertical, 1)
                                .background(TPTheme.warning)
                                .clipShape(Capsule())
                        }
                    }
                    .foregroundStyle(isActive ? .white : TPTheme.textSecondary)
                    .padding(.horizontal, 8)
                    .padding(.vertical, 4)
                    .background(isActive ? TPTheme.accent.opacity(0.3) : TPTheme.surface)
                    .clipShape(Capsule())
                    .overlay(
                        Capsule().stroke(isActive ? TPTheme.accent : TPTheme.border, lineWidth: 1)
                    )
                }
                .buttonStyle(.plain)
            }
        }
    }
}

struct AgeBadge: View {
    let tab: SafariTab

    var body: some View {
        Text(tab.ageText)
            .font(.system(size: 9, weight: .medium, design: .monospaced))
            .foregroundStyle(tab.ageCategory.color)
            .padding(.horizontal, 5)
            .padding(.vertical, 2)
            .background(tab.ageCategory.color.opacity(0.12))
            .clipShape(RoundedRectangle(cornerRadius: 3))
    }
}

struct DomainIcon: View {
    let initial: String
    let color: Color

    var body: some View {
        Text(initial)
            .font(.system(size: 10, weight: .bold, design: .rounded))
            .foregroundStyle(.white)
            .frame(width: 22, height: 22)
            .background(color)
            .clipShape(RoundedRectangle(cornerRadius: 5))
    }
}

struct TabRowView: View {
    let tab: SafariTab
    let isDuplicate: Bool
    let onSwitch: () -> Void
    let onClose: () -> Void

    @State private var isHovered = false
    @State private var showCloseConfirm = false

    var body: some View {
        HStack(spacing: 8) {
            DomainIcon(
                initial: tab.domainInitial,
                color: domainColor(for: tab.shortDomain)
            )

            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 4) {
                    Text(tab.title.isEmpty ? "Untitled" : tab.title)
                        .font(.system(size: 12, weight: .medium))
                        .foregroundStyle(TPTheme.textPrimary)
                        .lineLimit(1)
                        .truncationMode(.tail)

                    if isDuplicate {
                        Image(systemName: "doc.on.doc.fill")
                            .font(.system(size: 8))
                            .foregroundStyle(TPTheme.warning)
                    }
                }

                Text(tab.shortDomain)
                    .font(.system(size: 10))
                    .foregroundStyle(TPTheme.textSecondary)
                    .lineLimit(1)
            }

            Spacer()

            AgeBadge(tab: tab)

            Button(action: {
                showCloseConfirm = true
            }) {
                Image(systemName: "xmark.circle.fill")
                    .font(.system(size: 14))
                    .foregroundStyle(TPTheme.textSecondary)
            }
            .buttonStyle(.plain)
            .opacity(isHovered || showCloseConfirm ? 1 : 0)
            .popover(isPresented: $showCloseConfirm) {
                VStack(spacing: 8) {
                    Text("Close this tab?")
                        .font(.system(size: 12, weight: .medium))
                    Text(tab.title.prefix(50))
                        .font(.system(size: 10))
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                    HStack(spacing: 8) {
                        Button("Cancel") { showCloseConfirm = false }
                            .buttonStyle(.plain)
                            .font(.system(size: 11))
                        Button("Close") {
                            showCloseConfirm = false
                            onClose()
                        }
                        .buttonStyle(.plain)
                        .font(.system(size: 11, weight: .medium))
                        .foregroundStyle(TPTheme.error)
                    }
                }
                .padding(12)
            }
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 6)
        .background(isHovered ? TPTheme.surfaceHover : Color.clear)
        .clipShape(RoundedRectangle(cornerRadius: 6))
        .onTapGesture { onSwitch() }
        .onHover { isHovered = $0 }
    }

    func domainColor(for domain: String) -> Color {
        let hash = abs(domain.hashValue)
        return TabCluster.clusterColors[hash % TabCluster.clusterColors.count]
    }
}

struct DomainGroupView: View {
    let domain: String
    let tabs: [SafariTab]
    let duplicateURLs: Set<String>
    let onSwitch: (SafariTab) -> Void
    let onClose: (SafariTab) -> Void

    @State private var isExpanded = true

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            // Domain header
            Button(action: { withAnimation(.easeInOut(duration: 0.15)) { isExpanded.toggle() } }) {
                HStack(spacing: 6) {
                    Image(systemName: isExpanded ? "chevron.down" : "chevron.right")
                        .font(.system(size: 9, weight: .bold))
                        .foregroundStyle(TPTheme.textSecondary)
                        .frame(width: 12)

                    Text(domain)
                        .font(.system(size: 11, weight: .semibold))
                        .foregroundStyle(TPTheme.textPrimary)

                    TabCountBadge(count: tabs.count)

                    Spacer()
                }
                .padding(.horizontal, 10)
                .padding(.vertical, 6)
            }
            .buttonStyle(.plain)

            if isExpanded {
                ForEach(tabs) { tab in
                    TabRowView(
                        tab: tab,
                        isDuplicate: duplicateURLs.contains(tab.url),
                        onSwitch: { onSwitch(tab) },
                        onClose: { onClose(tab) }
                    )
                    .padding(.leading, 12)
                }
            }
        }
    }
}

struct ClusterGroupView: View {
    let cluster: TabCluster
    let tabs: [SafariTab]
    let duplicateURLs: Set<String>
    let onSwitch: (SafariTab) -> Void
    let onClose: (SafariTab) -> Void

    @State private var isExpanded = true

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            // Cluster header
            Button(action: { withAnimation(.easeInOut(duration: 0.15)) { isExpanded.toggle() } }) {
                HStack(spacing: 6) {
                    Image(systemName: isExpanded ? "chevron.down" : "chevron.right")
                        .font(.system(size: 9, weight: .bold))
                        .foregroundStyle(TPTheme.textSecondary)
                        .frame(width: 12)

                    Circle()
                        .fill(cluster.color)
                        .frame(width: 8, height: 8)

                    Text(cluster.name)
                        .font(.system(size: 11, weight: .semibold))
                        .foregroundStyle(TPTheme.textPrimary)

                    TabCountBadge(count: tabs.count)

                    Spacer()

                    Text(cluster.description)
                        .font(.system(size: 9))
                        .foregroundStyle(TPTheme.textSecondary)
                        .lineLimit(1)
                }
                .padding(.horizontal, 10)
                .padding(.vertical, 6)
            }
            .buttonStyle(.plain)

            if isExpanded {
                ForEach(tabs) { tab in
                    TabRowView(
                        tab: tab,
                        isDuplicate: duplicateURLs.contains(tab.url),
                        onSwitch: { onSwitch(tab) },
                        onClose: { onClose(tab) }
                    )
                    .padding(.leading, 12)
                }
            }
        }
    }
}

struct ContentView: View {
    let scanner: SafariScanner
    let clusterer: TabClusterer

    @State private var searchText = ""
    @State private var filterMode: FilterMode = .all
    @State private var viewMode: ViewMode = .domain
    @State private var nlQuery = ""
    @State private var showBulkCloseConfirm = false
    @State private var bulkCloseAction: BulkCloseAction = .stale
    @AppStorage("nlResponseHeight") private var nlResponseHeight: Double = 150
    @State private var showNLResponse = true
    @AppStorage("appHeight") private var appHeight: Double = 480
    @AppStorage("appWidth") private var appWidth: Double = 420
    @State private var showSettings = false

    enum BulkCloseAction {
        case stale, duplicates
        var label: String {
            switch self {
            case .stale: return "stale tabs"
            case .duplicates: return "duplicate tabs"
            }
        }
    }

    var filteredTabs: [SafariTab] {
        var result = scanner.tabs

        // Search filter
        if !searchText.isEmpty {
            let query = searchText.lowercased()
            result = result.filter {
                $0.title.lowercased().contains(query) ||
                $0.url.lowercased().contains(query)
            }
        }

        // Category filter
        switch filterMode {
        case .all: break
        case .fresh: result = result.filter { $0.ageCategory == .fresh }
        case .stale: result = result.filter { $0.ageCategory == .stale }
        case .duplicates:
            let dupeURLs = scanner.duplicateURLs
            result = result.filter { dupeURLs.contains($0.url) }
        }

        return result
    }

    var body: some View {
        VStack(spacing: 0) {
            // Header
            VStack(spacing: 8) {
                HStack(spacing: 8) {
                    Image(systemName: "safari")
                        .font(.system(size: 14))
                        .foregroundStyle(TPTheme.accent)

                    Text("TabPilot")
                        .font(.system(size: 14, weight: .bold))
                        .foregroundStyle(TPTheme.textPrimary)

                    Spacer()

                    // Tab count + age summary
                    HStack(spacing: 6) {
                        let staleCount = scanner.tabs.filter { $0.ageCategory == .stale }.count
                        if staleCount > 0 {
                            HStack(spacing: 2) {
                                Image(systemName: "clock.badge.exclamationmark")
                                    .font(.system(size: 9))
                                Text("\(staleCount) stale")
                                    .font(.system(size: 10))
                            }
                            .foregroundStyle(TPTheme.stale)
                        }

                        Text("\(scanner.tabCount) tabs")
                            .font(.system(size: 11, weight: .medium))
                            .foregroundStyle(TPTheme.textSecondary)
                    }

                    Button(action: { showSettings.toggle() }) {
                        Image(systemName: "gearshape")
                            .font(.system(size: 12))
                            .foregroundStyle(TPTheme.textSecondary)
                    }
                    .buttonStyle(.plain)
                    .popover(isPresented: $showSettings) {
                        VStack(alignment: .leading, spacing: 12) {
                            Text("Window Size")
                                .font(.system(size: 12, weight: .semibold))
                                .foregroundStyle(TPTheme.textPrimary)

                            VStack(alignment: .leading, spacing: 4) {
                                Text("Width: \(Int(appWidth))px")
                                    .font(.system(size: 11))
                                    .foregroundStyle(TPTheme.textSecondary)
                                Slider(value: $appWidth, in: 320...600, step: 10)
                                    .frame(width: 180)
                            }

                            VStack(alignment: .leading, spacing: 4) {
                                Text("Height: \(Int(appHeight))px")
                                    .font(.system(size: 11))
                                    .foregroundStyle(TPTheme.textSecondary)
                                Slider(value: $appHeight, in: 250...800, step: 10)
                                    .frame(width: 180)
                            }

                            VStack(alignment: .leading, spacing: 4) {
                                Text("AI Response: \(Int(nlResponseHeight))px")
                                    .font(.system(size: 11))
                                    .foregroundStyle(TPTheme.textSecondary)
                                Slider(value: $nlResponseHeight, in: 60...350, step: 10)
                                    .frame(width: 180)
                            }

                            Button("Reset Defaults") {
                                appWidth = 420
                                appHeight = 480
                                nlResponseHeight = 150
                            }
                            .font(.system(size: 11))
                            .foregroundStyle(TPTheme.accent)
                            .buttonStyle(.plain)
                        }
                        .padding(14)
                    }
                }

                // Search bar
                HStack(spacing: 6) {
                    Image(systemName: "magnifyingglass")
                        .font(.system(size: 11))
                        .foregroundStyle(TPTheme.textSecondary)

                    TextField("Search tabs...", text: $searchText)
                        .textFieldStyle(.plain)
                        .font(.system(size: 12))
                        .foregroundStyle(TPTheme.textPrimary)

                    if !searchText.isEmpty {
                        Button(action: { searchText = "" }) {
                            Image(systemName: "xmark.circle.fill")
                                .font(.system(size: 11))
                                .foregroundStyle(TPTheme.textSecondary)
                        }
                        .buttonStyle(.plain)
                    }
                }
                .padding(.horizontal, 8)
                .padding(.vertical, 5)
                .background(TPTheme.surface)
                .clipShape(RoundedRectangle(cornerRadius: 6))
                .overlay(RoundedRectangle(cornerRadius: 6).stroke(TPTheme.border))

                // Filter + View mode
                HStack {
                    FilterChips(selected: $filterMode, duplicateCount: scanner.duplicateCount)

                    Spacer()

                    // View mode toggle
                    Picker("", selection: $viewMode) {
                        ForEach(ViewMode.allCases, id: \.self) { mode in
                            Text(mode.rawValue).tag(mode)
                        }
                    }
                    .pickerStyle(.segmented)
                    .frame(width: 160)
                }
            }
            .padding(12)
            .background(TPTheme.surface.opacity(0.5))

            Divider().overlay(TPTheme.border)

            // Error state
            if let err = scanner.lastScanError {
                HStack(spacing: 6) {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .foregroundStyle(TPTheme.error)
                    Text(err)
                        .font(.system(size: 11))
                        .foregroundStyle(TPTheme.textSecondary)
                }
                .padding(10)
                .frame(maxWidth: .infinity)
                .background(TPTheme.error.opacity(0.1))

                Divider().overlay(TPTheme.border)
            }

            // Tab list
            if filteredTabs.isEmpty {
                VStack(spacing: 8) {
                    Image(systemName: scanner.tabs.isEmpty ? "safari" : "magnifyingglass")
                        .font(.system(size: 24))
                        .foregroundStyle(TPTheme.textSecondary)
                    Text(scanner.tabs.isEmpty ? "No Safari tabs found" : "No tabs match filters")
                        .font(.system(size: 12))
                        .foregroundStyle(TPTheme.textSecondary)
                    if scanner.tabs.isEmpty {
                        Text("Open some tabs in Safari to get started")
                            .font(.system(size: 11))
                            .foregroundStyle(TPTheme.textSecondary.opacity(0.6))
                    }
                }
                .frame(maxWidth: .infinity, minHeight: 120)
                .padding(20)
            } else {
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 2) {
                        if viewMode == .cluster && !clusterer.clusters.isEmpty {
                            // AI Cluster view
                            ForEach(clusterer.clusters) { cluster in
                                let clusterTabs = cluster.tabIndices.compactMap { idx -> SafariTab? in
                                    guard idx < scanner.tabs.count else { return nil }
                                    let tab = scanner.tabs[idx]
                                    return filteredTabs.contains(tab) ? tab : nil
                                }
                                if !clusterTabs.isEmpty {
                                    ClusterGroupView(
                                        cluster: cluster,
                                        tabs: clusterTabs,
                                        duplicateURLs: scanner.duplicateURLs,
                                        onSwitch: { scanner.switchToTab($0) },
                                        onClose: { scanner.closeTab($0) }
                                    )
                                }
                            }
                        } else {
                            // Domain view
                            let groups = Dictionary(grouping: filteredTabs, by: { $0.shortDomain })
                                .sorted { $0.value.count > $1.value.count }
                            ForEach(groups, id: \.key) { domain, tabs in
                                DomainGroupView(
                                    domain: domain,
                                    tabs: tabs,
                                    duplicateURLs: scanner.duplicateURLs,
                                    onSwitch: { scanner.switchToTab($0) },
                                    onClose: { scanner.closeTab($0) }
                                )
                            }
                        }
                    }
                    .padding(.vertical, 4)
                }
                .frame(maxHeight: .infinity)
            }

            Divider().overlay(TPTheme.border)

            // Footer: bulk actions + Codex status + NL input
            VStack(spacing: 6) {
                // Bulk actions row
                HStack(spacing: 8) {
                    let staleCount = scanner.tabs.filter { $0.ageCategory == .stale }.count
                    if staleCount > 0 {
                        Button(action: {
                            bulkCloseAction = .stale
                            showBulkCloseConfirm = true
                        }) {
                            HStack(spacing: 3) {
                                Image(systemName: "trash")
                                    .font(.system(size: 9))
                                Text("Close \(staleCount) stale")
                                    .font(.system(size: 10))
                            }
                            .foregroundStyle(TPTheme.stale)
                            .padding(.horizontal, 8)
                            .padding(.vertical, 3)
                            .background(TPTheme.stale.opacity(0.1))
                            .clipShape(Capsule())
                        }
                        .buttonStyle(.plain)
                    }

                    if scanner.duplicateCount > 0 {
                        let dupeCloseCount = scanner.duplicateCount - scanner.duplicateURLs.count
                        Button(action: {
                            bulkCloseAction = .duplicates
                            showBulkCloseConfirm = true
                        }) {
                            HStack(spacing: 3) {
                                Image(systemName: "doc.on.doc")
                                    .font(.system(size: 9))
                                Text("Close \(dupeCloseCount) dupes")
                                    .font(.system(size: 10))
                            }
                            .foregroundStyle(TPTheme.warning)
                            .padding(.horizontal, 8)
                            .padding(.vertical, 3)
                            .background(TPTheme.warning.opacity(0.1))
                            .clipShape(Capsule())
                        }
                        .buttonStyle(.plain)
                    }

                    Spacer()

                    // Cluster button
                    Button(action: {
                        clusterer.clusterTabs(scanner.tabs)
                        viewMode = .cluster
                    }) {
                        HStack(spacing: 4) {
                            if case .clustering = clusterer.state {
                                SwiftUI.ProgressView()
                                    .controlSize(.mini)
                            } else {
                                Image(systemName: "sparkles")
                                    .font(.system(size: 10))
                            }
                            Text(clusterer.clusters.isEmpty ? "Cluster with AI" : "Re-cluster")
                                .font(.system(size: 10, weight: .medium))
                        }
                        .foregroundStyle(.white)
                        .padding(.horizontal, 10)
                        .padding(.vertical, 4)
                        .background(TPTheme.accent)
                        .clipShape(Capsule())
                    }
                    .buttonStyle(.plain)
                    .disabled(clusterer.state == .clustering || clusterer.state == .connecting)
                }

                // Codex status
                if case .error(let msg) = clusterer.state {
                    HStack(spacing: 4) {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .font(.system(size: 9))
                        Text(msg)
                            .font(.system(size: 9))
                            .lineLimit(2)
                    }
                    .foregroundStyle(TPTheme.error)
                    .frame(maxWidth: .infinity, alignment: .leading)
                }

                // NL Response
                if showNLResponse && !clusterer.nlResponse.isEmpty {
                    VStack(spacing: 0) {
                        HStack {
                            Text("AI Response")
                                .font(.system(size: 9, weight: .medium))
                                .foregroundStyle(TPTheme.textSecondary)
                            Spacer()
                            Button(action: { showNLResponse = false }) {
                                Image(systemName: "xmark.circle.fill")
                                    .font(.system(size: 13))
                                    .foregroundStyle(TPTheme.textSecondary.opacity(0.6))
                            }
                            .buttonStyle(.plain)
                        }
                        .padding(.horizontal, 8)
                        .padding(.vertical, 4)

                        Divider().overlay(TPTheme.border)

                        ScrollView {
                            Text(LocalizedStringKey(clusterer.nlResponse))
                                .font(.system(size: 11))
                                .foregroundStyle(TPTheme.textPrimary)
                                .textSelection(.enabled)
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .padding(8)
                        }
                    }
                    .frame(minHeight: 100, maxHeight: nlResponseHeight)
                    .background(TPTheme.surface)
                    .clipShape(RoundedRectangle(cornerRadius: 6))
                }

                // NL input (Layer 3)
                HStack(spacing: 6) {
                    Image(systemName: "sparkle")
                        .font(.system(size: 10))
                        .foregroundStyle(TPTheme.accent)

                    TextField("Ask about your tabs...", text: $nlQuery)
                        .textFieldStyle(.plain)
                        .font(.system(size: 11))
                        .foregroundStyle(TPTheme.textPrimary)
                        .onSubmit {
                            guard !nlQuery.isEmpty else { return }
                            let q = nlQuery
                            nlQuery = ""
                            showNLResponse = true
                            clusterer.askAboutTabs(query: q, tabs: scanner.tabs, callback: nil)
                        }

                    if !nlQuery.isEmpty {
                        Button(action: {
                            let q = nlQuery
                            nlQuery = ""
                            showNLResponse = true
                            clusterer.askAboutTabs(query: q, tabs: scanner.tabs, callback: nil)
                        }) {
                            Image(systemName: "arrow.up.circle.fill")
                                .font(.system(size: 16))
                                .foregroundStyle(TPTheme.accent)
                        }
                        .buttonStyle(.plain)
                    }
                }
                .padding(.horizontal, 8)
                .padding(.vertical, 5)
                .background(TPTheme.surface)
                .clipShape(RoundedRectangle(cornerRadius: 6))
                .overlay(RoundedRectangle(cornerRadius: 6).stroke(TPTheme.border))

                // Version footer
                HStack {
                    Text("TabPilot v0.1.0")
                        .font(.system(size: 9))
                        .foregroundStyle(TPTheme.textSecondary.opacity(0.4))
                    Spacer()
                    Button("Quit") { NSApplication.shared.terminate(nil) }
                        .font(.system(size: 9))
                        .foregroundStyle(TPTheme.textSecondary.opacity(0.4))
                        .buttonStyle(.plain)
                }
            }
            .padding(10)
            .background(TPTheme.surface.opacity(0.5))

        }
        .background(TPTheme.bg)
        .frame(width: appWidth, height: appHeight)
        .popover(isPresented: $showBulkCloseConfirm) {
            VStack(spacing: 10) {
                Image(systemName: "exclamationmark.triangle.fill")
                    .font(.system(size: 24))
                    .foregroundStyle(TPTheme.warning)

                Text("Close \(bulkCloseAction.label)?")
                    .font(.system(size: 13, weight: .semibold))

                switch bulkCloseAction {
                case .stale:
                    let count = scanner.tabs.filter { $0.ageCategory == .stale }.count
                    Text("This will close \(count) tabs that haven't been visited in over 7 days.")
                        .font(.system(size: 11))
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                case .duplicates:
                    let count = scanner.duplicateCount - scanner.duplicateURLs.count
                    Text("This will close \(count) duplicate tabs, keeping one of each.")
                        .font(.system(size: 11))
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                }

                HStack(spacing: 12) {
                    Button("Cancel") { showBulkCloseConfirm = false }
                        .buttonStyle(.plain)
                        .font(.system(size: 12))

                    Button(action: {
                        showBulkCloseConfirm = false
                        switch bulkCloseAction {
                        case .stale: scanner.closeStaleTabs()
                        case .duplicates: scanner.closeDuplicates()
                        }
                        // Re-scan after closing
                        DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) {
                            scanner.scanAllTabs()
                        }
                    }) {
                        Text("Close Tabs")
                            .font(.system(size: 12, weight: .medium))
                            .foregroundStyle(.white)
                            .padding(.horizontal, 14)
                            .padding(.vertical, 5)
                            .background(TPTheme.error)
                            .clipShape(RoundedRectangle(cornerRadius: 5))
                    }
                    .buttonStyle(.plain)
                }
            }
            .padding(16)
            .frame(width: 280)
        }
    }
}

// MARK: - App

@main
struct TabPilotApp: App {
    @State private var scanner = SafariScanner()
    @State private var clusterer = TabClusterer()

    var menuBarLabel: String {
        let count = scanner.tabCount
        if count == 0 { return "0" }
        return "\(count)"
    }

    var body: some Scene {
        MenuBarExtra {
            ContentView(scanner: scanner, clusterer: clusterer)
        } label: {
            HStack(spacing: 3) {
                Image(systemName: "safari")
                Text(menuBarLabel)
                    .monospacedDigit()
            }
        }
        .menuBarExtraStyle(.window)
    }
}
