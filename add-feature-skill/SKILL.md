---
name: add-feature-skill
description: >
  Guide for adding new features to TabPilot. Covers architecture,
  extension points, patterns, and build process.
---

## Overview

TabPilot is a macOS menu bar app that serves as a Safari tab command center -- it polls Safari tabs via AppleScript, tracks tab age with JSON persistence, groups tabs by domain, and supports AI-powered semantic clustering via the Codex WebSocket protocol.

## Architecture

TabPilot is a single-file SwiftUI menu bar app (`TabPilot.swift`, ~1645 lines). It uses the `@main` struct `TabPilotApp` with a `MenuBarExtra(.window)` scene. Two `@Observable` classes own all mutable state:

- **`SafariScanner`** -- polls Safari every 5 seconds via AppleScript, maintains the live tab list, computes domain groups and duplicate detection, and persists tab history to `~/.tabpilot/tab_history.json`.
- **`TabClusterer`** -- connects to the Codex app-server over WebSocket (JSON-RPC 2.0), sends tab data for AI-powered semantic clustering, and supports natural-language tab queries.

Both are held as `@State` properties on the App struct and passed into `ContentView`.

## Key Types

| Type | Kind | Description |
|------|------|-------------|
| `TPTheme` | enum | Static color constants for the dark UI theme |
| `RawWebSocket` | class | NWConnection-based WebSocket client (shared pattern across apps) |
| `SafariTab` | struct | Identifiable tab with url, title, windowIndex, tabIndex, domain helpers |
| `AgeCategory` | enum | Four tiers: `.fresh`, `.warm`, `.cooling`, `.stale` with color and label |
| `TabCluster` | struct | AI-generated cluster with name, description, and tab list |
| `FilterMode` | enum | CaseIterable filter options (all, duplicates, fresh, warm, cooling, stale) |
| `ViewMode` | enum | CaseIterable view modes (domains, clusters) |
| `TabHistory` / `TabHistoryStore` | struct/enum | Codable persistence of first-seen timestamps per URL |
| `SafariScanner` | @Observable class | Safari polling, tab list, domain grouping, history tracking |
| `ClusterState` | enum | FSM for clustering: idle, connecting, clustering, done, error |
| `TabClusterer` | @Observable class | Codex AI integration for semantic clustering and NL queries |
| `TabCountBadge` | View | Displays tab count in a pill badge |
| `FilterChips` | View | Horizontal row of filter mode toggle buttons |
| `AgeBadge` | View | Colored dot + label for tab age category |
| `DomainIcon` | View | Favicon-style first-letter icon for a domain |
| `TabRowView` | View | Single tab row with title, domain, age, and action buttons |
| `DomainGroupView` | View | Collapsible section grouping tabs by domain |
| `ClusterGroupView` | View | Collapsible section grouping tabs by AI cluster |
| `ContentView` | View | Root view with filter chips, view mode toggle, tab list, and cluster UI |

## How to Add a Feature

1. **Define any new model types** at the top of `TabPilot.swift` in the `// MARK: - Models` section. Follow the existing pattern: Identifiable structs, CaseIterable enums.

2. **If the feature needs new state**, add properties to the appropriate `@Observable` class:
   - Tab data, scanning, or Safari interaction --> `SafariScanner`
   - AI/Codex integration or clustering --> `TabClusterer`
   - If neither fits, consider creating a new `@Observable` class and adding it as `@State` in `TabPilotApp`.

3. **If adding a new filter**, add a case to `FilterMode` and update the filtering logic in `ContentView` (the `filteredTabs` computed property).

4. **If adding a new view mode**, add a case to `ViewMode` and add a corresponding branch in `ContentView`'s body that renders the new grouping.

5. **If adding a new view**, create a new `struct MyView: View` in the `// MARK: - Views` section. Use `TPTheme` colors for all styling.

6. **If adding a new Codex AI interaction**, follow the `TabClusterer` pattern:
   - Connect via `RawWebSocket` to `127.0.0.1:4663`
   - Send `initialize` JSON-RPC request, then `thread/start`, then `turn/start` with your prompt
   - Handle streaming deltas via `item/agentMessage/delta` notifications
   - Parse the accumulated response when the turn completes

7. **Build and test** with `bash build.sh` then `open TabPilot.app`.

## Extension Points

- **New FilterMode cases** -- add to the `FilterMode` enum, implement filtering logic in ContentView
- **New ViewMode cases** -- add to `ViewMode` enum, implement grouping/rendering in ContentView
- **New scanner data** -- extend `SafariScanner.scanAllTabs()` AppleScript to extract additional tab properties (e.g., favicons, reading progress)
- **New AI-powered features** -- follow the `TabClusterer` pattern: create a new `@Observable` class with its own `ClusterState`-style FSM, connect to Codex, send prompts, parse streaming responses
- **New tab actions** -- add buttons to `TabRowView` that call AppleScript commands (close tab, move tab, open URL)
- **Tab history analytics** -- extend `TabHistory`/`TabHistoryStore` to track additional metrics (visit count, time spent)

## Conventions

- **Theme**: All colors come from `TPTheme` static properties. Use `TPTheme.bg` for backgrounds, `TPTheme.surface` for cards, `TPTheme.accent` for interactive elements.
- **WebSocket/JSON-RPC**: The `RawWebSocket` class handles raw TCP + WebSocket framing via NWConnection. JSON-RPC 2.0 messages use sequential integer IDs tracked in `pendingRequests: [Int: String]`. Always send `initialize` before `thread/start` before `turn/start`.
- **SF Symbols**: Used throughout for icons (`safari`, `arrow.clockwise`, `doc.on.doc`, `sparkles`, `xmark.circle`). Keep the icon style consistent.
- **AppleScript**: Safari interaction is done via `NSAppleScript`. Scripts query `every window` and `every tab` for URL and title. Keep scripts minimal for performance.
- **State machines**: Async operations use enum FSMs (e.g., `ClusterState`) to drive UI transitions. The view switches on state to show appropriate content.
- **Persistence**: Tab history is stored as JSON at `~/.tabpilot/tab_history.json` via `TabHistoryStore.save()/load()`.

## Build & Test

```bash
bash build.sh        # Compiles TabPilot.swift and creates TabPilot.app bundle
open TabPilot.app    # Run the app (appears in menu bar)
```

Requires macOS 14.0+ and Xcode command-line tools. The app runs as `LSUIElement` (no Dock icon). Safari automation requires user approval for AppleScript access.
