import AppKit
import Darwin
import ServiceManagement

// MARK: - Model

struct Host: Codable {
    var name: String
    var mac: String          // "AA:BB:CC:DD:EE:FF" or "aabbccddeeff" etc.
    var broadcast: String    // usually 255.255.255.255
    var port: UInt16         // usually 9
    var address: String?     // optional IP/hostname, used only for on/off status
}

// Online status, cached per host (keyed by MAC).
enum Status { case unknown, online, offline }

enum Net {
    /// IPv4 + netmask of the active interface (prefer en0, then en1, then any up iface).
    private static func activeIPv4() -> (ip: in_addr_t, mask: in_addr_t)? {
        var head: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head) == 0 else { return nil }
        defer { freeifaddrs(head) }
        var candidates: [(name: String, ip: in_addr_t, mask: in_addr_t)] = []
        var node = head
        while let n = node {
            let ifa = n.pointee
            node = ifa.ifa_next
            let flags = Int32(ifa.ifa_flags)
            guard let addrPtr = ifa.ifa_addr, addrPtr.pointee.sa_family == sa_family_t(AF_INET),
                  let maskPtr = ifa.ifa_netmask,
                  (flags & IFF_UP) != 0, (flags & IFF_LOOPBACK) == 0 else { continue }
            let ip = addrPtr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee.sin_addr.s_addr }
            let mask = maskPtr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee.sin_addr.s_addr }
            if ip == 0 { continue }
            candidates.append((String(cString: ifa.ifa_name), ip, mask))
        }
        let pick = candidates.first { $0.name == "en0" } ?? candidates.first { $0.name == "en1" } ?? candidates.first
        return pick.map { ($0.ip, $0.mask) }
    }

    /// Subnet-directed broadcast, e.g. "192.168.10.255". Falls back to "255.255.255.255".
    static func defaultBroadcast() -> String {
        guard let c = activeIPv4() else { return "255.255.255.255" }
        let bcast = in_addr(s_addr: (c.ip & c.mask) | ~c.mask)
        return String(cString: inet_ntoa(bcast))
    }

    /// Dotted-quad prefix of the local /24, e.g. "192.168.10." — or nil.
    static func localPrefix() -> String? {
        guard let c = activeIPv4() else { return nil }
        let s = String(cString: inet_ntoa(in_addr(s_addr: c.ip)))
        let parts = s.split(separator: ".")
        guard parts.count == 4 else { return nil }
        return "\(parts[0]).\(parts[1]).\(parts[2])."
    }

    /// The interface the kernel uses to reach the local subnet (e.g. "en0").
    /// On a multi-homed Mac this disambiguates which ARP entries are authoritative.
    static func subnetInterface() -> String? {
        guard let prefix = localPrefix() else { return nil }
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/sbin/route")
        p.arguments = ["-n", "get", "\(prefix)1"]
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = Pipe()
        do { try p.run() } catch { return nil }
        p.waitUntilExit()
        let out = String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        for line in out.split(separator: "\n") where line.contains("interface:") {
            return line.split(separator: ":").last?.trimmingCharacters(in: .whitespaces)
        }
        return nil
    }

    /// Ping every host in the local /24 to populate the ARP cache. Blocks until done (~a few s).
    static func pingSweep() {
        guard let prefix = localPrefix() else { return }
        let group = DispatchGroup()
        let sem = DispatchSemaphore(value: 32)
        let q = DispatchQueue(label: "wol.sweep", attributes: .concurrent)
        for h in 1...254 {
            sem.wait(); group.enter()
            q.async {
                let p = Process()
                p.executableURL = URL(fileURLWithPath: "/sbin/ping")
                p.arguments = ["-c", "1", "-t", "1", "-W", "300", "\(prefix)\(h)"]
                p.standardOutput = Pipe(); p.standardError = Pipe()
                try? p.run(); p.waitUntilExit()
                sem.signal(); group.leave()
            }
        }
        _ = group.wait(timeout: .now() + 12)
    }
}

enum Resolver {
    /// Best-effort device name for an IP: reverse-DNS, then NetBIOS (Windows). nil if none.
    static func name(forIP ip: String) -> String? {
        if let n = reverseDNS(ip) { return n }
        if let n = netbios(ip) { return n }
        return nil
    }

    /// Reverse DNS (PTR) via the system resolver. Returns the short host label.
    private static func reverseDNS(_ ip: String) -> String? {
        var sa = sockaddr_in()
        sa.sin_family = sa_family_t(AF_INET)
        sa.sin_addr.s_addr = inet_addr(ip)
        guard sa.sin_addr.s_addr != INADDR_NONE else { return nil }
        var hostBuf = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        let rc = withUnsafePointer(to: &sa) { p in
            p.withMemoryRebound(to: sockaddr.self, capacity: 1) { sp in
                getnameinfo(sp, socklen_t(MemoryLayout<sockaddr_in>.size),
                            &hostBuf, socklen_t(hostBuf.count), nil, 0, NI_NAMEREQD)
            }
        }
        guard rc == 0 else { return nil }
        let full = String(cString: hostBuf)
        if full.isEmpty || full == ip { return nil }
        return full.split(separator: ".").first.map(String.init) ?? full   // strip .local / domain
    }

    /// Native NetBIOS node-status query on UDP 137 (the nbtscan technique). Fast 1.2s timeout.
    /// Returns the workstation name for any Windows PC with NetBIOS over TCP/IP enabled.
    private static func netbios(_ ip: String) -> String? {
        let fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        guard fd >= 0 else { return nil }
        defer { close(fd) }
        var tv = timeval(tv_sec: 1, tv_usec: 200_000)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))

        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = UInt16(137).bigEndian
        addr.sin_addr.s_addr = inet_addr(ip)
        guard addr.sin_addr.s_addr != INADDR_NONE else { return nil }

        // NBSTAT query for the wildcard name "*".
        var q: [UInt8] = [0,0, 0,0, 0,1, 0,0, 0,0, 0,0]   // tid, flags, qd=1, an/ns/ar=0
        let wildcard: [UInt8] = [0x2A] + Array(repeating: 0, count: 15)
        var enc = [UInt8]()
        for b in wildcard { enc.append((b >> 4) + 0x41); enc.append((b & 0x0F) + 0x41) }
        q.append(0x20); q.append(contentsOf: enc); q.append(0x00)
        q.append(contentsOf: [0x00, 0x21])               // type NBSTAT
        q.append(contentsOf: [0x00, 0x01])               // class IN

        let sent = q.withUnsafeBytes { raw in
            withUnsafePointer(to: &addr) { ap in
                ap.withMemoryRebound(to: sockaddr.self, capacity: 1) { sp in
                    sendto(fd, raw.baseAddress, raw.count, 0, sp, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
        }
        guard sent == q.count else { return nil }

        var buf = [UInt8](repeating: 0, count: 1024)
        let n = recv(fd, &buf, buf.count, 0)
        guard n > 57 else { return nil }
        let count = Int(buf[56])
        var off = 57
        for _ in 0..<count {
            guard off + 18 <= n else { break }
            let suffix = buf[off + 15]
            let flags = (UInt16(buf[off + 16]) << 8) | UInt16(buf[off + 17])
            let isGroup = (flags & 0x8000) != 0
            if suffix == 0x00 && !isGroup {              // unique workstation name
                let name = String(bytes: buf[off..<off + 15], encoding: .ascii)?
                    .trimmingCharacters(in: .whitespaces)
                if let name, !name.isEmpty { return name }
            }
            off += 18
        }
        return nil
    }
}

enum Pinger {
    /// Send one ping to an address, ignoring the result. Used to populate/refresh the ARP cache —
    /// it triggers layer-2 resolution even when the host's firewall drops the ICMP echo reply.
    static func poke(_ addr: String) {
        let a = addr.trimmingCharacters(in: .whitespaces)
        guard !a.isEmpty else { return }
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/sbin/ping")
        p.arguments = ["-c", "1", "-t", "1", "-W", "800", a]
        p.standardOutput = Pipe()
        p.standardError = Pipe()
        do { try p.run() } catch { return }
        p.waitUntilExit()
    }

    /// Canonical-MAC → IP from the ARP table. Only counts *complete* entries; when an interface
    /// is given, only entries on that interface — so a stale entry left on another (multi-homed)
    /// interface for a powered-off host is ignored.
    static func arpMapByMAC(onInterface iface: String? = nil) -> [String: String] {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/sbin/arp")
        p.arguments = ["-a", "-n"]
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = Pipe()
        do { try p.run() } catch { return [:] }
        p.waitUntilExit()
        let out = String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        var map: [String: String] = [:]
        for line in out.split(separator: "\n") {
            if line.contains("incomplete") { continue }
            if let iface, !line.contains(" on \(iface) ") && !line.contains(" on \(iface)\t") { continue }
            guard let ipStart = line.firstIndex(of: "("), let ipEnd = line.firstIndex(of: ")"),
                  let at = line.range(of: " at ") else { continue }
            let ip = String(line[line.index(after: ipStart)..<ipEnd])
            let rest = line[at.upperBound...]
            guard let macTok = rest.split(separator: " ").first.map(String.init),
                  let mac = canonMAC(macTok) else { continue }
            map[mac] = ip   // first/any IP for this MAC is fine on a flat LAN
        }
        return map
    }

    /// Resolve a MAC to its current IP: read ARP; if absent, sweep once and re-read.
    static func resolveIP(forMAC mac: String) -> String? {
        guard let want = canonMAC(mac) else { return nil }
        let iface = Net.subnetInterface()
        if let ip = arpMapByMAC(onInterface: iface)[want] { return ip }
        Net.pingSweep()
        return arpMapByMAC(onInterface: iface)[want]
    }

    /// Canonical MAC: 6 colon-separated 2-digit lowercase hex octets, or nil.
    static func canonMAC(_ s: String) -> String? {
        let octets = s.split(separator: ":")
        guard octets.count == 6 else { return nil }
        var out = [String]()
        for o in octets {
            guard o.count <= 2, UInt8(o, radix: 16) != nil else { return nil }
            out.append((o.count == 1 ? "0" + o : String(o)).lowercased())
        }
        return out.joined(separator: ":")
    }
}

enum Store {
    static let key = "wakemenu.hosts"

    static func load() -> [Host] {
        guard let data = UserDefaults.standard.data(forKey: key),
              let hosts = try? JSONDecoder().decode([Host].self, from: data) else { return [] }
        return hosts
    }

    static func save(_ hosts: [Host]) {
        if let data = try? JSONEncoder().encode(hosts) {
            UserDefaults.standard.set(data, forKey: key)
        }
    }
}

// MARK: - Wake-on-LAN

enum WOL {
    /// Parse a MAC string into 6 bytes. Accepts ':', '-', '.' or no separators.
    static func parseMAC(_ s: String) -> [UInt8]? {
        let hex = s.filter { $0.isHexDigit }
        guard hex.count == 12 else { return nil }
        var bytes = [UInt8]()
        var idx = hex.startIndex
        for _ in 0..<6 {
            let next = hex.index(idx, offsetBy: 2)
            guard let b = UInt8(hex[idx..<next], radix: 16) else { return nil }
            bytes.append(b)
            idx = next
        }
        return bytes
    }

    /// Build the 102-byte magic packet: 6x 0xFF + 16x MAC.
    static func magicPacket(_ mac: [UInt8]) -> [UInt8] {
        var p = [UInt8](repeating: 0xFF, count: 6)
        for _ in 0..<16 { p.append(contentsOf: mac) }
        return p
    }

    /// Send the magic packet via a broadcast UDP socket. Returns nil on success, error string on failure.
    static func send(host: Host) -> String? {
        guard let mac = parseMAC(host.mac) else { return "Invalid MAC address: \(host.mac)" }
        let packet = magicPacket(mac)

        let fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        guard fd >= 0 else { return "socket() failed: \(String(cString: strerror(errno)))" }
        defer { close(fd) }

        var on: Int32 = 1
        guard setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &on, socklen_t(MemoryLayout<Int32>.size)) == 0 else {
            return "SO_BROADCAST failed: \(String(cString: strerror(errno)))"
        }

        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = host.port.bigEndian
        addr.sin_addr.s_addr = inet_addr(host.broadcast)
        guard addr.sin_addr.s_addr != INADDR_NONE else { return "Invalid broadcast address: \(host.broadcast)" }

        let sent = packet.withUnsafeBytes { raw -> Int in
            withUnsafePointer(to: &addr) { aptr in
                aptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { saptr in
                    sendto(fd, raw.baseAddress, raw.count, 0, saptr, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
        }
        if sent != packet.count {
            return "sendto() failed: \(String(cString: strerror(errno)))"
        }
        return nil
    }
}

// MARK: - App

final class AppDelegate: NSObject, NSApplicationDelegate, NSMenuDelegate, NSTableViewDataSource, NSTableViewDelegate {
    private var statusItem: NSStatusItem!
    private var hosts: [Host] = Store.load()
    private var status: [String: Status] = [:]       // keyed by MAC
    private var lastIP: [String: String] = [:]        // canonical MAC → last-seen IP
    private var lastSweep: Date?                       // throttle full subnet sweeps
    private var hostItems: [NSMenuItem] = []          // wake items, index-aligned with hosts
    private var pollTimer: Timer?

    // Window UI
    private var window: NSWindow?
    private var pcTable: NSTableView?                  // saved PCs
    private var discTable: NSTableView?                // discovered devices
    private var discovered: [(ip: String, mac: String, name: String)] = []
    private var scanSpinner: NSProgressIndicator?
    private var scanButton: NSButton?
    private var fName: NSTextField?
    private var fMAC: NSTextField?
    private var fBcast: NSTextField?

    func applicationDidFinishLaunching(_ note: Notification) {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        if let button = statusItem.button {
            button.image = NSImage(systemSymbolName: "power", accessibilityDescription: "Wake on LAN")
        }
        rebuildMenu()
        refreshStatuses()
        // Re-check every 30s while the app runs.
        pollTimer = Timer.scheduledTimer(withTimeInterval: 30, repeats: true) { [weak self] _ in
            self?.refreshStatuses()
        }
    }

    /// Muted status colors (blended toward gray so they read as subtle, not neon).
    private func statusColor(_ s: Status) -> NSColor {
        switch s {
        case .online:  return NSColor.systemGreen.blended(withFraction: 0.30, of: .gray) ?? .systemGreen
        case .offline: return NSColor.systemRed.blended(withFraction: 0.40, of: .gray) ?? .systemRed
        case .unknown: return .tertiaryLabelColor
        }
    }

    /// A small colored ● for the given status.
    private func bullet(_ s: Status, size: CGFloat) -> NSAttributedString {
        NSAttributedString(string: "●", attributes: [
            .foregroundColor: statusColor(s),
            .font: NSFont.systemFont(ofSize: size),
        ])
    }

    /// Menu item title: subtle dot + PC name.
    private func menuTitle(for host: Host) -> NSAttributedString {
        let s = status[host.mac] ?? .unknown
        let m = NSMutableAttributedString(attributedString: bullet(s, size: 9))
        m.append(NSAttributedString(string: "  \(host.name)", attributes: [
            .foregroundColor: NSColor.labelColor,
            .font: NSFont.menuFont(ofSize: 0),
        ]))
        return m
    }

    /// Determine each PC's status purely from its MAC:
    ///  1) Poke the last-known IP (and refresh the ARP cache) so a PC that just went off goes stale.
    ///  2) Read the ARP table; a MAC present there is online — at whatever IP DHCP gave it now.
    ///  3) If any MAC is missing, do one throttled subnet sweep to relocate it, then re-read.
    private func refreshStatuses() {
        let snapshot = hosts
        let knownIPs = lastIP
        let canSweep = (lastSweep.map { Date().timeIntervalSince($0) > 45 } ?? true)

        DispatchQueue.global(qos: .utility).async {
            let iface = Net.subnetInterface()        // authoritative interface for ARP reads

            // 1) Refresh ARP entries for IPs we last saw these PCs at.
            for ip in Set(knownIPs.values) { Pinger.poke(ip) }

            // 2) First pass over the existing ARP table (active interface only).
            var map = Pinger.arpMapByMAC(onInterface: iface)
            let needSweep = snapshot.contains { host in
                guard let c = Pinger.canonMAC(host.mac) else { return false }
                return map[c] == nil
            }

            // 3) Relocate any missing MAC with a single sweep (throttled).
            var didSweep = false
            if needSweep && canSweep {
                Net.pingSweep()
                map = Pinger.arpMapByMAC(onInterface: iface)
                didSweep = true
            }

            var newStatus: [String: Status] = [:]
            var newIPs: [String: String] = [:]
            for host in snapshot {
                guard let c = Pinger.canonMAC(host.mac) else { newStatus[host.mac] = .offline; continue }
                if let ip = map[c] {
                    newStatus[host.mac] = .online
                    newIPs[c] = ip
                } else {
                    newStatus[host.mac] = .offline
                }
            }

            DispatchQueue.main.async {
                for (mac, s) in newStatus { self.status[mac] = s }
                for (c, ip) in newIPs { self.lastIP[c] = ip }
                if didSweep { self.lastSweep = Date() }
                self.applyStatusToMenu()
            }
        }
    }

    /// Update existing menu item titles in place (so an open menu refreshes live), and the window table.
    private func applyStatusToMenu() {
        for (i, item) in hostItems.enumerated() where i < hosts.count {
            let host = hosts[i]
            item.attributedTitle = menuTitle(for: host)
            let ip = Pinger.canonMAC(host.mac).flatMap { lastIP[$0] }
            item.toolTip = "\(host.mac)" + (ip.map { "  →  \($0)" } ?? "")
        }
        if let t = pcTable {
            let sel = t.selectedRow
            t.reloadData()
            if sel >= 0, sel < hosts.count { t.selectRowIndexes(IndexSet(integer: sel), byExtendingSelection: false) }
        }
    }

    // NSMenuDelegate: refresh status each time the menu opens.
    func menuWillOpen(_ menu: NSMenu) { refreshStatuses() }

    private func rebuildMenu() {
        let menu = NSMenu()
        menu.delegate = self
        hostItems.removeAll()

        if hosts.isEmpty {
            let empty = NSMenuItem(title: "No PCs yet — add one below", action: nil, keyEquivalent: "")
            empty.isEnabled = false
            menu.addItem(empty)
        } else {
            let header = NSMenuItem(title: "Click a PC to wake it:", action: nil, keyEquivalent: "")
            header.isEnabled = false
            menu.addItem(header)
            for (i, host) in hosts.enumerated() {
                let item = NSMenuItem(title: host.name, action: #selector(wakeHost(_:)), keyEquivalent: "")
                item.attributedTitle = menuTitle(for: host)
                item.target = self
                item.tag = i
                item.toolTip = host.mac
                menu.addItem(item)
                hostItems.append(item)
            }
        }

        menu.addItem(.separator())

        let manage = NSMenuItem(title: "Manage PCs…", action: #selector(openWindow), keyEquivalent: "m")
        manage.target = self
        menu.addItem(manage)

        let launch = NSMenuItem(title: "Launch at Login", action: #selector(toggleLaunchAtLogin), keyEquivalent: "")
        launch.target = self
        launch.state = (SMAppService.mainApp.status == .enabled) ? .on : .off
        menu.addItem(launch)

        menu.addItem(.separator())
        let quit = NSMenuItem(title: "Quit", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        menu.addItem(quit)

        statusItem.menu = menu
    }

    // MARK: Index-based actions (shared by the menu and the window)

    private func wake(at index: Int) {
        guard index >= 0, index < hosts.count else { return }
        let host = hosts[index]
        if let err = WOL.send(host: host) {
            showAlert(title: "Wake failed", body: err)
        } else {
            flashSuccess(tooltip: "Sent magic packet to \(host.name)")
        }
    }

    private func add() {
        if let host = presentHostEditor(title: "Add a PC", confirm: "Add", prefill: nil) {
            hosts.append(host)
            Store.save(hosts)
            reloadAll()
        }
    }

    private func edit(at index: Int) {
        guard index >= 0, index < hosts.count else { return }
        if let host = presentHostEditor(title: "Edit PC", confirm: "Save", prefill: hosts[index]) {
            status[hosts[index].mac] = nil               // drop stale status under old MAC
            hosts[index] = host
            Store.save(hosts)
            reloadAll()
        }
    }

    private func remove(at index: Int) {
        guard index >= 0, index < hosts.count else { return }
        hosts.remove(at: index)
        Store.save(hosts)
        reloadAll()
    }

    /// Rebuild the menu, reload the window table (if open), and re-check status.
    private func reloadAll() {
        rebuildMenu()
        pcTable?.reloadData()
        refreshStatuses()
    }

    @objc private func toggleLaunchAtLogin() {
        do {
            if SMAppService.mainApp.status == .enabled {
                try SMAppService.mainApp.unregister()
            } else {
                try SMAppService.mainApp.register()
            }
        } catch {
            showAlert(title: "Couldn't change Launch at Login", body: error.localizedDescription)
        }
        rebuildMenu()
    }

    // Menu selectors → index helpers
    @objc private func wakeHost(_ sender: NSMenuItem) { wake(at: sender.tag) }
    @objc private func editHost(_ sender: NSMenuItem) { edit(at: sender.tag) }
    @objc private func addHost() { add() }

    // MARK: - Window UI

    @objc private func openWindow() {
        if let w = window {
            NSApp.activate(ignoringOtherApps: true)
            w.makeKeyAndOrderFront(nil)
            refreshStatuses()
            return
        }
        let w = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 460, height: 660),
                         styleMask: [.titled, .closable, .miniaturizable],
                         backing: .buffered, defer: false)
        w.title = "WakeMenu — PCs"
        w.isReleasedWhenClosed = false
        w.contentView = buildWindowContent()
        w.center()
        window = w
        NSApp.activate(ignoringOtherApps: true)
        w.makeKeyAndOrderFront(nil)
        refreshStatuses()
    }

    private func sectionLabel(_ s: String) -> NSTextField {
        let t = NSTextField(labelWithString: s)
        t.font = NSFont.boldSystemFont(ofSize: 13)
        return t
    }

    private func hr() -> NSBox {
        let b = NSBox(); b.boxType = .separator
        b.heightAnchor.constraint(equalToConstant: 1).isActive = true
        return b
    }

    private func makeTable(columns: [(id: String, title: String, width: CGFloat)], height: CGFloat) -> (NSScrollView, NSTableView) {
        let table = NSTableView()
        table.dataSource = self
        table.delegate = self
        table.usesAlternatingRowBackgroundColors = true
        table.allowsMultipleSelection = false
        table.rowHeight = 22
        for c in columns {
            let col = NSTableColumn(identifier: NSUserInterfaceItemIdentifier(c.id))
            col.title = c.title
            col.width = c.width
            table.addTableColumn(col)
        }
        let scroll = NSScrollView()
        scroll.documentView = table
        scroll.hasVerticalScroller = true
        scroll.borderType = .bezelBorder
        scroll.translatesAutoresizingMaskIntoConstraints = false
        scroll.heightAnchor.constraint(equalToConstant: height).isActive = true
        return (scroll, table)
    }

    private func buildWindowContent() -> NSView {
        let root = NSView(frame: NSRect(x: 0, y: 0, width: 460, height: 660))

        let stack = NSStackView()
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 8
        stack.translatesAutoresizingMaskIntoConstraints = false
        root.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 16),
            stack.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -16),
            stack.topAnchor.constraint(equalTo: root.topAnchor, constant: 16),
            stack.bottomAnchor.constraint(lessThanOrEqualTo: root.bottomAnchor, constant: -16),
        ])
        func fullWidth(_ v: NSView) { v.widthAnchor.constraint(equalTo: stack.widthAnchor).isActive = true }

        // --- 1. Discovery (top) ---
        let scanRow = NSStackView()
        scanRow.orientation = .horizontal
        scanRow.spacing = 8
        let scanLbl = sectionLabel("Devices on your network")
        let spinner = NSProgressIndicator()
        spinner.style = .spinning
        spinner.controlSize = .small
        spinner.isDisplayedWhenStopped = false
        spinner.translatesAutoresizingMaskIntoConstraints = false
        spinner.widthAnchor.constraint(equalToConstant: 16).isActive = true
        let scanBtn = NSButton(title: "Scan", target: self, action: #selector(scanAction))
        scanBtn.bezelStyle = .rounded
        scanRow.addArrangedSubview(scanLbl)
        scanRow.addArrangedSubview(NSView())   // flexible spacer
        scanRow.addArrangedSubview(spinner)
        scanRow.addArrangedSubview(scanBtn)
        scanSpinner = spinner
        scanButton = scanBtn
        stack.addArrangedSubview(scanRow); fullWidth(scanRow)

        let (discScroll, dTable) = makeTable(
            columns: [("d_ip", "IP", 100), ("d_mac", "MAC address", 150), ("d_name", "Name", 150)], height: 150)
        discTable = dTable
        stack.addArrangedSubview(discScroll); fullWidth(discScroll)

        let hint = NSTextField(labelWithString: "Select a device to fill the fields below — or enter them manually.")
        hint.font = NSFont.systemFont(ofSize: 11)
        hint.textColor = .secondaryLabelColor
        stack.addArrangedSubview(hint)

        stack.addArrangedSubview(hr()); fullWidth(stack.arrangedSubviews.last!)

        // --- 2. Saved PCs (middle) ---
        stack.addArrangedSubview(sectionLabel("Saved PCs"))
        let (pcScroll, pTable) = makeTable(
            columns: [("p_status", "", 24), ("p_name", "Name", 75),
                      ("p_mac", "MAC", 140), ("p_ip", "Current IP", 110)], height: 150)
        pcTable = pTable
        stack.addArrangedSubview(pcScroll); fullWidth(pcScroll)

        let btnRow = NSStackView()
        btnRow.orientation = .horizontal
        btnRow.spacing = 8
        for (title, sel) in [("Wake", #selector(wakeSelectedAction)),
                             ("Edit…", #selector(editSelectedAction)),
                             ("Remove", #selector(removeSelectedAction)),
                             ("Refresh", #selector(refreshAction))] {
            let b = NSButton(title: title, target: self, action: sel)
            b.bezelStyle = .rounded
            btnRow.addArrangedSubview(b)
        }
        stack.addArrangedSubview(btnRow); fullWidth(btnRow)

        stack.addArrangedSubview(hr()); fullWidth(stack.arrangedSubviews.last!)

        // --- 3. Add form (bottom) ---
        stack.addArrangedSubview(sectionLabel("Add a PC"))
        let nameF = NSTextField(); nameF.placeholderString = "Name (e.g. Office PC)"
        let macF = NSTextField();  macF.placeholderString = "MAC (AA:BB:CC:DD:EE:FF)"
        let bcastF = NSTextField(); bcastF.stringValue = Net.defaultBroadcast()
        for f in [nameF, macF, bcastF] { stack.addArrangedSubview(f); fullWidth(f) }
        fName = nameF; fMAC = macF; fBcast = bcastF

        let addBtn = NSButton(title: "Add PC", target: self, action: #selector(formAddAction))
        addBtn.bezelStyle = .rounded
        addBtn.keyEquivalent = "\r"
        stack.addArrangedSubview(addBtn)

        return root
    }

    // MARK: Window actions

    @objc private func scanAction() {
        scanButton?.isEnabled = false
        scanSpinner?.startAnimation(nil)
        DispatchQueue.global(qos: .userInitiated).async {
            Net.pingSweep()
            let map = Pinger.arpMapByMAC(onInterface: Net.subnetInterface())   // canonMAC → ip
            let list = map.map { (ip: $0.value, mac: $0.key, name: "") }
                .sorted { Self.ipLess($0.ip, $1.ip) }
            DispatchQueue.main.async {
                self.discovered = list
                self.discTable?.reloadData()
                self.scanSpinner?.stopAnimation(nil)
                self.scanButton?.isEnabled = true
                self.resolveNames(for: list.map { $0.ip })   // fill Name column as results arrive
            }
        }
    }

    /// Resolve device names in parallel and patch them into the table as each returns.
    private func resolveNames(for ips: [String]) {
        let q = DispatchQueue(label: "wol.names", attributes: .concurrent)
        let sem = DispatchSemaphore(value: 12)
        for ip in ips {
            sem.wait()
            q.async {
                let name = Resolver.name(forIP: ip) ?? ""
                sem.signal()
                guard !name.isEmpty else { return }
                DispatchQueue.main.async {
                    if let i = self.discovered.firstIndex(where: { $0.ip == ip }) {
                        self.discovered[i].name = name
                        self.discTable?.reloadData()
                    }
                }
            }
        }
    }

    @objc private func wakeSelectedAction() { if let r = pcTable?.selectedRow, r >= 0 { wake(at: r) } }
    @objc private func editSelectedAction() { if let r = pcTable?.selectedRow, r >= 0 { edit(at: r) } }
    @objc private func removeSelectedAction() { if let r = pcTable?.selectedRow, r >= 0 { remove(at: r) } }
    @objc private func refreshAction() { lastSweep = nil; refreshStatuses() }

    @objc private func formAddAction() {
        let name = (fName?.stringValue ?? "").trimmingCharacters(in: .whitespaces)
        let mac = (fMAC?.stringValue ?? "").trimmingCharacters(in: .whitespaces)
        let bcast = (fBcast?.stringValue ?? "").trimmingCharacters(in: .whitespaces)
        guard !name.isEmpty else { showAlert(title: "Not saved", body: "Name is required."); return }
        guard WOL.parseMAC(mac) != nil else { showAlert(title: "Not saved", body: "MAC must be 12 hex digits."); return }
        hosts.append(Host(name: name, mac: mac,
                          broadcast: bcast.isEmpty ? "255.255.255.255" : bcast, port: 9, address: nil))
        Store.save(hosts)
        fName?.stringValue = ""
        fMAC?.stringValue = ""
        fBcast?.stringValue = Net.defaultBroadcast()
        reloadAll()
    }

    private static func ipLess(_ a: String, _ b: String) -> Bool {
        a.split(separator: ".").compactMap { Int($0) }
            .lexicographicallyPrecedes(b.split(separator: ".").compactMap { Int($0) })
    }

    // MARK: NSTableView data source / delegate

    func numberOfRows(in tableView: NSTableView) -> Int {
        tableView === discTable ? discovered.count : hosts.count
    }

    func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? {
        guard let id = tableColumn?.identifier else { return nil }
        let cell: NSTableCellView
        if let reused = tableView.makeView(withIdentifier: id, owner: self) as? NSTableCellView {
            cell = reused
        } else {
            cell = NSTableCellView()
            cell.identifier = id
            let t = NSTextField(labelWithString: "")
            t.translatesAutoresizingMaskIntoConstraints = false
            t.lineBreakMode = .byTruncatingTail
            t.font = NSFont.systemFont(ofSize: 12)
            cell.addSubview(t)
            cell.textField = t
            NSLayoutConstraint.activate([
                t.leadingAnchor.constraint(equalTo: cell.leadingAnchor, constant: 2),
                t.trailingAnchor.constraint(equalTo: cell.trailingAnchor, constant: -2),
                t.centerYAnchor.constraint(equalTo: cell.centerYAnchor),
            ])
        }
        let label = cell.textField!

        if tableView === discTable {
            guard row < discovered.count else { label.stringValue = ""; return cell }
            let d = discovered[row]
            switch id.rawValue {
            case "d_ip":   label.stringValue = d.ip
            case "d_mac":  label.stringValue = d.mac
            case "d_name": label.stringValue = d.name.isEmpty ? "—" : d.name
            default:       label.stringValue = ""
            }
        } else {
            guard row < hosts.count else { label.stringValue = ""; return cell }
            let host = hosts[row]
            switch id.rawValue {
            case "p_status":
                label.alignment = .center
                label.attributedStringValue = bullet(status[host.mac] ?? .unknown, size: 11)
            case "p_name":   label.stringValue = host.name
            case "p_mac":    label.stringValue = host.mac
            case "p_ip":     label.stringValue = Pinger.canonMAC(host.mac).flatMap { lastIP[$0] } ?? "—"
            default:         label.stringValue = ""
            }
        }
        return cell
    }

    func tableViewSelectionDidChange(_ notification: Notification) {
        guard let t = notification.object as? NSTableView, t === discTable else { return }
        let r = t.selectedRow
        guard r >= 0, r < discovered.count else { return }
        let d = discovered[r]
        fMAC?.stringValue = d.mac                       // selecting a device fills the form
        fBcast?.stringValue = Net.defaultBroadcast()
        if !d.name.isEmpty { fName?.stringValue = d.name }   // prefill name if we resolved one
        window?.makeFirstResponder(fName)               // nudge user to confirm/type a name
    }

    /// Shared add/edit dialog. Returns the new/updated Host, or nil if cancelled/invalid.
    private func presentHostEditor(title: String, confirm: String, prefill: Host?) -> Host? {
        let alert = NSAlert()
        alert.messageText = title
        alert.informativeText = "Name and MAC are required.\nThe PC's IP is found automatically from its MAC. Broadcast defaults to your subnet."
        alert.addButton(withTitle: confirm)
        alert.addButton(withTitle: "Cancel")

        let stack = NSStackView(frame: NSRect(x: 0, y: 0, width: 300, height: 96))
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 6

        let nameField = NSTextField(frame: NSRect(x: 0, y: 0, width: 300, height: 22))
        nameField.placeholderString = "Name (e.g. Office PC)"
        let macField = NSTextField(frame: NSRect(x: 0, y: 0, width: 300, height: 22))
        macField.placeholderString = "MAC (AA:BB:CC:DD:EE:FF)"
        let bcastField = NSTextField(frame: NSRect(x: 0, y: 0, width: 300, height: 22))
        bcastField.stringValue = Net.defaultBroadcast()   // e.g. 192.168.10.255 for this network

        if let h = prefill {
            nameField.stringValue = h.name
            macField.stringValue = h.mac
            bcastField.stringValue = h.broadcast
        }

        for f in [nameField, macField, bcastField] {
            stack.addArrangedSubview(f)
            f.widthAnchor.constraint(equalToConstant: 300).isActive = true
        }
        alert.accessoryView = stack
        alert.window.initialFirstResponder = nameField

        NSApp.activate(ignoringOtherApps: true)
        guard alert.runModal() == .alertFirstButtonReturn else { return nil }

        let name = nameField.stringValue.trimmingCharacters(in: .whitespaces)
        let mac = macField.stringValue.trimmingCharacters(in: .whitespaces)
        let bcast = bcastField.stringValue.trimmingCharacters(in: .whitespaces)

        guard !name.isEmpty else { showAlert(title: "Not saved", body: "Name is required."); return nil }
        guard WOL.parseMAC(mac) != nil else { showAlert(title: "Not saved", body: "MAC must be 12 hex digits."); return nil }

        return Host(name: name, mac: mac,
                    broadcast: bcast.isEmpty ? "255.255.255.255" : bcast, port: 9, address: nil)
    }

    private func showAlert(title: String, body: String) {
        NSApp.activate(ignoringOtherApps: true)
        let a = NSAlert()
        a.messageText = title
        a.informativeText = body
        a.alertStyle = .warning
        a.addButton(withTitle: "OK")
        a.runModal()
    }

    /// Briefly swap the menu bar icon to a checkmark and set a tooltip.
    private func flashSuccess(tooltip: String) {
        guard let button = statusItem.button else { return }
        button.toolTip = tooltip
        let original = button.image
        button.image = NSImage(systemSymbolName: "checkmark.circle.fill", accessibilityDescription: "Sent")
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.2) {
            button.image = original
        }
    }
}

let app = NSApplication.shared
app.setActivationPolicy(.accessory)   // menu bar only, no Dock icon
let delegate = AppDelegate()
app.delegate = delegate
app.run()
