import AppKit
import ApplicationServices
import Foundation
import Security

private enum ExitCode: Int32 {
    case success = 0
    case invalidArguments = 64
    case invalidInput = 65
    case unavailable = 69
    case internalError = 70
    case targetNotFound = 71
    case permissionDenied = 77
    case unsupported = 78
}

private enum ErrorCode: String, Encodable {
    case invalidArguments = "INVALID_ARGUMENTS"
    case invalidInput = "INVALID_INPUT"
    case accessibilityPermissionDenied = "ACCESSIBILITY_PERMISSION_DENIED"
    case frontmostApplicationUnavailable = "FRONTMOST_APPLICATION_UNAVAILABLE"
    case unsupportedApplication = "UNSUPPORTED_APPLICATION"
    case urlUnavailable = "URL_UNAVAILABLE"
    case focusedWindowUnavailable = "FOCUSED_WINDOW_UNAVAILABLE"
    case focusedElementUnavailable = "FOCUSED_ELEMENT_UNAVAILABLE"
    case focusedFieldNotEditable = "FOCUSED_FIELD_NOT_EDITABLE"
    case focusedFieldOutsideWebContent = "FOCUSED_FIELD_OUTSIDE_WEB_CONTENT"
    case addressFieldFocused = "ADDRESS_FIELD_FOCUSED"
    case targetNotFound = "TARGET_NOT_FOUND"
    case targetActivationFailed = "TARGET_ACTIVATION_FAILED"
    case contextChanged = "CONTEXT_CHANGED"
    case fillFailed = "FILL_FAILED"
    case internalError = "INTERNAL_ERROR"
}

private struct ErrorOutput: Encodable {
    let ok = false
    let error: ErrorDetail
}

private struct ErrorDetail: Encodable {
    let code: ErrorCode
    let message: String
}

private struct PermissionOutput: Encodable {
    let ok = true
    let trusted: Bool
}

private struct FocusContext: Codable {
    let role: String?
    let subrole: String?
    let editable: Bool
    let secure: Bool
    let x: Double?
    let y: Double?
    let width: Double?
    let height: Double?
}

private struct BrowserContext: Encodable {
    let ok = true
    let pid: Int32
    let bundleIdentifier: String
    let browser: String
    let url: String
    let focus: FocusContext
}

private struct FillRequest: Decodable {
    let pid: Int32
    let bundleIdentifier: String
    let url: String
    let focus: FocusContext
    let username: String
    let password: String
}

private struct FillOutput: Encodable {
    let ok = true
    let filledUsername: Bool
    let filledPassword: Bool
}

private struct SelfTestOutput: Encodable {
    let ok: Bool
    let tests: Int
}

private struct FocusCandidateDiagnostic: Encodable {
    let source: String
    let present: Bool
    let pid: Int32?
    let belongsToFocusedWindow: Bool
    let containingWindowMatches: Bool?
    let role: String?
    let subrole: String?
    let focused: Bool?
    let editable: Bool
}

private struct FocusDiagnosticOutput: Encodable {
    let ok = true
    let bundleIdentifier: String
    let applicationPid: Int32
    let applicationElementPid: Int32?
    let focusedWindowPresent: Bool
    let focusedWindowPid: Int32?
    let candidates: [FocusCandidateDiagnostic]
    let windowTree: WindowTreeDiagnostic?
}

private struct WindowTreeElementDiagnostic: Encodable {
    let role: String?
    let subrole: String?
    let depth: Int
    let focused: Bool?
    let editable: Bool
    let childCount: Int
}

private struct WindowTreeDiagnostic: Encodable {
    let visited: Int
    let traversalComplete: Bool
    let maximumDepthSeen: Int
    let webAreaCount: Int
    let focusedElements: [WindowTreeElementDiagnostic]
    let editableElements: [WindowTreeElementDiagnostic]
}

private struct CommandFailure: Error {
    let code: ErrorCode
    let message: String
    let exitCode: ExitCode
}

private enum Browser: String {
    case safari
    case chrome
    case edge
    case arc
    case brave
    case vivaldi
    case opera
    case firefox

    var usesChromiumWebAccessibility: Bool {
        switch self {
        case .chrome, .edge, .arc, .brave, .vivaldi, .opera:
            return true
        case .safari, .firefox:
            return false
        }
    }

    private struct Registration {
        let bundleIdentifier: String
        let browser: Browser
        /** Nil is reserved for Apple-signed Safari builds. */
        let teamIdentifier: String?
    }

    private static let registrations = [
        Registration(bundleIdentifier: "com.apple.Safari", browser: .safari, teamIdentifier: nil),
        Registration(bundleIdentifier: "com.apple.SafariTechnologyPreview", browser: .safari, teamIdentifier: nil),
        Registration(bundleIdentifier: "com.google.Chrome", browser: .chrome, teamIdentifier: "EQHXZ8M8AV"),
        Registration(bundleIdentifier: "com.google.Chrome.beta", browser: .chrome, teamIdentifier: "EQHXZ8M8AV"),
        Registration(bundleIdentifier: "com.google.Chrome.canary", browser: .chrome, teamIdentifier: "EQHXZ8M8AV"),
        Registration(bundleIdentifier: "com.google.Chrome.dev", browser: .chrome, teamIdentifier: "EQHXZ8M8AV"),
        Registration(bundleIdentifier: "com.microsoft.edgemac", browser: .edge, teamIdentifier: "UBF8T346G9"),
        Registration(bundleIdentifier: "com.microsoft.edgemac.Beta", browser: .edge, teamIdentifier: "UBF8T346G9"),
        Registration(bundleIdentifier: "com.microsoft.edgemac.Canary", browser: .edge, teamIdentifier: "UBF8T346G9"),
        Registration(bundleIdentifier: "com.microsoft.edgemac.Dev", browser: .edge, teamIdentifier: "UBF8T346G9"),
        Registration(bundleIdentifier: "company.thebrowser.Browser", browser: .arc, teamIdentifier: "S6N382Y83G"),
        Registration(bundleIdentifier: "com.brave.Browser", browser: .brave, teamIdentifier: "KL8N8XSYF4"),
        Registration(bundleIdentifier: "com.brave.Browser.beta", browser: .brave, teamIdentifier: "KL8N8XSYF4"),
        Registration(bundleIdentifier: "com.brave.Browser.nightly", browser: .brave, teamIdentifier: "KL8N8XSYF4"),
        Registration(bundleIdentifier: "com.vivaldi.Vivaldi", browser: .vivaldi, teamIdentifier: "4XF3XNRN6Y"),
        Registration(bundleIdentifier: "com.vivaldi.Vivaldi.snapshot", browser: .vivaldi, teamIdentifier: "4XF3XNRN6Y"),
        Registration(bundleIdentifier: "com.operasoftware.Opera", browser: .opera, teamIdentifier: "A2P9LX4JPN"),
        Registration(bundleIdentifier: "com.operasoftware.OperaNext", browser: .opera, teamIdentifier: "A2P9LX4JPN"),
        Registration(bundleIdentifier: "com.operasoftware.OperaDeveloper", browser: .opera, teamIdentifier: "A2P9LX4JPN"),
        Registration(bundleIdentifier: "com.operasoftware.OperaGX", browser: .opera, teamIdentifier: "A2P9LX4JPN"),
        Registration(bundleIdentifier: "org.mozilla.firefox", browser: .firefox, teamIdentifier: "43AQ936H96"),
        Registration(bundleIdentifier: "org.mozilla.firefoxdeveloperedition", browser: .firefox, teamIdentifier: "43AQ936H96"),
        Registration(bundleIdentifier: "org.mozilla.nightly", browser: .firefox, teamIdentifier: "43AQ936H96"),
    ]

    static func from(bundleIdentifier: String) -> Browser? {
        registration(for: bundleIdentifier)?.browser
    }

    static var supportedBundleIdentifiers: [String] {
        registrations.map(\.bundleIdentifier)
    }

    static func signingRequirement(for bundleIdentifier: String) -> String? {
        guard let registration = registration(for: bundleIdentifier) else { return nil }
        if let teamIdentifier = registration.teamIdentifier {
            return "identifier \"\(bundleIdentifier)\" and anchor apple generic and certificate leaf[subject.OU] = \"\(teamIdentifier)\""
        }
        return "identifier \"\(bundleIdentifier)\" and anchor apple"
    }

    private static func registration(for bundleIdentifier: String) -> Registration? {
        registrations.first { $0.bundleIdentifier == bundleIdentifier }
    }
}

private func hasTrustedBrowserSignature(pid: pid_t, bundleIdentifier: String) -> Bool {
    guard let requirementText = Browser.signingRequirement(for: bundleIdentifier) else { return false }
    let attributes = [kSecGuestAttributePid as String: NSNumber(value: pid)] as CFDictionary
    var code: SecCode?
    guard SecCodeCopyGuestWithAttributes(nil, attributes, SecCSFlags(rawValue: 0), &code) == errSecSuccess,
          let code else { return false }
    var requirement: SecRequirement?
    guard SecRequirementCreateWithString(
        requirementText as CFString,
        SecCSFlags(rawValue: 0),
        &requirement
    ) == errSecSuccess,
          let requirement else { return false }
    return SecCodeCheckValidity(code, SecCSFlags(rawValue: 0), requirement) == errSecSuccess
}

private func hasValidSigningRequirement(bundleIdentifier: String) -> Bool {
    guard let requirementText = Browser.signingRequirement(for: bundleIdentifier) else { return false }
    var requirement: SecRequirement?
    return SecRequirementCreateWithString(
        requirementText as CFString,
        SecCSFlags(rawValue: 0),
        &requirement
    ) == errSecSuccess && requirement != nil
}

private enum AX {
    static func value(_ element: AXUIElement, _ attribute: String) -> AnyObject? {
        var rawValue: CFTypeRef?
        guard AXUIElementCopyAttributeValue(element, attribute as CFString, &rawValue) == .success else {
            return nil
        }
        return rawValue
    }

    static func string(_ element: AXUIElement, _ attribute: String) -> String? {
        value(element, attribute) as? String
    }

    static func bool(_ element: AXUIElement, _ attribute: String) -> Bool? {
        value(element, attribute) as? Bool
    }

    static func element(_ element: AXUIElement, _ attribute: String) -> AXUIElement? {
        guard let rawValue = value(element, attribute), CFGetTypeID(rawValue) == AXUIElementGetTypeID() else {
            return nil
        }
        return unsafeBitCast(rawValue, to: AXUIElement.self)
    }

    static func elements(_ element: AXUIElement, _ attribute: String) -> [AXUIElement] {
        guard let rawValues = value(element, attribute) as? [AnyObject] else { return [] }
        return rawValues.compactMap { rawValue in
            guard CFGetTypeID(rawValue) == AXUIElementGetTypeID() else { return nil }
            return unsafeBitCast(rawValue, to: AXUIElement.self)
        }
    }

    static func isSettable(_ element: AXUIElement, _ attribute: String) -> Bool {
        var settable = DarwinBoolean(false)
        return AXUIElementIsAttributeSettable(element, attribute as CFString, &settable) == .success && settable.boolValue
    }

    static func set(_ element: AXUIElement, _ attribute: String, _ value: CFTypeRef) -> Bool {
        AXUIElementSetAttributeValue(element, attribute as CFString, value) == .success
    }
}

private func normalizedWebURL(_ candidate: String?) -> String? {
    guard var candidate else { return nil }
    candidate = candidate.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !candidate.isEmpty else { return nil }

    if !candidate.contains("://"), candidate.contains("."), !candidate.contains(" ") {
        candidate = "https://\(candidate)"
    }

    guard var components = URLComponents(string: candidate),
          let scheme = components.scheme?.lowercased(),
          ["http", "https"].contains(scheme),
          components.host?.isEmpty == false else {
        return nil
    }
    // Authentication callbacks and reset links often put bearer-like values in
    // these URL components. Domain/path matching does not need them.
    components.user = nil
    components.password = nil
    components.query = nil
    components.fragment = nil
    return components.url?.absoluteString
}

private func fieldIsSecure(role: String?, subrole: String?) -> Bool {
    let combined = "\(role ?? "") \(subrole ?? "")".lowercased()
    return combined.contains("secure")
}

private func fieldIsTextEntry(role: String?) -> Bool {
    guard let role = role?.lowercased() else { return false }
    return role.contains("textfield") || role.contains("textarea") || role.contains("combobox")
}

private func focusContext(for element: AXUIElement) -> FocusContext {
    let role = AX.string(element, kAXRoleAttribute)
    let subrole = AX.string(element, kAXSubroleAttribute)
    var position = CGPoint.zero
    var size = CGSize.zero
    let positionValue = AX.value(element, kAXPositionAttribute)
    let sizeValue = AX.value(element, kAXSizeAttribute)
    let hasPosition = positionValue.map {
        CFGetTypeID($0) == AXValueGetTypeID() &&
            AXValueGetValue(unsafeBitCast($0, to: AXValue.self), .cgPoint, &position)
    } ?? false
    let hasSize = sizeValue.map {
        CFGetTypeID($0) == AXValueGetTypeID() &&
            AXValueGetValue(unsafeBitCast($0, to: AXValue.self), .cgSize, &size)
    } ?? false
    return FocusContext(
        role: role,
        subrole: subrole,
        editable: fieldIsTextEntry(role: role) && AX.isSettable(element, kAXValueAttribute),
        secure: fieldIsSecure(role: role, subrole: subrole),
        x: hasPosition ? position.x : nil,
        y: hasPosition ? position.y : nil,
        width: hasSize ? size.width : nil,
        height: hasSize ? size.height : nil
    )
}

private func focusMatches(_ expected: FocusContext, _ actual: FocusContext) -> Bool {
    guard expected.role == actual.role,
          expected.subrole == actual.subrole,
          expected.editable == actual.editable,
          expected.secure == actual.secure else { return false }
    let pairs = [
        (expected.x, actual.x),
        (expected.y, actual.y),
        (expected.width, actual.width),
        (expected.height, actual.height),
    ]
    return pairs.allSatisfy { expectedValue, actualValue in
        switch (expectedValue, actualValue) {
        case (.none, .none): return true
        case let (.some(expectedValue), .some(actualValue)):
            return abs(expectedValue - actualValue) <= 3
        default: return false
        }
    }
}

private func processIdentifier(for element: AXUIElement) -> pid_t? {
    var pid: pid_t = 0
    guard AXUIElementGetPid(element, &pid) == .success, pid > 0 else { return nil }
    return pid
}

private func element(_ element: AXUIElement, belongsTo window: AXUIElement) -> Bool {
    if let containingWindow = AX.element(element, kAXWindowAttribute) {
        return CFEqual(containingWindow, window)
    }

    var ancestor: AXUIElement? = element
    var depth = 0
    while let candidate = ancestor, depth < 32 {
        if CFEqual(candidate, window) { return true }
        ancestor = AX.element(candidate, kAXParentAttribute)
        depth += 1
    }
    return false
}

private func focusedElement(
    applicationElement: AXUIElement,
    pid: pid_t,
    focusedWindow: AXUIElement
) -> AXUIElement? {
    guard NSWorkspace.shared.frontmostApplication?.processIdentifier == pid,
          processIdentifier(for: applicationElement) == pid,
          let liveFocusedWindow = AX.element(applicationElement, kAXFocusedWindowAttribute),
          CFEqual(liveFocusedWindow, focusedWindow) else { return nil }

    let isTrustedCandidate: (AXUIElement) -> Bool = { candidate in
        // Chromium-family browsers may expose focused web controls through a renderer-process
        // AX element. Bind trust to the browser-owned, currently focused window instead of
        // requiring every descendant AX element to report the browser's main-process PID.
        element(candidate, belongsTo: focusedWindow)
    }

    let resolvedCandidate: (AXUIElement) -> AXUIElement? = { candidate in
        if focusContext(for: candidate).editable {
            return AX.bool(candidate, kAXFocusedAttribute) == false ? nil : candidate
        }
        return uniqueFocusedEditableDescendant(
            of: candidate,
            focusedWindow: focusedWindow
        ) ?? candidate
    }

    let applicationCandidate = AX.element(applicationElement, kAXFocusedUIElementAttribute)
        .flatMap { isTrustedCandidate($0) ? resolvedCandidate($0) : nil }
    let systemElement = AXUIElementCreateSystemWide()
    let systemCandidate = AX.element(systemElement, kAXFocusedUIElementAttribute)
        .flatMap { isTrustedCandidate($0) ? resolvedCandidate($0) : nil }
    if let applicationCandidate, let systemCandidate,
       focusContext(for: applicationCandidate).editable,
       focusContext(for: systemCandidate).editable,
       !CFEqual(applicationCandidate, systemCandidate) {
        return nil
    }
    if let applicationCandidate { return applicationCandidate }
    if let systemCandidate { return systemCandidate }

    let windowCandidate = AX.element(focusedWindow, kAXFocusedUIElementAttribute)
        .flatMap { isTrustedCandidate($0) ? $0 : nil }
    guard let windowCandidate, AX.bool(windowCandidate, kAXFocusedAttribute) == true else {
        return nil
    }
    return uniqueFocusedEditableDescendant(
        of: windowCandidate,
        focusedWindow: focusedWindow
    ) ?? windowCandidate
}

private func uniqueFocusedEditableDescendant(
    of root: AXUIElement,
    focusedWindow: AXUIElement
) -> AXUIElement? {
    guard !focusContext(for: root).editable else { return nil }
    var queue: [(AXUIElement, Int)] = AX.elements(root, kAXChildrenAttribute).map { ($0, 1) }
    var matches: [AXUIElement] = []
    var traversalComplete = true
    var index = 0
    let maximumElements = 200
    let maximumDepth = 8
    while index < queue.count && index < maximumElements {
        let (candidate, depth) = queue[index]
        index += 1
        if element(candidate, belongsTo: focusedWindow),
           AX.bool(candidate, kAXFocusedAttribute) == true,
           focusContext(for: candidate).editable {
            if !matches.contains(where: { CFEqual($0, candidate) }) { matches.append(candidate) }
        }
        let children = AX.elements(candidate, kAXChildrenAttribute)
        if depth < maximumDepth {
            queue.append(contentsOf: children.map { ($0, depth + 1) })
        } else if !children.isEmpty {
            traversalComplete = false
        }
    }
    if index < queue.count { traversalComplete = false }
    return traversalComplete && matches.count == 1 ? matches[0] : nil
}

private func urlFromAttribute(_ element: AXUIElement, _ attribute: String) -> String? {
    if let string = AX.string(element, attribute) {
        return normalizedWebURL(string)
    }
    if let url = AX.value(element, attribute) as? URL {
        return normalizedWebURL(url.absoluteString)
    }
    return nil
}

private func webContentURL(for element: AXUIElement, focusedWindow: AXUIElement) -> String? {
    var ancestor: AXUIElement? = element
    var depth = 0
    var candidates = Set<String>()
    while let candidate = ancestor, depth < 32 {
        for attribute in [kAXURLAttribute, kAXDocumentAttribute] {
            if let url = urlFromAttribute(candidate, attribute) { candidates.insert(url) }
        }
        if AX.string(candidate, kAXRoleAttribute)?.lowercased().contains("webarea") == true {
            return candidates.count == 1 ? candidates.first : nil
        }
        if CFEqual(candidate, focusedWindow) { return nil }
        ancestor = AX.element(candidate, kAXParentAttribute)
        depth += 1
    }
    return nil
}

private func addressFieldHintsIndicateBrowserChrome(_ hints: [String], browser: Browser) -> Bool {
    let normalizedHints = hints.map {
        $0.lowercased().trimmingCharacters(in: .whitespacesAndNewlines)
    }
    let exactHints = Set(["address", "location", "url", "omnibox"])
    let phrases = [
        "address and search",
        "address bar",
        "location bar",
        "search or enter",
        "url bar",
        "omnibox",
    ]
    if normalizedHints.contains(where: exactHints.contains) { return true }
    if normalizedHints.contains(where: { hint in phrases.contains(where: hint.contains) }) { return true }
    return browser == .firefox && normalizedHints.contains("search with google or enter address")
}

private func looksLikeAddressField(_ element: AXUIElement, browser: Browser) -> Bool {
    let role = AX.string(element, kAXRoleAttribute)?.lowercased() ?? ""
    guard role.contains("textfield") || role.contains("combobox") else { return false }
    let hints = [
        AX.string(element, kAXIdentifierAttribute),
        AX.string(element, kAXDescriptionAttribute),
        AX.string(element, kAXTitleAttribute),
        AX.string(element, kAXHelpAttribute),
    ].compactMap { $0 }
    return addressFieldHintsIndicateBrowserChrome(hints, browser: browser)
}

private func discoverURL(
    applicationElement: AXUIElement,
    focusedElement: AXUIElement,
    focusedWindow: AXUIElement?,
    browser: Browser
) -> String? {
    var ancestor: AXUIElement? = focusedElement
    var ancestorDepth = 0
    var reachedFocusedWindow = false
    var ancestorCandidates = Set<String>()
    while let element = ancestor, ancestorDepth < 32 {
        for attribute in [kAXURLAttribute, kAXDocumentAttribute] {
            if let url = urlFromAttribute(element, attribute) { ancestorCandidates.insert(url) }
        }
        if let focusedWindow, CFEqual(element, focusedWindow) {
            reachedFocusedWindow = true
            break
        }
        ancestor = AX.element(element, kAXParentAttribute)
        ancestorDepth += 1
    }

    guard let focusedWindow else { return nil }
    if reachedFocusedWindow {
        if ancestorCandidates.count == 1 { return ancestorCandidates.first }
        if ancestorCandidates.count > 1 { return nil }
    }
    // If the lineage reached a different window or application root, ignore every URL it exposed.
    // Fall back only to an independent scan rooted at the authoritative focused window.
    var queue: [(AXUIElement, Int)] = [(focusedWindow, 0)]
    var candidates = Set<String>()
    var traversalComplete = true
    var index = 0
    let maximumElements = 700
    let maximumDepth = 14

    while index < queue.count && index < maximumElements {
        let (element, depth) = queue[index]
        index += 1

        for attribute in [kAXURLAttribute, kAXDocumentAttribute] {
            if let url = urlFromAttribute(element, attribute) { candidates.insert(url) }
        }
        if looksLikeAddressField(element, browser: browser),
           let url = normalizedWebURL(AX.string(element, kAXValueAttribute)) {
            candidates.insert(url)
        }

        let children = AX.elements(element, kAXChildrenAttribute)
        if depth < maximumDepth {
            for child in children {
                queue.append((child, depth + 1))
            }
        } else if !children.isEmpty {
            traversalComplete = false
        }
    }
    if index < queue.count { traversalComplete = false }
    // Sidebar tabs and split views can expose several documents in one AX window. Filling is
    // safe only when the focused window has one unambiguous web URL.
    return uniqueURLIfTraversalComplete(candidates, traversalComplete: traversalComplete)
}

private func uniqueURLIfTraversalComplete(
    _ candidates: Set<String>,
    traversalComplete: Bool
) -> String? {
    traversalComplete && candidates.count == 1 ? candidates.first : nil
}

private func requireAccessibilityTrust(prompt: Bool = false) throws {
    let options = [kAXTrustedCheckOptionPrompt.takeUnretainedValue() as String: prompt] as CFDictionary
    guard AXIsProcessTrustedWithOptions(options) else {
        throw CommandFailure(
            code: .accessibilityPermissionDenied,
            message: "Accessibility permission is required.",
            exitCode: .permissionDenied
        )
    }
}

private func requestEnhancedWebAccessibility(
    applicationElement: AXUIElement,
    browser: Browser,
    timeout: TimeInterval = 3
) -> Bool {
    guard browser.usesChromiumWebAccessibility else { return false }
    let attribute = "AXEnhancedUserInterface"
    guard AX.bool(applicationElement, attribute) != true else { return false }
    guard AX.set(applicationElement, attribute, kCFBooleanTrue) else { return false }
    EnhancedAccessibilitySignalLease.acquire(applicationElement)
    let deadline = Date().addingTimeInterval(timeout)
    while Date() < deadline {
        RunLoop.current.run(until: Date().addingTimeInterval(0.05))
    }
    return true
}

private func releaseEnhancedWebAccessibility(
    applicationElement: AXUIElement,
    requested: Bool
) {
    guard requested else { return }
    _ = AX.set(applicationElement, "AXEnhancedUserInterface", kCFBooleanFalse)
    EnhancedAccessibilitySignalLease.clear()
}

private enum EnhancedAccessibilitySignalLease {
    private static var applicationElement: AXUIElement?
    private static var signalSource: DispatchSourceSignal?

    static func acquire(_ element: AXUIElement) {
        applicationElement = element
        signal(SIGTERM, SIG_IGN)
        let source = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .main)
        source.setEventHandler {
            if let applicationElement {
                _ = AX.set(applicationElement, "AXEnhancedUserInterface", kCFBooleanFalse)
            }
            clear()
            exit(ExitCode.unavailable.rawValue)
        }
        signalSource = source
        source.resume()
    }

    static func clear() {
        signalSource?.cancel()
        signalSource = nil
        applicationElement = nil
        signal(SIGTERM, SIG_DFL)
    }
}

private func contextCommand() throws -> BrowserContext {
    try requireAccessibilityTrust()
    guard let application = NSWorkspace.shared.frontmostApplication,
          let bundleIdentifier = application.bundleIdentifier else {
        throw CommandFailure(
            code: .frontmostApplicationUnavailable,
            message: "The frontmost application could not be determined.",
            exitCode: .unavailable
        )
    }
    guard let browser = Browser.from(bundleIdentifier: bundleIdentifier) else {
        throw CommandFailure(
            code: .unsupportedApplication,
            message: "The frontmost application is not a supported browser.",
            exitCode: .unsupported
        )
    }
    guard hasTrustedBrowserSignature(
        pid: application.processIdentifier,
        bundleIdentifier: bundleIdentifier
    ) else {
        throw CommandFailure(
            code: .unsupportedApplication,
            message: "The frontmost browser does not have the expected vendor signature.",
            exitCode: .unsupported
        )
    }

    let applicationElement = AXUIElementCreateApplication(application.processIdentifier)
    let enhancedAccessibilityRequested = requestEnhancedWebAccessibility(
        applicationElement: applicationElement,
        browser: browser
    )
    defer {
        releaseEnhancedWebAccessibility(
            applicationElement: applicationElement,
            requested: enhancedAccessibilityRequested
        )
    }
    guard let focusedWindow = AX.element(applicationElement, kAXFocusedWindowAttribute) else {
        throw CommandFailure(
            code: .focusedWindowUnavailable,
            message: "The focused browser window is unavailable.",
            exitCode: .unavailable
        )
    }
    guard let focusedElement = focusedElement(
              applicationElement: applicationElement,
              pid: application.processIdentifier,
              focusedWindow: focusedWindow
          ) else {
        throw CommandFailure(
            code: .focusedElementUnavailable,
            message: "The focused accessibility element is unavailable.",
            exitCode: .unavailable
        )
    }
    guard let url = discoverURL(
        applicationElement: applicationElement,
        focusedElement: focusedElement,
        focusedWindow: focusedWindow,
        browser: browser
    ) else {
        throw CommandFailure(
            code: .urlUnavailable,
            message: "The browser URL could not be read through Accessibility.",
            exitCode: .unavailable
        )
    }
    let focus = focusContext(for: focusedElement)
    guard focus.editable else {
        throw CommandFailure(
            code: .focusedFieldNotEditable,
            message: "The focused element is not an editable text field.",
            exitCode: .unavailable
        )
    }
    guard webContentURL(for: focusedElement, focusedWindow: focusedWindow) == url else {
        throw CommandFailure(
            code: .focusedFieldOutsideWebContent,
            message: "The focused field is not part of browser web content.",
            exitCode: .unavailable
        )
    }
    guard !looksLikeAddressField(focusedElement, browser: browser) else {
        throw CommandFailure(
            code: .addressFieldFocused,
            message: "The browser address field is focused.",
            exitCode: .unavailable
        )
    }

    return BrowserContext(
        pid: application.processIdentifier,
        bundleIdentifier: bundleIdentifier,
        browser: browser.rawValue,
        url: url,
        focus: focus
    )
}

private func focusDiagnostic(
    source: String,
    candidate: AXUIElement?,
    focusedWindow: AXUIElement?
) -> FocusCandidateDiagnostic {
    guard let candidate else {
        return FocusCandidateDiagnostic(
            source: source,
            present: false,
            pid: nil,
            belongsToFocusedWindow: false,
            containingWindowMatches: nil,
            role: nil,
            subrole: nil,
            focused: nil,
            editable: false
        )
    }
    let containingWindow = AX.element(candidate, kAXWindowAttribute)
    return FocusCandidateDiagnostic(
        source: source,
        present: true,
        pid: processIdentifier(for: candidate),
        belongsToFocusedWindow: focusedWindow.map { element(candidate, belongsTo: $0) } ?? false,
        containingWindowMatches: containingWindow.flatMap { window in
            focusedWindow.map { CFEqual(window, $0) }
        },
        role: AX.string(candidate, kAXRoleAttribute),
        subrole: AX.string(candidate, kAXSubroleAttribute),
        focused: AX.bool(candidate, kAXFocusedAttribute),
        editable: focusContext(for: candidate).editable
    )
}

private func diagnoseCommand() throws -> FocusDiagnosticOutput {
    try requireAccessibilityTrust()
    guard let application = NSWorkspace.shared.frontmostApplication,
          let bundleIdentifier = application.bundleIdentifier else {
        throw CommandFailure(
            code: .frontmostApplicationUnavailable,
            message: "The frontmost application could not be determined.",
            exitCode: .unavailable
        )
    }
    let applicationElement = AXUIElementCreateApplication(application.processIdentifier)
    let focusedWindow = AX.element(applicationElement, kAXFocusedWindowAttribute)
    let systemElement = AXUIElementCreateSystemWide()
    return FocusDiagnosticOutput(
        bundleIdentifier: bundleIdentifier,
        applicationPid: application.processIdentifier,
        applicationElementPid: processIdentifier(for: applicationElement),
        focusedWindowPresent: focusedWindow != nil,
        focusedWindowPid: focusedWindow.flatMap(processIdentifier),
        candidates: [
            focusDiagnostic(
                source: "application",
                candidate: AX.element(applicationElement, kAXFocusedUIElementAttribute),
                focusedWindow: focusedWindow
            ),
            focusDiagnostic(
                source: "system",
                candidate: AX.element(systemElement, kAXFocusedUIElementAttribute),
                focusedWindow: focusedWindow
            ),
            focusDiagnostic(
                source: "window",
                candidate: focusedWindow.flatMap { AX.element($0, kAXFocusedUIElementAttribute) },
                focusedWindow: focusedWindow
            ),
            focusDiagnostic(
                source: "window-descendant",
                candidate: focusedWindow.flatMap {
                    uniqueFocusedEditableDescendant(of: $0, focusedWindow: $0)
                },
                focusedWindow: focusedWindow
            ),
        ],
        windowTree: focusedWindow.map(windowTreeDiagnostic)
    )
}

private func windowTreeDiagnostic(_ focusedWindow: AXUIElement) -> WindowTreeDiagnostic {
    var queue: [(AXUIElement, Int)] = [(focusedWindow, 0)]
    var index = 0
    var maximumDepthSeen = 0
    var webAreaCount = 0
    var focusedElements: [WindowTreeElementDiagnostic] = []
    var editableElements: [WindowTreeElementDiagnostic] = []
    var traversalComplete = true
    let maximumElements = 2_000
    let maximumDepth = 20

    while index < queue.count && index < maximumElements {
        let (element, depth) = queue[index]
        index += 1
        maximumDepthSeen = max(maximumDepthSeen, depth)
        let role = AX.string(element, kAXRoleAttribute)
        let subrole = AX.string(element, kAXSubroleAttribute)
        let focused = AX.bool(element, kAXFocusedAttribute)
        let editable = focusContext(for: element).editable
        let children = AX.elements(element, kAXChildrenAttribute)
        let summary = WindowTreeElementDiagnostic(
            role: role,
            subrole: subrole,
            depth: depth,
            focused: focused,
            editable: editable,
            childCount: children.count
        )
        if role?.lowercased().contains("webarea") == true { webAreaCount += 1 }
        if focused == true, focusedElements.count < 16 { focusedElements.append(summary) }
        if editable, editableElements.count < 16 { editableElements.append(summary) }
        if depth < maximumDepth {
            queue.append(contentsOf: children.map { ($0, depth + 1) })
        } else if !children.isEmpty {
            traversalComplete = false
        }
    }
    if index < queue.count { traversalComplete = false }
    return WindowTreeDiagnostic(
        visited: index,
        traversalComplete: traversalComplete,
        maximumDepthSeen: maximumDepthSeen,
        webAreaCount: webAreaCount,
        focusedElements: focusedElements,
        editableElements: editableElements
    )
}

private func readFillRequest() throws -> FillRequest {
    let maximumInputBytes = 1_048_576
    var data = Data()
    do {
        while data.count <= maximumInputBytes {
            let remaining = maximumInputBytes + 1 - data.count
            guard let chunk = try FileHandle.standardInput.read(upToCount: min(65_536, remaining)),
                  !chunk.isEmpty else {
                break
            }
            data.append(chunk)
        }
    } catch {
        throw CommandFailure(
            code: .invalidInput,
            message: "Fill input could not be read.",
            exitCode: .invalidInput
        )
    }
    guard !data.isEmpty, data.count <= maximumInputBytes else {
        throw CommandFailure(
            code: .invalidInput,
            message: "Fill input must be non-empty JSON no larger than 1 MiB.",
            exitCode: .invalidInput
        )
    }
    do {
        let request = try JSONDecoder().decode(FillRequest.self, from: data)
        guard request.pid > 0,
              Browser.from(bundleIdentifier: request.bundleIdentifier) != nil,
              normalizedWebURL(request.url) == request.url,
              request.username.utf8.count <= 65_536,
              request.password.utf8.count <= 65_536 else {
            throw CommandFailure(
                code: .invalidInput,
                message: "Fill input contains an invalid pid or oversized credential.",
                exitCode: .invalidInput
            )
        }
        return request
    } catch let failure as CommandFailure {
        throw failure
    } catch {
        throw CommandFailure(
            code: .invalidInput,
            message: "Fill input is not valid JSON.",
            exitCode: .invalidInput
        )
    }
}

private func waitForFocusedElement(
    applicationElement: AXUIElement,
    pid: pid_t,
    focusedWindow: AXUIElement,
    excluding original: AXUIElement? = nil,
    timeout: TimeInterval = 1.5
) -> AXUIElement? {
    let deadline = Date().addingTimeInterval(timeout)
    repeat {
        guard let liveFocusedWindow = AX.element(applicationElement, kAXFocusedWindowAttribute),
              CFEqual(liveFocusedWindow, focusedWindow) else { return nil }
        if let candidate = focusedElement(
            applicationElement: applicationElement,
            pid: pid,
            focusedWindow: focusedWindow
        ) {
            if let original {
                if !CFEqual(candidate, original) { return candidate }
            } else {
                return candidate
            }
        }
        RunLoop.current.run(until: Date().addingTimeInterval(0.025))
    } while Date() < deadline
    return nil
}

private func setTextIfStillFocused(
    _ text: String,
    on element: AXUIElement,
    applicationElement: AXUIElement,
    pid: pid_t,
    focusedWindow: AXUIElement
) -> Bool {
    guard let liveFocusedWindow = AX.element(applicationElement, kAXFocusedWindowAttribute),
          CFEqual(liveFocusedWindow, focusedWindow),
          let liveFocusedElement = focusedElement(
              applicationElement: applicationElement,
              pid: pid,
              focusedWindow: focusedWindow
          ),
          CFEqual(liveFocusedElement, element),
          fieldIsTextEntry(role: AX.string(element, kAXRoleAttribute)),
          AX.isSettable(element, kAXValueAttribute) else { return false }
    return AX.set(element, kAXValueAttribute, text as CFString)
}

private func waitForActivation(_ application: NSRunningApplication, timeout: TimeInterval = 1.5) -> Bool {
    let deadline = Date().addingTimeInterval(timeout)
    repeat {
        if application.isActive { return true }
        RunLoop.current.run(until: Date().addingTimeInterval(0.025))
    } while Date() < deadline
    return application.isActive
}

private func pressTab(for pid: pid_t) -> Bool {
    guard let source = CGEventSource(stateID: .combinedSessionState),
          let keyDown = CGEvent(keyboardEventSource: source, virtualKey: 0x30, keyDown: true),
          let keyUp = CGEvent(keyboardEventSource: source, virtualKey: 0x30, keyDown: false) else {
        return false
    }
    keyDown.postToPid(pid)
    keyUp.postToPid(pid)
    return true
}

private func fillCommand() throws -> FillOutput {
    let request = try readFillRequest()
    try requireAccessibilityTrust()

    guard let application = NSRunningApplication(processIdentifier: request.pid),
          let bundleIdentifier = application.bundleIdentifier else {
        throw CommandFailure(code: .targetNotFound, message: "The target application is not running.", exitCode: .targetNotFound)
    }
    guard bundleIdentifier == request.bundleIdentifier,
          let browser = Browser.from(bundleIdentifier: bundleIdentifier) else {
        throw CommandFailure(code: .unsupportedApplication, message: "The target application is not a supported browser.", exitCode: .unsupported)
    }
    guard hasTrustedBrowserSignature(pid: request.pid, bundleIdentifier: bundleIdentifier) else {
        throw CommandFailure(code: .unsupportedApplication, message: "The target browser signature is not trusted.", exitCode: .unsupported)
    }
    guard application.activate(options: []), waitForActivation(application) else {
        throw CommandFailure(code: .targetActivationFailed, message: "The target application could not be activated.", exitCode: .unavailable)
    }

    let applicationElement = AXUIElementCreateApplication(request.pid)
    let enhancedAccessibilityRequested = requestEnhancedWebAccessibility(
        applicationElement: applicationElement,
        browser: browser
    )
    defer {
        releaseEnhancedWebAccessibility(
            applicationElement: applicationElement,
            requested: enhancedAccessibilityRequested
        )
    }
    guard let focusedWindow = AX.element(applicationElement, kAXFocusedWindowAttribute),
          let initialElement = waitForFocusedElement(
              applicationElement: applicationElement,
              pid: request.pid,
              focusedWindow: focusedWindow
          ) else {
        throw CommandFailure(code: .focusedElementUnavailable, message: "The target has no focused accessibility element.", exitCode: .unavailable)
    }
    guard webContentURL(for: initialElement, focusedWindow: focusedWindow) == request.url,
          !looksLikeAddressField(initialElement, browser: browser),
          focusMatches(request.focus, focusContext(for: initialElement)),
          discoverURL(
              applicationElement: applicationElement,
              focusedElement: initialElement,
              focusedWindow: focusedWindow,
              browser: browser
          ) == request.url else {
        throw CommandFailure(code: .contextChanged, message: "The browser context changed before fill.", exitCode: .unavailable)
    }
    let initialRole = AX.string(initialElement, kAXRoleAttribute)
    let initialSubrole = AX.string(initialElement, kAXSubroleAttribute)

    if fieldIsSecure(role: initialRole, subrole: initialSubrole) {
        guard setTextIfStillFocused(
            request.password,
            on: initialElement,
            applicationElement: applicationElement,
            pid: request.pid,
            focusedWindow: focusedWindow
        ) else {
            throw CommandFailure(code: .fillFailed, message: "The password field rejected the accessibility value.", exitCode: .internalError)
        }
        return FillOutput(filledUsername: false, filledPassword: true)
    }

    guard setTextIfStillFocused(
        request.username,
        on: initialElement,
        applicationElement: applicationElement,
        pid: request.pid,
        focusedWindow: focusedWindow
    ) else {
        throw CommandFailure(code: .fillFailed, message: "The username field rejected the accessibility value.", exitCode: .internalError)
    }
    guard pressTab(for: request.pid),
          let passwordElement = waitForFocusedElement(
              applicationElement: applicationElement,
              pid: request.pid,
              focusedWindow: focusedWindow,
              excluding: initialElement
          ),
          webContentURL(for: passwordElement, focusedWindow: focusedWindow) == request.url,
          !looksLikeAddressField(passwordElement, browser: browser),
          fieldIsSecure(
              role: AX.string(passwordElement, kAXRoleAttribute),
              subrole: AX.string(passwordElement, kAXSubroleAttribute)
          ),
          AX.element(applicationElement, kAXFocusedWindowAttribute).map({ CFEqual($0, focusedWindow) }) == true,
          discoverURL(
              applicationElement: applicationElement,
              focusedElement: passwordElement,
              focusedWindow: focusedWindow,
              browser: browser
          ) == request.url,
          setTextIfStillFocused(
              request.password,
              on: passwordElement,
              applicationElement: applicationElement,
              pid: request.pid,
              focusedWindow: focusedWindow
          ) else {
        throw CommandFailure(code: .fillFailed, message: "The password field could not be focused or filled.", exitCode: .internalError)
    }
    return FillOutput(filledUsername: true, filledPassword: true)
}

private func selfTestCommand() -> SelfTestOutput {
    let checks = [
        normalizedWebURL("example.com/login") == "https://example.com/login",
        normalizedWebURL("https://example.com/a?b=c#fragment") == "https://example.com/a",
        normalizedWebURL("https://user:password@example.com/login") == "https://example.com/login",
        normalizedWebURL("javascript:alert(1)") == nil,
        normalizedWebURL("not a url") == nil,
        Browser.from(bundleIdentifier: "com.apple.Safari") == .safari,
        Browser.from(bundleIdentifier: "com.google.Chrome") == .chrome,
        Browser.from(bundleIdentifier: "com.google.Chrome.beta") == .chrome,
        Browser.from(bundleIdentifier: "com.google.Chrome.canary") == .chrome,
        Browser.from(bundleIdentifier: "org.chromium.Chromium") == nil,
        Browser.from(bundleIdentifier: "com.microsoft.edgemac") == .edge,
        Browser.from(bundleIdentifier: "com.microsoft.edgemac.Dev") == .edge,
        Browser.from(bundleIdentifier: "company.thebrowser.Browser") == .arc,
        Browser.arc.usesChromiumWebAccessibility,
        !Browser.safari.usesChromiumWebAccessibility,
        Browser.from(bundleIdentifier: "com.brave.Browser") == .brave,
        Browser.from(bundleIdentifier: "com.brave.Browser.beta") == .brave,
        Browser.from(bundleIdentifier: "com.vivaldi.Vivaldi") == .vivaldi,
        Browser.from(bundleIdentifier: "com.operasoftware.Opera") == .opera,
        Browser.from(bundleIdentifier: "com.operasoftware.OperaGX") == .opera,
        Browser.from(bundleIdentifier: "org.mozilla.firefox") == .firefox,
        Browser.from(bundleIdentifier: "company.thebrowser.Browser.beta") == nil,
        Browser.from(bundleIdentifier: "com.brave.Browser.fake") == nil,
        Browser.from(bundleIdentifier: "com.example.Unknown") == nil,
        Browser.supportedBundleIdentifiers.count == Set(Browser.supportedBundleIdentifiers).count,
        Browser.supportedBundleIdentifiers.allSatisfy(hasValidSigningRequirement),
        uniqueURLIfTraversalComplete(["https://example.com"], traversalComplete: true) == "https://example.com",
        uniqueURLIfTraversalComplete(["https://example.com", "https://other.example"], traversalComplete: true) == nil,
        uniqueURLIfTraversalComplete(["https://example.com"], traversalComplete: false) == nil,
        fieldIsSecure(role: "AXSecureTextField", subrole: nil),
        !fieldIsSecure(role: "AXTextField", subrole: nil),
        fieldIsTextEntry(role: "AXTextField"),
        !fieldIsTextEntry(role: "AXButton"),
        !addressFieldHintsIndicateBrowserChrome(["Email address"], browser: .arc),
        !addressFieldHintsIndicateBrowserChrome(["returnUrl"], browser: .arc),
        addressFieldHintsIndicateBrowserChrome(["Address and Search Bar"], browser: .arc),
    ]
    return SelfTestOutput(ok: checks.allSatisfy { $0 }, tests: checks.count)
}

private func encode<T: Encodable>(_ output: T) throws -> Data {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    var data = try encoder.encode(output)
    data.append(0x0A)
    return data
}

private func writeJSON<T: Encodable>(_ output: T, to handle: FileHandle) {
    do {
        try handle.write(contentsOf: encode(output))
    } catch {
        // A broken output pipe cannot be reported safely through the same pipe.
    }
}

@main
private enum MacOSAutofillHelper {
    static func main() {
        do {
            let arguments = Array(CommandLine.arguments.dropFirst())
            guard let command = arguments.first else {
                throw CommandFailure(
                    code: .invalidArguments,
                    message: "Expected one of: context, diagnose, fill, permission, self-test.",
                    exitCode: .invalidArguments
                )
            }

            switch command {
            case "context" where arguments.count == 1:
                writeJSON(try contextCommand(), to: .standardOutput)
            case "diagnose" where arguments.count == 1:
                writeJSON(try diagnoseCommand(), to: .standardOutput)
            case "fill" where arguments.count == 1:
                writeJSON(try fillCommand(), to: .standardOutput)
            case "permission" where arguments.count == 1 || (arguments.count == 2 && arguments[1] == "--prompt"):
                let prompt = arguments.count == 2
                let options = [kAXTrustedCheckOptionPrompt.takeUnretainedValue() as String: prompt] as CFDictionary
                writeJSON(PermissionOutput(trusted: AXIsProcessTrustedWithOptions(options)), to: .standardOutput)
            case "self-test" where arguments.count == 1:
                let output = selfTestCommand()
                writeJSON(output, to: .standardOutput)
                if !output.ok { exit(ExitCode.internalError.rawValue) }
            default:
                throw CommandFailure(
                    code: .invalidArguments,
                    message: "Invalid command or arguments.",
                    exitCode: .invalidArguments
                )
            }
        } catch let failure as CommandFailure {
            writeJSON(ErrorOutput(error: ErrorDetail(code: failure.code, message: failure.message)), to: .standardError)
            exit(failure.exitCode.rawValue)
        } catch {
            writeJSON(
                ErrorOutput(error: ErrorDetail(code: .internalError, message: "An internal error occurred.")),
                to: .standardError
            )
            exit(ExitCode.internalError.rawValue)
        }
    }
}
