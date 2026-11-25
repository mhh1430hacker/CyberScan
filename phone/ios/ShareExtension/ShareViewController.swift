// CyberScan Share Extension (iOS): "Share -> CyberScan" from any app.
//
// It copies the shared files (or takes the shared link/text) into the App Group container that
// the app and the extension share, writes shared.json, and opens the app with cyberscan://shared.
// The app (AppDelegate.swift, channel "cyberscan/native", method "ready") reads shared.json and
// hands it to Dart in the same shape as Android, so lib/checks.dart scans it the same way.
// Nothing is uploaded. Setup steps: ios/ShareExtension/README.md (Xcode is needed; this target
// cannot be built on Windows).
import MobileCoreServices
import UIKit
import UniformTypeIdentifiers

let appGroup = "group.io.github.mhh1430hacker.cyberscan"
let maxFile = 100 << 20

class ShareViewController: UIViewController {
    override func viewDidAppear(_ animated: Bool) {
        super.viewDidAppear(animated)
        Task { await collect() }
    }

    private func collect() async {
        guard let container = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: appGroup) else { return done() }
        let folder = container.appendingPathComponent("shared", isDirectory: true)
        try? FileManager.default.removeItem(at: folder)
        try? FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        var files: [[String: Any]] = []
        var text: String? = nil
        var skipped = 0
        let items = (extensionContext?.inputItems as? [NSExtensionItem]) ?? []
        for item in items {
            for provider in item.attachments ?? [] {
                if provider.hasItemConformingToTypeIdentifier(UTType.fileURL.identifier) || provider.hasItemConformingToTypeIdentifier(UTType.data.identifier)
                    && !provider.hasItemConformingToTypeIdentifier(UTType.url.identifier) && !provider.hasItemConformingToTypeIdentifier(UTType.plainText.identifier) {
                    if let url = try? await loadFile(provider) {
                        let size = (try? url.resourceValues(forKeys: [.fileSizeKey]).fileSize) ?? 0
                        if size > maxFile { skipped += 1; continue }
                        let target = folder.appendingPathComponent("\(files.count)-\(url.lastPathComponent)")
                        if (try? FileManager.default.copyItem(at: url, to: target)) != nil {
                            files.append(["name": url.lastPathComponent, "path": target.path, "size": size, "tooBig": false])
                        } else { skipped += 1 }
                    } else { skipped += 1 }
                } else if provider.hasItemConformingToTypeIdentifier(UTType.url.identifier) {
                    if let url = try? await provider.loadItem(forTypeIdentifier: UTType.url.identifier) as? URL { text = url.absoluteString }
                } else if provider.hasItemConformingToTypeIdentifier(UTType.plainText.identifier) {
                    if let s = try? await provider.loadItem(forTypeIdentifier: UTType.plainText.identifier) as? String { text = s }
                }
            }
        }
        let event: [String: Any] = files.isEmpty
            ? ["type": "text", "text": text ?? ""]
            : ["type": "files", "files": files, "skipped": skipped]
        if let data = try? JSONSerialization.data(withJSONObject: event) {
            try? data.write(to: container.appendingPathComponent("shared.json"))
        }
        openApp(URL(string: "cyberscan://shared")!)
        done()
    }

    private func loadFile(_ provider: NSItemProvider) async throws -> URL {
        try await withCheckedThrowingContinuation { cont in
            provider.loadFileRepresentation(forTypeIdentifier: UTType.data.identifier) { url, error in
                guard let url else { return cont.resume(throwing: error ?? NSError(domain: "share", code: 1)) }
                // the system deletes `url` when this block returns: copy it first
                let copy = FileManager.default.temporaryDirectory.appendingPathComponent(url.lastPathComponent)
                try? FileManager.default.removeItem(at: copy)
                do { try FileManager.default.copyItem(at: url, to: copy); cont.resume(returning: copy) } catch { cont.resume(throwing: error) }
            }
        }
    }

    // Extensions can't call UIApplication.shared.open directly; walk the responder chain.
    private func openApp(_ url: URL) {
        var responder: UIResponder? = self
        while let r = responder {
            if let app = r as? UIApplication { app.open(url); return }
            responder = r.next
        }
    }

    private func done() {
        DispatchQueue.main.async { self.extensionContext?.completeRequest(returningItems: nil) }
    }
}
