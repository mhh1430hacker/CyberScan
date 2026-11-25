import Flutter
import UIKit

@main
@objc class AppDelegate: FlutterAppDelegate {
  private let appGroup = "group.io.github.mhh1430hacker.cyberscan"
  private var channel: FlutterMethodChannel?

  override func application(
    _ application: UIApplication,
    didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?
  ) -> Bool {
    GeneratedPluginRegistrant.register(with: self)
    // Share to CyberScan (ios/ShareExtension): the extension leaves shared.json in the App Group
    // and opens cyberscan://shared; Dart asks for it with "ready" (same shape as Android).
    if let controller = window?.rootViewController as? FlutterViewController {
      let ch = FlutterMethodChannel(name: "cyberscan/native", binaryMessenger: controller.binaryMessenger)
      ch.setMethodCallHandler { [weak self] call, result in
        if call.method == "ready" { result(self?.takeShared()) } else { result(FlutterMethodNotImplemented) }
      }
      channel = ch
    }
    return super.application(application, didFinishLaunchingWithOptions: launchOptions)
  }

  override func application(_ app: UIApplication, open url: URL, options: [UIApplication.OpenURLOptionsKey: Any] = [:]) -> Bool {
    if url.scheme == "cyberscan", url.host == "shared", let event = takeShared() {
      channel?.invokeMethod("incoming", arguments: event)
      return true
    }
    return super.application(app, open: url, options: options)
  }

  private func takeShared() -> [String: Any]? {
    guard let container = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: appGroup) else { return nil }
    let file = container.appendingPathComponent("shared.json")
    guard let data = try? Data(contentsOf: file),
          let event = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return nil }
    try? FileManager.default.removeItem(at: file)
    return event
  }
}
