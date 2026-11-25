# iOS: Share to CyberScan

The code is here, but the extension target has to be added in Xcode on a Mac (it cannot be built
on Windows, and hand-editing `project.pbxproj` is error-prone).

1. Open `ios/Runner.xcworkspace` in Xcode.
2. File > New > Target > **Share Extension**. Product name `ShareExtension`, language Swift,
   bundle id `io.github.mhh1430hacker.cyberscan.ShareExtension`. Do not activate the new scheme.
3. Replace the generated `ShareViewController.swift` and `Info.plist` with the files in this
   folder; delete the generated `MainInterface.storyboard` (this controller has no storyboard).
4. Signing & Capabilities: add **App Groups** to *both* the Runner and ShareExtension targets,
   with `group.io.github.mhh1430hacker.cyberscan`. Point *Code Signing Entitlements* at
   `Runner/Runner.entitlements` and `ShareExtension/ShareExtension.entitlements`.
5. Set the extension's deployment target to the Runner's (iOS 15+ recommended; the code uses
   `async`/`UTType`).
6. `flutter build ios`. `AppDelegate.swift` already answers the channel and the
   `cyberscan://shared` link (`Info.plist` declares the scheme).

The home-screen widget and the watched folder are Android-only for now (iOS widgets need a
WidgetKit target and iOS has no shared Downloads folder an app can list).
