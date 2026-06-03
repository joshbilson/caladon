import SwiftUI

/// Swifty — privacy-first, attested-confidential AI assistant (iOS + macOS).
/// The app is a thin SwiftUI shell over SwiftyKit (seed identity, attestation verifier,
/// confidential gateway client). This is the entry point; real flows live in SwiftyKit.
@main
struct SwiftyApp: App {
    var body: some Scene {
        WindowGroup {
            RootView()
        }
    }
}
