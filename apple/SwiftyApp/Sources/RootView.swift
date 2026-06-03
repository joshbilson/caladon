import SwiftUI
import SwiftyKit

/// Top-level flow: load the stored seed on launch → onboard if there is none, else home.
/// The seed lives ONLY in the device Keychain (KeychainSeedStore, device-only + non-synced).
/// Keychain errors are surfaced (never swallowed) so a failed save can't silently lose the
/// user's phrase and a locked-device read can't be mistaken for "no account → re-onboard".
struct RootView: View {
    private let store: SeedStore = KeychainSeedStore()
    @State private var seed: Data?
    @State private var loaded = false
    @State private var storageError: String?

    var body: some View {
        Group {
            if let storageError {
                StorageErrorView(message: storageError, retry: reload)
            } else if !loaded {
                ProgressView()
            } else if seed == nil {
                OnboardingView { newSeed in
                    // Only advance once the seed is actually persisted (else it's lost on relaunch).
                    do {
                        try store.save(newSeed)
                        seed = newSeed
                    } catch {
                        storageError = "Couldn't securely save your recovery phrase. "
                            + "Make sure the device is unlocked and try again."
                    }
                }
            } else {
                HomeView(seed: seed!) {
                    // Honour erase: only drop the in-memory seed if the Keychain delete succeeded.
                    do {
                        try store.deleteSeed()
                        seed = nil
                    } catch {
                        storageError = "Couldn't erase the seed from this device. Try again."
                    }
                }
            }
        }
        .task { reload() }
    }

    private func reload() {
        storageError = nil
        do {
            seed = try store.load()  // nil == no account yet; a thrown error is NOT "no account"
            loaded = true
        } catch {
            // e.g. device locked at launch (errSecInteractionNotAllowed) — do NOT fall through
            // to onboarding (which would overwrite an existing, unreadable seed).
            storageError = "Couldn't read secure storage. Make sure the device is unlocked."
            loaded = true
        }
    }
}

private struct StorageErrorView: View {
    let message: String
    let retry: () -> Void
    var body: some View {
        VStack(spacing: 16) {
            Image(systemName: "exclamationmark.lock.fill").font(.largeTitle).foregroundStyle(.orange)
            Text(message).font(.callout).multilineTextAlignment(.center).padding(.horizontal)
            Button("Retry", action: retry).buttonStyle(.borderedProminent)
        }
        .padding()
        .frame(minWidth: 360, minHeight: 360)
    }
}
