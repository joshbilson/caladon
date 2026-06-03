import SwiftUI
import SwiftyKit

/// Post-onboarding placeholder. Shows the seed-derived account_id (zero-PII routing id) and a
/// sign-out (delete seed). The chat UI wired to GatewayClient lands in a later iteration.
struct HomeView: View {
    let seed: Data
    let onSignOut: () -> Void

    @State private var accountID = "…"
    @AppStorage("gatewayURL") private var gatewayURL: String = ""

    var body: some View {
        NavigationStack {
            VStack(spacing: 16) {
                Image(systemName: "checkmark.shield.fill").font(.largeTitle).foregroundStyle(.green)
                Text("You're set up").font(.title2.bold())
                Text("Account (zero-PII routing id)").font(.caption).foregroundStyle(.secondary)
                Text(accountID)
                    .font(.system(.footnote, design: .monospaced))
                    .multilineTextAlignment(.center)
                    .textSelection(.enabled)
                    .padding(.horizontal)

                VStack(alignment: .leading, spacing: 4) {
                    Text("Gateway URL").font(.caption).foregroundStyle(.secondary)
                    TextField("https://…", text: $gatewayURL)
                        .textFieldStyle(.roundedBorder)
                        #if os(iOS)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        #endif
                }.padding(.horizontal)

                NavigationLink("Open chat") {
                    ChatView(seed: seed, gatewayURL: gatewayURL)
                }
                .buttonStyle(.borderedProminent)
                .disabled(gatewayURL.isEmpty)

                Spacer().frame(height: 8)
                Button("Sign out (erase seed from this device)", role: .destructive, action: onSignOut)
                    .font(.footnote)
            }
            .padding()
            .frame(minWidth: 360, minHeight: 420)
        }
        .task {
            // Argon2id is CPU-bound — derive off the main actor. Production params (the real
            // ones the client commits to) so the displayed account_id matches the gateway.
            let s = seed
            accountID = await Task.detached(priority: .userInitiated) { () -> String in
                guard
                    let root = try? SeedIdentity.deriveRoot(
                        seed: s,
                        opsLimit: SwiftyCrypto.opsLimitProduction,
                        memLimit: SwiftyCrypto.memLimitProduction
                    ),
                    let id = try? SeedIdentity.accountID(root)
                else { return "—" }
                return id
            }.value
        }
    }
}
