import SwiftUI
import SwiftyKit

struct ChatMessage: Identifiable {
    let id = UUID()
    let role: String   // "you" | "swifty" | "system"
    let text: String
}

/// Placeholder attestation verifier — FAILS CLOSED. The real regime verifier
/// (dcap-qvl-swift for TDX, tinfoil-swift for SEV) lands in a later iteration; until then any
/// T1 connection is correctly refused rather than trusting an unverified enclave.
private struct UnavailableVerifier: QuoteVerifier {
    func verify(regime: Regime, raw: [String: String]) -> Result<VerifiedQuote, VerdictReason> {
        .failure(.regimeUnsupported)
    }
}

@MainActor
final class ChatViewModel: ObservableObject {
    @Published var messages: [ChatMessage] = []
    @Published var input: String = ""
    @Published var status: String = "Not connected"
    @Published var connected = false
    @Published var busy = false

    private let seed: Data
    private let gatewayURL: String
    private var client: GatewayClient?
    private var sessionKey: Data?

    // Measurement allow-list — pinned per reproducible build (docs/security/measurements.md).
    // Empty until the first pinned release; the fail-closed verifier blocks T1 regardless for now.
    private let pinned = PinnedSet(measurements: [], composeHashes: [], workloadIDs: [])

    init(seed: Data, gatewayURL: String) {
        self.seed = seed
        self.gatewayURL = gatewayURL
    }

    func connect() async {
        // Normalise a schemeless host (e.g. "gw.caladon.ai") to https so URLSession can connect.
        let raw = gatewayURL.trimmingCharacters(in: .whitespaces)
        let normalized = raw.hasPrefix("http://") || raw.hasPrefix("https://") ? raw : "https://" + raw
        guard !raw.isEmpty, let url = URL(string: normalized) else {
            status = "Set a gateway URL first"; return
        }
        busy = true; defer { busy = false }
        status = "Connecting…"
        do {
            let seed = self.seed
            let root = try await Task.detached(priority: .userInitiated) {
                try SeedIdentity.deriveRoot(
                    seed: seed, opsLimit: SwiftyCrypto.opsLimitProduction, memLimit: SwiftyCrypto.memLimitProduction
                )
            }.value
            let c = try GatewayClient.make(baseURL: url, root: root, verifier: UnavailableVerifier(), pinned: pinned)
            // Register the account with the gateway (idempotent) before the attested handshake,
            // else the gateway rejects the unknown account (401).
            status = "Registering…"
            try await c.onboard()
            status = "Verifying enclave…"
            // §6: deliver WMK over the attested channel. Fails closed if the enclave doesn't verify.
            sessionKey = try await c.establishSession(wmk: SeedIdentity.wmk(root))
            client = c
            connected = true
            status = "Connected (attested)"
        } catch {
            connected = false
            status = "Could not establish a verified session — \(Self.describe(error))"
        }
    }

    func send() async {
        let prompt = input.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !prompt.isEmpty, connected, let client, let sessionKey, !busy else { return }
        busy = true; defer { busy = false }
        messages.append(ChatMessage(role: "you", text: prompt))
        input = ""
        do {
            let deltas = try await client.chat(prompt: prompt, sessionKey: sessionKey)
            messages.append(ChatMessage(role: "swifty", text: deltas.joined()))
        } catch {
            messages.append(ChatMessage(role: "system", text: Self.describe(error)))
        }
    }

    /// Map errors to CONTROLLED user-facing strings — never interpolate a raw `error` (so a
    /// future error carrying a URL/response excerpt can't leak into the UI / crash logs).
    static func describe(_ error: Error) -> String {
        switch error {
        case GatewayError.attestationFailed(let reason): return "enclave attestation failed (\(reason.rawValue))"
        case GatewayError.http(let code): return "server error (HTTP \(code))"
        case GatewayError.decode: return "unexpected server response"
        default: return "connection error"
        }
    }
}

struct ChatView: View {
    @StateObject var model: ChatViewModel

    init(seed: Data, gatewayURL: String) {
        _model = StateObject(wrappedValue: ChatViewModel(seed: seed, gatewayURL: gatewayURL))
    }

    var body: some View {
        VStack(spacing: 0) {
            Text(model.status).font(.caption).foregroundStyle(.secondary).padding(6)
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 8) {
                    ForEach(model.messages) { m in
                        Text(m.text)
                            .padding(8)
                            .background(m.role == "you" ? Color.accentColor.opacity(0.15) : Color.gray.opacity(0.12))
                            .clipShape(RoundedRectangle(cornerRadius: 8))
                            .frame(maxWidth: .infinity, alignment: m.role == "you" ? .trailing : .leading)
                    }
                }.padding()
            }
            HStack {
                TextField("Message", text: $model.input)
                    .textFieldStyle(.roundedBorder)
                    .disabled(!model.connected || model.busy)
                Button("Send") { Task { await model.send() } }
                    .disabled(!model.connected || model.busy)
            }.padding()
        }
        .navigationTitle("Caladon")
        .task { await model.connect() }
    }
}
