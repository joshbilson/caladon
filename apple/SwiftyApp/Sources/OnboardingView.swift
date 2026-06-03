import SwiftUI
import SwiftyKit

/// First-run seed onboarding. The 256-bit seed is the user's only key; it is shown once as a
/// Mullvad-style transcribable phrase (SeedCodec) for the user to write down — there is no
/// recovery by default. On "continue", the seed is handed to the caller to persist.
struct OnboardingView: View {
    /// Called with the generated seed once the user confirms they've written the phrase down.
    let onComplete: (Data) -> Void

    @State private var seed: Data?
    @State private var phrase: String = ""
    @State private var error: String?

    var body: some View {
        VStack(spacing: 20) {
            Text("Caladon").font(.largeTitle.bold())
            Text("Your recovery phrase is the only key to your data. Write it down and keep it "
                + "safe — by default there is no recovery if it is lost.")
                .font(.footnote).foregroundStyle(.secondary)
                .multilineTextAlignment(.center).padding(.horizontal)

            if !phrase.isEmpty {
                Text(phrase)
                    .font(.system(.body, design: .monospaced))
                    .multilineTextAlignment(.center)
                    .textSelection(.enabled)
                    .padding()
                    .frame(maxWidth: .infinity)
                    .background(.quaternary)
                    .clipShape(RoundedRectangle(cornerRadius: 10))
                    .padding(.horizontal)

                Button("I've written it down — continue") {
                    if let seed { onComplete(seed) }
                }
                .buttonStyle(.borderedProminent)
            } else {
                Button("Generate recovery phrase") {
                    do {
                        let s = try Seed.generate()
                        seed = s
                        phrase = try SeedCodec.encode(s)
                        error = nil
                    } catch {
                        self.error = "Could not generate a seed."
                    }
                }
                .buttonStyle(.borderedProminent)
            }

            if let error { Text(error).font(.caption).foregroundStyle(.red) }
        }
        .padding()
        .frame(minWidth: 360, minHeight: 360)
    }
}

#Preview {
    OnboardingView { _ in }
}
