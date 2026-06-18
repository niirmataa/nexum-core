import SwiftUI

struct ChallengeReviewView: View {
    @EnvironmentObject var vaultStore: VaultStore
    @EnvironmentObject var auditLog: AuditLogStore
    @Environment(\.dismiss) var dismiss
    
    let challenge: NexumChallenge
    
    @State private var selectedKey: VaultKey?
    @State private var isSigning = false
    @State private var showResult = false
    @State private var response: NexumResponse?
    @State private var showError = false
    @State private var errorMessage = ""
    
    private let knownOrigins: Set<String> = ["https://igrowpro.pl"]
    
    var body: some View {
        NavigationStack {
            List {
                Section("Challenge Details") {
                    LabeledContent("Purpose", value: challenge.purpose.rawValue.capitalized)
                    LabeledContent("Origin", value: challenge.origin)
                    LabeledContent("Challenge ID") {
                        Text(challenge.challengeId)
                            .font(.caption.monospaced())
                            .textSelection(.enabled)
                    }
                    
                    if let display = challenge.display {
                        if let title = display.title, !title.isEmpty {
                            LabeledContent("Title", value: title)
                        }
                        if let desc = display.description, !desc.isEmpty {
                            LabeledContent("Description", value: desc)
                        }
                        if let amount = display.amount, !amount.isEmpty {
                            LabeledContent("Amount", value: amount)
                        }
                        if let counterparty = display.counterparty, !counterparty.isEmpty {
                            LabeledContent("Counterparty", value: counterparty)
                        }
                    }
                }
                
                Section("Timing") {
                    LabeledContent("Issued", value: challenge.issuedAt.formatted(date: .abbreviated, time: .standard))
                    LabeledContent("Expires", value: challenge.expiresAt.formatted(date: .abbreviated, time: .standard))
                    
                    if challenge.isExpired {
                        Label("Challenge has expired", systemImage: "exclamationmark.triangle.fill")
                            .foregroundColor(.red)
                    } else {
                        let remaining = challenge.expiresAt.timeIntervalSince(Date())
                        if remaining > 0 {
                            LabeledContent("Remaining") {
                                Text("\(Int(remaining))s")
                                    .foregroundColor(remaining < 30 ? .orange : .primary)
                            }
                        }
                    }
                }
                
                Section("Fingerprint") {
                    Text(challenge.fingerprint)
                        .font(.caption.monospaced())
                        .textSelection(.enabled)
                }
                
                if !knownOrigins.contains(challenge.origin) {
                    Section {
                        Label {
                            VStack(alignment: .leading, spacing: 4) {
                                Text("Unknown Origin")
                                    .fontWeight(.semibold)
                                Text("This origin is not in your trusted list. Verify before signing.")
                                    .font(.caption)
                            }
                        } icon: {
                            Image(systemName: "exclamationmark.triangle.fill")
                                .foregroundColor(.orange)
                        }
                    }
                }
                
                Section("Select Key") {
                    if vaultStore.keys.isEmpty {
                        Label("No keys available. Create a vault first.", systemImage: "key.slash")
                            .foregroundColor(.red)
                    } else {
                        Picker("Signing Key", selection: $selectedKey) {
                            Text("Select a key").tag(nil as VaultKey?)
                            ForEach(vaultStore.keys) { key in
                                Text("\(key.keyId) — \(key.algorithm)").tag(key as VaultKey?)
                            }
                        }
                    }
                }
                
                Section {
                    Button(action: signChallenge) {
                        HStack {
                            Spacer()
                            if isSigning {
                                ProgressView()
                            } else {
                                Label("Sign Challenge", systemImage: "signature")
                            }
                            Spacer()
                        }
                    }
                    .disabled(selectedKey == nil || challenge.isExpired || isSigning)
                }
            }
            .navigationTitle("Review Challenge")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button("Cancel") { dismiss() }
                }
            }
            .onAppear {
                selectedKey = vaultStore.keys.first
            }
            .sheet(isPresented: $showResult) {
                if let response = response {
                    SignatureResultView(
                        response: response,
                        challenge: challenge,
                        callbackUrl: challenge.callbackUrl
                    )
                }
            }
            .alert("Signing Error", isPresented: $showError) {
                Button("OK") {}
            } message: {
                Text(errorMessage)
            }
        }
    }
    
    private func signChallenge() {
        guard let key = selectedKey else { return }
        isSigning = true
        
        Task {
            do {
                let service = SignatureService(vaultStore: vaultStore)
                let signed = try await service.signChallenge(challenge, key: key)
                
                auditLog.log(
                    purpose: challenge.purpose.rawValue,
                    origin: challenge.origin,
                    challengeId: challenge.challengeId,
                    keyId: key.keyId,
                    status: .signed,
                    deviceName: key.deviceName
                )
                
                response = signed
                showResult = true
            } catch {
                errorMessage = error.localizedDescription
                showError = true
                
                auditLog.log(
                    purpose: challenge.purpose.rawValue,
                    origin: challenge.origin,
                    challengeId: challenge.challengeId,
                    keyId: key.keyId,
                    status: .rejected,
                    deviceName: key.deviceName
                )
            }
            isSigning = false
        }
    }
}
