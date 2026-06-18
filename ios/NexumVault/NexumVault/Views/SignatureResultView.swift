import SwiftUI

struct SignatureResultView: View {
    @EnvironmentObject var auditLog: AuditLogStore
    @Environment(\.dismiss) var dismiss
    
    let response: NexumResponse
    let challenge: NexumChallenge
    let callbackUrl: String?
    
    @State private var showQR = false
    @State private var callbackStatus: CallbackStatus = .pending
    @State private var callbackResult: CallbackResult?
    @State private var showError = false
    @State private var errorMessage = ""
    
    enum CallbackStatus {
        case pending
        case sending
        case success
        case failed
        case notConfigured
    }
    
    var body: some View {
        NavigationStack {
            List {
                Section("Signature") {
                    Label("Signed Successfully", systemImage: "checkmark.seal.fill")
                        .foregroundColor(.green)
                    LabeledContent("Challenge ID") {
                        Text(response.challengeId)
                            .font(.caption.monospaced())
                            .textSelection(.enabled)
                    }
                    LabeledContent("Key ID", value: response.keyId)
                    LabeledContent("Algorithm", value: response.algorithm)
                    LabeledContent("Signed At", value: response.signedAt.formatted(date: .abbreviated, time: .standard))
                }
                
                if let callbackUrl = callbackUrl, !callbackUrl.isEmpty {
                    Section("Callback") {
                        LabeledContent("Endpoint") {
                            Text(callbackUrl)
                                .font(.caption)
                                .textSelection(.enabled)
                        }
                        
                        switch callbackStatus {
                        case .pending:
                            Button("Send to Callback") {
                                Task { await sendCallback() }
                            }
                        case .sending:
                            HStack {
                                ProgressView()
                                Text("Sending...")
                            }
                        case .success:
                            Label("Delivered", systemImage: "checkmark.circle.fill")
                                .foregroundColor(.green)
                            if let result = callbackResult {
                                LabeledContent("HTTP Status", value: "\(result.statusCode)")
                            }
                        case .failed:
                            Label("Delivery Failed", systemImage: "xmark.circle.fill")
                                .foregroundColor(.red)
                            Button("Retry") {
                                Task { await sendCallback() }
                            }
                        case .notConfigured:
                            EmptyView()
                        }
                    }
                }
                
                Section("QR Response") {
                    Button(action: { showQR.toggle() }) {
                        Label(showQR ? "Hide QR" : "Show Response QR", systemImage: "qrcode")
                    }
                    
                    if showQR {
                        VStack(spacing: 12) {
                            QRCodeView(data: responseJSON())
                                .frame(width: 250, height: 250)
                                .padding(.vertical, 8)
                            
                            Text("Storefront can scan this QR to verify your signature")
                                .font(.caption)
                                .foregroundColor(.secondary)
                                .multilineTextAlignment(.center)
                            
                            Button(action: {
                                UIPasteboard.general.string = responseJSON()
                            }) {
                                Label("Copy Response JSON", systemImage: "doc.on.doc")
                            }
                        }
                    }
                }
                
                Section("Response JSON") {
                    ScrollView(.horizontal, showsIndicators: false) {
                        Text(responseJSON())
                            .font(.system(.caption, design: .monospaced))
                            .textSelection(.enabled)
                            .padding(4)
                    }
                }
            }
            .navigationTitle("Signature Result")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("Done") { dismiss() }
                }
            }
            .onAppear {
                if callbackUrl == nil || callbackUrl?.isEmpty == true {
                    callbackStatus = .notConfigured
                }
            }
            .alert("Callback Error", isPresented: $showError) {
                Button("OK") {}
            } message: {
                Text(errorMessage)
            }
        }
    }
    
    private func responseJSON() -> String {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        guard let data = try? encoder.encode(response),
              let string = String(data: data, encoding: .utf8) else {
            return "{}"
        }
        return string
    }
    
    private func sendCallback() async {
        guard let callbackUrl = callbackUrl, !callbackUrl.isEmpty else { return }
        callbackStatus = .sending
        
        do {
            let client = CallbackClient()
            let result = try await client.sendResponse(response, to: callbackUrl)
            callbackResult = result
            
            if result.success {
                callbackStatus = .success
                auditLog.log(
                    purpose: challenge.purpose.rawValue,
                    origin: challenge.origin,
                    challengeId: challenge.challengeId,
                    keyId: response.keyId,
                    status: .callbackSuccess,
                    deviceName: response.device?.name ?? "unknown"
                )
            } else {
                callbackStatus = .failed
                auditLog.log(
                    purpose: challenge.purpose.rawValue,
                    origin: challenge.origin,
                    challengeId: challenge.challengeId,
                    keyId: response.keyId,
                    status: .callbackFailed,
                    deviceName: response.device?.name ?? "unknown"
                )
            }
        } catch {
            callbackStatus = .failed
            errorMessage = error.localizedDescription
        }
    }
}
