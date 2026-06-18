import SwiftUI

struct ScanChallengeView: View {
    @EnvironmentObject var vaultStore: VaultStore
    @EnvironmentObject var auditLog: AuditLogStore
    @Environment(\.dismiss) var dismiss
    
    @StateObject private var scanner = QRScanner()
    @State private var challenge: NexumChallenge?
    @State private var showReview = false
    @State private var showError = false
    @State private var errorMessage = ""
    @State private var manualInput = ""
    @State private var showManualInput = false
    
    var body: some View {
        NavigationStack {
            VStack {
                if scanner.permissionDenied {
                    VStack(spacing: 20) {
                        Image(systemName: "camera.fill")
                            .font(.system(size: 60))
                            .foregroundColor(.secondary)
                        Text("Camera Access Required")
                            .font(.title2)
                            .fontWeight(.bold)
                        Text("Enable camera access in Settings to scan QR codes.")
                            .font(.subheadline)
                            .foregroundColor(.secondary)
                            .multilineTextAlignment(.center)
                            .padding(.horizontal)
                        Button("Open Settings") {
                            if let url = URL(string: UIApplication.openSettingsURLString) {
                                UIApplication.shared.open(url)
                            }
                        }
                        .buttonStyle(.borderedProminent)
                        
                        Divider()
                        
                        Button("Paste JSON Manually") {
                            showManualInput = true
                        }
                    }
                    .padding()
                } else if showManualInput {
                    VStack(spacing: 16) {
                        Text("Paste Challenge JSON")
                            .font(.headline)
                        TextEditor(text: $manualInput)
                            .font(.system(.caption, design: .monospaced))
                            .frame(height: 200)
                            .overlay(
                                RoundedRectangle(cornerRadius: 8)
                                    .stroke(Color.gray.opacity(0.3))
                            )
                        Button("Parse") {
                            parseChallenge(manualInput)
                        }
                        .buttonStyle(.borderedProminent)
                        .disabled(manualInput.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                    }
                    .padding()
                } else {
                    ZStack {
                        ScannerView(scanner: scanner)
                            .ignoresSafeArea()
                        
                        VStack {
                            Spacer()
                            VStack(spacing: 12) {
                                Text("Scan Challenge QR")
                                    .font(.headline)
                                    .foregroundColor(.white)
                                Text("Point camera at the QR code")
                                    .font(.caption)
                                    .foregroundColor(.white.opacity(0.8))
                                Button("Paste JSON Manually") {
                                    showManualInput = true
                                    scanner.stopScanning()
                                }
                                .font(.caption)
                                .foregroundColor(.white)
                                .padding(.top, 4)
                            }
                            .padding()
                            .background(.ultraThinMaterial)
                            .cornerRadius(16)
                            .padding()
                        }
                    }
                }
            }
            .navigationTitle("Scan")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button("Cancel") {
                        scanner.stopScanning()
                        dismiss()
                    }
                }
            }
            .onAppear {
                scanner.requestPermissionAndStart()
            }
            .onDisappear {
                scanner.stopScanning()
            }
            .onChange(of: scanner.scannedCode) { _, newValue in
                if let code = newValue {
                    parseChallenge(code)
                }
            }
            .sheet(isPresented: $showReview) {
                if let challenge = challenge {
                    ChallengeReviewView(challenge: challenge)
                }
            }
            .alert("Error", isPresented: $showError) {
                Button("OK") {
                    scanner.scannedCode = nil
                    if !showManualInput {
                        scanner.startScanning()
                    }
                }
            } message: {
                Text(errorMessage)
            }
        }
    }
    
    private func parseChallenge(_ input: String) {
        do {
            let parsed = try ChallengeParser.parse(qrContent: input)
            challenge = parsed
            showReview = true
        } catch {
            errorMessage = error.localizedDescription
            showError = true
        }
    }
}
