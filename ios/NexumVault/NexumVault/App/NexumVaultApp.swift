import SwiftUI

@main
struct NexumVaultApp: App {
    @StateObject private var vaultStore = VaultStore()
    @StateObject private var auditLog = AuditLogStore()
    @StateObject private var biometricAuth = BiometricAuth()
    @State private var isLocked = true
    
    var body: some Scene {
        WindowGroup {
            Group {
                if isLocked {
                    LockScreenView(isLocked: $isLocked, biometricAuth: biometricAuth)
                } else {
                    VaultHomeView()
                        .environmentObject(vaultStore)
                        .environmentObject(auditLog)
                        .environmentObject(biometricAuth)
                }
            }
            .onReceive(NotificationCenter.default.publisher(for: UIApplication.didEnterBackgroundNotification)) { _ in
                isLocked = true
            }
            .onReceive(NotificationCenter.default.publisher(for: UIApplication.willEnterForegroundNotification)) { _ in
                // stays locked until user authenticates
            }
        }
    }
}

struct LockScreenView: View {
    @Binding var isLocked: Bool
    @ObservedObject var biometricAuth: BiometricAuth
    @State private var showError = false
    @State private var errorMessage = ""
    
    var body: some View {
        VStack(spacing: 32) {
            Spacer()
            
            Image(systemName: "lock.shield.fill")
                .font(.system(size: 80))
                .foregroundColor(.blue)
            
            Text("Nexum Vault")
                .font(.largeTitle)
                .fontWeight(.bold)
            
            Text("Authenticate to access your vault")
                .font(.subheadline)
                .foregroundColor(.secondary)
            
            Button(action: authenticate) {
                Label(
                    biometricAuth.biometricType == .faceID ? "Unlock with Face ID" : "Unlock",
                    systemImage: biometricAuth.biometricType == .faceID ? "faceid" : "lock.open"
                )
                .frame(maxWidth: .infinity)
                .padding()
                .background(Color.blue)
                .foregroundColor(.white)
                .cornerRadius(12)
            }
            .padding(.horizontal, 40)
            
            Spacer()
        }
        .alert("Authentication Error", isPresented: $showError) {
            Button("Retry") { authenticate() }
            Button("OK", role: .cancel) {}
        } message: {
            Text(errorMessage)
        }
    }
    
    private func authenticate() {
        Task {
            do {
                let success = try await biometricAuth.authenticateWithPasscode(reason: "Unlock Nexum Vault")
                if success {
                    isLocked = false
                }
            } catch {
                errorMessage = error.localizedDescription
                showError = true
            }
        }
    }
}
