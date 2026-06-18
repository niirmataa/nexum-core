import SwiftUI

struct SettingsView: View {
    @EnvironmentObject var vaultStore: VaultStore
    @EnvironmentObject var auditLog: AuditLogStore
    @Environment(\.dismiss) var dismiss
    
    @State private var showDeleteConfirmation = false
    @State private var exportedData: Data?
    @State private var showExportSheet = false
    @State private var showError = false
    @State private var errorMessage = ""
    @State private var showPassphraseInput = false
    @State private var backupPassphrase = ""
    @State private var backupPassphraseConfirm = ""
    @State private var exportMode: ExportMode = .plain
    
    enum ExportMode {
        case plain
        case encrypted
    }
    
    var body: some View {
        NavigationStack {
            List {
                Section("Vault") {
                    LabeledContent("Keys", value: "\(vaultStore.keys.count)")
                    
                    if let key = vaultStore.keys.first {
                        LabeledContent("Primary Key", value: key.keyId)
                        LabeledContent("Algorithm", value: key.algorithm)
                    }
                }
                
                Section("Security") {
                    Label("Private keys encrypted in Keychain", systemImage: "lock.shield.fill")
                    Label("kSecAttrAccessibleWhenUnlockedThisDeviceOnly", systemImage: "lock.iphone")
                    Label("HKDF per-key encryption key derivation", systemImage: "key.horizontal")
                    Label("Rate limited: \(10) signs/minute max", systemImage: "speedometer")
                    Label("Biometric authentication required", systemImage: "faceid")
                    Label("No secrets logged", systemImage: "eye.slash")
                }
                
                Section("Audit Log") {
                    LabeledContent("Entries", value: "\(auditLog.entries.count)")
                    
                    NavigationLink("View Audit Log") {
                        AuditLogView()
                    }
                    
                    Button("Export Audit Log") {
                        exportAuditLog()
                    }
                }
                
                Section("Backup") {
                    Button("Export Plain Backup") {
                        exportMode = .plain
                        exportBackup()
                    }
                    
                    Button("Export Encrypted Backup") {
                        exportMode = .encrypted
                        showPassphraseInput = true
                    }
                    
                    if let data = exportedData {
                        ShareLink(item: data, preview: SharePreview("Nexum Vault Backup"))
                    }
                }
                
                Section("Danger Zone") {
                    Button("Delete All Keys", role: .destructive) {
                        showDeleteConfirmation = true
                    }
                }
                
                Section("About") {
                    LabeledContent("Version", value: "1.0.0")
                    LabeledContent("Protocol", value: "nexum-mobile-qr v1")
                    LabeledContent("Platform", value: "iOS 17+")
                    LabeledContent("Falcon", value: "Falcon-1024 (reference C)")
                }
            }
            .navigationTitle("Settings")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("Done") { dismiss() }
                }
            }
            .alert("Delete All Keys?", isPresented: $showDeleteConfirmation) {
                Button("Delete", role: .destructive) {
                    vaultStore.deleteVault()
                    auditLog.clear()
                }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text("This action cannot be undone. Make sure you have a backup of your keys.")
            }
            .alert("Error", isPresented: $showError) {
                Button("OK") {}
            } message: {
                Text(errorMessage)
            }
            .sheet(isPresented: $showPassphraseInput) {
                EncryptedBackupSheet(
                    passphrase: $backupPassphrase,
                    passphraseConfirm: $backupPassphraseConfirm,
                    onExport: {
                        exportEncryptedBackup()
                        showPassphraseInput = false
                    }
                )
            }
        }
    }
    
    private func exportBackup() {
        do {
            exportedData = try vaultStore.exportBackup(includeAuditLog: true, auditEntries: auditLog.entries)
        } catch {
            errorMessage = error.localizedDescription
            showError = true
        }
    }
    
    private func exportEncryptedBackup() {
        guard backupPassphrase == backupPassphraseConfirm else {
            errorMessage = "Passphrases do not match"
            showError = true
            return
        }
        guard backupPassphrase.count >= 12 else {
            errorMessage = "Passphrase must be at least 12 characters"
            showError = true
            return
        }
        do {
            exportedData = try vaultStore.exportEncryptedBackup(
                passphrase: backupPassphrase,
                auditEntries: auditLog.entries
            )
            backupPassphrase = ""
            backupPassphraseConfirm = ""
        } catch {
            errorMessage = error.localizedDescription
            showError = true
        }
    }
    
    private func exportAuditLog() {
        do {
            exportedData = try auditLog.exportData()
        } catch {
            errorMessage = error.localizedDescription
            showError = true
        }
    }
}

struct EncryptedBackupSheet: View {
    @Binding var passphrase: String
    @Binding var passphraseConfirm: String
    let onExport: () -> Void
    @Environment(\.dismiss) var dismiss
    
    var body: some View {
        NavigationStack {
            VStack(spacing: 16) {
                Text("Enter a strong passphrase to encrypt your backup. You will need this passphrase to restore.")
                    .font(.subheadline)
                    .foregroundColor(.secondary)
                    .padding(.horizontal)
                
                SecureField("Passphrase (min 12 chars)", text: $passphrase)
                    .textFieldStyle(.roundedBorder)
                    .padding(.horizontal)
                
                SecureField("Confirm passphrase", text: $passphraseConfirm)
                    .textFieldStyle(.roundedBorder)
                    .padding(.horizontal)
                
                if passphrase != passphraseConfirm && !passphraseConfirm.isEmpty {
                    Text("Passphrases do not match")
                        .font(.caption)
                        .foregroundColor(.red)
                }
                
                Button("Export Encrypted Backup") {
                    onExport()
                }
                .buttonStyle(.borderedProminent)
                .disabled(passphrase.count < 12 || passphrase != passphraseConfirm)
                
                Spacer()
            }
            .padding(.top, 20)
            .navigationTitle("Encrypted Backup")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button("Cancel") { dismiss() }
                }
            }
        }
    }
}

struct AuditLogView: View {
    @EnvironmentObject var auditLog: AuditLogStore
    
    var body: some View {
        List {
            if auditLog.entries.isEmpty {
                ContentUnavailableView(
                    "No Audit Entries",
                    systemImage: "doc.text",
                    description: Text("Signing activity will appear here")
                )
            } else {
                ForEach(auditLog.entries) { entry in
                    VStack(alignment: .leading, spacing: 4) {
                        HStack {
                            Text(entry.purpose.capitalized)
                                .font(.headline)
                            Spacer()
                            Text(entry.status.rawValue)
                                .font(.caption)
                                .padding(.horizontal, 8)
                                .padding(.vertical, 2)
                                .background(statusColor(entry.status))
                                .foregroundColor(.white)
                                .cornerRadius(4)
                        }
                        Text(entry.origin)
                            .font(.subheadline)
                            .foregroundColor(.secondary)
                        Text("Challenge: \(entry.challengeId)")
                            .font(.caption.monospaced())
                            .foregroundColor(.secondary)
                        Text("Key: \(entry.keyId)")
                            .font(.caption)
                            .foregroundColor(.secondary)
                        Text(entry.signedAt.formatted(date: .long, time: .standard))
                            .font(.caption2)
                            .foregroundColor(.secondary)
                    }
                    .padding(.vertical, 4)
                }
            }
        }
        .navigationTitle("Audit Log")
    }
    
    private func statusColor(_ status: AuditStatus) -> Color {
        switch status {
        case .signed, .callbackSuccess: return .green
        case .rejected, .callbackFailed: return .red
        case .expired: return .orange
        case .qrDisplayed: return .blue
        }
    }
}
