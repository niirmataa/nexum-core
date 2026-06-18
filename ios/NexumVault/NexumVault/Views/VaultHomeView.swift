import SwiftUI

struct VaultHomeView: View {
    @EnvironmentObject var vaultStore: VaultStore
    @EnvironmentObject var auditLog: AuditLogStore
    @State private var showCreateVault = false
    @State private var showScanner = false
    @State private var showSettings = false
    @State private var showImport = false
    @State private var showError = false
    @State private var errorMessage = ""
    
    var body: some View {
        NavigationStack {
            List {
                Section("Keys") {
                    if vaultStore.keys.isEmpty {
                        ContentUnavailableView(
                            "No Keys",
                            systemImage: "key.slash",
                            description: Text("Create a vault to generate your Falcon key pair")
                        )
                    } else {
                        ForEach(vaultStore.keys) { key in
                            NavigationLink(destination: PublicKeyView(key: key)) {
                                KeyRowView(key: key)
                            }
                        }
                    }
                }
                
                if !vaultStore.keys.isEmpty {
                    Section("Actions") {
                        Button(action: { showScanner = true }) {
                            Label("Scan Challenge QR", systemImage: "qrcode.viewfinder")
                        }
                    }
                    
                    Section("Recent Activity") {
                        let recent = Array(auditLog.entries.prefix(5))
                        if recent.isEmpty {
                            Text("No activity yet")
                                .foregroundColor(.secondary)
                        } else {
                            ForEach(recent) { entry in
                                AuditRowView(entry: entry)
                            }
                        }
                    }
                }
            }
            .navigationTitle("Nexum Vault")
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Menu {
                        Button(action: { showCreateVault = true }) {
                            Label("Create Vault", systemImage: "plus.circle")
                        }
                        Button(action: { showImport = true }) {
                            Label("Import Backup", systemImage: "square.and.arrow.down")
                        }
                        Button(action: { showSettings = true }) {
                            Label("Settings", systemImage: "gear")
                        }
                    } label: {
                        Image(systemName: "ellipsis.circle")
                    }
                }
            }
            .sheet(isPresented: $showCreateVault) {
                CreateVaultView()
            }
            .fullScreenCover(isPresented: $showScanner) {
                ScanChallengeView()
            }
            .sheet(isPresented: $showSettings) {
                SettingsView()
            }
            .fileImporter(
                isPresented: $showImport,
                allowedContentTypes: [.json]
            ) { result in
                if case .success(let url) = result {
                    importBackup(from: url)
                }
            }
            .alert("Import Error", isPresented: $showError) {
                Button("OK") {}
            } message: {
                Text(errorMessage)
            }
        }
    }
    
    private func importBackup(from url: URL) {
        guard url.startAccessingSecurityScopedResource() else {
            errorMessage = "Cannot access file"
            showError = true
            return
        }
        defer { url.stopAccessingSecurityScopedResource() }
        
        do {
            let data = try Data(contentsOf: url)
            try vaultStore.importBackup(data)
        } catch {
            errorMessage = error.localizedDescription
            showError = true
        }
    }
}

struct KeyRowView: View {
    let key: VaultKey
    
    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(key.keyId)
                .font(.headline)
            HStack {
                Text(key.algorithm)
                    .font(.caption)
                    .foregroundColor(.secondary)
                Spacer()
                Text(key.createdAt.formatted(date: .abbreviated, time: .shortened))
                    .font(.caption2)
                    .foregroundColor(.secondary)
            }
        }
    }
}

struct AuditRowView: View {
    let entry: AuditEntry
    
    var body: some View {
        HStack {
            Image(systemName: statusIcon)
                .foregroundColor(statusColor)
                .frame(width: 20)
            VStack(alignment: .leading, spacing: 2) {
                Text(entry.purpose.capitalized)
                    .font(.subheadline)
                Text(entry.origin)
                    .font(.caption)
                    .foregroundColor(.secondary)
                    .lineLimit(1)
            }
            Spacer()
            Text(entry.signedAt.formatted(date: .abbreviated, time: .shortened))
                .font(.caption2)
                .foregroundColor(.secondary)
        }
    }
    
    private var statusIcon: String {
        switch entry.status {
        case .signed: return "checkmark.seal.fill"
        case .rejected: return "xmark.seal.fill"
        case .expired: return "clock.badge.exclamationmark"
        case .callbackSuccess: return "arrow.up.circle.fill"
        case .callbackFailed: return "arrow.down.circle.fill"
        case .qrDisplayed: return "qrcode"
        }
    }
    
    private var statusColor: Color {
        switch entry.status {
        case .signed, .callbackSuccess: return .green
        case .rejected, .callbackFailed: return .red
        case .expired: return .orange
        case .qrDisplayed: return .blue
        }
    }
}
