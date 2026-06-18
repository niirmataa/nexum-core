import SwiftUI

struct CreateVaultView: View {
    @EnvironmentObject var vaultStore: VaultStore
    @Environment(\.dismiss) var dismiss
    
    @State private var deviceName = UIDevice.current.name
    @State private var isCreating = false
    @State private var createdKey: VaultKey?
    @State private var showPublicKey = false
    @State private var showError = false
    @State private var errorMessage = ""
    
    var body: some View {
        NavigationStack {
            VStack(spacing: 24) {
                Image(systemName: "key.fill")
                    .font(.system(size: 60))
                    .foregroundColor(.blue)
                
                Text("Create New Vault")
                    .font(.title2)
                    .fontWeight(.bold)
                
                Text("Generate a new Falcon-1024 key pair. The private key will be encrypted and stored in your device Keychain.")
                    .font(.subheadline)
                    .foregroundColor(.secondary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal)
                
                TextField("Device Name", text: $deviceName)
                    .textFieldStyle(.roundedBorder)
                    .padding(.horizontal)
                
                if isCreating {
                    VStack(spacing: 8) {
                        ProgressView()
                        Text("Generating Falcon-1024 key pair...")
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                }
                
                Button(action: createVault) {
                    Label("Generate Key Pair", systemImage: "key.2.on.ring")
                        .frame(maxWidth: .infinity)
                        .padding()
                        .background(deviceName.trimmingCharacters(in: .whitespaces).isEmpty ? Color.gray : Color.blue)
                        .foregroundColor(.white)
                        .cornerRadius(12)
                }
                .disabled(deviceName.trimmingCharacters(in: .whitespaces).isEmpty || isCreating)
                .padding(.horizontal)
                
                Spacer()
            }
            .padding(.top, 40)
            .navigationTitle("New Vault")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button("Cancel") { dismiss() }
                }
            }
            .alert("Error", isPresented: $showError) {
                Button("OK") {}
            } message: {
                Text(errorMessage)
            }
            .sheet(isPresented: $showPublicKey) {
                if let key = createdKey {
                    NavigationStack {
                        PublicKeyView(key: key)
                            .toolbar {
                                ToolbarItem(placement: .navigationBarTrailing) {
                                    Button("Done") { dismiss() }
                                }
                            }
                    }
                }
            }
        }
    }
    
    private func createVault() {
        isCreating = true
        Task {
            do {
                let name = deviceName.trimmingCharacters(in: .whitespaces)
                let key = try vaultStore.createVault(deviceName: name)
                createdKey = key
                showPublicKey = true
            } catch {
                errorMessage = error.localizedDescription
                showError = true
            }
            isCreating = false
        }
    }
}
