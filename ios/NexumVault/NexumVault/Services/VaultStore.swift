import Foundation
import Security
import LocalAuthentication
import CryptoKit

final class VaultStore: ObservableObject {
    @Published var keys: [VaultKey] = []
    @Published var isUnlocked = false
    
    private let keychainService = "com.nexum.vault"
    private let masterKeyTag = "com.nexum.vault.masterkey"
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()
    
    private var signAttempts: [Date] = []
    private let maxSignAttemptsPerMinute = 10
    
    init() {
        encoder.dateEncodingStrategy = .iso8601
        decoder.dateDecodingStrategy = .iso8601
        loadKeys()
    }
    
    // MARK: - Key Generation
    
    func createVault(deviceName: String, falcon: FalconCryptoProtocol = FalconCrypto()) throws -> VaultKey {
        let keypair = try falcon.generateKeyPair(logn: 10)
        let masterKey = try getOrCreateMasterKey()
        let derived = deriveKeyEncryptionKey(masterKey: masterKey, keyId: "new_\(UUID().uuidString)")
        let encryptedPrivKey = try encryptAESGCM(keypair.privateKey, with: derived)
        
        let keyId = generateKeyId()
        let key = VaultKey(
            id: UUID().uuidString,
            keyId: keyId,
            algorithm: keypair.algorithm,
            publicKeyBase64url: keypair.publicKeyBase64url,
            encryptedPrivateKey: encryptedPrivKey,
            keyEncryptionKeyId: masterKeyTag,
            createdAt: Date(),
            deviceName: deviceName
        )
        
        keys.append(key)
        saveKeys()
        return key
    }
    
    // MARK: - Private Key Access (requires biometrics)
    
    func decryptPrivateKey(for key: VaultKey) async throws -> Data {
        try await authenticateBiometrics(reason: "Sign challenge with \(key.keyId)")
        try checkRateLimit()
        
        let masterKey = try getOrCreateMasterKey()
        let derived = deriveKeyEncryptionKey(masterKey: masterKey, keyId: key.keyId)
        let decrypted = try decryptAESGCM(key.encryptedPrivateKey, with: derived)
        
        recordSignAttempt()
        return decrypted
    }
    
    // MARK: - Rate Limiting
    
    private func checkRateLimit() throws {
        let cutoff = Date().addingTimeInterval(-60)
        signAttempts = signAttempts.filter { $0 > cutoff }
        if signAttempts.count >= maxSignAttemptsPerMinute {
            throw VaultError.rateLimited
        }
    }
    
    private func recordSignAttempt() {
        signAttempts.append(Date())
    }
    
    // MARK: - Biometric Authentication
    
    func authenticateBiometrics(reason: String) async throws {
        let context = LAContext()
        context.localizedCancelTitle = "Cancel"
        context.touchIDAuthenticationAllowableReuseDuration = 10
        
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
            if let laError = error as? LAError {
                switch laError.code {
                case .biometryNotEnrolled:
                    throw VaultError.biometricNotEnrolled
                case .biometryLockout:
                    throw VaultError.biometricLockout
                default:
                    break
                }
            }
            throw VaultError.biometricUnavailable(error?.localizedDescription ?? "Unknown")
        }
        
        let success = try await context.evaluatePolicy(
            .deviceOwnerAuthenticationWithBiometrics,
            localizedReason: reason
        )
        guard success else {
            throw VaultError.biometricFailed
        }
    }
    
    // MARK: - Import / Export
    
    func importBackup(_ backupData: Data) throws {
        let backup = try decoder.decode(VaultBackup.self, from: backupData)
        guard backup.version == 1 else {
            throw VaultError.unsupportedBackupVersion(backup.version)
        }
        for key in backup.keys {
            guard key.keyId.hasPrefix("vk_") else {
                throw VaultError.invalidBackupFormat("Invalid keyId: \(key.keyId)")
            }
            if !keys.contains(where: { $0.keyId == key.keyId }) {
                keys.append(key)
            }
        }
        saveKeys()
    }
    
    func exportBackup(includeAuditLog: Bool, auditEntries: [AuditEntry]) throws -> Data {
        let backup = VaultBackup(
            version: 1,
            exportedAt: Date(),
            keys: keys,
            auditLog: includeAuditLog ? auditEntries : []
        )
        return try encoder.encode(backup)
    }
    
    func exportEncryptedBackup(passphrase: String, auditEntries: [AuditEntry]) throws -> Data {
        guard passphrase.count >= 12 else {
            throw VaultError.weakPassphrase
        }
        
        let plaintext = try exportBackup(includeAuditLog: true, auditEntries: auditEntries)
        let salt = randomBytes(32)
        let key = derivePassphraseKey(passphrase: passphrase, salt: salt)
        let sealed = try AES.GCM.seal(plaintext, using: key)
        guard let combined = sealed.combined else {
            throw VaultError.encryptionFailed
        }
        
        var envelope = Data()
        envelope.append(0x01)
        envelope.append(salt)
        envelope.append(combined)
        return envelope
    }
    
    func importEncryptedBackup(_ envelope: Data, passphrase: String) throws {
        guard envelope.count > 33 else {
            throw VaultError.invalidBackupFormat("Envelope too small")
        }
        guard envelope[0] == 0x01 else {
            throw VaultError.unsupportedBackupVersion(Int(envelope[0]))
        }
        
        let salt = envelope[1..<33]
        let combined = envelope[33...]
        let key = derivePassphraseKey(passphrase: passphrase, salt: Data(salt))
        let sealedBox = try AES.GCM.SealedBox(combined: combined)
        let plaintext = try AES.GCM.open(sealedBox, using: key)
        try importBackup(plaintext)
    }
    
    func deleteVault() {
        keys.removeAll()
        deleteMasterKey()
        saveKeys()
    }
    
    // MARK: - Keychain / Master Key
    
    private func getOrCreateMasterKey() throws -> Data {
        if let existing = loadMasterKey() {
            return existing
        }
        let keyData = randomBytes(32)
        try storeMasterKey(keyData)
        return keyData
    }
    
    private func storeMasterKey(_ key: Data) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: masterKeyTag,
            kSecValueData as String: key,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]
        SecItemDelete(query as CFDictionary)
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw VaultError.keychainError(status)
        }
    }
    
    private func loadMasterKey() -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: masterKeyTag,
            kSecReturnData as String: true
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let data = result as? Data else {
            return nil
        }
        return data
    }
    
    private func deleteMasterKey() {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: masterKeyTag
        ]
        SecItemDelete(query as CFDictionary)
    }
    
    // MARK: - Key Derivation
    
    private func deriveKeyEncryptionKey(masterKey: Data, keyId: String) -> SymmetricKey {
        let salt = Data(keyId.utf8)
        let info = Data("com.nexum.vault.kek.v1".utf8)
        return HKDF<SHA256>.deriveKey(
            salt: salt,
            info: info,
            inputKeyMaterial: SymmetricKey(data: masterKey),
            outputByteCount: 32
        )
    }
    
    private func derivePassphraseKey(passphrase: String, salt: Data) -> SymmetricKey {
        let passphraseKey = SymmetricKey(data: Data(passphrase.utf8))
        let info = Data("com.nexum.vault.backup.v1".utf8)
        return HKDF<SHA256>.deriveKey(
            salt: salt,
            info: info,
            inputKeyMaterial: passphraseKey,
            outputByteCount: 32
        )
    }
    
    // MARK: - AES-GCM
    
    private func encryptAESGCM(_ plaintext: Data, with key: SymmetricKey) throws -> Data {
        let sealed = try AES.GCM.seal(plaintext, using: key)
        guard let combined = sealed.combined else {
            throw VaultError.encryptionFailed
        }
        return combined
    }
    
    private func decryptAESGCM(_ ciphertext: Data, with key: SymmetricKey) throws -> Data {
        let sealedBox = try AES.GCM.SealedBox(combined: ciphertext)
        return try AES.GCM.open(sealedBox, using: key)
    }
    
    // MARK: - Helpers
    
    private func randomBytes(_ count: Int) -> Data {
        var data = Data(count: count)
        let status = data.withUnsafeMutableBytes { ptr in
            SecRandomCopyBytes(kSecRandomDefault, count, ptr.baseAddress!)
        }
        precondition(status == errSecSuccess, "SecRandomCopyBytes failed")
        return data
    }
    
    // MARK: - Persistence
    
    private func saveKeys() {
        guard let data = try? encoder.encode(keys) else { return }
        UserDefaults.standard.set(data, forKey: "nexum_vault_keys")
    }
    
    private func loadKeys() {
        guard let data = UserDefaults.standard.data(forKey: "nexum_vault_keys"),
              let decoded = try? decoder.decode([VaultKey].self, from: data) else { return }
        keys = decoded
    }
    
    private func generateKeyId() -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyyMMdd"
        let dateStr = formatter.string(from: Date())
        let random = UUID().uuidString.prefix(8).lowercased()
        return "vk_\(dateStr)_\(random)"
    }
}

enum VaultError: Error, LocalizedError {
    case biometricUnavailable(String)
    case biometricNotEnrolled
    case biometricLockout
    case biometricFailed
    case masterKeyGenerationFailed
    case keychainError(OSStatus)
    case encryptionFailed
    case decryptionFailed
    case unsupportedBackupVersion(Int)
    case invalidBackupFormat(String)
    case noActiveKey
    case rateLimited
    case weakPassphrase
    
    var errorDescription: String? {
        switch self {
        case .biometricUnavailable(let r): return "Biometrics unavailable: \(r)"
        case .biometricNotEnrolled: return "No biometrics enrolled. Set up Face ID or Touch ID in Settings."
        case .biometricLockout: return "Biometrics locked. Use device passcode."
        case .biometricFailed: return "Biometric authentication failed"
        case .masterKeyGenerationFailed: return "Failed to generate master key"
        case .keychainError(let s): return "Keychain error: \(s)"
        case .encryptionFailed: return "Encryption failed"
        case .decryptionFailed: return "Decryption failed"
        case .unsupportedBackupVersion(let v): return "Unsupported backup version: \(v)"
        case .invalidBackupFormat(let m): return "Invalid backup: \(m)"
        case .noActiveKey: return "No active key in vault"
        case .rateLimited: return "Too many signing attempts. Wait a moment."
        case .weakPassphrase: return "Passphrase must be at least 12 characters"
        }
    }
}
