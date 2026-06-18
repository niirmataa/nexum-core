import Foundation

struct VaultKey: Codable, Identifiable {
    let id: String
    let keyId: String
    let algorithm: String
    let publicKeyBase64url: String
    let encryptedPrivateKey: Data
    let keyEncryptionKeyId: String
    let createdAt: Date
    let deviceName: String
    
    var publicKeyData: Data? {
        Data(base64urlEncoded: publicKeyBase64url)
    }
}

struct VaultKeyMetadata: Codable {
    let keyId: String
    let algorithm: String
    let createdAt: Date
    let deviceName: String
    let publicKeyFingerprint: String
}

extension Data {
    init?(base64urlEncoded string: String) {
        var base64 = string
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let remainder = base64.count % 4
        if remainder > 0 {
            base64 += String(repeating: "=", count: 4 - remainder)
        }
        self.init(base64Encoded: base64)
    }
    
    var base64urlEncodedString: String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
