import Foundation

public struct VaultKey: Codable, Identifiable, Sendable {
    public let id: String
    public let keyId: String
    public let algorithm: String
    public let publicKeyBase64url: String
    public let encryptedPrivateKey: Data
    public let keyEncryptionKeyId: String
    public let createdAt: Date
    public let deviceName: String
    
    public init(
        id: String,
        keyId: String,
        algorithm: String,
        publicKeyBase64url: String,
        encryptedPrivateKey: Data,
        keyEncryptionKeyId: String,
        createdAt: Date,
        deviceName: String
    ) {
        self.id = id
        self.keyId = keyId
        self.algorithm = algorithm
        self.publicKeyBase64url = publicKeyBase64url
        self.encryptedPrivateKey = encryptedPrivateKey
        self.keyEncryptionKeyId = keyEncryptionKeyId
        self.createdAt = createdAt
        self.deviceName = deviceName
    }
    
    public var publicKeyData: Data? {
        Data(base64urlEncoded: publicKeyBase64url)
    }
}

extension Data {
    public init?(base64urlEncoded string: String) {
        var base64 = string
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let remainder = base64.count % 4
        if remainder > 0 {
            base64 += String(repeating: "=", count: 4 - remainder)
        }
        self.init(base64Encoded: base64)
    }
    
    public var base64urlEncodedString: String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
