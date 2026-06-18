import Foundation

final class SignatureService {
    private let falcon: FalconCryptoProtocol
    private let vaultStore: VaultStore
    
    init(falcon: FalconCryptoProtocol = FalconCrypto(), vaultStore: VaultStore) {
        self.falcon = falcon
        self.vaultStore = vaultStore
    }
    
    func signChallenge(_ challenge: NexumChallenge, key: VaultKey) async throws -> NexumResponse {
        let canonicalData = try CanonicalJSON.canonicalizeData(challengeToDict(challenge))
        
        let privateKeyData = try await vaultStore.decryptPrivateKey(for: key)
        
        defer {
            // Zero private key from memory
            var mutable = privateKeyData
            mutable.withUnsafeMutableBytes { ptr in
                if let base = ptr.baseAddress {
                    memset(base, 0, ptr.count)
                }
            }
        }
        
        let falconSig = try falcon.sign(message: canonicalData, privateKey: privateKeyData)
        
        return NexumResponse(
            version: 1,
            type: "nexum.response",
            challengeId: challenge.challengeId,
            publicKey: key.publicKeyBase64url,
            keyId: key.keyId,
            algorithm: key.algorithm,
            signature: falconSig.signatureBase64url,
            nonce: falconSig.nonceBase64url,
            signedAt: Date(),
            device: ResponseDevice(
                name: key.deviceName,
                platform: "ios"
            )
        )
    }
    
    func verifyResponse(_ response: NexumResponse, challenge: NexumChallenge) throws -> Bool {
        guard response.challengeId == challenge.challengeId else {
            throw SignatureError.challengeMismatch
        }
        
        let canonicalData = try CanonicalJSON.canonicalizeData(challengeToDict(challenge))
        
        guard let publicKeyData = Data(base64urlEncoded: response.publicKey) else {
            throw SignatureError.invalidPublicKeyEncoding
        }
        guard let signatureData = Data(base64urlEncoded: response.signature) else {
            throw SignatureError.invalidSignatureEncoding
        }
        guard let nonceData = Data(base64urlEncoded: response.nonce) else {
            throw SignatureError.invalidNonceEncoding
        }
        
        return try falcon.verify(
            message: canonicalData,
            signature: signatureData,
            nonce: nonceData,
            publicKey: publicKeyData
        )
    }
    
    private func challengeToDict(_ challenge: NexumChallenge) -> [String: Any] {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        
        var dict: [String: Any] = [
            "version": challenge.version,
            "type": challenge.type,
            "purpose": challenge.purpose.rawValue,
            "challengeId": challenge.challengeId,
            "nonce": challenge.nonce,
            "issuedAt": formatter.string(from: challenge.issuedAt),
            "expiresAt": formatter.string(from: challenge.expiresAt),
            "origin": challenge.origin
        ]
        
        if let callbackUrl = challenge.callbackUrl {
            dict["callbackUrl"] = callbackUrl
        }
        if let payloadHash = challenge.payloadHash {
            dict["payloadHash"] = payloadHash
        }
        if let display = challenge.display {
            var displayDict: [String: Any] = [:]
            if let title = display.title { displayDict["title"] = title }
            if let desc = display.description { displayDict["description"] = desc }
            if let amount = display.amount { displayDict["amount"] = amount }
            if let cp = display.counterparty { displayDict["counterparty"] = cp }
            if !displayDict.isEmpty {
                dict["display"] = displayDict
            }
        }
        
        return dict
    }
}

enum SignatureError: Error, LocalizedError {
    case challengeMismatch
    case invalidPublicKeyEncoding
    case invalidSignatureEncoding
    case invalidNonceEncoding
    
    var errorDescription: String? {
        switch self {
        case .challengeMismatch: return "Response challengeId does not match challenge"
        case .invalidPublicKeyEncoding: return "Invalid public key encoding"
        case .invalidSignatureEncoding: return "Invalid signature encoding"
        case .invalidNonceEncoding: return "Invalid nonce encoding"
        }
    }
}
