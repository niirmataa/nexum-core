import Foundation

public struct NexumChallenge: Codable, Sendable {
    public let version: Int
    public let type: String
    public let purpose: ChallengePurpose
    public let challengeId: String
    public let nonce: String
    public let issuedAt: Date
    public let expiresAt: Date
    public let origin: String
    public let callbackUrl: String?
    public let payloadHash: String?
    public let display: ChallengeDisplay?
    
    public init(
        version: Int,
        type: String,
        purpose: ChallengePurpose,
        challengeId: String,
        nonce: String,
        issuedAt: Date,
        expiresAt: Date,
        origin: String,
        callbackUrl: String? = nil,
        payloadHash: String? = nil,
        display: ChallengeDisplay? = nil
    ) {
        self.version = version
        self.type = type
        self.purpose = purpose
        self.challengeId = challengeId
        self.nonce = nonce
        self.issuedAt = issuedAt
        self.expiresAt = expiresAt
        self.origin = origin
        self.callbackUrl = callbackUrl
        self.payloadHash = payloadHash
        self.display = display
    }
    
    public var isExpired: Bool {
        Date() > expiresAt
    }
    
    public var fingerprint: String {
        var dict: [String: Any] = [
            "challengeId": challengeId,
            "nonce": nonce,
            "origin": origin,
            "purpose": purpose.rawValue
        ]
        if let ph = payloadHash, !ph.isEmpty {
            dict["payloadHash"] = ph
        }
        guard let canonical = try? CanonicalJSON.canonicalize(dict) else {
            return "error"
        }
        let hash = SHA256.hash(data: Data(canonical.utf8))
        return hash.prefix(8).map { String(format: "%02x", $0) }.joined()
    }
}

public enum ChallengePurpose: String, Codable, Sendable {
    case login
    case checkout
    case escrow
    case message
}

public struct ChallengeDisplay: Codable, Sendable {
    public let title: String?
    public let description: String?
    public let amount: String?
    public let counterparty: String?
    
    public init(
        title: String? = nil,
        description: String? = nil,
        amount: String? = nil,
        counterparty: String? = nil
    ) {
        self.title = title
        self.description = description
        self.amount = amount
        self.counterparty = counterparty
    }
}

public struct NexumResponse: Codable, Sendable {
    public let version: Int
    public let type: String
    public let challengeId: String
    public let publicKey: String
    public let keyId: String
    public let algorithm: String
    public let signature: String
    public let nonce: String
    public let signedAt: Date
    public let device: ResponseDevice?
    
    public init(
        version: Int,
        type: String,
        challengeId: String,
        publicKey: String,
        keyId: String,
        algorithm: String,
        signature: String,
        nonce: String,
        signedAt: Date,
        device: ResponseDevice? = nil
    ) {
        self.version = version
        self.type = type
        self.challengeId = challengeId
        self.publicKey = publicKey
        self.keyId = keyId
        self.algorithm = algorithm
        self.signature = signature
        self.nonce = nonce
        self.signedAt = signedAt
        self.device = device
    }
}

public struct ResponseDevice: Codable, Sendable {
    public let name: String
    public let platform: String
    
    public init(name: String, platform: String) {
        self.name = name
        self.platform = platform
    }
}

import CryptoKit

private enum SHA256 {
    static func hash(data: Data) -> Data {
        let digest = CryptoKit.SHA256.hash(data: data)
        return Data(digest)
    }
}
