import Foundation
import CryptoKit

struct NexumChallenge: Codable {
    let version: Int
    let type: String
    let purpose: ChallengePurpose
    let challengeId: String
    let nonce: String
    let issuedAt: Date
    let expiresAt: Date
    let origin: String
    let callbackUrl: String?
    let payloadHash: String?
    let display: ChallengeDisplay?
    
    var isExpired: Bool {
        Date() > expiresAt
    }
    
    var fingerprint: String {
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

enum ChallengePurpose: String, Codable {
    case login
    case checkout
    case escrow
    case message
}

struct ChallengeDisplay: Codable {
    let title: String?
    let description: String?
    let amount: String?
    let counterparty: String?
}

struct NexumResponse: Codable {
    let version: Int
    let type: String
    let challengeId: String
    let publicKey: String
    let keyId: String
    let algorithm: String
    let signature: String
    let nonce: String
    let signedAt: Date
    let device: ResponseDevice?
}

struct ResponseDevice: Codable {
    let name: String
    let platform: String
}
