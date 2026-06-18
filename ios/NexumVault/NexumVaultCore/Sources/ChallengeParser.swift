import Foundation

public enum ChallengeParser {
    private static let decoder: JSONDecoder = {
        let d = JSONDecoder()
        d.dateDecodingStrategy = .iso8601
        return d
    }()
    
    public static func parse(qrContent: String) throws -> NexumChallenge {
        guard let data = qrContent.data(using: .utf8) else {
            throw ChallengeParserError.invalidEncoding
        }
        return try parse(data: data)
    }
    
    public static func parse(data: Data) throws -> NexumChallenge {
        let challenge: NexumChallenge
        do {
            challenge = try decoder.decode(NexumChallenge.self, from: data)
        } catch {
            throw ChallengeParserError.decodingFailed(error.localizedDescription)
        }
        try validate(challenge)
        return challenge
    }
    
    public static func validate(_ challenge: NexumChallenge) throws {
        guard challenge.version == 1 else {
            throw ChallengeParserError.unsupportedVersion(challenge.version)
        }
        guard challenge.type == "nexum.challenge" else {
            throw ChallengeParserError.invalidType(challenge.type)
        }
        guard !challenge.challengeId.isEmpty, challenge.challengeId.count <= 64 else {
            throw ChallengeParserError.invalidChallengeId
        }
        guard challenge.challengeId.hasPrefix("ch_") else {
            throw ChallengeParserError.invalidChallengeId
        }
        guard !challenge.nonce.isEmpty else {
            throw ChallengeParserError.missingNonce
        }
        guard challenge.issuedAt < challenge.expiresAt else {
            throw ChallengeParserError.invalidTimeRange
        }
        guard let originURL = URL(string: challenge.origin),
              originURL.scheme == "https" else {
            throw ChallengeParserError.insecureOrigin(challenge.origin)
        }
        if challenge.isExpired {
            throw ChallengeParserError.challengeExpired
        }
    }
    
    public static func isKnownOrigin(_ origin: String, knownOrigins: Set<String>) -> Bool {
        knownOrigins.contains(origin)
    }
}

public enum ChallengeParserError: Error, LocalizedError {
    case invalidEncoding
    case decodingFailed(String)
    case unsupportedVersion(Int)
    case invalidType(String)
    case invalidChallengeId
    case missingNonce
    case invalidTimeRange
    case insecureOrigin(String)
    case challengeExpired
    case unknownOrigin(String)
    
    public var errorDescription: String? {
        switch self {
        case .invalidEncoding: return "QR content is not valid UTF-8"
        case .decodingFailed(let msg): return "Failed to decode challenge: \(msg)"
        case .unsupportedVersion(let v): return "Unsupported challenge version: \(v)"
        case .invalidType(let t): return "Invalid challenge type: \(t)"
        case .invalidChallengeId: return "Invalid or missing challenge ID (must start with ch_)"
        case .missingNonce: return "Challenge nonce is missing"
        case .invalidTimeRange: return "issuedAt must be before expiresAt"
        case .insecureOrigin(let o): return "Origin must use HTTPS: \(o)"
        case .challengeExpired: return "Challenge has expired"
        case .unknownOrigin(let o): return "Unknown origin: \(o)"
        }
    }
}
