import XCTest
@testable import NexumVaultCore

final class ChallengeParserTests: XCTestCase {
    
    private func futureDate() -> String {
        "2099-12-31T23:59:59Z"
    }
    
    func testValidChallenge() throws {
        let json = """
        {
            "version": 1,
            "type": "nexum.challenge",
            "purpose": "login",
            "challengeId": "ch_01TEST123",
            "nonce": "dGVzdG5vbmNl",
            "issuedAt": "2026-06-17T10:30:00Z",
            "expiresAt": "\(futureDate())",
            "origin": "https://igrowpro.pl"
        }
        """
        let challenge = try ChallengeParser.parse(qrContent: json)
        XCTAssertEqual(challenge.version, 1)
        XCTAssertEqual(challenge.type, "nexum.challenge")
        XCTAssertEqual(challenge.purpose, .login)
        XCTAssertEqual(challenge.challengeId, "ch_01TEST123")
        XCTAssertEqual(challenge.origin, "https://igrowpro.pl")
        XCTAssertFalse(challenge.isExpired)
    }
    
    func testInvalidVersion() {
        let json = """
        {"version":2,"type":"nexum.challenge","purpose":"login","challengeId":"ch_test","nonce":"abc","issuedAt":"2026-06-17T10:30:00Z","expiresAt":"\(futureDate())","origin":"https://example.com"}
        """
        XCTAssertThrowsError(try ChallengeParser.parse(qrContent: json)) { error in
            guard let e = error as? ChallengeParserError, case .unsupportedVersion(2) = e else {
                XCTFail("Expected unsupportedVersion(2), got \(error)")
                return
            }
        }
    }
    
    func testInvalidType() {
        let json = """
        {"version":1,"type":"wrong.type","purpose":"login","challengeId":"ch_test","nonce":"abc","issuedAt":"2026-06-17T10:30:00Z","expiresAt":"\(futureDate())","origin":"https://example.com"}
        """
        XCTAssertThrowsError(try ChallengeParser.parse(qrContent: json)) { error in
            guard let e = error as? ChallengeParserError, case .invalidType = e else {
                XCTFail("Expected invalidType, got \(error)")
                return
            }
        }
    }
    
    func testMissingChallengeIdPrefix() {
        let json = """
        {"version":1,"type":"nexum.challenge","purpose":"login","challengeId":"invalid_id","nonce":"abc","issuedAt":"2026-06-17T10:30:00Z","expiresAt":"\(futureDate())","origin":"https://example.com"}
        """
        XCTAssertThrowsError(try ChallengeParser.parse(qrContent: json)) { error in
            guard let e = error as? ChallengeParserError, case .invalidChallengeId = e else {
                XCTFail("Expected invalidChallengeId, got \(error)")
                return
            }
        }
    }
    
    func testExpiredChallenge() {
        let json = """
        {"version":1,"type":"nexum.challenge","purpose":"login","challengeId":"ch_test","nonce":"abc","issuedAt":"2020-01-01T00:00:00Z","expiresAt":"2020-01-01T00:01:00Z","origin":"https://example.com"}
        """
        XCTAssertThrowsError(try ChallengeParser.parse(qrContent: json)) { error in
            guard let e = error as? ChallengeParserError, case .challengeExpired = e else {
                XCTFail("Expected challengeExpired, got \(error)")
                return
            }
        }
    }
    
    func testInsecureOrigin() {
        let json = """
        {"version":1,"type":"nexum.challenge","purpose":"login","challengeId":"ch_test","nonce":"abc","issuedAt":"2026-06-17T10:30:00Z","expiresAt":"\(futureDate())","origin":"http://example.com"}
        """
        XCTAssertThrowsError(try ChallengeParser.parse(qrContent: json)) { error in
            guard let e = error as? ChallengeParserError, case .insecureOrigin = e else {
                XCTFail("Expected insecureOrigin, got \(error)")
                return
            }
        }
    }
    
    func testInvalidTimeRange() {
        let json = """
        {"version":1,"type":"nexum.challenge","purpose":"login","challengeId":"ch_test","nonce":"abc","issuedAt":"2026-06-17T10:35:00Z","expiresAt":"2026-06-17T10:30:00Z","origin":"https://example.com"}
        """
        XCTAssertThrowsError(try ChallengeParser.parse(qrContent: json)) { error in
            guard let e = error as? ChallengeParserError, case .invalidTimeRange = e else {
                XCTFail("Expected invalidTimeRange, got \(error)")
                return
            }
        }
    }
    
    func testMissingNonce() {
        let json = """
        {"version":1,"type":"nexum.challenge","purpose":"login","challengeId":"ch_test","nonce":"","issuedAt":"2026-06-17T10:30:00Z","expiresAt":"\(futureDate())","origin":"https://example.com"}
        """
        XCTAssertThrowsError(try ChallengeParser.parse(qrContent: json)) { error in
            guard let e = error as? ChallengeParserError, case .missingNonce = e else {
                XCTFail("Expected missingNonce, got \(error)")
                return
            }
        }
    }
    
    func testAllPurposes() throws {
        for purpose in ["login", "checkout", "escrow", "message"] {
            let json = """
            {"version":1,"type":"nexum.challenge","purpose":"\(purpose)","challengeId":"ch_test_\(purpose)","nonce":"dGVzdA","issuedAt":"2026-06-17T10:30:00Z","expiresAt":"\(futureDate())","origin":"https://example.com"}
            """
            let challenge = try ChallengeParser.parse(qrContent: json)
            XCTAssertEqual(challenge.purpose.rawValue, purpose)
        }
    }
    
    func testChallengeWithDisplay() throws {
        let json = """
        {"version":1,"type":"nexum.challenge","purpose":"checkout","challengeId":"ch_checkout_001","nonce":"dGVzdG5vbmNl","issuedAt":"2026-06-17T10:30:00Z","expiresAt":"\(futureDate())","origin":"https://igrowpro.pl","display":{"title":"Complete Purchase","description":"Pay for order","amount":"0.5 XMR","counterparty":"iGrowPro"}}
        """
        let challenge = try ChallengeParser.parse(qrContent: json)
        XCTAssertEqual(challenge.display?.title, "Complete Purchase")
        XCTAssertEqual(challenge.display?.amount, "0.5 XMR")
        XCTAssertEqual(challenge.display?.counterparty, "iGrowPro")
    }
    
    func testKnownOriginCheck() {
        let known: Set<String> = ["https://igrowpro.pl"]
        XCTAssertTrue(ChallengeParser.isKnownOrigin("https://igrowpro.pl", knownOrigins: known))
        XCTAssertFalse(ChallengeParser.isKnownOrigin("https://evil.com", knownOrigins: known))
    }
}
