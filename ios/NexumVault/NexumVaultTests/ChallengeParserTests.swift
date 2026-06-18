import XCTest
@testable import NexumVault

final class ChallengeParserTests: XCTestCase {
    
    func testValidChallenge() throws {
        let json = """
        {
            "version": 1,
            "type": "nexum.challenge",
            "purpose": "login",
            "challengeId": "ch_01TEST123",
            "nonce": "dGVzdG5vbmNl",
            "issuedAt": "2026-06-17T10:30:00Z",
            "expiresAt": "2099-12-31T23:59:59Z",
            "origin": "https://igrowpro.pl"
        }
        """
        let challenge = try ChallengeParser.parse(qrContent: json)
        XCTAssertEqual(challenge.version, 1)
        XCTAssertEqual(challenge.type, "nexum.challenge")
        XCTAssertEqual(challenge.purpose, .login)
        XCTAssertEqual(challenge.challengeId, "ch_01TEST123")
        XCTAssertEqual(challenge.origin, "https://igrowpro.pl")
    }
    
    func testInvalidVersion() {
        let json = """
        {
            "version": 2,
            "type": "nexum.challenge",
            "purpose": "login",
            "challengeId": "ch_test",
            "nonce": "abc",
            "issuedAt": "2026-06-17T10:30:00Z",
            "expiresAt": "2026-06-17T10:35:00Z",
            "origin": "https://example.com"
        }
        """
        XCTAssertThrowsError(try ChallengeParser.parse(qrContent: json)) { error in
            guard let parserError = error as? ChallengeParserError else {
                XCTFail("Expected ChallengeParserError")
                return
            }
            if case .unsupportedVersion(let v) = parserError {
                XCTAssertEqual(v, 2)
            } else {
                XCTFail("Expected unsupportedVersion error")
            }
        }
    }
    
    func testInvalidType() {
        let json = """
        {
            "version": 1,
            "type": "wrong.type",
            "purpose": "login",
            "challengeId": "ch_test",
            "nonce": "abc",
            "issuedAt": "2026-06-17T10:30:00Z",
            "expiresAt": "2026-06-17T10:35:00Z",
            "origin": "https://example.com"
        }
        """
        XCTAssertThrowsError(try ChallengeParser.parse(qrContent: json)) { error in
            guard let parserError = error as? ChallengeParserError,
                  case .invalidType = parserError else {
                XCTFail("Expected invalidType error")
                return
            }
        }
    }
    
    func testMissingChallengeIdPrefix() {
        let json = """
        {
            "version": 1,
            "type": "nexum.challenge",
            "purpose": "login",
            "challengeId": "invalid_id",
            "nonce": "abc",
            "issuedAt": "2026-06-17T10:30:00Z",
            "expiresAt": "2026-06-17T10:35:00Z",
            "origin": "https://example.com"
        }
        """
        XCTAssertThrowsError(try ChallengeParser.parse(qrContent: json)) { error in
            guard let parserError = error as? ChallengeParserError,
                  case .invalidChallengeId = parserError else {
                XCTFail("Expected invalidChallengeId error")
                return
            }
        }
    }
    
    func testExpiredChallenge() {
        let json = """
        {
            "version": 1,
            "type": "nexum.challenge",
            "purpose": "login",
            "challengeId": "ch_test",
            "nonce": "abc",
            "issuedAt": "2020-01-01T00:00:00Z",
            "expiresAt": "2020-01-01T00:01:00Z",
            "origin": "https://example.com"
        }
        """
        XCTAssertThrowsError(try ChallengeParser.parse(qrContent: json)) { error in
            guard let parserError = error as? ChallengeParserError,
                  case .challengeExpired = parserError else {
                XCTFail("Expected challengeExpired error")
                return
            }
        }
    }
    
    func testInsecureOrigin() {
        let json = """
        {
            "version": 1,
            "type": "nexum.challenge",
            "purpose": "login",
            "challengeId": "ch_test",
            "nonce": "abc",
            "issuedAt": "2026-06-17T10:30:00Z",
            "expiresAt": "2099-12-31T23:59:59Z",
            "origin": "http://example.com"
        }
        """
        XCTAssertThrowsError(try ChallengeParser.parse(qrContent: json)) { error in
            guard let parserError = error as? ChallengeParserError,
                  case .insecureOrigin = parserError else {
                XCTFail("Expected insecureOrigin error")
                return
            }
        }
    }
    
    func testInvalidTimeRange() {
        let json = """
        {
            "version": 1,
            "type": "nexum.challenge",
            "purpose": "login",
            "challengeId": "ch_test",
            "nonce": "abc",
            "issuedAt": "2026-06-17T10:35:00Z",
            "expiresAt": "2026-06-17T10:30:00Z",
            "origin": "https://example.com"
        }
        """
        XCTAssertThrowsError(try ChallengeParser.parse(qrContent: json)) { error in
            guard let parserError = error as? ChallengeParserError,
                  case .invalidTimeRange = parserError else {
                XCTFail("Expected invalidTimeRange error")
                return
            }
        }
    }
    
    func testMissingNonce() {
        let json = """
        {
            "version": 1,
            "type": "nexum.challenge",
            "purpose": "login",
            "challengeId": "ch_test",
            "nonce": "",
            "issuedAt": "2026-06-17T10:30:00Z",
            "expiresAt": "2026-06-17T10:35:00Z",
            "origin": "https://example.com"
        }
        """
        XCTAssertThrowsError(try ChallengeParser.parse(qrContent: json)) { error in
            guard let parserError = error as? ChallengeParserError,
                  case .missingNonce = parserError else {
                XCTFail("Expected missingNonce error")
                return
            }
        }
    }
    
    func testAllPurposes() throws {
        for purpose in ["login", "checkout", "escrow", "message"] {
            let json = """
            {
                "version": 1,
                "type": "nexum.challenge",
                "purpose": "\(purpose)",
                "challengeId": "ch_test_\(purpose)",
                "nonce": "dGVzdA",
                "issuedAt": "2026-06-17T10:30:00Z",
                "expiresAt": "2099-12-31T23:59:59Z",
                "origin": "https://example.com"
            }
            """
            let challenge = try ChallengeParser.parse(qrContent: json)
            XCTAssertEqual(challenge.purpose.rawValue, purpose)
        }
    }
    
    func testChallengeWithDisplay() throws {
        let json = """
        {
            "version": 1,
            "type": "nexum.challenge",
            "purpose": "checkout",
            "challengeId": "ch_checkout_001",
            "nonce": "dGVzdG5vbmNl",
            "issuedAt": "2026-06-17T10:30:00Z",
            "expiresAt": "2099-12-31T23:59:59Z",
            "origin": "https://igrowpro.pl",
            "display": {
                "title": "Complete Purchase",
                "description": "Pay for order #12345",
                "amount": "0.5 XMR",
                "counterparty": "iGrowPro Shop"
            }
        }
        """
        let challenge = try ChallengeParser.parse(qrContent: json)
        XCTAssertEqual(challenge.display?.title, "Complete Purchase")
        XCTAssertEqual(challenge.display?.amount, "0.5 XMR")
        XCTAssertEqual(challenge.display?.counterparty, "iGrowPro Shop")
    }
}
