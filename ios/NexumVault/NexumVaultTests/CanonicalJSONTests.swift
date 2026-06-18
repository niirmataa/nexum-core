import XCTest
@testable import NexumVault

final class CanonicalJSONTests: XCTestCase {
    
    func testStableKeyOrder() throws {
        let input = """
        {"z": 1, "a": 2, "m": 3}
        """
        let result = try CanonicalJSON.canonicalize(input)
        XCTAssertEqual(result, "{\"a\":2,\"m\":3,\"z\":1}")
    }
    
    func testNestedKeyOrder() throws {
        let input = """
        {"b": {"z": 1, "a": 2}, "a": 1}
        """
        let result = try CanonicalJSON.canonicalize(input)
        XCTAssertEqual(result, "{\"a\":1,\"b\":{\"a\":2,\"z\":1}}")
    }
    
    func testArrayPreservesOrder() throws {
        let input = """
        {"items": [3, 1, 2]}
        """
        let result = try CanonicalJSON.canonicalize(input)
        XCTAssertEqual(result, "{\"items\":[3,1,2]}")
    }
    
    func testNoWhitespace() throws {
        let input = """
        { "a" : 1 , "b" : 2 }
        """
        let result = try CanonicalJSON.canonicalize(input)
        XCTAssertEqual(result, "{\"a\":1,\"b\":2}")
    }
    
    func testDeterministic() throws {
        let input = """
        {"challengeId": "ch_test", "nonce": "abc123", "origin": "https://example.com", "version": 1}
        """
        let result1 = try CanonicalJSON.canonicalize(input)
        let result2 = try CanonicalJSON.canonicalize(input)
        XCTAssertEqual(result1, result2)
    }
    
    func testChallengeCanonicalForm() throws {
        let input = """
        {
            "version": 1,
            "type": "nexum.challenge",
            "purpose": "login",
            "challengeId": "ch_01TEST123",
            "nonce": "dGVzdG5vbmNl",
            "issuedAt": "2026-06-17T10:30:00Z",
            "expiresAt": "2026-06-17T10:35:00Z",
            "origin": "https://igrowpro.pl"
        }
        """
        let result = try CanonicalJSON.canonicalize(input)
        
        // Keys should be sorted: challengeId, expiresAt, issuedAt, nonce, origin, purpose, type, version
        XCTAssertTrue(result.hasPrefix("{\"challengeId\":"))
        XCTAssertTrue(result.contains("\"version\":1"))
        // No whitespace
        XCTAssertFalse(result.contains(" "))
    }
    
    func testStringValues() throws {
        let input = """
        {"name": "Alice", "amount": "0.5 XMR"}
        """
        let result = try CanonicalJSON.canonicalize(input)
        XCTAssertEqual(result, "{\"amount\":\"0.5 XMR\",\"name\":\"Alice\"}")
    }
    
    func testNullValues() throws {
        let input = """
        {"a": null, "b": "test"}
        """
        let result = try CanonicalJSON.canonicalize(input)
        XCTAssertEqual(result, "{\"a\":null,\"b\":\"test\"}")
    }
}
