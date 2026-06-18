import XCTest
@testable import NexumVault

final class SignatureTests: XCTestCase {
    
    private var mockBridge: FalconBridgeMock!
    private var falcon: FalconCrypto!
    
    override func setUp() {
        super.setUp()
        mockBridge = FalconBridgeMock()
        falcon = FalconCrypto(bridge: mockBridge)
    }
    
    func testKeyGeneration() throws {
        let keypair = try falcon.generateKeyPair(logn: 10)
        XCTAssertFalse(keypair.publicKey.isEmpty)
        XCTAssertFalse(keypair.privateKey.isEmpty)
        XCTAssertEqual(keypair.algorithm, "Falcon-1024")
    }
    
    func testKeyGeneration512() throws {
        let keypair = try falcon.generateKeyPair(logn: 9)
        XCTAssertEqual(keypair.algorithm, "Falcon-512")
    }
    
    func testSignAndVerify() throws {
        let keypair = try falcon.generateKeyPair()
        let message = Data("test message for signing".utf8)
        
        let signature = try falcon.sign(message: message, privateKey: keypair.privateKey)
        XCTAssertFalse(signature.signature.isEmpty)
        XCTAssertEqual(signature.nonce.count, 40)
        
        let valid = try falcon.verify(
            message: message,
            signature: signature.signature,
            nonce: signature.nonce,
            publicKey: keypair.publicKey
        )
        XCTAssertTrue(valid)
    }
    
    func testResponseContainsNoPrivateKey() throws {
        let keypair = try falcon.generateKeyPair()
        let message = Data("challenge canonical".utf8)
        let signature = try falcon.sign(message: message, privateKey: keypair.privateKey)
        
        let response = NexumResponse(
            version: 1,
            type: "nexum.response",
            challengeId: "ch_test",
            publicKey: keypair.publicKeyBase64url,
            keyId: "vk_test",
            algorithm: keypair.algorithm,
            signature: signature.signatureBase64url,
            nonce: signature.nonceBase64url,
            signedAt: Date(),
            device: ResponseDevice(name: "Test", platform: "ios")
        )
        
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        let data = try encoder.encode(response)
        let json = String(data: data, encoding: .utf8) ?? ""
        
        XCTAssertFalse(json.lowercased().contains("privatekey"))
        XCTAssertFalse(json.lowercased().contains("private_key"))
    }
    
    func testBase64urlEncoding() {
        let data = Data([0xFF, 0x00, 0xAB, 0xCD])
        let encoded = data.base64urlEncodedString
        XCTAssertFalse(encoded.contains("+"))
        XCTAssertFalse(encoded.contains("/"))
        XCTAssertFalse(encoded.contains("="))
        
        let decoded = Data(base64urlEncoded: encoded)
        XCTAssertEqual(decoded, data)
    }
    
    func testBase64urlRoundtrip() {
        let original = Data((0..<256).map { UInt8($0) })
        let encoded = original.base64urlEncodedString
        let decoded = Data(base64urlEncoded: encoded)
        XCTAssertEqual(decoded, original)
    }
    
    func testInvalidLogn() {
        XCTAssertThrowsError(try falcon.generateKeyPair(logn: 0)) { error in
            guard let fe = error as? FalconError, case .invalidParameter = fe else {
                XCTFail("Expected invalidParameter")
                return
            }
        }
        XCTAssertThrowsError(try falcon.generateKeyPair(logn: 11)) { error in
            guard let fe = error as? FalconError, case .invalidParameter = fe else {
                XCTFail("Expected invalidParameter")
                return
            }
        }
    }
    
    func testNoPrivateKeyThrows() {
        XCTAssertThrowsError(try falcon.sign(message: Data(), privateKey: Data())) { error in
            guard let fe = error as? FalconError, case .noPrivateKey = fe else {
                XCTFail("Expected noPrivateKey")
                return
            }
        }
    }
    
    func testInvalidNonceLength() {
        XCTAssertThrowsError(try falcon.verify(
            message: Data(),
            signature: Data([1]),
            nonce: Data(count: 20),
            publicKey: Data([1])
        )) { error in
            guard let fe = error as? FalconError, case .invalidNonce = fe else {
                XCTFail("Expected invalidNonce")
                return
            }
        }
    }
    
    func testBridgeFailure() {
        mockBridge.shouldFail = true
        XCTAssertThrowsError(try falcon.generateKeyPair())
        XCTAssertThrowsError(try falcon.sign(message: Data(), privateKey: Data([1])))
    }
    
    func testCanonicalJSONInSignaturePayload() throws {
        let dict: [String: Any] = [
            "version": 1,
            "type": "nexum.challenge",
            "purpose": "login",
            "challengeId": "ch_01TEST",
            "nonce": "dGVzdA",
            "issuedAt": "2026-06-17T10:30:00Z",
            "expiresAt": "2026-06-17T10:35:00Z",
            "origin": "https://igrowpro.pl"
        ]
        
        let canonical1 = try CanonicalJSON.canonicalize(dict)
        let canonical2 = try CanonicalJSON.canonicalize(dict)
        XCTAssertEqual(canonical1, canonical2)
        
        let data = Data(canonical1.utf8)
        let parsed = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        let keys = Array(parsed?.keys ?? [])
        XCTAssertEqual(keys, keys.sorted())
    }
}
