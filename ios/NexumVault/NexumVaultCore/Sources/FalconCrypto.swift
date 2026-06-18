import Foundation

public protocol FalconCryptoProtocol {
    func generateKeyPair(logn: UInt) throws -> FalconKeyPair
    func sign(message: Data, privateKey: Data) throws -> FalconSignature
    func verify(message: Data, signature: Data, nonce: Data, publicKey: Data) throws -> Bool
}

public struct FalconKeyPair: Sendable {
    public let publicKey: Data
    public let privateKey: Data
    public let algorithm: String
    
    public init(publicKey: Data, privateKey: Data, algorithm: String) {
        self.publicKey = publicKey
        self.privateKey = privateKey
        self.algorithm = algorithm
    }
    
    public var publicKeyBase64url: String {
        publicKey.base64urlEncodedString
    }
}

public struct FalconSignature: Sendable {
    public let signature: Data
    public let nonce: Data
    
    public init(signature: Data, nonce: Data) {
        self.signature = signature
        self.nonce = nonce
    }
    
    public var signatureBase64url: String {
        signature.base64urlEncodedString
    }
    
    public var nonceBase64url: String {
        nonce.base64urlEncodedString
    }
}

public enum FalconError: Error, LocalizedError {
    case invalidParameter(String)
    case keyGenerationFailed
    case noPrivateKey
    case noPublicKey
    case noSignature
    case invalidNonce
    case signingFailed
    case verificationFailed
    case bridgeError(String)
    
    public var errorDescription: String? {
        switch self {
        case .invalidParameter(let msg): return "Invalid parameter: \(msg)"
        case .keyGenerationFailed: return "Falcon key generation failed"
        case .noPrivateKey: return "No private key provided"
        case .noPublicKey: return "No public key provided"
        case .noSignature: return "No signature provided"
        case .invalidNonce: return "Nonce must be exactly 40 bytes"
        case .signingFailed: return "Falcon signing failed"
        case .verificationFailed: return "Falcon signature verification failed"
        case .bridgeError(let msg): return "Falcon bridge error: \(msg)"
        }
    }
}

public protocol FalconBridgeProtocol {
    func keygen(logn: UInt, compression: Int32) throws -> (publicKey: Data, privateKey: Data)
    func sign(message: Data, privateKey: Data, compression: Int32) throws -> (signature: Data, nonce: Data)
    func verify(message: Data, signature: Data, nonce: Data, publicKey: Data) throws -> Bool
}

public final class FalconBridgeMock: FalconBridgeProtocol {
    public var shouldFail = false
    
    public init() {}
    
    public func keygen(logn: UInt, compression: Int32) throws -> (publicKey: Data, privateKey: Data) {
        if shouldFail { throw FalconError.keyGenerationFailed }
        let pubSize = 897
        let privSize = 1281
        var pub = Data(count: pubSize)
        var priv = Data(count: privSize)
        for i in 0..<pubSize { pub[i] = UInt8(i % 256) }
        for i in 0..<privSize { priv[i] = UInt8((i &+ 128) % 256) }
        return (publicKey: pub, privateKey: priv)
    }
    
    public func sign(message: Data, privateKey: Data, compression: Int32) throws -> (signature: Data, nonce: Data) {
        if shouldFail { throw FalconError.signingFailed }
        var sig = Data(count: 667)
        var nonce = Data(count: 40)
        for i in 0..<667 { sig[i] = UInt8(i % 256) }
        for i in 0..<40 { nonce[i] = UInt8((i &+ 200) % 256) }
        return (signature: sig, nonce: nonce)
    }
    
    public func verify(message: Data, signature: Data, nonce: Data, publicKey: Data) throws -> Bool {
        if shouldFail { throw FalconError.verificationFailed }
        return true
    }
}

public final class FalconCrypto: FalconCryptoProtocol {
    private let bridge: FalconBridgeProtocol
    
    public init(bridge: FalconBridgeProtocol = FalconBridgeMock()) {
        self.bridge = bridge
    }
    
    public func generateKeyPair(logn: UInt = 10) throws -> FalconKeyPair {
        guard logn >= 1 && logn <= 10 else {
            throw FalconError.invalidParameter("logn must be 1-10")
        }
        let result = try bridge.keygen(logn: logn, compression: 0)
        guard !result.publicKey.isEmpty, !result.privateKey.isEmpty else {
            throw FalconError.keyGenerationFailed
        }
        return FalconKeyPair(
            publicKey: result.publicKey,
            privateKey: result.privateKey,
            algorithm: "Falcon-\(1 << logn)"
        )
    }
    
    public func sign(message: Data, privateKey: Data) throws -> FalconSignature {
        guard !privateKey.isEmpty else {
            throw FalconError.noPrivateKey
        }
        let result = try bridge.sign(message: message, privateKey: privateKey, compression: 0)
        guard !result.signature.isEmpty, result.nonce.count == 40 else {
            throw FalconError.signingFailed
        }
        return FalconSignature(signature: result.signature, nonce: result.nonce)
    }
    
    public func verify(message: Data, signature: Data, nonce: Data, publicKey: Data) throws -> Bool {
        guard !publicKey.isEmpty else { throw FalconError.noPublicKey }
        guard !signature.isEmpty else { throw FalconError.noSignature }
        guard nonce.count == 40 else { throw FalconError.invalidNonce }
        return try bridge.verify(message: message, signature: signature, nonce: nonce, publicKey: publicKey)
    }
}
