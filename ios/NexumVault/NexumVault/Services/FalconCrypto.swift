import Foundation
import Security

protocol FalconCryptoProtocol {
    func generateKeyPair(logn: UInt) throws -> FalconKeyPair
    func sign(message: Data, privateKey: Data) throws -> FalconSignature
    func verify(message: Data, signature: Data, nonce: Data, publicKey: Data) throws -> Bool
}

struct FalconKeyPair {
    let publicKey: Data
    let privateKey: Data
    let algorithm: String
    
    var publicKeyBase64url: String {
        publicKey.base64urlEncodedString
    }
}

struct FalconSignature {
    let signature: Data
    let nonce: Data
    
    var signatureBase64url: String {
        signature.base64urlEncodedString
    }
    
    var nonceBase64url: String {
        nonce.base64urlEncodedString
    }
}

final class FalconCrypto: FalconCryptoProtocol {
    
    private let bridge: FalconBridgeProtocol
    
    init(bridge: FalconBridgeProtocol = FalconBridgeNative()) {
        self.bridge = bridge
    }
    
    func generateKeyPair(logn: UInt = 10) throws -> FalconKeyPair {
        guard logn >= 1 && logn <= 10 else {
            throw FalconError.invalidParameter("logn must be 1-10")
        }
        
        let result = try bridge.keygen(logn: logn, compression: Int32(FALCON_COMP_NONE))
        
        guard !result.publicKey.isEmpty, !result.privateKey.isEmpty else {
            throw FalconError.keyGenerationFailed
        }
        
        return FalconKeyPair(
            publicKey: result.publicKey,
            privateKey: result.privateKey,
            algorithm: "Falcon-\(1 << logn)"
        )
    }
    
    func sign(message: Data, privateKey: Data) throws -> FalconSignature {
        guard !privateKey.isEmpty else {
            throw FalconError.noPrivateKey
        }
        
        let result = try bridge.sign(
            message: message,
            privateKey: privateKey,
            compression: Int32(FALCON_COMP_NONE)
        )
        
        guard !result.signature.isEmpty, result.nonce.count == 40 else {
            throw FalconError.signingFailed
        }
        
        return FalconSignature(
            signature: result.signature,
            nonce: result.nonce
        )
    }
    
    func verify(message: Data, signature: Data, nonce: Data, publicKey: Data) throws -> Bool {
        guard !publicKey.isEmpty else {
            throw FalconError.noPublicKey
        }
        guard !signature.isEmpty else {
            throw FalconError.noSignature
        }
        guard nonce.count == 40 else {
            throw FalconError.invalidNonce
        }
        
        return try bridge.verify(
            message: message,
            signature: signature,
            nonce: nonce,
            publicKey: publicKey
        )
    }
}

enum FalconError: Error, LocalizedError {
    case invalidParameter(String)
    case keyGenerationFailed
    case noPrivateKey
    case noPublicKey
    case noSignature
    case invalidNonce
    case signingFailed
    case verificationFailed
    case bridgeError(String)
    
    var errorDescription: String? {
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

// MARK: - Bridge Protocol

protocol FalconBridgeProtocol {
    func keygen(logn: UInt, compression: Int32) throws -> (publicKey: Data, privateKey: Data)
    func sign(message: Data, privateKey: Data, compression: Int32) throws -> (signature: Data, nonce: Data)
    func verify(message: Data, signature: Data, nonce: Data, publicKey: Data) throws -> Bool
}

// MARK: - Native Bridge (calls into C Falcon via bridging header)

final class FalconBridgeNative: FalconBridgeProtocol {
    
    func keygen(logn: UInt, compression: Int32) throws -> (publicKey: Data, privateKey: Data) {
        guard let fk = falcon_keygen_new(UInt32(logn), 0) else {
            throw FalconError.bridgeError("falcon_keygen_new returned NULL")
        }
        defer { falcon_keygen_free(fk) }
        
        let maxPriv = falcon_keygen_max_privkey_size(fk)
        let maxPub = falcon_keygen_max_pubkey_size(fk)
        
        guard maxPriv > 0, maxPub > 0 else {
            throw FalconError.keyGenerationFailed
        }
        
        var privKey = Data(count: maxPriv)
        var pubKey = Data(count: maxPub)
        var privLen = maxPriv
        var pubLen = maxPub
        
        let ok: Int32 = privKey.withUnsafeMutableBytes { privPtr in
            pubKey.withUnsafeMutableBytes { pubPtr in
                falcon_keygen_make(
                    fk,
                    compression,
                    privPtr.baseAddress!,
                    &privLen,
                    pubPtr.baseAddress!,
                    &pubLen
                )
            }
        }
        
        guard ok == 1 else {
            throw FalconError.keyGenerationFailed
        }
        
        return (
            publicKey: Data(pubKey.prefix(pubLen)),
            privateKey: Data(privKey.prefix(privLen))
        )
    }
    
    func sign(message: Data, privateKey: Data, compression: Int32) throws -> (signature: Data, nonce: Data) {
        guard let fs = falcon_sign_new() else {
            throw FalconError.bridgeError("falcon_sign_new returned NULL")
        }
        defer { falcon_sign_free(fs) }
        
        let setKeyOk: Int32 = privateKey.withUnsafeBytes { ptr in
            falcon_sign_set_private_key(fs, ptr.baseAddress!, privateKey.count)
        }
        guard setKeyOk == 1 else {
            throw FalconError.bridgeError("falcon_sign_set_private_key failed")
        }
        
        var nonce = Data(count: 40)
        let startOk: Int32 = nonce.withUnsafeMutableBytes { ptr in
            falcon_sign_start(fs, ptr.baseAddress!)
        }
        guard startOk == 1 else {
            throw FalconError.bridgeError("falcon_sign_start failed")
        }
        
        message.withUnsafeBytes { ptr in
            falcon_sign_update(fs, ptr.baseAddress!, message.count)
        }
        
        let maxSigLen = 2 * 1024 + 1
        var sig = Data(count: maxSigLen)
        let sigLen: Int = sig.withUnsafeMutableBytes { ptr in
            Int(falcon_sign_generate(fs, ptr.baseAddress!, maxSigLen, compression))
        }
        
        guard sigLen > 0 else {
            throw FalconError.signingFailed
        }
        
        return (
            signature: Data(sig.prefix(sigLen)),
            nonce: nonce
        )
    }
    
    func verify(message: Data, signature: Data, nonce: Data, publicKey: Data) throws -> Bool {
        guard let fv = falcon_vrfy_new() else {
            throw FalconError.bridgeError("falcon_vrfy_new returned NULL")
        }
        defer { falcon_vrfy_free(fv) }
        
        let setKeyOk: Int32 = publicKey.withUnsafeBytes { ptr in
            falcon_vrfy_set_public_key(fv, ptr.baseAddress!, publicKey.count)
        }
        guard setKeyOk == 1 else {
            throw FalconError.bridgeError("falcon_vrfy_set_public_key failed")
        }
        
        nonce.withUnsafeBytes { ptr in
            falcon_vrfy_start(fv, ptr.baseAddress!, nonce.count)
        }
        
        message.withUnsafeBytes { ptr in
            falcon_vrfy_update(fv, ptr.baseAddress!, message.count)
        }
        
        let result: Int32 = signature.withUnsafeBytes { ptr in
            falcon_vrfy_verify(fv, ptr.baseAddress!, signature.count)
        }
        
        switch result {
        case 1: return true
        case 0: return false
        case -1: throw FalconError.bridgeError("Signature decoding error")
        case -2: throw FalconError.bridgeError("Public key was not set")
        default: throw FalconError.bridgeError("Unknown verify result: \(result)")
        }
    }
}

// MARK: - Mock Bridge for Testing

final class FalconBridgeMock: FalconBridgeProtocol {
    var shouldFail = false
    
    func keygen(logn: UInt, compression: Int32) throws -> (publicKey: Data, privateKey: Data) {
        if shouldFail { throw FalconError.keyGenerationFailed }
        let pubSize = 897
        let privSize = 1281
        var pub = Data(count: pubSize)
        var priv = Data(count: privSize)
        for i in 0..<pubSize { pub[i] = UInt8(i % 256) }
        for i in 0..<privSize { priv[i] = UInt8((i &+ 128) % 256) }
        return (publicKey: pub, privateKey: priv)
    }
    
    func sign(message: Data, privateKey: Data, compression: Int32) throws -> (signature: Data, nonce: Data) {
        if shouldFail { throw FalconError.signingFailed }
        var sig = Data(count: 667)
        var nonce = Data(count: 40)
        for i in 0..<667 { sig[i] = UInt8(i % 256) }
        for i in 0..<40 { nonce[i] = UInt8((i &+ 200) % 256) }
        return (signature: sig, nonce: nonce)
    }
    
    func verify(message: Data, signature: Data, nonce: Data, publicKey: Data) throws -> Bool {
        if shouldFail { throw FalconError.verificationFailed }
        return true
    }
}
