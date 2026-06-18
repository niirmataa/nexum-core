import Foundation
import Security
import CryptoKit

final class CallbackClient: NSObject, URLSessionDelegate {
    private lazy var session: URLSession = {
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 30
        config.timeoutIntervalForResource = 60
        config.waitsForConnectivity = true
        return URLSession(configuration: config, delegate: self, delegateQueue: nil)
    }()
    
    private let pinnedHosts: Set<String>
    private let pinnedHashes: [String: [String]]
    
    init(pinnedHosts: Set<String> = [], pinnedHashes: [String: [String]] = [:]) {
        self.pinnedHosts = pinnedHosts
        self.pinnedHashes = pinnedHashes
        super.init()
    }
    
    func sendResponse(_ response: NexumResponse, to callbackUrl: String) async throws -> CallbackResult {
        guard let url = URL(string: callbackUrl), url.scheme == "https" else {
            throw CallbackError.invalidUrl(callbackUrl)
        }
        
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        let body = try encoder.encode(response)
        
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("NexumVault/1.0 iOS", forHTTPHeaderField: "User-Agent")
        request.timeoutInterval = 30
        request.httpBody = body
        
        let (data, httpResponse) = try await session.data(for: request)
        let statusCode = (httpResponse as? HTTPURLResponse)?.statusCode ?? 0
        let responseBody = String(data: data, encoding: .utf8) ?? ""
        
        return CallbackResult(
            success: (200...299).contains(statusCode),
            statusCode: statusCode,
            responseBody: responseBody
        )
    }
    
    // MARK: - Certificate Pinning
    
    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let trust = challenge.protectionSpace.serverTrust else {
            completionHandler(.performDefaultHandling, nil)
            return
        }
        
        let host = challenge.protectionSpace.host
        
        guard pinnedHosts.contains(host) else {
            completionHandler(.performDefaultHandling, nil)
            return
        }
        
        var error: CFError?
        guard SecTrustEvaluateWithError(trust, &error) else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        
        guard let serverCert = SecTrustGetCertificateAtIndex(trust, 0),
              let serverCertData = SecCertificateCopyData(serverCert) as Data? else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        
        let serverHash = SHA256.hash(data: serverCertData)
        let serverHashB64 = Data(serverHash).base64EncodedString()
        
        if let pinned = pinnedHashes[host], pinned.contains(serverHashB64) {
            completionHandler(.useCredential, URLCredential(trust: trust))
        } else if pinnedHashes[host] == nil {
            completionHandler(.useCredential, URLCredential(trust: trust))
        } else {
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }
}

struct CallbackResult {
    let success: Bool
    let statusCode: Int
    let responseBody: String
}

enum CallbackError: Error, LocalizedError {
    case invalidUrl(String)
    case networkError(String)
    case pinningFailure
    
    var errorDescription: String? {
        switch self {
        case .invalidUrl(let url): return "Invalid callback URL (must be HTTPS): \(url)"
        case .networkError(let msg): return "Network error: \(msg)"
        case .pinningFailure: return "Certificate pinning validation failed"
        }
    }
}
