import Foundation

public struct AuditEntry: Codable, Identifiable, Sendable {
    public let id: UUID
    public let signedAt: Date
    public let purpose: String
    public let origin: String
    public let challengeId: String
    public let keyId: String
    public let status: AuditStatus
    public let deviceName: String
    
    public init(
        id: UUID = UUID(),
        signedAt: Date = Date(),
        purpose: String,
        origin: String,
        challengeId: String,
        keyId: String,
        status: AuditStatus,
        deviceName: String
    ) {
        self.id = id
        self.signedAt = signedAt
        self.purpose = purpose
        self.origin = origin
        self.challengeId = challengeId
        self.keyId = keyId
        self.status = status
        self.deviceName = deviceName
    }
}

public enum AuditStatus: String, Codable, Sendable {
    case signed
    case rejected
    case expired
    case callbackSuccess = "callback_success"
    case callbackFailed = "callback_failed"
    case qrDisplayed = "qr_displayed"
}

public struct VaultBackup: Codable, Sendable {
    public let version: Int
    public let exportedAt: Date
    public let keys: [VaultKey]
    public let auditLog: [AuditEntry]
    
    public init(version: Int, exportedAt: Date, keys: [VaultKey], auditLog: [AuditEntry]) {
        self.version = version
        self.exportedAt = exportedAt
        self.keys = keys
        self.auditLog = auditLog
    }
}
