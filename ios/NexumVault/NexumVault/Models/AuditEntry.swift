import Foundation

struct AuditEntry: Codable, Identifiable {
    let id: UUID
    let signedAt: Date
    let purpose: String
    let origin: String
    let challengeId: String
    let keyId: String
    let status: AuditStatus
    let deviceName: String
    
    init(
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

enum AuditStatus: String, Codable {
    case signed
    case rejected
    case expired
    case callbackSuccess = "callback_success"
    case callbackFailed = "callback_failed"
    case qrDisplayed = "qr_displayed"
}

struct VaultBackup: Codable {
    let version: Int
    let exportedAt: Date
    let keys: [VaultKey]
    let auditLog: [AuditEntry]
}
