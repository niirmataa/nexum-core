import Foundation

final class AuditLogStore: ObservableObject {
    @Published var entries: [AuditEntry] = []
    
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()
    private let storageKey = "nexum_audit_log"
    private let maxEntries = 1000
    
    init() {
        encoder.dateEncodingStrategy = .iso8601
        decoder.dateDecodingStrategy = .iso8601
        load()
    }
    
    func log(
        purpose: String,
        origin: String,
        challengeId: String,
        keyId: String,
        status: AuditStatus,
        deviceName: String
    ) {
        let entry = AuditEntry(
            purpose: purpose,
            origin: origin,
            challengeId: challengeId,
            keyId: keyId,
            status: status,
            deviceName: deviceName
        )
        
        entries.insert(entry, at: 0)
        
        if entries.count > maxEntries {
            entries = Array(entries.prefix(maxEntries))
        }
        
        save()
    }
    
    func entries(for keyId: String) -> [AuditEntry] {
        entries.filter { $0.keyId == keyId }
    }
    
    func clear() {
        entries.removeAll()
        save()
    }
    
    func exportData() throws -> Data {
        try encoder.encode(entries)
    }
    
    private func save() {
        guard let data = try? encoder.encode(entries) else { return }
        UserDefaults.standard.set(data, forKey: storageKey)
    }
    
    private func load() {
        guard let data = UserDefaults.standard.data(forKey: storageKey),
              let decoded = try? decoder.decode([AuditEntry].self, from: data) else { return }
        entries = decoded
    }
}
