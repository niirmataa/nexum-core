import LocalAuthentication
import SwiftUI

final class BiometricAuth: ObservableObject {
    @Published var isSupported = false
    @Published var biometricType: BiometricType = .none
    
    enum BiometricType {
        case none
        case faceID
        case touchID
    }
    
    init() {
        checkSupport()
    }
    
    func checkSupport() {
        let context = LAContext()
        var error: NSError?
        
        if context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) {
            isSupported = true
            switch context.biometryType {
            case .faceID:
                biometricType = .faceID
            case .touchID:
                biometricType = .touchID
            default:
                biometricType = .none
            }
        } else {
            isSupported = false
            biometricType = .none
        }
    }
    
    func authenticate(reason: String) async throws -> Bool {
        let context = LAContext()
        context.localizedCancelTitle = "Cancel"
        
        return try await context.evaluatePolicy(
            .deviceOwnerAuthenticationWithBiometrics,
            localizedReason: reason
        )
    }
    
    func authenticateWithPasscode(reason: String) async throws -> Bool {
        let context = LAContext()
        context.localizedCancelTitle = "Cancel"
        
        return try await context.evaluatePolicy(
            .deviceOwnerAuthentication,
            localizedReason: reason
        )
    }
}
