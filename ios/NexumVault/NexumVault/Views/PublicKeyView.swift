import SwiftUI
import CoreImage.CIFilterBuiltins

struct PublicKeyView: View {
    let key: VaultKey
    @State private var showQR = false
    @State private var copied = false
    
    var body: some View {
        List {
            Section("Key Information") {
                LabeledContent("Key ID", value: key.keyId)
                LabeledContent("Algorithm", value: key.algorithm)
                LabeledContent("Device", value: key.deviceName)
                LabeledContent("Created", value: key.createdAt.formatted(date: .long, time: .shortened))
            }
            
            Section("Public Key") {
                Text(key.publicKeyBase64url)
                    .font(.system(.caption, design: .monospaced))
                    .textSelection(.enabled)
                
                Button(action: {
                    UIPasteboard.general.string = key.publicKeyBase64url
                    copied = true
                    DispatchQueue.main.asyncAfter(deadline: .now() + 2) {
                        copied = false
                    }
                }) {
                    Label(copied ? "Copied!" : "Copy Public Key", systemImage: copied ? "checkmark" : "doc.on.doc")
                }
            }
            
            Section("Registration QR") {
                Button(action: { showQR.toggle() }) {
                    Label(showQR ? "Hide QR" : "Show QR for Registration", systemImage: "qrcode")
                }
                
                if showQR {
                    VStack(spacing: 12) {
                        QRCodeView(data: registrationQRData())
                            .frame(width: 200, height: 200)
                            .padding(.vertical, 8)
                        
                        Text("Scan this QR in the storefront to register your public key")
                            .font(.caption)
                            .foregroundColor(.secondary)
                            .multilineTextAlignment(.center)
                    }
                }
            }
            
            Section("Security") {
                Label("Private key encrypted in Keychain", systemImage: "lock.shield.fill")
                Label("Protected by Face ID / Touch ID", systemImage: "faceid")
                Label("Never leaves this device", systemImage: "iphone")
            }
        }
        .navigationTitle("Public Key")
    }
    
    private func registrationQRData() -> String {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        let payload: [String: Any] = [
            "version": 1,
            "type": "nexum.publickey",
            "keyId": key.keyId,
            "algorithm": key.algorithm,
            "publicKey": key.publicKeyBase64url,
            "device": key.deviceName,
            "registeredAt": formatter.string(from: key.createdAt)
        ]
        guard let data = try? JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys]),
              let string = String(data: data, encoding: .utf8) else {
            return "{}"
        }
        return string
    }
}

struct QRCodeView: View {
    let data: String
    
    var body: some View {
        if let image = generateQRCode(from: data) {
            Image(uiImage: image)
                .interpolation(.none)
                .resizable()
        } else {
            Image(systemName: "xmark.qrcode")
                .foregroundColor(.secondary)
        }
    }
    
    private func generateQRCode(from string: String) -> UIImage? {
        let context = CIContext()
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(string.utf8)
        filter.correctionLevel = "H"
        
        guard let output = filter.outputImage else { return nil }
        
        let transform = CGAffineTransform(scaleX: 10, y: 10)
        let scaled = output.transformed(by: transform)
        
        guard let cgImage = context.createCGImage(scaled, from: scaled.extent) else { return nil }
        return UIImage(cgImage: cgImage)
    }
}
