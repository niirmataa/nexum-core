import AVFoundation
import SwiftUI

final class QRScanner: NSObject, ObservableObject {
    @Published var scannedCode: String?
    @Published var isScanning = false
    @Published var permissionDenied = false
    
    var session: AVCaptureSession?
    
    func requestPermissionAndStart() {
        switch AVCaptureDevice.authorizationStatus(for: .video) {
        case .authorized:
            startScanning()
        case .notDetermined:
            AVCaptureDevice.requestAccess(for: .video) { [weak self] granted in
                DispatchQueue.main.async {
                    if granted {
                        self?.startScanning()
                    } else {
                        self?.permissionDenied = true
                    }
                }
            }
        case .denied, .restricted:
            permissionDenied = true
        @unknown default:
            break
        }
    }
    
    func startScanning() {
        let session = AVCaptureSession()
        
        guard let device = AVCaptureDevice.default(for: .video),
              let input = try? AVCaptureDeviceInput(device: device) else {
            return
        }
        
        guard session.canAddInput(input) else { return }
        session.addInput(input)
        
        let output = AVCaptureMetadataOutput()
        guard session.canAddOutput(output) else { return }
        session.addOutput(output)
        
        output.setMetadataObjectsDelegate(self, queue: .main)
        output.metadataObjectTypes = [.qr]
        
        self.session = session
        
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            session.startRunning()
            DispatchQueue.main.async {
                self?.isScanning = true
            }
        }
    }
    
    func stopScanning() {
        session?.stopRunning()
        session = nil
        isScanning = false
    }
}

extension QRScanner: AVCaptureMetadataOutputObjectsDelegate {
    func metadataOutput(
        _ output: AVCaptureMetadataOutput,
        didOutput metadataObjects: [AVMetadataObject],
        from connection: AVCaptureConnection
    ) {
        guard let object = metadataObjects.first as? AVMetadataMachineReadableCodeObject,
              object.type == .qr,
              let value = object.stringValue else { return }
        
        scannedCode = value
        stopScanning()
    }
}

struct ScannerView: UIViewRepresentable {
    @ObservedObject var scanner: QRScanner
    
    func makeUIView(context: Context) -> PreviewUIView {
        let view = PreviewUIView()
        view.backgroundColor = .black
        return view
    }
    
    func updateUIView(_ uiView: PreviewUIView, context: Context) {
        if let session = scanner.session,
           uiView.previewLayer.session !== session {
            uiView.previewLayer.session = session
        }
        DispatchQueue.main.async {
            uiView.previewLayer.frame = uiView.bounds
        }
    }
}

final class PreviewUIView: UIView {
    override class var layerClass: AnyClass {
        AVCaptureVideoPreviewLayer.self
    }
    
    var previewLayer: AVCaptureVideoPreviewLayer {
        layer as! AVCaptureVideoPreviewLayer
    }
    
    override func layoutSubviews() {
        super.layoutSubviews()
        previewLayer.frame = bounds
    }
}
