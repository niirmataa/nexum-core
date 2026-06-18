// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "NexumVaultCore",
    platforms: [.iOS(.v17), .macOS(.v14)],
    targets: [
        .target(
            name: "NexumVaultCore",
            path: "NexumVaultCore/Sources",
            exclude: ["FalconC"]
        ),
        .testTarget(
            name: "NexumVaultCoreTests",
            dependencies: ["NexumVaultCore"],
            path: "NexumVaultCore/Tests"
        ),
    ]
)
