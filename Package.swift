// swift-tools-version:5.0
// Adapted from https://github.com/IBM-Swift/Kitura-CredentialsGoogle

import PackageDescription

let package = Package(
    name: "CredentialsMicrosoft",
    products: [
        // Products define the executables and libraries produced by a package, and make them visible to other packages.
        .library(
            name: "CredentialsMicrosoft",
            targets: ["CredentialsMicrosoft"]),
    ],
    dependencies: [
        .package(url: "https://github.com/IBM-Swift/Kitura-Credentials.git", .upToNextMajor(from: "2.4.1"))
    ],
    targets: [
        // Targets are the basic building blocks of a package. A target can define a module or a test suite.
        // Targets can depend on other targets in this package, and on products in packages which this package depends on.
        .target(
            name: "CredentialsMicrosoft",
            dependencies: ["Credentials"]),
        .testTarget(
            name: "CredentialsMicrosoftTests",
            dependencies: ["CredentialsMicrosoft"]),
    ]
)
