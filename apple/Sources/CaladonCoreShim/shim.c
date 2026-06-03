// Intentionally empty. This target only vends the caladon_coreFFI C module (header +
// modulemap); the symbols are provided by the CaladonCoreFFI.xcframework static archive,
// linked via the binaryTarget. Keeping the modulemap here (not in the xcframework) avoids the
// two-static-xcframework `include/module.modulemap` collision under xcodebuild.
