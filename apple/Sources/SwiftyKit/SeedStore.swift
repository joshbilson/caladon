import Foundation

#if canImport(Security)
import Security
#endif

/// Persistence for the 256-bit seed (identity-envelope.md §2). The seed is the user's only
/// key, so storage is device-only and never synced.
public protocol SeedStore: Sendable {
    func save(_ seed: Data) throws
    func load() throws -> Data?
    func deleteSeed() throws
}

public enum SeedStoreError: Error, Equatable {
    case unexpectedStatus(Int32)
    case badSeedLength
}

#if canImport(Security)
/// Keychain-backed seed storage. Stored with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`
/// → NOT synced to iCloud and excluded from encrypted device backups, so the seed never
/// leaves the device (identity-envelope §2).
///
/// NOTE (honest scope): the Secure Enclave cannot hold an arbitrary 32-byte secret directly
/// (it stores P-256 keys), so true SE *wrapping* of the seed (an SE key encrypting it) is a
/// documented follow-up. This baseline already gives device-only, non-synced, backup-excluded
/// storage — the §2 storage requirements minus the SE wrap.
public struct KeychainSeedStore: SeedStore {
    let service: String
    let account: String

    public init(service: String = "com.swifty.seed", account: String = "primary") {
        self.service = service
        self.account = account
    }

    private func baseQuery() -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: service,
         kSecAttrAccount as String: account]
    }

    public func save(_ seed: Data) throws {
        guard seed.count == Seed.byteCount else { throw SeedStoreError.badSeedLength }
        SecItemDelete(baseQuery() as CFDictionary)  // overwrite (idempotent)
        var add = baseQuery()
        add[kSecValueData as String] = seed
        add[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        let status = SecItemAdd(add as CFDictionary, nil)
        guard status == errSecSuccess else { throw SeedStoreError.unexpectedStatus(status) }
    }

    public func load() throws -> Data? {
        var q = baseQuery()
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var out: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &out)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = out as? Data else {
            throw SeedStoreError.unexpectedStatus(status)
        }
        return data
    }

    public func deleteSeed() throws {
        let status = SecItemDelete(baseQuery() as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw SeedStoreError.unexpectedStatus(status)
        }
    }
}
#endif

/// In-memory store for tests/previews ONLY — no persistence across launches.
public final class InMemorySeedStore: SeedStore, @unchecked Sendable {
    private var seed: Data?
    private let lock = NSLock()
    public init() {}
    public func save(_ seed: Data) throws {
        guard seed.count == Seed.byteCount else { throw SeedStoreError.badSeedLength }
        lock.lock(); defer { lock.unlock() }
        self.seed = seed
    }
    public func load() throws -> Data? { lock.lock(); defer { lock.unlock() }; return seed }
    public func deleteSeed() throws { lock.lock(); defer { lock.unlock() }; seed = nil }
}
