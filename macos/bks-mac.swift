// bks-mac: the macOS-only parts of bks. bks runs it as a child process.
//
//   bks-mac enroll          stdin: unlock secret (hex)  stdout: {"key":…,"sealed":…}
//   bks-mac unseal          stdin: {"key":…,"sealed":…} stdout: unlock secret (hex)   [Touch ID]
//   bks-mac watch           stdout: "ready", then one event per line; exits on stdin EOF
//   bks-mac copy            stdin: text                 stdout: pasteboard changeCount
//   bks-mac clear-if <n>    clears the pasteboard if its changeCount is still n
//   bks-mac version
//
// Exit codes: 0 ok, 1 error, 2 cancelled, 3 user chose the GPG fallback,
// 4 Touch ID unavailable or changed (re-enrol needed).
//
// The Secure Enclave key needs Touch ID with the fingerprints enrolled at
// creation (.biometryCurrentSet) and only works while the Mac is unlocked.
// Its blob is useless on any other Mac. Sealing is ECIES: ephemeral P-256
// ECDH with the enclave key, HKDF-SHA256, AES-GCM.

import AppKit
import CryptoKit
import Foundation
import LocalAuthentication

let version = "bks-mac 1"
let hkdfInfo = Data("bks-touchid-v1".utf8)
// Fixed here, never taken from arguments: whoever runs this helper cannot
// make the Touch ID dialog say something else.
let touchIDReason = "unlock your bks password vault"

func fail(_ code: Int32, _ message: String) -> Never {
    FileHandle.standardError.write(Data(("bks-mac: " + message + "\n").utf8))
    exit(code)
}

func readStdin() -> Data { FileHandle.standardInput.readDataToEndOfFile() }

func hexDecode(_ s: String) -> Data? {
    let t = s.trimmingCharacters(in: .whitespacesAndNewlines)
    guard t.count % 2 == 0 else { return nil }
    var out = Data(capacity: t.count / 2)
    var i = t.startIndex
    while i < t.endIndex {
        let j = t.index(i, offsetBy: 2)
        guard let b = UInt8(t[i..<j], radix: 16) else { return nil }
        out.append(b)
        i = j
    }
    return out
}

func hexEncode(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }

func kek(_ shared: SharedSecret) -> SymmetricKey {
    shared.hkdfDerivedSymmetricKey(using: SHA256.self, salt: Data(), sharedInfo: hkdfInfo, outputByteCount: 32)
}

struct Blob: Codable {
    let key: String     // base64 Secure Enclave key (dataRepresentation)
    let sealed: String  // base64 ephemeral public key (65) || AES-GCM combined box
}

func enroll() {
    guard SecureEnclave.isAvailable else { fail(4, "this Mac has no Secure Enclave") }
    guard let secret = String(data: readStdin(), encoding: .utf8).flatMap(hexDecode), !secret.isEmpty else {
        fail(1, "expected the unlock secret as hex on stdin")
    }
    var err: Unmanaged<CFError>?
    guard let access = SecAccessControlCreateWithFlags(
        nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage, .biometryCurrentSet], &err)
    else { fail(1, "access control: \(err!.takeRetainedValue())") }
    do {
        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access)
        let eph = P256.KeyAgreement.PrivateKey()
        let box = try AES.GCM.seal(secret, using: kek(try eph.sharedSecretFromKeyAgreement(with: key.publicKey)))
        let blob = Blob(key: key.dataRepresentation.base64EncodedString(),
                        sealed: (eph.publicKey.x963Representation + box.combined!).base64EncodedString())
        FileHandle.standardOutput.write(try JSONEncoder().encode(blob))
    } catch {
        fail(4, "creating the Secure Enclave key failed: \(error)")
    }
}

func unseal() {
    guard let blob = try? JSONDecoder().decode(Blob.self, from: readStdin()),
          let keyData = Data(base64Encoded: blob.key), let sealed = Data(base64Encoded: blob.sealed),
          sealed.count > 65
    else { fail(1, "expected {\"key\":…,\"sealed\":…} on stdin") }

    // Ask for Touch ID explicitly first: it gives clear answers (cancel,
    // fallback, lockout), and the evaluated context then unlocks the key
    // without a second prompt.
    //
    // Security: this result only picks the message. The secret is released
    // by the Secure Enclave key below, whose access control
    // (.biometryCurrentSet) the Secure Enclave enforces itself. A hooked or
    // faked evaluatePolicy yields an unauthenticated context, and the key
    // operation then fails or asks again. (Snyk's "Device Authentication
    // Bypass" for evaluatePolicy does not apply: the gate is the key, not
    // this boolean.)
    let ctx = LAContext()
    ctx.localizedFallbackTitle = "Use GPG passphrase"
    var policyErr: NSError?
    guard ctx.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &policyErr) else {
        fail(4, "Touch ID is not available: \(policyErr?.localizedDescription ?? "unknown")")
    }
    let done = DispatchSemaphore(value: 0)
    var authError: Error?
    ctx.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: touchIDReason) { ok, error in
        if !ok { authError = error ?? NSError(domain: "bks", code: -1) }
        done.signal()
    }
    done.wait()
    if let e = authError as? LAError {
        switch e.code {
        case .userCancel, .systemCancel, .appCancel: fail(2, "cancelled")
        case .userFallback: fail(3, "GPG fallback chosen")
        case .biometryLockout, .biometryNotEnrolled, .biometryNotAvailable: fail(4, e.localizedDescription)
        default: fail(1, e.localizedDescription)
        }
    } else if let e = authError {
        fail(1, "\(e)")
    }

    do {
        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: keyData, authenticationContext: ctx)
        let eph = try P256.KeyAgreement.PublicKey(x963Representation: sealed.prefix(65))
        let box = try AES.GCM.SealedBox(combined: sealed.dropFirst(65))
        let secret = try AES.GCM.open(box, using: kek(try key.sharedSecretFromKeyAgreement(with: eph)))
        print(hexEncode(secret))
    } catch {
        // With .biometryCurrentSet the key stops working once fingerprints change.
        fail(4, "the Touch ID key no longer works (fingerprints changed?): \(error)")
    }
}

func watch() {
    func emit(_ event: String) {
        print(event)
        fflush(stdout)
    }
    let dnc = DistributedNotificationCenter.default()
    for (name, event) in [("com.apple.screenIsLocked", "locked"), ("com.apple.screensaver.didstart", "screensaver")] {
        dnc.addObserver(forName: Notification.Name(name), object: nil, queue: .main) { _ in emit(event) }
    }
    let ws = NSWorkspace.shared.notificationCenter
    for (name, event) in [(NSWorkspace.willSleepNotification, "sleep"),
                          (NSWorkspace.screensDidSleepNotification, "display-sleep"),
                          (NSWorkspace.sessionDidResignActiveNotification, "switch")] {
        ws.addObserver(forName: name, object: nil, queue: .main) { _ in emit(event) }
    }
    // bks holds our stdin; when it exits or re-execs, stdin ends and so do we.
    Thread.detachNewThread {
        while readLine() != nil {}
        exit(0)
    }
    emit("ready")
    RunLoop.main.run()
}

let concealed = NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType")
let transient = NSPasteboard.PasteboardType("org.nspasteboard.TransientType")

// BKS_PASTEBOARD names a private pasteboard for tests, so they never touch
// the real clipboard.
func pasteboard() -> NSPasteboard {
    if let name = ProcessInfo.processInfo.environment["BKS_PASTEBOARD"], !name.isEmpty {
        return NSPasteboard(name: NSPasteboard.Name(name))
    }
    return NSPasteboard.general
}

func copyToPasteboard() {
    guard let text = String(data: readStdin(), encoding: .utf8) else { fail(1, "stdin is not UTF-8") }
    let pb = pasteboard()
    // This Mac only: no Universal Clipboard to iPhone or other Macs.
    pb.prepareForNewContents(with: .currentHostOnly)
    guard pb.setString(text, forType: .string) else { fail(1, "could not write the pasteboard") }
    // nspasteboard.org markers: clipboard-history tools skip these.
    pb.setData(Data(), forType: concealed)
    pb.setData(Data(), forType: transient)
    // Refuse to report success unless the markers really are there.
    guard let types = pb.types, types.contains(concealed), types.contains(transient) else {
        pb.clearContents()
        fail(1, "the pasteboard dropped the concealed/transient markers; copy withdrawn")
    }
    print(pb.changeCount)
}

func clearIf(_ arg: String) {
    guard let n = Int(arg) else { fail(1, "usage: bks-mac clear-if <changeCount>") }
    let pb = pasteboard()
    if pb.changeCount == n { // still ours: nothing new was copied since
        pb.clearContents()
    }
}

let args = CommandLine.arguments
switch args.count > 1 ? args[1] : "" {
case "enroll": enroll()
case "unseal": unseal()
case "watch": watch()
case "copy": copyToPasteboard()
case "clear-if" where args.count == 3: clearIf(args[2])
case "types": print((pasteboard().types ?? []).map(\.rawValue).joined(separator: "\n"))  // type names only, never contents
case "version": print(version)
default: fail(1, "usage: bks-mac enroll|unseal|watch|copy|clear-if <n>|types|version")
}
