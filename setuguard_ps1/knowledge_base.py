"""SetuGuard PS1 — static knowledge base for the RAG report stage.

Each chunk paraphrases (in our own words) a MITRE ATT&CK for Mobile technique
and/or OWASP MASTG guidance, and explains how it shows up in static analysis.
Coverage is scoped to exactly what static_analysis.py can surface: the eight
suspicious_apis categories, the accessibility synthetic entry, the dangerous
permission set, and the certificate/exported-component fields. Two chunks
(T1444, T1398) aren't in the primary API-catalog technique list but are
included because they ground fields the schema emits (certificate, boot
receivers/RECEIVE_BOOT_COMPLETED) that would otherwise have no retrievable
context.
"""

CHUNKS = [
    {
        "id": "T1407",
        "title": "Download New Code at Runtime (Dynamic Code Loading)",
        "mitre": "T1407",
        "text": (
            "Malware can defer loading part of its logic until after installation by pulling in "
            "additional DEX/APK/JAR code at runtime, letting a submitted app look clean while its "
            "real payload arrives later or is decrypted on-device. On Android this shows up as calls "
            "to dalvik.system.DexClassLoader, PathClassLoader, or BaseDexClassLoader constructing a "
            "loader from a file path rather than the app's own compiled code. A confirmed "
            "(cross-referenced) call to one of these constructors is evidence the app can execute "
            "code that never shipped inside the original APK."
        ),
    },
    {
        "id": "T1406",
        "title": "Obfuscated Files or Information (Reflection-based obfuscation)",
        "mitre": "T1406",
        "text": (
            "Attackers hide sensitive API calls from static scanners by invoking them indirectly "
            "through Java reflection instead of calling them directly, so a plaintext string match "
            "on the sensitive method name never appears in the bytecode. The common pattern is "
            "Class.forName() to resolve a class by string, followed by Method.invoke() to call a "
            "method whose name may also have been assembled or decrypted at runtime. This is a weak, "
            "low-specificity signal on its own — reflection is heavily used by legitimate Android "
            "frameworks (DI, serialization, testing libraries) too — so a hit should raise suspicion "
            "only alongside other indicators, never stand alone."
        ),
    },
    {
        "id": "T1582",
        "title": "SMS Control",
        "mitre": "T1582",
        "text": (
            "Banking trojans often send or manipulate SMS messages to intercept one-time passwords, "
            "sign the device up for premium-rate services, or relay stolen OTP codes to an attacker's "
            "number. The static signature is a confirmed call to android.telephony.SmsManager's "
            "sendTextMessage or sendMultipartTextMessage, ideally paired with the SEND_SMS permission "
            "in the manifest. Legitimate use exists (2FA relay apps), but this call combined with "
            "banking-related permissions or strings is a strong indicator."
        ),
    },
    {
        "id": "T1417.001",
        "title": "Input Capture — Accessibility-service keylogging",
        "mitre": "T1417.001",
        "text": (
            "Android's Accessibility Service API, meant to help users with disabilities, can be "
            "abused to read the content and events of whatever screen the user is looking at, "
            "effectively acting as a keylogger or screen-scraper for credentials and OTPs typed into "
            "other apps. Because even benign apps fire AccessibilityEvent callbacks routinely, "
            "matching on those calls in the DEX is too noisy to be useful. The reliable static signal "
            "is declarative: the BIND_ACCESSIBILITY_SERVICE permission in the manifest, or a <service> "
            "whose intent-filter advertises the android.accessibilityservice.AccessibilityService "
            "action, meaning the app has registered itself as an accessibility service at all."
        ),
    },
    {
        "id": "T1417.002",
        "title": "Input Capture — GUI Input Capture (overlay attacks)",
        "mitre": "T1417.002",
        "text": (
            "Rather than reading input through the accessibility API, some malware draws a fake "
            "login screen or transparent overlay on top of a legitimate banking app to capture the "
            "credentials the user types into what they believe is the real UI. This depends on being "
            "able to draw over other apps, which requires the SYSTEM_ALERT_WINDOW permission, and is "
            "frequently paired with accessibility abuse or foreground-service persistence so the "
            "overlay triggers at the right moment. Static analysis can't see the overlay itself, but "
            "SYSTEM_ALERT_WINDOW combined with banking-targeting strings is the closest offline proxy."
        ),
    },
    {
        "id": "T1626",
        "title": "Abuse Elevation Control Mechanism (Device Administrator abuse)",
        "mitre": "T1626",
        "text": (
            "Apps registered as a Device Administrator gain privileged control over the device — "
            "including forcing a lock screen or wiping all data — which malware abuses to resist "
            "uninstallation, ransom the device, or destroy evidence when tampered with. The static "
            "signature is a confirmed call to android.app.admin.DevicePolicyManager's lockNow or "
            "wipeData; because this API requires user-granted device-admin status, its presence "
            "alongside admin-related manifest components is a strong sign the app resists removal."
        ),
    },
    {
        "id": "T1418",
        "title": "Software/Application Discovery (installed-app enumeration)",
        "mitre": "T1418",
        "text": (
            "Banking trojans frequently enumerate the other apps installed on a device to check "
            "whether a specific bank's app is present before deciding which fake overlay or targeted "
            "attack to launch. The static signature is a confirmed call to "
            "android.content.pm.PackageManager's getInstalledPackages or getInstalledApplications; "
            "on its own this is a mild signal since ad SDKs and launchers also enumerate installed "
            "apps, but combined with SMS or accessibility indicators it points toward targeted "
            "banking-fraud reconnaissance."
        ),
    },
    {
        "id": "T1426",
        "title": "System Information Discovery (Device fingerprinting)",
        "mitre": "T1426",
        "text": (
            "Malware often collects hardware identifiers like the IMEI, device ID, or subscriber "
            "(SIM) ID to fingerprint the device, evade emulator/sandbox analysis, or register the "
            "victim with a command-and-control server. The static signature is a confirmed call to "
            "android.telephony.TelephonyManager's getDeviceId, getImei, or getSubscriberId, usually "
            "paired with the READ_PHONE_STATE dangerous permission required to invoke them at runtime."
        ),
    },
    {
        "id": "T1623",
        "title": "Command and Scripting Interpreter (Shell execution)",
        "mitre": "T1623",
        "text": (
            "Executing shell commands directly from an app — rather than through normal Android APIs "
            "— lets malware perform actions like changing file permissions, mounting partitions, or "
            "invoking a root shell that aren't exposed through the SDK, common after gaining root or "
            "when working around security controls. The static signature is a confirmed call to "
            "java.lang.Runtime's exec method; it is more suspicious when the executed string (visible "
            "as a suspicious string match) references /system/bin, su, chmod 777, or mount -o remount."
        ),
    },
    {
        "id": "T1521",
        "title": "Encrypted Channel (Cipher/crypto usage)",
        "mitre": "T1521",
        "text": (
            "Malware often encrypts its command-and-control traffic or its own payload/configuration "
            "to evade network and static signature detection, using standard Android crypto APIs "
            "rather than a custom cipher. The static signature is a confirmed call to "
            "javax.crypto.Cipher's doFinal or to SecretKeySpec's constructor. This is explicitly "
            "dual-use — encryption is standard practice in legitimate apps handling sensitive data "
            "too — so it should be reported as context rather than auto-flagged as malicious."
        ),
    },
    {
        "id": "T1636.003",
        "title": "Protected User Data — Contact List",
        "mitre": "T1636.003",
        "text": (
            "Harvesting the victim's contact list lets malware identify high-value targets, "
            "propagate malicious links via SMS or messaging to the victim's contacts (worm-like "
            "spread), or build a social graph for further social engineering. The manifest signature "
            "is the READ_CONTACTS dangerous permission being declared; combined with SMS-sending "
            "capability, this is a common building block of self-propagating banking malware."
        ),
    },
    {
        "id": "T1636.004",
        "title": "Protected User Data — SMS Messages",
        "mitre": "T1636.004",
        "text": (
            "Reading the content of a user's SMS inbox lets malware intercept one-time passwords and "
            "transaction-verification codes sent by banks — one of the most direct ways banking "
            "trojans defeat SMS-based two-factor authentication. The manifest signature is the "
            "READ_SMS or RECEIVE_SMS dangerous permission. Unlike T1582 (SMS Control), which covers "
            "actively sending messages, this covers passively reading incoming messages; the two are "
            "frequently found together in the same sample."
        ),
    },
    {
        "id": "T1437",
        "title": "Application Layer Protocol (C2 over standard web traffic)",
        "mitre": "T1437",
        "text": (
            "To blend in with normal network traffic and avoid raising alarms, malware typically "
            "talks to its command-and-control server over ordinary HTTP/HTTPS rather than a bespoke "
            "protocol. Static analysis can't observe live network traffic, but hardcoded URLs or raw "
            "IP-address literals found in the app's strings are the offline proxy signal — a "
            "suspicious string of kind 'url' or 'ip' is a candidate C2 endpoint or exfiltration "
            "target worth flagging even before any traffic is observed."
        ),
    },
    {
        "id": "T1541",
        "title": "Foreground Persistence",
        "mitre": "T1541",
        "text": (
            "Malware that needs to keep running in the background without being killed by Android's "
            "memory manager, or that wants a fraudulent overlay ready to trigger at any moment, runs "
            "as a foreground service with a persistent notification, which the OS is much less likely "
            "to terminate. There's no single API call that proves this alone, but an exported "
            "<service> with broad intent-filters, combined with boot-persistence and "
            "accessibility/overlay permissions, indicates the app is engineered to stay active long "
            "after installation."
        ),
    },
    {
        "id": "T1444",
        "title": "Masquerade as Legitimate Application",
        "mitre": "T1444",
        "text": (
            "Repackaged and counterfeit banking trojans frequently pose as a legitimate bank's app or "
            "a common utility, hoping the user won't scrutinize the signer. A strong static tell is "
            "the signing certificate: legitimate published apps are signed with a stable, long-lived "
            "developer certificate, whereas malware and hastily repackaged APKs are often self-signed "
            "(subject equals issuer) or still carry the default Android debug certificate — both "
            "strong indicators the app never went through a normal release/signing pipeline."
        ),
    },
    {
        "id": "T1398",
        "title": "Boot or Logon Initialization Scripts",
        "mitre": "T1398",
        "text": (
            "To guarantee it starts running immediately whenever the device reboots — without "
            "requiring the user to open it — malware registers a broadcast receiver for the "
            "BOOT_COMPLETED system event, letting it restart persistence mechanisms like foreground "
            "services or C2 beacons before the user even unlocks the phone. The static signature is "
            "the RECEIVE_BOOT_COMPLETED dangerous permission combined with an exported <receiver> "
            "whose intent-filter listens for the android.intent.action.BOOT_COMPLETED action."
        ),
    },
]
