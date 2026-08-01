"""D2 A/B negative-evidence chunks — approved for the D2 A/B experiment.

NOT one of the six frozen pipeline files. Not added to knowledge_base.py, not
imported by knowledge_base.py, and does not modify it. Consumed only by
d2_ab_harness.py, which monkeypatches these onto rag_report.CHUNKS at runtime.

Same {id, title, mitre, text} shape as knowledge_base.CHUNKS so build_user_prompt()
renders them identically. Per review feedback: "mitre" is NOT a "BENIGN" sentinel —
that would double-purpose the field as a verdict-priming tell (the literal string
"BENIGN" is one of the three legal verdict enum values, so a model that reacts to
the flag rather than the content would contaminate the measurement). Instead,
following the real 16 chunks' own convention (id == mitre, confirmed Phase 0.6) and
the codebase's existing snake_case category-naming style (suspicious_apis
categories like "dynamic_code_loading", "installed_app_discovery"), each chunk's
"id" and "mitre" are the same neutral, content-descriptive category label (e.g.
"normal_messaging_profile") — descriptive of what the chunk is about, not
evaluative of what verdict it should produce.

Acknowledged, irreducible difference from the real 16: real chunk ids are literal
MITRE ATT&CK technique codes (T1407, etc.) because they document real techniques.
These chunks don't document a technique — inventing a fake MITRE code for them
would be a worse, more misleading form of contamination than a descriptive label.

Second revision (per review feedback): every chunk in the first draft carried an
"unless combined with [accessibility abuse / SMS interception / device-admin abuse /
targeted bank package / C2 URL]" clause. That clause exculpates a benign sample (the
aggravating factors are absent) but INCRIMINATES a malicious sample retrieving the
same chunk (the clause reads back as a checklist of co-indicators the trojan
actually has) — so the chunk would act on both arms, and any separation improvement
in the A/B couldn't be attributed to "benign evidence helps benignware" vs "the
clause told the model the decision rule." That also risks smuggling a D1-style
prompt decision-rule in through the corpus. Every chunk below states only what is
normal/expected and stops — it does not enumerate malicious co-indicators or
instruct the model on what verdict to reach. The existing 16 malicious chunks still
carry all malicious framing on their own, retrieved alongside these for actually
malicious samples.

Third fix (fintech chunk specifically): the first draft's escape hatch was "on an
app that IS a bank/fintech app, as opposed to an app impersonating one" — but
static permissions/API evidence is exactly what PS1 cannot use to tell a real bank
app from an impersonator; that's the detection problem itself, not something a
knowledge-base chunk can presuppose. Rewritten to describe why READ_PHONE_STATE /
CALL_PHONE / SYSTEM_ALERT_WINDOW have ordinary, non-malicious purposes independent
of what kind of app holds them, without asserting or requiring a real-vs-fake-bank
determination.

These are NOT added to knowledge_base.py; they will only ever be monkeypatched
onto rag_report.CHUNKS at runtime by the (not-yet-built) D2 A/B harness.

Each chunk deliberately reuses the actual vocabulary that
_build_retrieval_query() draws from (dangerous_permissions names, suspicious_apis
categories, suspicious_strings kinds) so it can actually compete for retrieval
against the existing all-malicious chunks on the same query terms.
"""

NEGATIVE_CHUNKS = [
    {
        "id": "normal_messaging_profile",
        "title": "SMS permissions are normal for messaging and communication apps",
        "mitre": "normal_messaging_profile",
        "text": (
            "SEND_SMS, READ_SMS, and RECEIVE_SMS are declared by many entirely legitimate "
            "categories of app: SMS backup/restore tools, dual-SIM managers, RCS/SMS bridge apps, "
            "group-messaging clients that fall back to SMS, and OTP-autofill helpers that read an "
            "incoming code so the user doesn't have to copy it manually. These are core, expected "
            "permissions for this whole category of ordinary messaging and communication software."
        ),
    },
    {
        "id": "normal_fintech_profile",
        "title": "Phone-state, call, and overlay permissions have ordinary non-malicious purposes",
        "mitre": "normal_fintech_profile",
        "text": (
            "READ_PHONE_STATE lets an app read basic telephony state — network type, carrier/SIM "
            "info, call state — commonly used to adapt behavior to network conditions, verify a "
            "phone number during signup, or detect a SIM change for an account-recovery flow. "
            "CALL_PHONE lets an app place a call directly, commonly used for a one-tap 'call this "
            "number' or 'call support' button. SYSTEM_ALERT_WINDOW lets an app draw content above "
            "other apps, commonly used for picture-in-picture video, chat-head bubbles, floating "
            "notes, or an app's own PIN/lock overlay drawn above its own content. Each of these "
            "permissions has an ordinary, non-malicious purpose on its own."
        ),
    },
    {
        "id": "normal_boot_persistence_profile",
        "title": "RECEIVE_BOOT_COMPLETED is standard for media, sync, and utility apps",
        "mitre": "normal_boot_persistence_profile",
        "text": (
            "Media players, backup/sync tools, alarm and reminder apps, launchers, and background "
            "download managers all commonly register for RECEIVE_BOOT_COMPLETED so they can resume "
            "a paused download, restart a sync job, or re-arm a scheduled alarm after the device "
            "reboots. This is ordinary Android app behavior for any app that needs to resume "
            "background work after a restart."
        ),
    },
    {
        "id": "normal_package_management_profile",
        "title": "Package-management permissions are normal for app stores and utility apps",
        "mitre": "normal_package_management_profile",
        "text": (
            "REQUEST_INSTALL_PACKAGES and QUERY_ALL_PACKAGES are declared by app stores and "
            "alternative marketplaces (like F-Droid clients), backup/restore utilities that "
            "reinstall a user's apps, launchers that list installed apps for their app drawer, and "
            "antivirus/cleaner utilities that need to enumerate installed software to do their job. "
            "Installed-app enumeration and the ability to trigger installs are core, expected "
            "functionality for this whole category of legitimate utility app."
        ),
    },
    {
        "id": "normal_dualuse_api_profile",
        "title": "Reflection and encryption APIs are pervasive in ordinary app frameworks",
        "mitre": "normal_dualuse_api_profile",
        "text": (
            "Class.forName() and Method.invoke() (Java reflection) are used constantly by ordinary "
            "Android apps through dependency-injection frameworks, serialization libraries (Gson, "
            "Moshi), and testing/mocking libraries — most apps that use any modern framework touch "
            "reflection somewhere without the developer even being aware of it. Likewise, "
            "javax.crypto.Cipher and SecretKeySpec are the standard, recommended way for any app to "
            "encrypt local data such as an offline cache, encrypted SharedPreferences, or a local "
            "database. Both are ordinary building blocks of modern Android app development."
        ),
    },
    {
        "id": "normal_network_strings_profile",
        "title": "Hardcoded URLs and IP addresses are ubiquitous in ordinary apps",
        "mitre": "normal_network_strings_profile",
        "text": (
            "Nearly every networked Android app contains hardcoded URLs and occasionally raw IP "
            "addresses in its strings — API base URLs, CDN asset links, analytics/crash-reporting "
            "SDK endpoints, open-source project or privacy-policy links, and so on. Finding a URL or "
            "IP string in an app's binary is close to universal across ordinary, non-malicious apps "
            "that talk to any server at all."
        ),
    },
]
