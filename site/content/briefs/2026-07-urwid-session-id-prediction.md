---
title: 'CVE-2026-9323: Urwid Web Display Backend Session ID Prediction Vulnerability'
slug: 2026-07-urwid-session-id-prediction
description: A vulnerability, CVE-2026-9323, in the urwid web display backend (urwid/display/web.py) allows attackers to predict and hijack web session identifiers ('urwid_id') due to the use of a non-cryptographically secure pseudo-random number generator (Python's Mersenne Twister) and the exposure of these IDs as filenames in a world-listable `/tmp` directory, potentially leading to OS-level code execution or denial of service by injecting keystrokes or terminating sessions.
date: "2026-07-18T14:23:20Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve-2026-9323
  - session-hijacking
  - rce
  - prng-vulnerability
  - linux
  - macos
vendors:
  - Urwid
products:
  - urwid web display backend
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    evidence: reconstruct the internal state and predict all past and future session IDs
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: inject keystrokes into the victim's session (yielding OS-level code execution with the session owner's privileges if the session runs a shell)
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: local user on the host can list /tmp to enumerate active session tokens directly
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1056
    technique_name: ""
    evidence: inject keystrokes into the victim's session
    confidence_band: med
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: inject exit sequences or flood the FIFO to terminate or crash the session.
    confidence_band: high
cves:
  - id: CVE-2026-9323
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-9323
---

CVE-2026-9323 describes a critical vulnerability in the urwid web display backend, specifically within `urwid/display/web.py`. The system generates web session identifiers, known as `urwid_id`, by concatenating two calls to `random.randrange(10**9)`. This process relies on Python's Mersenne Twister PRNG, which is not cryptographically secure. An attacker who observes approximately 334 such session IDs, for instance via the `X-Urwid-ID` HTTP response header, can fully reconstruct the PRNG's internal state (approximately 19,937 bits) and subsequently predict all past and future session IDs. Compounding this, the same `urwid_id` is used as the filename for a FIFO created in the world-listable `/tmp` directory (e.g., `/tmp/urwid375487765176907690.in`), allowing any local user to enumerate active session tokens directly. This vulnerability enables session hijacking, leading to the ability to read terminal screens, inject keystrokes for OS-level code execution, or cause denial of service by terminating or crashing sessions.

## Attack Chain

1. An attacker observes approximately 334 `urwid_id` session identifiers, typically via the `X-Urwid-ID` HTTP response header in network traffic.
2. Using the observed identifiers, the attacker reconstructs the internal state of Python's Mersenne Twister Pseudo-Random Number Generator (PRNG).
3. Based on the reconstructed PRNG state, the attacker can accurately predict past and future `urwid_id` session identifiers for any active urwid web session.
4. Alternatively, a local attacker on the host lists the world-listable `/tmp` directory to enumerate active session tokens directly from the FIFO filenames (e.g., `/tmp/urwid*.in`).
5. With a predicted or enumerated valid `urwid_id`, the attacker gains unauthorized access to the victim's urwid terminal session.
6. The attacker reads the victim's terminal screen content via the session's polling endpoint, potentially exfiltrating sensitive information.
7. The attacker injects keystrokes into the victim's session, which, if the session is running a shell, can lead to OS-level code execution with the privileges of the session owner.
8. As a final impact, the attacker can inject exit sequences or flood the session's associated FIFO file, causing the session to terminate or crash, resulting in a denial of service.

## Impact

Successful exploitation of CVE-2026-9323 can lead to severe consequences for affected urwid web display backend deployments. While specific victim counts are not available, any organization using the vulnerable version of urwid could be at risk. The primary impact includes unauthorized information disclosure through reading terminal screens, allowing attackers to view sensitive data. More critically, attackers can achieve OS-level code execution with the privileges of the compromised session owner, enabling data manipulation, further system compromise, or persistent access. Additionally, the vulnerability can be leveraged for denial of service by terminating or crashing user sessions, disrupting critical operations.

## Recommendation

* Patch CVE-2026-9323 by upgrading the urwid web display backend to a version that uses a cryptographically secure PRNG for session ID generation and addresses the `/tmp` directory exposure.
* Implement host-based intrusion detection to monitor for suspicious access patterns to FIFO files within the `/tmp` directory, specifically those matching the `urwid*.in` filename pattern mentioned in CVE-2026-9323.
* Monitor HTTP response headers for an unusually high volume of `X-Urwid-ID` headers being observed or collected by unauthorized systems, potentially indicating reconnaissance related to CVE-2026-9323.
