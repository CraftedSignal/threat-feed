---
title: CVE-2026-65701 - SoftVC VITS Singing Voice Conversion Path Traversal Vulnerability
slug: 2026-07-softvc-vits-path-traversal
description: A path traversal vulnerability exists in the full-song inference server of SoftVC VITS Singing Voice Conversion, affecting versions through commit 730930d, allowing unauthenticated remote attackers to read and exfiltrate arbitrary files by manipulating the 'audio_path' field in an unauthenticated POST request to the '/wav2wav' route.
date: "2026-07-23T18:22:56Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - path-traversal
  - file-exfiltration
  - arbitrary-file-write
  - web-application
vendors:
  - SoftVC
products:
  - VITS Singing Voice Conversion (through commit 730930d)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: SoftVC VITS Singing Voice Conversion through commit 730930d contains a path traversal vulnerability in the full-song inference server that allows unauthenticated remote attackers to read and exfiltrate arbitrary files by supplying attacker-controlled filesystem paths through the audio_path field of an unauthenticated POST request to the /wav2wav route.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: allows unauthenticated remote attackers to read and exfiltrate arbitrary files by supplying attacker-controlled filesystem paths
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1567
    technique_name: Exfiltration Over Web Service
    evidence: causing the server to decode and return file contents via the HTTP response body
    confidence_band: high
  - tactic_id: TA0008
    tactic_name: Impact
    technique_id: T1490
    technique_name: Inhibit System Recovery
    evidence: while also writing attacker-specified .wav files to arbitrary locations on the filesystem
    confidence_band: med
cves:
  - id: CVE-2026-65701
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-65701
rules:
  - title: Detects CVE-2026-65701 Exploitation - SoftVC VITS Path Traversal
    description: Detects exploitation attempts for CVE-2026-65701 via HTTP POST requests to /wav2wav with path traversal sequences in the 'audio_path' parameter, indicating arbitrary file read or write attempts.
    platform: sigma
    severity: critical
    tactics:
      - impact
      - initial_access
    techniques:
      - T1083
      - T1190
      - T1567.002
    data_sources:
      - webserver
rules_count: 1
---

A critical path traversal vulnerability, tracked as CVE-2026-65701, has been identified in the full-song inference server of SoftVC VITS Singing Voice Conversion, specifically affecting versions up to and including commit 730930d. This flaw permits unauthenticated remote attackers to exploit the server by manipulating the `audio_path` field within an HTTP POST request directed at the `/wav2wav` route. By supplying attacker-controlled filesystem paths, threat actors can force the application to read and exfiltrate arbitrary files, returning their contents via the HTTP response body. Furthermore, the vulnerability enables the writing of attacker-specified `.wav` files to arbitrary locations on the server's filesystem, leveraging functions like `librosa.load`, `torchaudio.load`, and `soundfile.write`. This vulnerability presents a significant risk for data exfiltration and potential arbitrary file write leading to further compromise.

## Attack Chain

1. An unauthenticated remote attacker identifies a SoftVC VITS Singing Voice Conversion instance exposing the vulnerable full-song inference server.
2. The attacker crafts a malicious HTTP POST request targeting the `/wav2wav` route of the application.
3. The request includes an `audio_path` parameter containing path traversal sequences (e.g., `../../../../etc/passwd`) to specify an arbitrary file on the server's filesystem.
4. The vulnerable server receives the request and passes the attacker-controlled `audio_path` value directly to file loading functions such as `librosa.load` or `torchaudio.load`.
5. The application reads the content of the arbitrary file (e.g., `/etc/passwd`) from the server's filesystem.
6. The content of the accessed file is then decoded and included in the HTTP response body, effectively exfiltrating the data to the attacker.
7. Alternatively, the attacker can specify a writable arbitrary path in the `audio_path` parameter, causing `soundfile.write` to create a `.wav` file at the specified location with attacker-controlled content.

## Impact

Successful exploitation of CVE-2026-65701 can lead to severe consequences for affected organizations. Attackers can read sensitive configuration files, user data, source code, or other proprietary information directly from the server's filesystem, leading to unauthorized disclosure and data exfiltration. The ability to write arbitrary `.wav` files to any location on the filesystem can also be abused for denial-of-service, planting malicious executables, or achieving persistence by writing web shells in publicly accessible directories. The high CVSS score of 9.1 reflects the critical nature of this vulnerability, indicating potential for complete compromise of confidentiality, integrity, and availability.

## Recommendation

* **Patch CVE-2026-65701**: Immediately update SoftVC VITS Singing Voice Conversion to a version beyond commit 730930d to remediate CVE-2026-65701.
* **Deploy the Sigma rule** to your SIEM to detect attempts at exploiting this vulnerability.
* **Enable web server access logging** for the `webserver` category to ensure HTTP POST requests and their parameters to `/wav2wav` are recorded for detection and forensics.
