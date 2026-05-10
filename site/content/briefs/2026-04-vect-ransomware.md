---
title: VECT Ransomware Destroys Files Due to Encryption Flaw
slug: 2026-04-vect-ransomware
description: VECT 2.0 ransomware, a RaaS offering, permanently destroys large files due to an encryption flaw, discarding decryption nonces for files above 128 KB, rendering them unrecoverable and effectively acting as a wiper; it uses raw ChaCha20-IETF with no authentication.
date: "2026-04-28T13:03:01Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - TeamPCP
tags:
  - ransomware
  - wiper
  - raas
vendors:
  - VMware
  - Check Point
  - Checkmarx
  - Telnyx
products:
  - ESXi
  - Trivy
  - KICS
  - LiteLLM
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1486
    technique_name: Data Encrypted for Impact
references:
  - https://research.checkpoint.com/2026/vect-ransomware-by-design-wiper-by-accident/
rules:
  - title: Detect VECT Ransomware Execution
    description: Detects execution of VECT ransomware based on image path anomalies.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1204.002
    data_sources:
      - process_creation
      - windows
  - title: Detect VECT Ransomware Linux Execution
    description: Detects execution of VECT ransomware on Linux systems based on image path anomalies.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1204.002
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

VECT Ransomware is a Ransomware-as-a-Service (RaaS) that emerged in December 2025 and gained notoriety after partnering with TeamPCP in March 2026. This partnership aimed to exploit victims of TeamPCP's supply chain attacks, which injected malware into software packages like Trivy, Checkmarx’ KICS, LiteLLM and Telnyx. VECT 2.0, released in February 2026, targets Windows, Linux, and ESXi, built from a single flawed codebase using libsodium and the ChaCha20-IETF cipher. A critical flaw causes the ransomware to discard decryption nonces for files larger than 128KB, resulting in data corruption and irrecoverable files. Advertised encryption speed modes (--fast, --medium, --secure) are parsed, but ignored.

## Attack Chain

1.  Affiliate gains access to the VECT RaaS platform via BreachForums, after VECT announced the partnership with BreachForums in April 2026.
2.  Affiliate builds a custom ransomware payload (Windows, Linux, or ESXi) via the VECT builder panel.
3.  Ransomware binary is deployed to the target system.
4.  The VECT ransomware begins encrypting files.
5.  For files larger than 128 KB, the ransomware discards three of four decryption nonces due to a flaw in its encryption implementation.
6.  Files are encrypted using ChaCha20-IETF (RFC 8439) without authentication.
7.  A ransom note is displayed, demanding payment for decryption.
8.  Due to the discarded nonces, files larger than 128KB are unrecoverable, even with the correct decryption key.

## Impact

The VECT ransomware acts as a wiper for files larger than 128KB due to a flaw in its encryption process, causing permanent data loss. This includes enterprise assets such as VM disks, databases, documents and backups. The leak site has listed two victims, both originating from the TeamPCP supply chain attacks. If successful, the attack results in significant data loss.

## Recommendation

*   Monitor process creation events for executables with file names similar to legitimate system tools but located in unusual directories, which could indicate the presence of VECT ransomware on a system (see Sigma rule `Detect VECT Ransomware Execution`).
*   Implement network monitoring to detect unusual outbound connections from systems, which might indicate lateral movement or communication with a command-and-control server.
*   Deploy endpoint detection and response (EDR) solutions to detect and block suspicious file encryption activity on endpoints.
*   Review and update incident response plans to include procedures for handling potential ransomware attacks, with a focus on data recovery and business continuity.
