---
title: Grav File Cache Insecure Deserialization Vulnerability
slug: 2024-01-30-grav-filecache-deserialization
description: Grav versions 1.7.44 through 1.7.49.5 are vulnerable to insecure deserialization in the File Cache component, where the `unserialize` function with `allowed_classes => true` can lead to arbitrary code execution if an attacker tampers with cache files.
date: "2024-01-30T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - insecure-deserialization
  - code-execution
  - grav
  - web-application
vendors:
  - getgrav
products:
  - grav (< 2.0.0-beta.2)
affected_os:
  - linux
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-gwfr-jfjf-92vv
rules:
  - title: Detect Cache File Modification in Grav CMS
    description: Detects modification of cache files in Grav CMS which may indicate a cache poisoning attempt leading to deserialization attacks.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege_escalation
    data_sources:
      - file_event
      - linux
  - title: Detect Unserialize Function Usage with allowed_classes in PHP
    description: Detects the usage of the `unserialize` function in PHP with `allowed_classes => true`, which can be indicative of insecure deserialization vulnerabilities.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Grav, a flat-file CMS, versions 1.7.44 through 1.7.49.5 are susceptible to an insecure deserialization vulnerability within the `FileCache` component. Specifically, the `unserialize()` function in `system/src/Grav/Framework/Cache/Adapter/FileCache.php` utilizes the `allowed_classes => true` option, which permits the instantiation of arbitrary classes without any restrictions. This vulnerability can be exploited if an attacker gains the ability to tamper with or poison the cache files used by Grav. By injecting malicious serialized objects into these cache files, an attacker can trigger the execution of arbitrary code when the application attempts to deserialize the tampered cache data. This issue was reported on May 5th, 2026. A fix has been implemented in Grav core on the 2.0 branch (commit `c66dfeb5f`), set to be included in version 2.0.0-beta.2. This fix introduces HMAC signing and verification to ensure the integrity of cache payloads.

## Attack Chain

1. The attacker gains access to the Grav server's filesystem with write privileges to the cache directory.
2. The attacker crafts a malicious PHP object that, when unserialized, will execute arbitrary code. This payload could leverage existing classes or magic methods like `__wakeup()` to achieve code execution.
3. The attacker serializes the malicious PHP object using the `serialize()` function.
4. The attacker overwrites an existing cache file or creates a new one containing the serialized payload in the Grav cache directory (location varies based on configuration, but default is often in `cache/`).
5. The Grav application attempts to read the tampered cache file using the `FileCache::doGet()` function.
6. The `unserialize($value, ['allowed_classes' => true])` function is called on the tampered cache data.
7. The malicious PHP object is deserialized, triggering the execution of the attacker's code.
8. The attacker achieves arbitrary code execution on the Grav server, potentially leading to full system compromise, data exfiltration, or further malicious activities.

## Impact

Successful exploitation of this vulnerability allows attackers to execute arbitrary code on the Grav server. This can lead to complete system compromise, data exfiltration, defacement of websites, or the installation of backdoors for persistent access. Given that Grav is a CMS, this can impact any website or application built on the platform. The number of potential victims is dependent on the number of Grav installations running the vulnerable versions (1.7.44 - 1.7.49.5) and the attacker's ability to access and modify the cache files.

## Recommendation

*   Upgrade to Grav version 2.0.0-beta.2 or later, where the vulnerability is addressed with HMAC signing of cache payloads, as detailed in commit `c66dfeb5f`.
*   Monitor file system access, particularly writes to the cache directory, for suspicious activity. Consider deploying file integrity monitoring tools to detect unauthorized modifications to cache files.
*   If upgrading is not immediately feasible, implement strict access controls to the cache directory to prevent unauthorized write access.
*   Review and audit any plugins or custom code that utilize the `Grav\Framework\Cache\Adapter\FileCache` class, ensuring they are not susceptible to cache poisoning attacks.
*   Implement the provided PoC locally to validate your exposure and test the effectiveness of mitigations.
