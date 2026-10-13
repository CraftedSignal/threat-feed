---
title: Path Traversal in NLTK WekaClassifier
slug: 2026-10-nltk-path-traversal
description: NLTK versions up to 3.10.3 contain a path traversal vulnerability in the WekaClassifier component that allows attackers to probe or write files outside of defined data roots.
date: "2026-10-13T14:39:01Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:nltk:nltk:*:*:*:*:*:*:*:*
vendors:
  - NLTK Project
products:
  - NLTK (<= 3.10.3)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: NLTK through 3.10.3 contains a path traversal vulnerability in WekaClassifier that allows attackers to bypass nltk.pathsec containment.
    confidence_band: high
cves:
  - id: CVE-2026-109956
    cvss: 7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-109956
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  mitigation_plan:
    - priority: immediate
      action: Upgrade NLTK to a patched version beyond 3.10.3
      owner: IT Operations
      addresses: CVE-2026-109956
      evidence: NLTK through 3.10.3 contains a path traversal vulnerability
---

NLTK (Natural Language Toolkit) versions through 3.10.3 are affected by a path traversal vulnerability residing within the WekaClassifier component. The flaw exists because the library fails to properly validate input provided to the 'model_filename' or 'model' arguments before processing them. An attacker capable of influencing these arguments can bypass the 'nltk.pathsec' containment mechanism. By manipulating the paths, the underlying Weka Java Virtual Machine (JVM) instance can be forced to read ('-l') or write ('-d') files in locations outside the intended application data directory. This vulnerability provides a vector for unauthorized file access or potential configuration file overwriting, depending on the environment where the NLTK application is running.

## Impact

Successful exploitation allows for unauthorized file system interactions, including probing for sensitive files or overwriting critical files on the underlying host system. This vulnerability affects any Python application utilizing the NLTK WekaClassifier module with user-supplied input.

## Recommendation

* Update NLTK to a version beyond 3.10.3 immediately upon the availability of a patch.
* Review applications using the WekaClassifier component to ensure that the 'model_filename' or 'model' parameters are not sourced from untrusted or user-supplied input.
* Implement strict filesystem permission controls for the service account running the Python application to limit the impact of potential directory traversal.
