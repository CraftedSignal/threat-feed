---
title: Integrity Vulnerability in Thermo Fisher Genetic Analyzer Software
slug: 2026-08-thermo-fisher-integrity
description: Thermo Fisher Applied Biosystems Genetic Analyzer software lacks integrity checks for output data files, enabling local users to modify DNA analysis results (CVE-2026-17583).
date: "2026-08-04T16:38:21Z"
type: advisory
types:
  - advisory
severities:
  - medium
vendors:
  - Thermo Fisher
products:
  - Applied Biosystems 3500/3500xL Series Data Collection Software
  - Applied Biosystems 3730/3730xL Series Data Collection Software
  - Applied Biosystems SeqStudio Genetic Analyzer Data Collection Software
  - Applied Biosystems SeqStudio Flex Series Instrument Software
  - Applied Biosystems GeneMapper ID-X Software
  - Applied Biosystems 3130 Series Data Collection Software
  - ABI PRISM 3100/3100-Avant Data Collection Software
  - ABI PRISM 310 Data Collection Software
references:
  - https://www.cisa.gov/news-events/ics-medical-advisories/icsma-26-216-01
  - https://www.cve.org/CVERecord?id=CVE-2026-17583
  - https://documents.thermofisher.com/TFS-Assets/CORP/Product-Guides/fsa_hid_bulletin.pdf
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Patch all supported versions to the recommended vendor versions listed in the advisory.
      owner: IT Operations
      due: 72h
      evidence: Vendor fix documentation
  mitigation_plan:
    - priority: immediate
      action: Isolate EoL instruments from production networks and implement FIM on .fsa/.hid data directories.
      owner: IT Operations
      addresses: CVE-2026-17583
      evidence: Vendor mitigation recommendations
---

Thermo Fisher Scientific has identified a high-severity vulnerability (CVE-2026-17583) affecting multiple versions of its Applied Biosystems Genetic Analyzer data collection and instrument software. The vulnerability, categorized as CWE-353: Missing Support for Integrity Check, allows for the modification of output files with .fsa or .hid extensions. Because these files lack digital signatures or integrity verification mechanisms, an unauthorized actor with local access to the instrument or analysis workstation can tamper with the underlying DNA data. Successful exploitation could lead to falsified test outcomes, impacting the reliability of forensic or clinical data. This issue is not exploitable remotely and requires local access to the system. While the vendor has provided software patches for supported versions, legacy systems that are End of Life (EoL) remain permanently vulnerable and require robust compensating controls to ensure chain-of-custody.

## Impact

The vulnerability directly threatens the integrity of genomic data, which is critical in healthcare, public health, and forensic sectors. If exploited, an attacker could manipulate sensitive DNA data, potentially leading to inaccurate test results, misidentifications, or the compromise of scientific research. Organizations using the affected software must treat these workstations as high-value targets, given that an attacker capable of local file manipulation could undermine the legal and scientific validity of all generated output files.

## Recommendation

- Prioritize the deployment of provided vendor software updates for all supported Thermo Fisher Applied Biosystems Genetic Analyzer platforms to implement digital signature validation.
- For End of Life (EoL) systems where updates are unavailable (e.g., 3130 Series, 3100/3100-Avant, 310), isolate the host workstations from the production network and enforce strict physical access controls.
- Implement File Integrity Monitoring (FIM) on directories containing .fsa and .hid files to detect unauthorized changes to the data records.
- Restrict user permissions on workstations hosting the instrumentation software using the principle of least privilege, ensuring that only necessary accounts have write access to data directories.
- Implement full-disk encryption and store finalized analysis files on encrypted, password-protected removable media to maintain a secure chain of custody.
- Apply network-level restrictions, such as host-based firewalls or NACLs, to ensure these systems cannot reach or be reached by untrusted external sources.
