---
brief_id: brief-2026-11-10-ie-firstrun-disable
event_id: brief-2026-11-10-ie-firstrun-disable
revision: 1
activity_at: "2026-11-10T03:09:07Z"
title: Internet Explorer DisableFirstRunCustomize Registry Modification
slug: 2026-11-ie-firstrun-disable
description: This detection identifies the modification of the Internet Explorer DisableFirstRunCustomize registry key, a technique previously associated with malware installers and defense impairment to suppress browser initialization wizards.
date: "2026-11-10T03:09:07Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Needs environment validation for filter tuning.
tags:
  - windows
  - registry
  - defense-impairment
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: The registry key prevents the first run wizard, which can be used to hide malicious activity or browser hijacking.
    confidence_band: med
references:
  - https://www.ncsc.gov.uk/files/NCSC-MAR-Devil-Bait.pdf
  - https://unit42.paloaltonetworks.com/operation-ke3chang-resurfaces-with-new-tidepool-malware/
  - https://admx.help/?Category=InternetExplorer&Policy=Microsoft.Policies.InternetExplorer::NoFirstRunCustomise
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_internet_explorer_disable_first_run_customize.yml
rules:
  - title: Detect Modification of Internet Explorer DisableFirstRunCustomize
    description: Detects changes to the Internet Explorer DisableFirstRunCustomize value which prevents the first run wizard, a technique used for defense impairment or silent installation
    platform: sigma
    severity: medium
    tactics:
      - defense-impairment
    data_sources:
      - registry_set
      - windows
rules_count: 1
action_plan:
  priority: monitor_or_close
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma rule to monitor for registry persistence
      owner: Detection Engineering
      due: 7d
      evidence: Registry modification can impair defense visibility or indicate browser hijacking.
  hunt_leads:
    - lead: Search for unknown processes modifying registry paths under HKLM/HKCU \Microsoft\Internet Explorer\Main
      technique_id: T1562
      data_needed:
        - Registry set telemetry
      priority: medium
      confidence: medium
      disposition: convert_to_detection
      evidence: The key is often used to suppress setup wizards during stealthy malware installation.
  mitigation_plan:
    - priority: medium
      action: Enforce browser initialization settings via secure GPO
      owner: IT Operations
      addresses: Defense impairment via browser configuration
      evidence: Centralized policy management reduces unauthorized manual modifications.
---

The modification of the `DisableFirstRunCustomize` registry key prevents Internet Explorer from triggering the first-run initialization wizard. While this key can be managed via Group Policy, it has historically been observed as an artifact used by various malware campaigns and installers to suppress user-visible browser initialization prompts. This brief provides a detection rule to identify non-standard modifications to this registry path.

## Impact

Legitimate use of this key is common via corporate Group Policy Objects (GPOs). Unauthorized modification may indicate an attempt by malicious software to suppress browser setup or perform silent modifications to browser behavior.

## Recommendation

- Deploy the provided Sigma rule to your SIEM to monitor for unauthorized modifications to the `DisableFirstRunCustomize` registry value.
- Baseline existing GPO-managed systems to identify expected modification patterns and tune the detection filters to reduce noise.
- Investigate any suspicious processes modifying this key that originate outside of expected administrative processes or known software installers.
