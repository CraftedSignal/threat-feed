---
title: Abuse of Google Drive Download URLs for Malicious Payload Delivery
slug: 2026-09-google-drive-malicious-dl
description: Adversaries are exploiting Google Drive by appending parameters to download URLs that instruct the service to bypass antivirus scanning, facilitating the delivery of malicious payloads.
date: "2026-09-18T19:04:59Z"
type: advisory
types:
  - advisory
severities:
  - medium
vendors:
  - Google
products:
  - Google Drive
affected_os:
  - Windows
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1102
    technique_name: Web Service
    evidence: Adversaries may exploit its trusted nature to distribute malicious files, bypassing security measures by using download links with antivirus checks disabled.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
    evidence: Adversaries may exploit its trusted nature to distribute malicious files, bypassing security measures by using download links with antivirus checks disabled.
    confidence_band: high
rules:
  - title: Detect Suspicious Google Drive Download with AV Bypass
    description: Detects processes downloading files from Google Drive where the 'confirm=no_antivirus' parameter is present, indicating an attempt to bypass security scanning.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1102.003
      - T1105
    data_sources:
      - process_creation
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma detection rule to track processes attempting to download from Google Drive with AV bypass flags.
      owner: Detection Engineering
      due: 48h
      evidence: Source documentation on bypass parameter 'confirm=no_antivirus'.
  hunt_leads:
    - lead: Search logs for any occurrence of 'confirm=no_antivirus' in command-line arguments.
      technique_id: T1105
      data_needed:
        - Endpoint process creation logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source explicitly identifies these parameters as indicators of abuse.
---

Threat actors are increasingly leveraging the trusted infrastructure of Google Drive to host and distribute malicious payloads, including malware such as Matanbuchus. By crafting specific download URLs that include the 'export=download' and 'confirm=no_antivirus' parameters, attackers intentionally bypass Google's automated virus scanning mechanisms for large files. This technique allows malicious files to be delivered directly to victims via a platform that is typically trusted by enterprise security policies and web filters. Defenders must monitor process execution logs to identify browser-based or command-line utility-based downloads that contain these specific URL parameters, as they represent an active attempt to deliver payloads while subverting standard cloud-based security controls.

## Attack Chain

1. Attacker stages a malicious payload (e.g., installer or script) on a Google Drive account.
2. Attacker configures the file permissions to public access and generates a shareable download link.
3. Attacker modifies the URL to include 'export=download' and 'confirm=no_antivirus' to bypass Google's security checks.
4. Victim is lured via phishing or social engineering to click the malicious URL.
5. The victim's browser or a command-line tool (curl/wget) executes the download request.
6. Endpoint security logs record the process command line containing the bypass parameters.
7. The file is saved to the local filesystem for execution.
8. Final objective is achieved through the execution of the downloaded malicious payload.

## Impact

Successful exploitation allows for the delivery of malware directly to endpoints while evading native cloud security scanning. This facilitates the initial access or secondary payload deployment stages of an attack, potentially leading to system compromise, data exfiltration, or further lateral movement within an organization.

## Recommendation

Prioritize the detection of file download activity originating from Google Drive that attempts to explicitly skip security scanning.
- Deploy the provided Sigma rule to identify command-line activity containing 'confirm=no_antivirus'.
- Monitor logs for unauthorized use of command-line tools like curl or wget to reach cloud storage providers.
- Educate users on the risks of clicking links from untrusted sources, even if they point to reputable domains like drive.google.com.
- If the environment does not rely on external cloud storage for business, consider blocking access to specific 'export=download' patterns at the proxy or gateway level.
