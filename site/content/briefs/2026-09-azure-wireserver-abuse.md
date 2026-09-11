---
title: Azure WireServer Metadata Service Abuse via Unauthorized CMS Decryption
slug: 2026-09-azure-wireserver-abuse
description: Threat actors are abusing the Azure WireServer metadata service to decrypt sensitive VM extension protectedSettings by minting unauthorized identity certificates and performing unauthorized CMS/PKCS7 decryption.
date: "2026-09-11T18:49:49Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - credential-access
  - defense-evasion
  - cloud
  - linux
  - azure
vendors:
  - Microsoft
products:
  - Azure Linux Agent
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: Adversaries can scrape WireServer certificates, mint a LinuxTransport identity, and decrypt extension protectedSettings.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1140
    technique_name: Deobfuscate/Decode Files or Information
    evidence: Adversaries... decrypt extension protectedSettings with openssl cms -decrypt or smime -decrypt.
    confidence_band: high
references:
  - https://cybercx.com.au/blog/azure-ssrf-metadata/
  - https://www.netspi.com/blog/technical-blog/cloud-pentesting/decrypting-vm-extension-settings-with-azure-wireserver/
  - https://cloud.google.com/blog/topics/threat-intelligence/escalating-privileges-azure-kubernetes-services
  - https://gtfobins.github.io/gtfobins/openssl/
iocs:
  - type: ip
    value: 168.63.129.16
ioc_counts:
  ip: 1
rules:
  - title: Detect Anomalous OpenSSL CMS Decryption or LinuxTransport Generation
    description: Detects OpenSSL performing CMS/PKCS7 decryption or generating certificates with /CN=LinuxTransport outside of the expected Azure Linux Agent execution path.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1140
      - T1552.005
    data_sources:
      - process_creation
      - linux
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy OpenSSL detection rule to environment.
      owner: Detection Engineering
      due: 48h
      evidence: Source provides explicit rule logic for identifying WireServer abuse.
  enrichment_needed:
    - item: StorageRead logs
      owner: SOC
      reason: Check for anonymous or SAS GetBlob requests following detected decryption attempts.
      evidence: Investigation guide note.
  hunt_leads:
    - lead: Search for generated key files like temp.key or wireserver.key in /tmp.
      technique_id: T1140
      data_needed:
        - File system auditing or EDR file creation events.
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Suggested investigation step in source.
  mitigation_plan:
    - priority: immediate
      action: Rotate VM managed identity and secrets found in protectedSettings.
      owner: IT Operations
      addresses: Credential access TTPs
      evidence: Response and remediation section.
---

Adversaries are targeting Azure virtual machines by exploiting the WireServer metadata service (accessible at 168.63.129.16) to gain unauthorized access to sensitive VM extension settings. By using the OpenSSL binary to generate certificates with the common name (CN) of 'LinuxTransport' or by using custom keys to decrypt CMS/PKCS7-encoded blobs, attackers can bypass the intended security controls of the Azure Linux Agent. This activity allows the retrieval of plaintext credentials, such as Shared Access Signature (SAS) tokens, database connection strings, and contents of custom script extensions. The attack is significant because it allows for privilege escalation and further movement within the cloud environment by extracting secrets managed by the VM extension framework. Defenders should focus on identifying OpenSSL invocations that perform cryptographic operations against metadata-related payloads without the expected provenance of the Azure Linux Agent.

## Attack Chain

1. Attacker establishes initial access on an Azure virtual machine, typically via an interactive shell or a malicious Run Command execution.
2. Attacker uses a locally available OpenSSL binary to generate a self-signed X.509 certificate with the Subject common name set to '/CN=LinuxTransport'.
3. Attacker interacts with the Azure WireServer metadata endpoint (168.63.129.16) to register the newly minted public certificate via the 'comp=certificates' component.
4. Attacker retrieves the target protectedSettings payload from the metadata service.
5. Attacker locates or generates a private key file (e.g., 'wireserver.key' or 'temp.key') to facilitate decryption.
6. Attacker invokes 'openssl cms -decrypt' or 'openssl smime -decrypt' using the retrieved blob and the unauthorized private key.
7. Attacker parses the resulting plaintext output to extract secrets, connection strings, and SAS tokens.
8. Attacker uses extracted credentials to access secondary cloud storage or database resources for further exfiltration or privilege escalation.

## Impact

Successful exploitation leads to the compromise of sensitive credentials stored within Azure VM extension configurations. This can expose SAS tokens providing storage account access, database connection strings, and embedded scripts, facilitating lateral movement and privilege escalation across the cloud environment.

## Recommendation

- Deploy the provided detection rule to identify anomalous OpenSSL activity and audit process execution paths.
- Review all VM extension configurations for unnecessary secrets and ensure managed identities are used instead of static connection strings.
- Rotate secrets, including SAS tokens and managed identity credentials, if signs of unauthorized decryption are observed.
- Isolate compromised VMs and purge attacker-created artifacts such as 'temp.key' or 'wireserver.key' files from /tmp or other temporary directories.
