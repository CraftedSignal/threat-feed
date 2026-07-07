---
title: Microsoft Security Updates — July 2026
slug: 2026-07-microsoft-security-updates
description: Roundup of Microsoft security advisories published in July 2026.
date: "2026-07-03T10:31:01Z"
lastmod: "2026-07-07T07:36:26Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:microsoft:edge_chromium:*:*:*:*:-:*:*:*
tags:
  - roundup
vendors:
  - Microsoft
  - Simon Tatham
  - VMware
  - Omnissa
  - SysAid
  - IGEL
  - Elastic
products:
  - PowerShell
  - Windows
  - Outlook
  - .NET
  - Windows Defender
  - Windows PowerShell
  - AppLocker
  - Windows Protected Storage Service
  - SharePoint
  - Microsoft SQL Server
  - Microsoft Graph API
  - Microsoft Entra ID
  - Microsoft 365
  - Remote Desktop Protocol
  - Windows OpenSSH
  - Plink
  - Azure AD Graph
  - Entra ID
  - SMB (Windows File Sharing)
  - Microsoft Teams
  - Quick Assist
  - Microsoft Edge (Chromium-based)
  - Edge (Chromium-based)
  - Microsoft Edge for Android
  - Edge for Android
  - Microsoft Edge (Chromium-based) < 150.0.4078.48
  - Microsoft Edge (Chromium-based) (< 150.0.4078.48)
  - nslookup.exe
  - Microsoft Identity Platform
  - Windows Command Prompt
  - PowerShell Core
  - Local Security Authority Subsystem Service (LSASS)
  - Active Directory Certificate Services
  - Active Directory
  - Windows kernel
  - VMware View
  - Horizon
  - SysAidServer
  - IGEL RemoteManager
  - Elastic Defend
  - Sysmon
  - Microsoft Authentication Broker
  - Exchange Online
  - Microsoft Graph
  - SSH SFTP server
affected_os:
  - Windows
  - macOS
  - Linux
  - Android
cves:
  - id: CVE-2026-57977
    cvss: 7.1
    epss: 0.00406
  - id: CVE-2026-57983
    cvss: 8.7
    epss: 0.00464
  - id: CVE-2026-58292
    cvss: 7.5
    epss: 0.00285
  - id: CVE-2026-57992
    cvss: 7.5
    epss: 0.00438
  - id: CVE-2026-58284
    cvss: 8.3
    epss: 0.00414
  - id: CVE-2026-58297
    cvss: 7.1
    epss: 0.00316
  - id: CVE-2026-57985
    cvss: 7.6
    epss: 0.00419
  - id: CVE-2026-58283
    cvss: 8.1
    epss: 0.00406
  - id: CVE-2026-58287
    cvss: 8.3
    epss: 0.00448
references:
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/powershell_pinvoke_process_injection_api_chain.yml
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/registry_keys_used_for_persistence.yml
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/executables_or_script_creation_in_temp_path.yml
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/windows_disable_or_modify_tools_via_taskkill.yml
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/windows_powershell_cryptography_namespace.yml
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/windows_process_injection_remote_thread.yml
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/windows_suspicious_process_file_path.yml
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/windows_unsecured_outlook_credentials_access_in_registry.yml
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/windows_system_network_connections_discovery_netsh.yml
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/powershell_environment_variable_execution.yml
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/powershell_loading_dotnet_into_memory_via_reflection.yml
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/powershell_processing_stream_of_data.yml
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/powershell_remove_windows_defender_directory.yml
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/powershell_windows_defender_exclusion_commands.yml
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/windows_powershell_import_applocker_policy.yml
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/windows_powershell_logoff_user_via_quser.yml
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/credential_access_protected_storage_service_access.toml
  - https://sploitus.com/exploit?id=816BFD0D-57FA-5C9C-B54C-3F0F88BD2C84&utm_source=rss&utm_medium=rss
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/initial_access_mssql_potential_sql_injection.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/azure/collection_graph_email_access_by_unusual_public_client_via_graph.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/network/command_and_control_rdp_remote_desktop_protocol_from_the_internet.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/command_and_control_openssh_reverse_port_forwarding.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/azure/initial_access_aad_graph_unusual_asn.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/network/initial_access_rpc_remote_procedure_call_from_the_internet.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/network/initial_access_smb_windows_file_sharing_activity_to_the_internet.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/defense_evasion_amsi_bypass_rpc_ndrclientcall.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/o365/initial_access_teams_rogue_helpdesk_chat.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/command_and_control_quick_assist_fullcontrol_sharing.toml
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-56645
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-57985
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-57987
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-57988
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-57992
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-57993
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-58282
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-58283
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-58522
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-57974
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-57977
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-57981
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-57986
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-58276
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-58278
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-58285
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-58286
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-58289
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-58293
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-58294
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-58298
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-58300
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-58291
  - https://nvd.nist.gov/vuln/detail/CVE-2026-57975
  - https://nvd.nist.gov/vuln/detail/CVE-2026-57983
  - https://nvd.nist.gov/vuln/detail/CVE-2026-57984
  - https://nvd.nist.gov/vuln/detail/CVE-2026-57991
  - https://nvd.nist.gov/vuln/detail/CVE-2026-58284
  - https://nvd.nist.gov/vuln/detail/CVE-2026-58287
  - https://nvd.nist.gov/vuln/detail/CVE-2026-58288
  - https://nvd.nist.gov/vuln/detail/CVE-2026-58290
  - https://nvd.nist.gov/vuln/detail/CVE-2026-58292
  - https://nvd.nist.gov/vuln/detail/CVE-2026-58295
  - https://nvd.nist.gov/vuln/detail/CVE-2026-58296
  - https://nvd.nist.gov/vuln/detail/CVE-2026-58297
  - https://nvd.nist.gov/vuln/detail/CVE-2026-58299
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/command_and_control_dns_tunneling_nslookup.toml
  - https://securelist.com/microsoft-device-code-phishing-attack/120350/
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/create_remote_thread_in_shell_application.yml
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/create_remote_thread_into_lsass.yml
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/powershell_remote_thread_to_known_windows_process.yml
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/windows_uncommon_remote_thread_creation_in_browser_process.yml
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/petitpotam_suspicious_kerberos_tgt_request.yml
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/defense_evasion_untrusted_driver_loaded.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/lateral_movement_credential_access_kerberos_correlation.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/azure/initial_access_entra_id_oauth_device_code_phishing_tycoon_aitm.toml
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-55952
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-54886
iocs:
  - type: url
    value: https://www.microsoft.com/security/blog/2022/01/15/destructive-malware-targeting-ukrainian-organizations/
  - type: url
    value: https://tccontre.blogspot.com/2020/01/remcos-rat-evading-windows-defender-av.html
  - type: url
    value: https://app.any.run/tasks/cf1245de-06a7-4366-8209-8e3006f2bfe5/
  - type: url
    value: https://app.any.run/tasks/a6f2ffe2-e6e2-4396-ae2e-04ea0143f2d8/
  - type: url
    value: https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/import_applocker_policy/windows-powershell-xml2.log
  - type: url
    value: https://devblogs.microsoft.com/scripting/automating-quser-through-powershell/
  - type: url
    value: https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1531/log_off_user/pwh_quser_logoff.log
  - type: url
    value: https://sploitus.com/exploit?id=816BFD0D-57FA-5C9C-B54C-3F0F88BD2C84
  - type: domain
    value: sharepoint.local
  - type: url
    value: http://127.0.0.1:8080
  - type: domain
    value: graph.windows.net
  - type: url
    value: https://github.com/andreisss/Ghosting-AMSI
  - type: domain
    value: nvd.nist.gov
  - type: domain
    value: msrc.microsoft.com
  - type: url
    value: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-57983
  - type: email
    value: nvd@nist.gov
  - type: email
    value: soc@us-cert.gov
  - type: url
    value: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-58288
  - type: url
    value: https://nvd.nist.gov
  - type: url
    value: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-58292
  - type: domain
    value: nist.gov
  - type: domain
    value: microsoft.com
  - type: url
    value: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-58297
  - type: url
    value: https://microsoft.com/devicelogin
  - type: url
    value: https://login.microsoftonline.com/{tenant}/oauth2/v2.0/devicecode
  - type: url
    value: https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token
  - type: url
    value: https://2017.zeronights.org/wp-content/uploads/materials/ZN17_Kheirkhabarov_Hunting_for_Credentials_Dumping_in_Windows_Environment.pdf
  - type: url
    value: https://twitter.com/pr0xylife/status/1585612370441031680?s=46&t=Dc3CJi4AnM-8rNoacLbScg
  - type: url
    value: https://thedfirreport.com/2023/06/12/a-truly-graceful-wipe-out/
  - type: url
    value: https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/qakbot/qbot_wermgr2/sysmon_wermgr2.log
  - type: url
    value: https://github.com/its-a-feature/bifrost
ioc_counts:
  domain: 6
  email: 2
  url: 23
updates:
  - at: "2026-07-06T15:08:10Z"
    level: L2
    summary: added CVE-2026-57974 +4
    sources:
      - elastic
  - at: "2026-07-06T15:08:30Z"
    level: L2
    summary: added CVE-2026-57975 +3
    sources:
      - elastic
  - at: "2026-07-06T20:27:20Z"
    level: L2
    summary: added CVE-2026-57977 +1
    sources:
      - elastic
  - at: "2026-07-07T07:36:14Z"
    level: L2
    summary: added CVE-2026-57983 +3
    sources:
      - msrc
  - at: "2026-07-07T07:36:26Z"
    level: L2
    summary: added CVE-2026-57985 +3
    sources:
      - msrc
---

Aggregated Microsoft security advisories for July 2026. CVEs from this cycle are folded
into the list below as they are published.

## Recommendation

Review affected products and apply Microsoft's July 2026 security updates.
