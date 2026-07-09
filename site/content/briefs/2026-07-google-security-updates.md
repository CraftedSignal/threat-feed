---
title: Google Security Updates — July 2026
slug: 2026-07-google-security-updates
description: Roundup of Google security advisories published in July 2026.
date: "2026-07-03T10:41:13Z"
lastmod: "2026-07-09T17:39:04Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:golang:crypto:*:*:*:*:*:go:*:*
tags:
  - roundup
vendors:
  - Google
  - Red Hat
  - Brave Software
  - Opera
  - Vivaldi Technologies
  - Microsoft
  - Mozilla
  - Splunk
  - Opera Software
  - Elastic
products:
  - golang.org/x/crypto/ssh (< 0.52.0)
  - golang.org/x/crypto/ssh < 0.52.0
  - golang.org/x/crypto/ssh/agent < 0.52.0
  - golang.org/x/image (< 0.41.0)
  - Chrome
  - Brave
  - Opera
  - Vivaldi
  - Microsoft Edge
  - Google Chrome
  - Brave Browser
  - Mozilla Firefox
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Opera Browser
  - Vivaldi Browser
  - Edge
  - Firefox
  - Chromium
  - Google Workspace
  - Google Drive
  - Google Docs
  - Google Sheets
  - Google Forms
  - Google Apps Script
  - Google Workspace Marketplace
  - Google Workspace Drive
  - GCP
  - Google Kubernetes Engine
  - GKE
  - GCP Audit Logs
  - Kubernetes API
  - Kubernetes
  - Google Cloud Platform
  - Google Kubernetes Engine (GKE)
  - Google Cloud Platform (GCP) Audit Logs
  - Android (<= 2026-07-06)
  - Dialogflow CX <= 2026-06-30
  - Cloud Run <= 2026-06-30
  - Chrome (< 150.0.7871.114)
  - Chrome (< 150.0.7871.115)
  - Google Chrome (for Windows and macOS < 150.0.7871.115)
  - Google Chrome (for Linux < 150.0.7871.114)
affected_os:
  - Windows
  - Linux
  - Android
  - macOS
cves:
  - id: CVE-2026-39830
    cvss: 9.1
    epss: 0.00513
  - id: CVE-2026-46599
    cvss: 7.5
    epss: 0.00353
  - id: CVE-2026-15109
  - id: CVE-2026-15110
    cvss: 8.8
  - id: CVE-2026-15122
    cvss: 8.3
references:
  - https://github.com/advisories/GHSA-rm3j-f69w-wqmq
  - https://github.com/advisories/GHSA-vgwf-h737-ff37
  - https://github.com/advisories/GHSA-jppx-rxg9-jmrx
  - https://github.com/advisories/GHSA-q675-qj96-32m9
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/headless_browser_usage.yml
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/windows_browser_process_launched_with_unusual_flags.yml
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/windows_chromium_browser_no_security_sandbox_process.yml
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/windows_chromium_browser_with_custom_user_data_directory.yml
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/windows_credentials_from_password_stores_chrome_copied_in_temp_dir.yml
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/windows_credentials_from_password_stores_chrome_extension_access.yml
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/windows_credentials_from_password_stores_chrome_localstate_access.yml
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/windows_credentials_from_password_stores_chrome_login_data_access.yml
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/windows_disable_or_stop_browser_process.yml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/google_workspace/initial_access_google_workspace_login_impossible_travel.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/google_workspace/defense_evasion_google_workspace_new_oauth_login_from_third_party_application.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/google_workspace/persistence_google_workspace_api_access_granted_via_dwd.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/google_workspace/initial_access_object_copied_to_external_drive_with_app_consent.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/google_workspace/persistence_application_added_to_google_workspace_domain.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/google_workspace/credential_access_google_workspace_drive_encryption_key_accessed_by_anonymous_user.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/google_workspace/defense_evasion_domain_added_to_google_workspace_trusted_domains.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/google_workspace/impact_google_workspace_mfa_enforcement_disabled.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/google_workspace/persistence_google_workspace_2sv_policy_disabled.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/google_workspace/persistence_google_workspace_password_policy_modified.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/google_workspace/persistence_mfa_disabled_for_google_workspace_organization.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/gcp/credential_access_gcp_gke_secret_access_suspicious_user_agent.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/gcp/credential_access_gcp_gke_secrets_list_unusual_source_asn.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/gcp/discovery_gcp_gke_api_request_failure_burst.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/gcp/discovery_gcp_gke_suspicious_self_subject_review.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/gcp/execution_gcp_gke_user_exec_into_pod.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/gcp/persistence_gcp_gke_admission_webhook_created_or_modified.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/gcp/persistence_gcp_gke_cluster_admin_role_binding.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/gcp/privilege_escalation_gcp_gke_excessive_linux_capabilities.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/gcp/privilege_escalation_gcp_gke_pod_host_network.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/gcp/privilege_escalation_gcp_gke_pod_host_pid.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/gcp/privilege_escalation_gcp_gke_privileged_pod_created.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/gcp/privilege_escalation_gcp_gke_sensitive_hostpath_volume.toml
  - https://cyber.gc.ca/en/alerts-advisories/android-security-advisory-july-2026-monthly-rollup-av26-662
  - https://www.darkreading.com/application-security/dialogflow-cx-rogue-agent-flaw-enabled-ai-chatbot-data-theft
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0848/
  - https://cyber.gc.ca/en/alerts-advisories/google-chrome-security-advisory-av26-679
iocs:
  - type: url
    value: https://www.recordedfuture.com/research/from-castleloader-to-castlerat-tag-150-advances-operations
  - type: url
    value: https://peter.sh/experiments/chromium-command-line-switches/
  - type: url
    value: https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1185/browser_unusual_flag/castle_chrome_shell32.log
  - type: file_name
    value: Local State
  - type: file_name
    value: Login Data
  - type: file_path
    value: '*\temp\*'
  - type: url
    value: https://malpedia.caad.fkie.fraunhofer.de/details/win.redline_stealer
  - type: file_path
    value: '*\AppData\Local\Google\Chrome\User Data\Default\Login Data'
  - type: url
    value: https://x.com/suyog41/status/1825869470323056748
  - type: url
    value: https://g0njxa.medium.com/from-vietnam-to-united-states-malware-fraud-and-dropshipping-98b7a7b2c36d
  - type: domain
    value: apps.googleusercontent.com
  - type: url
    value: https://support.google.com/a/answer/175197
  - type: url
    value: https://support.google.com/a/answer/7587183
  - type: url
    value: https://support.google.com/a/answer/7061566
  - type: url
    value: https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-module-google_workspace.html
  - type: url
    value: https://www.elastic.co/security-labs/google-workspace-attack-surface-part-one
  - type: url
    value: https://www.elastic.co/security-labs/google-workspace-attack-surface-part-two
ioc_counts:
  domain: 1
  file_name: 2
  file_path: 2
  url: 12
updates:
  - at: "2026-07-06T16:55:29Z"
    level: L2
    summary: google kubernetes engine version GKE; google cloud platform version GCP) Audit Logs
    sources:
      - elastic
  - at: "2026-07-07T15:42:30Z"
    level: L1
    summary: OS android
    sources:
      - cccs
  - at: "2026-07-07T20:56:10Z"
    level: L1
    summary: new product
    sources:
      - dark-reading
  - at: "2026-07-09T14:29:38Z"
    level: L2
    summary: added CVE-2026-15109 +2; chrome version < 150.0.7871.115; OS macos
    sources:
      - anssi
    source_urls:
      - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0848/
  - at: "2026-07-09T17:39:04Z"
    level: L2
    summary: google chrome version for Linux < 150.0.7871.114
    sources:
      - cccs
    source_urls:
      - https://cyber.gc.ca/en/alerts-advisories/google-chrome-security-advisory-av26-679
---

Aggregated Google security advisories for July 2026. CVEs from this cycle are folded
into the list below as they are published.

## Recommendation

Review affected products and apply Google's July 2026 security updates.
