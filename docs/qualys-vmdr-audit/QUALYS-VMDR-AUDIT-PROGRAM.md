# Qualys VMDR Deployment — Read-Only Audit Program

| Item | Value |
|---|---|
| Document | Audit program: review of an existing Qualys VMDR deployment and associated Qualys Cloud Platform modules |
| Version | 1.0 (template, ready for engagement-specific tailoring) |
| Access model | **Read-only throughout.** No procedure in this program requires create, edit, delete, launch, purge, approve or assign rights |
| Audience | Audit lead, Qualys SME auditors, platform owner (auditee), CISO / audit sponsor |
| Placeholders | `<ORG>`, `<POD>` (Qualys platform, e.g. US1/EU2/…), `<AUDIT-USER>`, `<PERIOD>` — replace before issue |

> **How to use this program.** Sections 1–3 are set once per engagement. Section 4 is the role configuration that must be in
> place before fieldwork (do Section 7, the pre-audit access requests, first). Section 5 is the executable test program: every
> procedure carries its criteria reference, steps, evidence, the read-only view it needs, and a pass/fail threshold.
> Sections 6 and 8 cover responsibilities and reporting. Appendices hold the evidence register, API read calls and QQL queries.
>
> **Version note.** Qualys renames menus and permission labels between platform releases. Navigation paths and permission
> names below match the current UI conventions (VMDR / CSAM / Administration utility) but are marked *indicative*; the
> pre-audit visibility check (PA-02) confirms each one in `<ORG>`'s subscription before fieldwork starts.

---

## Contents

1. [Audit objectives](#1-audit-objectives)
2. [Audit scope](#2-audit-scope)
3. [Audit criteria (standards and baselines)](#3-audit-criteria-standards-and-baselines)
4. [Read-only role and access configuration](#4-read-only-role-and-access-configuration)
5. [Audit procedures](#5-audit-procedures)
   - 5.0 Pre-audit and governance (PA, GV)
   - 5.1 Asset management (AM)
   - 5.2 Scanning and detection (SD)
   - 5.3 Remediation workflow (RW)
   - 5.4 Policy Compliance / Policy Audit and compensating controls (PC)
   - 5.5 Web Application Scanning and other modules (WA, MX)
   - 5.6 Reporting and compliance (RC)
6. [Roles and responsibilities](#6-roles-and-responsibilities)
7. [Pre-audit access requests (prioritised)](#7-pre-audit-access-requests-prioritised)
8. [Reporting and follow-up](#8-reporting-and-follow-up)
9. [Appendices](#9-appendices)

---

## 1. Audit objectives

The audit gives `<ORG>` management independent assurance, as at the audit date and over `<PERIOD>`, on the following:

| # | Objective | Question the audit answers |
|---|---|---|
| O1 | **Configuration integrity** | Is the Qualys subscription (users, scanners, agents, option profiles, authentication, tags, KnowledgeBase customisations, policies) configured in line with Qualys vendor-recommended baselines and `<ORG>` policy, and protected against unauthorised change? |
| O2 | **Coverage and asset accuracy** | Does the Qualys asset inventory reconcile to `<ORG>`'s authoritative inventories (CMDB, AD, cloud accounts, DHCP/IPAM, EDR), with stale and duplicate records controlled? |
| O3 | **Detection effectiveness** | Do scans and agents run as scheduled, authenticate successfully, use appropriate option profiles, and produce complete, current detection data? |
| O4 | **Risk prioritisation** | Are TruRisk, Asset Criticality Scores (ACS), tags and severity customisations tuned so that prioritisation reflects business risk rather than defaults? |
| O5 | **Remediation operational effectiveness** | Are findings routed, tracked, remediated (patch jobs, mitigations) and closed within `<ORG>`'s SLAs, with exceptions and compensating controls approved, time-bound and reviewed? |
| O6 | **Compliance alignment** | Are Policy Compliance / Policy Audit policies aligned with current CIS benchmarks (and other mandated frameworks), with posture, exceptions and evidence suitable for ISO 27001, PCI DSS or other external assessment? |
| O7 | **Reporting reliability** | Do dashboards and executive reports reflect the underlying data accurately and completely, and are compliance evidence packages reproducible? |
| O8 | **Governance of the platform itself** | Are access to Qualys, API use, integrations and change activity governed (least privilege, SSO/MFA, joiner–mover–leaver, activity log review)? |

---

## 2. Audit scope

### 2.1 In scope — Qualys modules and subscription features

Tick what `<ORG>` has licensed (Help → About / Account Info, or Administration → Subscription). Unlicensed modules are recorded
as "not licensed" in the scope memo, not silently skipped.

| Area | Modules / features | Primary procedures |
|---|---|---|
| Core VM | **VMDR** (Vulnerability Management, Detection and Response), VM legacy UI (scans, maps, reports, remediation tickets), KnowledgeBase, Search Lists, Asset Groups, Option Profiles, Authentication records, Scanner Appliances (physical, virtual, cloud), Networks | AM, SD, RW, RC |
| Asset inventory | **CyberSecurity Asset Management (CSAM)** / Global AssetView, tagging engine, EASM (external attack surface), EOL/EOS data, asset criticality | AM |
| Agents | **Cloud Agent** (Windows, Linux, macOS, Unix), activation keys, configuration profiles, agent modules (VM, PC, Inventory, PM, EDR, FIM, SCA) | SD-06/07 |
| Prioritisation | **TruRisk** scoring (TruRisk Score, QDS, ACS), VMDR Prioritization, Threat Intelligence (RTIs) | AM-06, RW-01 |
| Remediation | **Patch Management** (deployment jobs, patch catalog), **TruRisk Mitigate / Eliminate** (mitigation and isolation actions, where licensed), VM remediation policies & tickets, **ITSM integration** (e.g. ServiceNow Vulnerability Response / ITSM connector, Jira) | RW |
| Exceptions | VMDR exception management, VM "ignored" vulnerabilities and ticket ignores, KnowledgeBase disabled QIDs / custom severities, PC exceptions | RW-05/06, PC-04 |
| Compliance | **Policy Compliance (PC)** / **Policy Audit**, Security Configuration Assessment (SCA), mandates library (CIS, DISA STIG), Custom Assessment and Remediation (CAR), PCI ASV (if used) | PC, RC-05 |
| Web | **Web Application Scanning (WAS)**, WAF (if licensed) | WA |
| Other modules (if licensed) | TotalCloud / CloudView (CSPM), Container Security, EDR, FIM, CertView, Unified Dashboard (UD) | MX |
| Platform | Administration utility (users, roles, scopes), Unified Dashboard, connectors (AWS/Azure/GCP, ServiceNow, SIEM), API usage, subscription security settings, activity log | GV |

### 2.2 In scope — assets and infrastructure

- **Asset groups and tags:** all asset groups and all tags (business unit, environment, criticality, OS, owner, cloud). No
  asset group is excluded unless listed in 2.3 with a reason.
- **Scan infrastructure:** every scanner appliance (internal virtual/physical, cloud, external Qualys scanners), all
  scheduled scans, maps and agent configuration profiles.
- **Business units:** all Qualys business units (BUs) and their Unit Managers.
- **Period:** detection and remediation testing covers `<PERIOD>` (recommended: the trailing 90 days for operational
  metrics, trailing 12 months for exceptions, users and activity log).

### 2.3 Out of scope / limitations

- Operation of systems outside Qualys (e.g. the effectiveness of the patching tool itself if not Qualys PM, ServiceNow
  workflow beyond the integration hand-off). Integration hand-off points remain in scope.
- Re-performance by launching scans, deploying patches, editing tags or approving exceptions — **excluded by design**
  (read-only constraint). Where re-performance is needed, the auditee performs it under observation (see 4.6).
- Penetration testing or validation of individual vulnerability findings on endpoints (sample-based "false
  positive/negative" checks are limited to comparing Qualys data with other read-only sources).

### 2.4 Read-only statement

> All fieldwork is performed with a dedicated, named, read-only Qualys account (`<AUDIT-USER>`) configured per Section 4.
> The auditor will not create, modify, delete, launch, purge, approve, assign or schedule any Qualys object. Downloading
> existing list views, reports and configuration exports, and calling **read** (list/search/get/export) API actions, are
> permitted. Any evidence that the read-only role cannot see is produced by the auditee's Qualys administrator under
> auditor observation (4.6). The account is disabled at the close of fieldwork (PA-05).

**Definition of "read-only" for this program.** Permitted: view, list, search, download, export of existing objects.
Not permitted: any action that changes configuration, asset data, scan/agent state, tickets, policies, exceptions, users
or subscription settings. Generating a **new** report or dashboard creates an object in Report Share / Unified Dashboard;
this program therefore uses (a) existing scheduled reports, (b) UI list downloads and API reads, or (c) auditee-generated
reports under observation. On-demand report generation by `<AUDIT-USER>` is allowed **only** if the engagement letter
explicitly classes report output as a non-configuration artifact (record the decision in PA-01).

---

## 3. Audit criteria (standards and baselines)

Each procedure in Section 5 cites one or more of the criteria IDs below. "V" = Qualys vendor-documented recommendation
(Qualys user guides, best-practice guides, Qualys Training/Certification material, Qualys Community best-practice
articles); "F" = external framework; "P" = `<ORG>` internal policy; "A" = auditor-proposed default threshold to be
confirmed or replaced by `<ORG>` policy during planning.

### 3.1 Qualys vendor-recommended configuration baselines (V)

| ID | Baseline area | Vendor-recommended practice (summary) |
|---|---|---|
| V-01 | Authenticated scanning | Use authenticated (trusted) scanning for all hosts that support it; maintain authentication records per platform (Windows, Unix/SSH, databases, VMware, network devices); prefer vault integration (CyberArk, HashiCorp, Thycotic/Delinea, etc.) over stored passwords; monitor authentication results via the Authentication Report and authentication QIDs (e.g. QID 105015 Windows Authentication Failed) and fix failures. |
| V-02 | Agent-first for endpoints and cloud | Deploy Cloud Agent on servers, workstations and cloud workloads, especially intermittently connected or remote devices; use network scanners for unagentable assets (network devices, appliances, OT/IoT) and for "outside-in" coverage; keep agents current (auto-update) and checking in. |
| V-03 | Agent configuration profiles | Separate configuration profiles by asset class (servers vs workstations, critical vs standard); enable the required modules (VM, PC, Inventory, PM) via activation keys; set performance level and blackout windows appropriately; avoid a single all-purpose default profile in large estates. |
| V-04 | Option profiles | Use dedicated option profiles per purpose (discovery / inventory, authenticated vulnerability, PCI, compliance); enable authentication; use a port scope appropriate to the target (Standard vs Full/"light" vs targeted); avoid running unauthenticated "Initial Options"-style defaults as the production vulnerability profile; review performance settings (parallel hosts/processes) against network capacity. |
| V-05 | Scanner appliance health | Keep appliances online, on current software/signature versions (auto-update), sized for target counts, placed so that they scan without NAT/firewall interference; use Networks/VLAN/static-route configuration where address space overlaps. |
| V-06 | Scheduling and cadence | Schedule recurring scans (at least weekly authenticated VM for servers; continuous via agent); avoid gaps from schedule overlaps, expired schedules, or scans that repeatedly end "Paused/Cancelled/Interrupted"; use discovery maps to find unmanaged assets. |
| V-07 | Asset tracking and data hygiene | Choose the host-tracking method that suits the network (IP / DNS / NetBIOS; agent ID for agents); configure **purge rules** for hosts not scanned/checked-in within a defined period; correlate agent and scanner data for the same host (unified asset view / agent correlation) to avoid duplicates; maintain asset groups/tags as the scan-target basis. |
| V-08 | Tagging strategy | Use dynamic, rule-based tags (QQL, OS, network range, cloud metadata, software) over static tags; establish a tag hierarchy (business unit, environment, owner, criticality); use tags for scope in VMDR, PC, PM, dashboards and RBAC. |
| V-09 | TruRisk tuning | Assign **Asset Criticality Score (ACS, 1–5)** through business-criticality tags; review TruRisk Score (0–1000) and Qualys Detection Score (QDS, 1–100) inputs; configure TruRisk weighting/customisation where business context requires; prioritise using Real-Time Threat Indicators (RTIs: active exploitation, ransomware, CISA KEV, etc.) rather than CVSS/severity alone. |
| V-10 | KnowledgeBase customisation control | Changes to QID severity (custom severity), **disabled QIDs**, and search lists affect what all users see; customisations should be documented, justified, minimal, and reviewed periodically. |
| V-11 | Remediation workflow | Use VMDR Prioritization and Patch Management (or integrate with the patching tool); use remediation policies/ticketing or ITSM integration to assign ownership; close the loop with re-scan/agent re-assessment; use **TruRisk Mitigate** or documented mitigations where a patch is unavailable. |
| V-12 | Exception management | Exceptions (VMDR exceptions, PC exceptions, ignored vulnerabilities) should carry justification, approver, compensating control, and **expiration date**; expired exceptions should be reviewed; exceptions must not be used to hide un-remediated risk from reports without trace. |
| V-13 | Policy Compliance / Policy Audit | Build policies from the Qualys **mandate/CIS library** (current benchmark version for the deployed OS), set control criticality, use authentication records shared with VM, review posture trends, use PC exceptions with expiry, and use the vendor-provided **remediation / mitigation guidance** in each control (see 3.2). |
| V-14 | Users and RBAC | Least privilege: minimum number of Managers; use Unit Managers / business units and tag-scoped roles in the Administration utility; enable **SSO (SAML)** and/or **two-factor authentication**; set password policy, session timeout and **IP allow-listing** for UI/API; disable inactive users; use dedicated API service accounts with minimum role. |
| V-15 | Reporting and dashboards | Base dashboards and reports on documented QQL / templates with consistent filters; schedule reports with restricted distribution; secure (encrypted PDF) delivery for sensitive reports; retain report share in line with policy; use Unified Dashboard templates (VMDR, TruRisk, PC) as a reference baseline. |
| V-16 | Integrations and connectors | Cloud connectors (AWS/Azure/GCP) should cover all accounts/subscriptions/projects with least-privilege IAM roles and healthy sync status; ITSM/SIEM connectors should run without sync errors; API credentials should be scoped and rotated. |
| V-17 | WAS | Maintain complete web-application inventory, use authentication records for authenticated crawling, define crawl scope and exclusions, schedule recurring scans, review findings by severity and retest after fixes. |
| V-18 | Subscription change auditability | Review the **Activity Log** (and Administration audit logs) for configuration changes, user changes and scan/report activity. |

> **Vendor baseline evidence.** For each V-item tested, the workpaper records the specific Qualys document (title, version or
> date, URL/section) used as the baseline at the time of fieldwork, because Qualys revises guidance with each release. The
> Qualys SME auditor captures this list in workpaper WP-00 during planning.

### 3.2 Vendor-suggested mitigation and compensating controls (Policy Compliance / Policy Audit and VMDR)

| ID | Source within Qualys | What the audit expects |
|---|---|---|
| M-01 | **Control-level remediation text** in PC / Policy Audit controls (from CIS/DISA/Qualys library content) | Failed controls have a remediation action, or an exception that references a compensating control. |
| M-02 | **PC exceptions** (request → approve/reject, with expiry, comments, status history) | Every active PC exception has business justification, approver independent of requester, defined compensating control, expiry ≤ policy maximum (A: 12 months), and periodic review. |
| M-03 | **KnowledgeBase "Solution", "Workaround/Mitigation" and Threat Intelligence fields** per QID, and **TruRisk Mitigate** mitigation actions (where licensed) | For vulnerabilities with no patch or a deferred patch, the documented compensating control maps to a vendor-provided mitigation/workaround, and its application is verified (e.g. control evidence, mitigation job status, configuration QID). |
| M-04 | **VMDR exceptions / ignored vulnerabilities** with comment and expiry | Same attributes as M-02; no permanent ignores without approval. |
| M-05 | **Policy Audit / SCA control "compensating" status and evidence** (e.g. control status reasons, evidence attachments) | Compensating-control claims are evidenced, not just asserted. |

### 3.3 External frameworks (F) — apply those relevant to `<ORG>`

| ID | Framework | Relevant clauses / controls (examples) |
|---|---|---|
| F-01 | **ISO/IEC 27001:2022** Annex A | A.5.9 inventory of assets, A.5.15/5.18 access control & access rights, A.8.2 privileged access, A.8.8 management of technical vulnerabilities, A.8.9 configuration management, A.8.15/8.16 logging & monitoring, A.8.32 change management, A.5.36 compliance with policies |
| F-02 | **CIS Critical Security Controls v8.1** | CIS 1 (enterprise asset inventory), 2 (software inventory), 4 (secure configuration), 5/6 (account & access control), 7 (continuous vulnerability management — 7.1–7.7), 8 (audit log management), 16.x (application software security, for WAS) |
| F-03 | **CIS Benchmarks** | Current benchmark version per deployed OS/application; Level 1/Level 2 profile chosen by `<ORG>` |
| F-04 | **NIST SP 800-53 Rev.5 / NIST CSF 2.0** (if used) | RA-5 vulnerability monitoring & scanning (incl. RA-5(5) privileged access), CM-6, CM-8, SI-2 flaw remediation, AC-2, AC-6, AU-6; CSF ID.AM, ID.RA, PR.PS, DE.CM |
| F-05 | **PCI DSS v4.0.1** (if cardholder data in scope) | Req. 6.3.1/6.3.3 (identify & patch), 11.3.1 (internal scans quarterly, authenticated per 11.3.1.2), 11.3.2 (external ASV scans), 2.2 (secure configuration) |
| F-06 | Regional / sector regulation (if applicable) | e.g. NCA ECC / CCC, SAMA CSF, NIS2, DORA — map vulnerability-management and configuration clauses in WP-00 |

### 3.4 Internal policy (P) and default thresholds (A)

Planning obtains `<ORG>`'s vulnerability-management standard, patching SLA, exception policy, asset-management standard,
access-control policy and configuration-hardening standard. Where `<ORG>` has no defined value, the auditor proposes the
**default thresholds** below; management confirms them before fieldwork (record in WP-00).

| ID | Metric | Default threshold (A) |
|---|---|---|
| A-01 | Authentication success rate (scanner-assessed hosts that support auth) | ≥ 95 % pass; 0 critical-tier hosts failing for > 2 consecutive scans |
| A-02 | Agent check-in | ≥ 95 % of agents checked in within 7 days; agents silent > 30 days purged or investigated |
| A-03 | Stale assets | No scanner-tracked host unscanned > 30 days in active inventory without purge/justification |
| A-04 | Inventory reconciliation | ≥ 98 % of CMDB/AD/cloud in-scope assets present in Qualys; unknown assets in Qualys investigated |
| A-05 | Duplicate assets | < 1 % duplicate records (same hostname/agent/MAC/cloud instance ID) |
| A-06 | Remediation SLA (example) | Critical / TruRisk ≥ 850 or RTI "actively exploited/CISA KEV": 15 days; High: 30 days; Medium: 90 days; Low: 180 days |
| A-07 | Exceptions | 100 % with approver, justification, compensating control and expiry ≤ 12 months; 0 expired-but-active |
| A-08 | Privileged Qualys users | Managers ≤ minimum operational need (target ≤ 3 named, non-shared); 0 inactive > 90 days; SSO or 2FA for 100 % |
| A-09 | Scanner appliances | 100 % online and on current version during sample period |
| A-10 | Scan completion | ≥ 95 % of scheduled scans finish (not cancelled / paused / interrupted / error) |

---

## 4. Read-only role and access configuration

### 4.1 Recommended configuration (summary)

`<AUDIT-USER>` = **one dedicated, named, non-shared account** with:

| Layer | Setting | Value |
|---|---|---|
| VM/VMDR/PC user role (legacy user model) | **User Role** | **Reader** |
| | **Business Unit** | **Unassigned** (global / top-level — not inside a BU, otherwise visibility is limited to that BU) |
| | **Asset Groups** | **All** (the "All" asset group), or every asset group if "All" cannot be assigned |
| | **Extended permission: "Allow user view access to all objects"** | **Enabled** — gives view access to all objects in the subscription (asset groups, scans, schedules, maps, reports, option profiles, authentication records, appliances, etc.) and not only those the user owns or is assigned |
| | All other extended permissions ("Add assets", "Create option profiles", "Purge host information/history", "Create/edit remediation policy", "Create/edit authentication records", "Manage compliance", "Manage web applications", "Manage PCI…", etc.) | **Disabled** |
| | Access | GUI = enabled; **API = enabled only if** API read evidence (Appendix B) is used; restricted to auditor source IPs |
| Administration utility (Cloud Platform RBAC — CSAM, VMDR app, Cloud Agent, PM, WAS, TotalCloud, CS, EDR, FIM, CertView, UD, PC/Policy Audit app) | **Role(s)** | The predefined **READER** role (synchronised from the VM Reader role) **plus** a custom role, e.g. **`AUDIT_READ_ONLY_ALL_MODULES`**, holding only *view/list/download/export* permissions for every licensed module (4.3) |
| | **Scope** | **Full scope** (no tag restriction). If the UI offers "Allow user view access to all objects" / "All assets" at scope level, enable it. Do **not** restrict by tag |
| Authentication | SSO (SAML) with MFA, or Qualys two-factor authentication | Mandatory |
| Lifetime | Account expiry / manual deactivation date | End of fieldwork + reporting window (e.g. +30 days) |

### 4.2 Role distinctions the audit team must understand

| Role | Module reach | Read-only? | Use in this audit |
|---|---|---|---|
| **Manager** | Entire subscription | **No** — full write | **Never** for the auditor. The auditee's Manager produces "observed" evidence (4.6). |
| **Unit Manager** | One business unit | No — manages BU users, assets, scans | Not used. |
| **Scanner** | Assigned asset groups | No — can launch scans/maps, create reports | Not used. |
| **Reader** | Assigned asset groups (VM/VMDR, PC data for those assets; WAS if web-app permission granted) | **Yes for configuration** — cannot launch scans, edit assets, policies or users; can view and (per subscription) generate reports | **Base role.** Combined with BU = Unassigned, Asset Groups = All, and "Allow user view access to all objects", it becomes a **global read-only role**. |
| **Auditor** | **Policy Compliance only** (available when PC is enabled); no VM vulnerability data | **Not strictly read-only** — Auditors can manage compliance policies, run compliance reports and handle PC exceptions | **Not recommended** as the audit account role. It is *module-specific*, lacks VM/VMDR/WAS visibility and carries PC write capability. Only consider if `<ORG>` explicitly accepts the residual write capability; otherwise PC exceptions workflow evidence is captured through Reader view plus observed export. |
| **Remediation User** | Assigned tickets only | Partially (can update own tickets) | Not used. |
| **KnowledgeBase Only** | KnowledgeBase | Yes | Not sufficient. |
| **Contact** | Notifications | n/a | Not used. |
| **Custom Administration role (`AUDIT_READ_ONLY_ALL_MODULES`)** | Any module, per permission | Yes, if built only from view permissions | **Required** for cloud apps whose RBAC is granular (CSAM, Cloud Agent, PM, WAS, TotalCloud, Container Security, EDR, FIM, CertView, UD, Policy Audit). |

**Key point — module-specific vs global.** "Auditor" is a *module-specific* (PC) role and, despite its name, is not a pure
view-only role. Full, cross-module, view-only visibility comes from **Reader + global visibility settings (Unassigned BU,
All asset groups, "Allow user view access to all objects") + a custom view-only Administration role with Full scope**.
Reader alone, left with default scope, sees only the asset groups/tags assigned to it, so an audit run with an
un-scoped Reader will under-report the estate and produce false "coverage gap" findings.

### 4.3 Custom role `AUDIT_READ_ONLY_ALL_MODULES` — permission build sheet

Build in **Administration → User Management → Roles → New Role** (indicative path). For each licensed module, select the
module's **UI access** permission and only its **view / list / search / download / export** permissions. Explicitly leave
unselected every permission containing *Create, Edit, Update, Delete, Manage, Launch, Deploy, Approve, Assign, Purge,
Uninstall, Activate, Deactivate, Execute, Isolate, Mitigate, Import*.

| Module (Administration permission group) | Grant (view-type examples) | Must NOT grant (examples) |
|---|---|---|
| CSAM / Global AssetView / Asset Management & Tagging | Asset inventory access, view assets, view tags, view EOL/EOS, view EASM findings, download/export | Create/edit/delete tag, edit asset, purge asset, edit ACS, manage connectors |
| VMDR app / VM | VMDR UI access, view vulnerabilities, view prioritization reports, view TruRisk configuration, view exceptions | Create/approve exception, edit TruRisk settings, create prioritization report jobs |
| Cloud Agent | View agents, view configuration profiles, view activation keys, download agent lists | Create/edit profile or key, activate/deactivate/uninstall agent, on-demand scan |
| Patch Management | View jobs, view job progress/results, view patch catalog, view assets | Create/edit/enable/disable job, deploy, approve, isolate |
| TruRisk Mitigate / Eliminate (if licensed) | View mitigation jobs and results | Create/run mitigation |
| Policy Compliance / Policy Audit / SCA | View policies, controls, posture, exceptions, reports | Create/edit/lock policy, request/approve exception, import mandates |
| WAS | View web apps, scans, schedules, findings, option profiles, authentication records (permission names may read "view web application", "view scan") | Create/edit web app, launch scan, ignore finding |
| TotalCloud / CloudView, Container Security, EDR, FIM, CertView, CAR | Module UI access + view permissions | Any remediation, response, policy edit, script execution |
| Unified Dashboard | View dashboards (and dashboards shared to role) | Create/edit/share dashboards |
| Administration (user & role view) | View users, view roles, view audit/activity logs (if the release offers a view-only admin permission) | Create/edit users, roles, scopes, subscription settings |
| API | API access (only if Appendix B used) | — |

### 4.4 Scope configuration

1. Administration → Users → `<AUDIT-USER>` → **Roles and Scopes** → assign `READER` + `AUDIT_READ_ONLY_ALL_MODULES`.
2. **Scope** tab → select **Full Scope** (all assets). Do not add tag-restricted scope.
3. VM/VMDR user record → **Business Unit = Unassigned**, **Asset Groups = All**, tick **"Allow user view access to all objects"**.
4. WAS: confirm the user can see all web applications (WAS uses tag scope; Full scope is required).
5. If the subscription uses multiple **business units**, confirm global (Unassigned) placement is permitted by `<ORG>`'s
   access policy; if not, create one audit user per BU and record the residual limitation.

### 4.5 Access validation (no write actions)

The auditor validates the configuration by **observation, not by attempting write actions**:

- Capture screenshots of the user record, role permission list (both roles) and scope tab, taken by the auditee admin
  (or visible to the auditor if the view-only admin permission exists).
- Run PA-02 (visibility check): count of assets, tags, asset groups, appliances, schedules, option profiles, agents,
  web apps, PC policies, users visible to `<AUDIT-USER>` vs counts provided by the auditee Manager. Differences > 0 are
  scope gaps to fix before fieldwork.
- Confirm in the UI that create/edit/launch buttons are absent or disabled (screenshot); do not click them.

### 4.6 Evidence the read-only role typically cannot see — "auditee-performed, auditor-observed"

Some objects are Manager-only in many subscriptions. For these, the auditee's Qualys Manager performs the export in a
screen-share or in person while the auditor watches, and sends the file directly to the auditor (hash recorded). The
auditor never receives Manager credentials.

| Typical Manager-only evidence | Used by |
|---|---|
| Full user list with roles, BUs, last login, extended permissions, API/GUI flags | GV-01 |
| Activity Log export (configuration, user, scan, report changes) for `<PERIOD>` | GV-04 |
| Subscription security settings: password policy, session timeout, SSO/SAML, 2FA enforcement, IP allow-list, API access restrictions | GV-02 |
| Purge rule configuration, host-tracking method settings | AM-03 |
| KnowledgeBase customisation list (if not visible to Reader) | SD-09 |
| Connector credentials configuration (shown without secrets) | GV-05 |

---

## 5. Audit procedures

**Procedure format.** *Objective → Criteria → Read-only view required → Steps → Evidence → Threshold / expected result.*
Evidence IDs follow `EV-<procedure>-<n>` and are logged in the evidence register (Appendix A). All screenshots must show
the URL/module, filters applied, the logged-in user (`<AUDIT-USER>` or observed Manager) and the date/time.

### 5.0 Pre-audit and governance

#### PA-01 Planning, scope memo and criteria confirmation
- **Objective:** O1–O8 planning. **Criteria:** 3.1–3.4.
- **Read-only view:** none (documents).
- **Steps:** (1) Obtain licensed module list, subscription ID/POD, number of BUs, IP/asset limits. (2) Obtain `<ORG>` policies
  (VM standard, patch SLA, exception policy, hardening standard, access policy). (3) Agree default thresholds (3.4) and
  report-generation stance (2.4). (4) Build WP-00: criteria matrix with the exact Qualys guide/version used for each V-item.
- **Evidence:** EV-PA01-1 scope memo signed by sponsor; EV-PA01-2 WP-00 criteria matrix; EV-PA01-3 policy set.

#### PA-02 Access provisioning and visibility check
- **Objective:** ensure the read-only role sees 100 % of objects. **Criteria:** V-14, Section 4.
- **Read-only view:** all modules.
- **Steps:** (1) Confirm account built per 4.1–4.4 (observed screenshots). (2) For each object class, record count seen by
  `<AUDIT-USER>` and count reported by auditee Manager. (3) Resolve gaps; repeat.
- **Evidence:** EV-PA02-1 role/scope screenshots; EV-PA02-2 visibility reconciliation table (Appendix A.2).
- **Expected:** zero unexplained count differences.

#### GV-01 Qualys user access review
- **Objective:** O8. **Criteria:** V-14, A-08, F-01 A.5.15/A.5.18/A.8.2, F-02 CIS 5/6, F-04 AC-2/AC-6.
- **Read-only view:** Administration → Users (view) or observed export (4.6).
- **Steps:** (1) Export all users: role, BU, asset groups/scope, extended permissions, GUI/API flag, status, last login,
  creation date, SSO flag. (2) Reconcile to HR/AD leavers list and to approved access requests (sample 25 or 100 % if < 50
  users). (3) Identify: Managers count; shared/generic accounts; users inactive > 90 days; API-enabled users and their
  purpose; users with "Purge" / "Add assets" / "Manage compliance" extended permissions without need; Unit Managers with
  out-of-BU access. (4) Review custom Administration roles for excessive permissions.
- **Evidence:** EV-GV01-1 user export; EV-GV01-2 role permission exports; EV-GV01-3 reconciliation workpaper.
- **Expected:** A-08 met; no leavers active; every privileged user approved.

#### GV-02 Subscription security settings
- **Objective:** O8. **Criteria:** V-14, F-01 A.8.5, F-02 CIS 6.
- **Read-only view:** Administration / Users → Setup → Security (observed if Manager-only).
- **Steps:** Record SSO (SAML) status and IdP, 2FA enforcement, password policy, session timeout, login IP allow-list for UI
  and API, API rate/user restrictions, "allow remote access by Qualys support" setting, notification settings.
- **Evidence:** EV-GV02-1 screenshots of each settings page.
- **Expected:** SSO with MFA or Qualys 2FA for all interactive users; IP restriction for API service accounts; timeout per policy.

#### GV-03 API service accounts and integrations credentials
- **Objective:** O8. **Criteria:** V-14, V-16.
- **Read-only view:** user list (API flag), Administration roles, connector list.
- **Steps:** Identify each API/integration account (ServiceNow, SIEM, scripts), its role and scope, owner, last use, source
  IP restriction, credential rotation evidence (from owner).
- **Evidence:** EV-GV03-1 integration account inventory.
- **Expected:** least-privilege role (e.g. Reader + specific permissions), named owner, IP-restricted, rotated per policy.

#### GV-04 Activity log and change control
- **Objective:** O1, O8. **Criteria:** V-18, F-01 A.8.15/A.8.32, F-04 AU-6.
- **Read-only view:** Activity Log (observed export if Manager-only), Administration audit log.
- **Steps:** (1) Export activity log for `<PERIOD>`. (2) Filter configuration changes: option profiles, authentication records,
  schedules deleted/disabled, purge actions, KnowledgeBase edits, user/role changes, tag rule edits, exception approvals.
  (3) Sample 25 changes; trace to change tickets/approvals. (4) Confirm someone reviews the log (evidence of review).
- **Evidence:** EV-GV04-1 log export (hash); EV-GV04-2 change sample trace.
- **Expected:** all sampled significant changes approved; periodic log review evidenced.

#### GV-05 Connectors and integration health
- **Objective:** O2, O8. **Criteria:** V-16.
- **Read-only view:** CSAM/Connectors (AWS, Azure, GCP), TotalCloud connectors, ITSM/ServiceNow app status, SIEM integrations.
- **Steps:** List connectors, accounts/subscriptions covered vs cloud account inventory from `<ORG>`, last successful sync,
  error states, IAM role used (from cloud owner — least privilege, read-only).
- **Evidence:** EV-GV05-1 connector list export / screenshots; EV-GV05-2 cloud-account reconciliation.
- **Expected:** 100 % of in-scope cloud accounts connected; no connector in error > 7 days.

### 5.1 Asset management

#### AM-01 Asset inventory reconciliation
- **Objective:** O2. **Criteria:** V-02, V-07, A-04, F-01 A.5.9, F-02 CIS 1.1/1.2, F-04 CM-8.
- **Read-only view:** CSAM Inventory / VMDR Assets (all assets), Asset Groups list; external authoritative sources from auditee.
- **Steps:** (1) Download full Qualys asset list (hostname, IP, OS, agent ID, cloud instance ID, last scan/check-in, tags,
  source = agent/scanner/connector). (2) Obtain CMDB, AD computer objects (enabled, logged-on ≤ 30 days), cloud inventories,
  EDR console export, DHCP/IPAM ranges. (3) Normalise and match (hostname/FQDN, IP, instance ID, serial). (4) Report: in
  source not in Qualys (coverage gap), in Qualys not in source (unmanaged/shadow asset), by BU/environment. (5) Compare
  network ranges in asset groups/scanner targets with IPAM ranges (unscanned subnets). (6) Review EASM/external discovery for
  internet-facing assets not in inventory.
- **Evidence:** EV-AM01-1 Qualys asset export; EV-AM01-2 source exports (received from auditee, hashed); EV-AM01-3 reconciliation workbook.
- **Expected:** A-04 met; every gap explained.

#### AM-02 Stale hosts
- **Objective:** O2. **Criteria:** V-07, A-02, A-03.
- **Read-only view:** CSAM/VMDR asset list with last-scan and last check-in dates; Cloud Agent agent list.
- **Steps:** Using QQL (Appendix C), count assets whose last scan > 30 days and agents not checked in > 7 / 30 days; split by
  tag/BU; sample 10 stale assets and determine status with auditee (decommissioned, offline, scanning broken).
- **Evidence:** EV-AM02-1 stale-asset query results + screenshot of query; EV-AM02-2 sample explanations.
- **Expected:** decommissioned assets purged per purge rule; live stale assets have an open action.

#### AM-03 Duplicate hosts, host tracking and purge rules
- **Objective:** O1, O2. **Criteria:** V-07, A-05.
- **Read-only view:** asset list; purge rule & tracking settings (observed if Manager-only).
- **Steps:** (1) Identify duplicates (same hostname / MAC / agent / cloud instance ID with multiple asset records; agent and
  scanner records for the same host not correlated). (2) Record tracking method per asset group/IP range (IP vs DNS vs NetBIOS)
  and assess against DHCP use (DHCP ranges tracked by IP cause duplicates/merges). (3) Record purge rules (criteria, age,
  agent vs scanner assets) and whether purges ran (activity log). (4) Check agent correlation / unified view setting.
- **Evidence:** EV-AM03-1 duplicate analysis; EV-AM03-2 purge/tracking settings screenshots.
- **Expected:** A-05 met; DHCP ranges not IP-tracked; purge rule defined and operating.

#### AM-04 Tagging strategy and tag hygiene
- **Objective:** O1, O4. **Criteria:** V-08.
- **Read-only view:** CSAM/Asset Management → Tags (tag tree, rule definitions).
- **Steps:** (1) Export the tag tree with rule types (static, dynamic QQL, IP range, OS, cloud, asset group, software). (2) Assess
  against `<ORG>` tag taxonomy (business unit, environment, owner, criticality, data classification). (3) Identify: static tags
  used where dynamic should be, orphan/unused tags (0 assets), overlapping/contradictory rules, assets with no BU/owner tag,
  tags used in RBAC scopes, scan targets, PM jobs and dashboards (dependency). (4) Sample 15 assets: verify tag correctness
  against CMDB attributes.
- **Evidence:** EV-AM04-1 tag export/screenshots of rules; EV-AM04-2 untagged-asset query; EV-AM04-3 sample test.
- **Expected:** 100 % of assets carry owner/BU and criticality tags; rules documented.

#### AM-05 Asset groups and business units
- **Objective:** O1. **Criteria:** V-07, V-14.
- **Read-only view:** Assets → Asset Groups (all, via "view all objects").
- **Steps:** List asset groups (IP ranges, DNS, appliances, business impact, owners, BU); identify overlapping groups, empty groups,
  groups not covered by any schedule, and business-impact values not aligned with ACS tags.
- **Evidence:** EV-AM05-1 asset group export.
- **Expected:** every in-scope range in at least one scanned asset group; business impact consistent with ACS.

#### AM-06 TruRisk and Asset Criticality tuning
- **Objective:** O4. **Criteria:** V-09, A-06.
- **Read-only view:** VMDR/CSAM asset details (ACS, TruRisk Score), TruRisk configuration page (view), criticality tags.
- **Steps:** (1) Record how ACS is assigned (tags with criticality values) and distribution of ACS 1–5 across assets; flag if
  most assets remain at default. (2) Record any TruRisk customisation (weighting factors, severity/QDS weighting) and approval.
  (3) Sample 10 crown-jewel assets from `<ORG>`'s BIA/CMDB: confirm ACS ≥ 4 and highest-priority TruRisk ranking. (4) Compare
  top-20 assets by TruRisk vs top-20 by CVSS/severity count; confirm prioritisation reflects RTIs (active exploitation, CISA KEV).
  (5) Confirm SLAs/policies reference TruRisk/QDS consistently.
- **Evidence:** EV-AM06-1 ACS distribution; EV-AM06-2 TruRisk config screenshot; EV-AM06-3 crown-jewel sample.
- **Expected:** ACS assigned from business criticality, not defaults; customisations approved and documented.

#### AM-07 Software inventory and EOL/EOS (CSAM)
- **Objective:** O2, O4. **Criteria:** V-02, F-02 CIS 2.
- **Read-only view:** CSAM software inventory, EOL/EOS lifecycle views.
- **Steps:** Report EOL/EOS operating systems and software by asset criticality; confirm they are tracked as risk (exception, plan
  or compensating control M-03).
- **Evidence:** EV-AM07-1 EOL/EOS export.
- **Expected:** every EOL OS on critical assets has a plan or approved exception.

### 5.2 Scanning and detection

#### SD-01 Authentication success rate
- **Objective:** O3. **Criteria:** V-01, A-01, F-04 RA-5(5), F-05 11.3.1.2.
- **Read-only view:** existing Authentication Report (VM → Reports) or scan results; VMDR/QQL for auth-failed QIDs; Authentication
  records list (Scans → Authentication).
- **Steps:** (1) For the last 90 days of scheduled scans, obtain authentication status per host (Passed / Failed / Not attempted)
  per technology (Windows, Unix, DB, VMware, network). (2) Calculate success rate by asset group, BU, OS. (3) List hosts failing
  > 2 consecutive scans, with failure reason (e.g. QID 105015). (4) Review authentication records: coverage of all ranges,
  vault integration vs stored passwords, credential owner, last modification, use of least-privilege accounts, record
  overlap/conflicts. (5) Confirm a process exists to review auth failures (ticket evidence).
- **Evidence:** EV-SD01-1 authentication report (existing or observed); EV-SD01-2 calculated rates; EV-SD01-3 auth record list screenshots.
- **Expected:** A-01 met; vault used per `<ORG>` policy.

#### SD-02 Scan schedules and execution
- **Objective:** O3. **Criteria:** V-06, A-10, F-02 CIS 7.5/7.6, F-05 11.3.1.
- **Read-only view:** Scans → Schedules (all); Scans → Scans history; Maps schedules.
- **Steps:** (1) Export all schedules: target (AG/tag/IPs), option profile, appliance, recurrence, next run, owner, status
  (active/deactivated/expired). (2) Map schedules to asset groups/ranges — any in-scope range with no schedule = gap. (3) From scan
  history (90 days), compute completion rates; list cancelled/paused/interrupted/error scans and recurrence. (4) Check overlapping
  schedules and scans exceeding windows. (5) Confirm external perimeter scans and (if applicable) PCI ASV cadence.
- **Evidence:** EV-SD02-1 schedule export; EV-SD02-2 scan history export; EV-SD02-3 coverage matrix.
- **Expected:** every in-scope range scheduled at policy cadence; A-10 met.

#### SD-03 Option profiles
- **Objective:** O1, O3. **Criteria:** V-04.
- **Read-only view:** Scans → Option Profiles (view all); API option-profile export (Appendix B).
- **Steps:** (1) Export each option profile used by an active schedule. (2) Compare to vendor baseline: authentication enabled,
  port scope, detection = complete vs custom search list, performance settings, "dead host" handling, password brute forcing
  disabled unless approved, dissolvable agent use, load-balancer/ICMP settings, PC/VM separation. (3) Identify profiles excluding
  QIDs/search lists that reduce detection and confirm justification. (4) Identify unused/duplicate profiles.
- **Evidence:** EV-SD03-1 option-profile exports (XML); EV-SD03-2 baseline comparison table.
- **Expected:** production vulnerability profiles authenticated and complete; deviations approved.

#### SD-04 Scanner appliance health and placement
- **Objective:** O3. **Criteria:** V-05, A-09.
- **Read-only view:** Scans → Appliances (all), appliance details.
- **Steps:** List appliances (type, version, status/heartbeat, last update, capacity, interfaces, VLANs/static routes, assigned
  asset groups); identify offline/outdated appliances, overloaded appliances (scan durations), ranges without a reachable
  appliance; obtain network diagram from auditee to confirm no firewall/NAT/IPS between scanner and targets (or exemption rules).
- **Evidence:** EV-SD04-1 appliance list; EV-SD04-2 network placement review.
- **Expected:** A-09 met; placement avoids filtering.

#### SD-05 Discovery and unmanaged assets
- **Objective:** O2, O3. **Criteria:** V-06, F-02 CIS 1.3.
- **Read-only view:** Maps and map results, CSAM unmanaged/unknown assets, EASM.
- **Steps:** Confirm recurring discovery maps or discovery scans across all IPAM ranges; review newly discovered hosts not in asset
  groups/agents for the last 90 days and their disposition.
- **Evidence:** EV-SD05-1 map schedule + latest results.
- **Expected:** discovery runs at least monthly; unknown hosts triaged.

#### SD-06 Cloud Agent deployment and health
- **Objective:** O3. **Criteria:** V-02, V-03, A-02.
- **Read-only view:** Cloud Agent → Agents (all), Activation Keys, Configuration Profiles.
- **Steps:** (1) Export agents: version, OS, status, last check-in, modules activated, last VM/PC/Inventory scan, profile, key.
  (2) Compute check-in rates, outdated agent versions, agents with modules not activated (e.g. VM activated but PC/PM required),
  agents with errors/"provisioned but never checked in". (3) Reconcile agent count to AD/CMDB endpoints (AM-01). (4) Review
  activation keys: unlimited/unrestricted keys, expired keys, keys with wide module sets, key usage counts.
- **Evidence:** EV-SD06-1 agent export; EV-SD06-2 activation-key screenshots; EV-SD06-3 health metrics.
- **Expected:** A-02 met; agents auto-updating within supported versions.

#### SD-07 Agent configuration profiles
- **Objective:** O1. **Criteria:** V-03.
- **Read-only view:** Cloud Agent → Configuration Profiles (view details).
- **Steps:** For each profile record: assigned agents/tags, VM/PC/inventory scan intervals, performance level, blackout windows,
  auto-update, logging, suspend-scanning settings, FIM/EDR settings. Compare to vendor guidance and asset class.
- **Evidence:** EV-SD07-1 profile screenshots/exports.
- **Expected:** profiles differentiated by asset class; intervals meet policy.

#### SD-08 Detection completeness spot-check (read-only re-performance)
- **Objective:** O3. **Criteria:** V-01, V-02.
- **Read-only view:** host detection list (VMDR asset detail / API host detection list), KnowledgeBase.
- **Steps:** Sample 10 hosts (mix of OS/BUs). Compare Qualys OS/software and detected vulnerabilities with an independent
  read-only source (EDR software inventory, patch tool compliance report provided by auditee) for 3 recent high-profile CVEs.
  Investigate discrepancies (auth failure, missing QID coverage, agent module off). Check QID 45038 (Host Scan Time) and
  45017 (OS detected) style information-gathered QIDs for scan quality.
- **Evidence:** EV-SD08-1 sample comparison workbook.
- **Expected:** no unexplained false negatives on sampled critical CVEs.

#### SD-09 KnowledgeBase customisations, disabled QIDs and search lists
- **Objective:** O1, O4. **Criteria:** V-10, F-02 CIS 7.
- **Read-only view:** KnowledgeBase (filter "edited"/custom severity, disabled), Search Lists (view all).
- **Steps:** List QIDs with custom severity, disabled QIDs, and search lists used in option profiles/reports. For each: who, when
  (activity log), justification, approval. Flag disabled QIDs or severity downgrades on vulnerabilities with RTIs or CISA KEV.
- **Evidence:** EV-SD09-1 KB customisation list; EV-SD09-2 approvals trace.
- **Expected:** every customisation documented and approved; none hide KEV/actively exploited QIDs.

### 5.3 Remediation workflow

#### RW-01 Prioritisation and SLA performance
- **Objective:** O4, O5. **Criteria:** V-09, V-11, A-06, F-01 A.8.8, F-04 SI-2, F-05 6.3.3.
- **Read-only view:** VMDR vulnerability views (QQL), existing prioritization reports, host detection data (API), existing scheduled
  trend reports.
- **Steps:** (1) Extract open and fixed detections for `<PERIOD>` with first-found, last-found, fixed dates, severity, QDS, RTIs,
  TruRisk/ACS, tags. (2) Compute mean time to remediate and SLA compliance by priority tier and BU. (3) List overdue
  critical/KEV items on ACS ≥ 4 assets. (4) Confirm reopened ("re-opened") detections are tracked.
- **Evidence:** EV-RW01-1 detection extract; EV-RW01-2 SLA calculation workbook.
- **Expected:** SLA compliance per A-06/`<ORG>` policy.

#### RW-02 Patch Management jobs
- **Objective:** O5. **Criteria:** V-11.
- **Read-only view:** Patch Management → Jobs (view), job results, patch catalog, PM assets.
- **Steps:** (1) List deployment jobs: target tags, schedule/recurrence, patch selection criteria (automatic by QQL vs manual),
  approval, reboot settings, status (enabled/disabled), owner. (2) For 90 days, compute job success/failure rates, assets with
  repeated failures, missing PM licence/agent module. (3) Trace 10 critical vulnerabilities from RW-01 to the job that addressed
  them and confirm closure by subsequent detection. (4) Check test/pilot ring before production (change control link).
- **Evidence:** EV-RW02-1 job list; EV-RW02-2 job result exports; EV-RW02-3 trace sample.
- **Expected:** jobs cover all patchable in-scope assets; failures followed up.

#### RW-03 Ticketing and ITSM integration
- **Objective:** O5. **Criteria:** V-11, V-16.
- **Read-only view:** VM Remediation → Policies and Tickets (view), ITSM integration status; ITSM records (read-only from ITSM owner).
- **Steps:** (1) Record remediation policies (rules, assignee, deadlines, ticket closure on fix) or ITSM integration rules (filters,
  assignment groups, sync frequency). (2) Sample 25 vulnerabilities meeting ticket criteria: verify a ticket exists with correct
  owner and due date. (3) Sample 25 closed tickets: verify Qualys confirms fix (re-scan/agent) rather than manual closure.
  (4) Check sync errors and orphaned tickets.
- **Evidence:** EV-RW03-1 policy screenshots; EV-RW03-2 ticket samples (both systems).
- **Expected:** 100 % in-criteria vulnerabilities ticketed; closures verified by detection.

#### RW-04 Mitigation and compensating controls (no patch available / deferred)
- **Objective:** O5. **Criteria:** V-11, M-03, M-05.
- **Read-only view:** KnowledgeBase QID detail (solution/workaround/threat), TruRisk Mitigate job list & results (if licensed),
  relevant PC/SCA control status.
- **Steps:** Sample 10 open critical vulnerabilities with no fix or deferred fix. Confirm documented mitigation aligns with the
  vendor workaround/mitigation in the QID, is applied (mitigation job result, configuration control pass, network control
  evidence) and is tracked to expiry.
- **Evidence:** EV-RW04-1 sample with QID mitigation text and verification.
- **Expected:** every sample has verified vendor-aligned mitigation.

#### RW-05 VMDR exceptions and ignored vulnerabilities
- **Objective:** O5. **Criteria:** V-12, M-04, A-07.
- **Read-only view:** VMDR exceptions list (view), ignored vulnerabilities / ticket ignores, KnowledgeBase disabled QIDs (SD-09).
- **Steps:** (1) Export all exceptions/ignores: QID/asset scope, requester, approver, justification, compensating control, created,
  expiry, status. (2) Test 100 % (or 25 sample) against A-07 and `<ORG>` exception policy: segregation of duties (requester ≠
  approver), expiry, re-review. (3) Identify broad-scope exceptions (all assets / whole QIDs) and exceptions on KEV/RTI QIDs.
  (4) Confirm reports/dashboards disclose excepted risk.
- **Evidence:** EV-RW05-1 exception export; EV-RW05-2 test workbook.
- **Expected:** A-07 met.

#### RW-06 Closed-loop verification
- **Objective:** O5. **Criteria:** V-11.
- **Read-only view:** host detection history (fixed/reopened status).
- **Steps:** For 15 detections marked Fixed in `<PERIOD>`, confirm a subsequent authenticated scan or agent assessment shows Fixed
  (not just disappearance due to auth failure or host not scanned). Check "Fixed" status of hosts with auth failures.
- **Evidence:** EV-RW06-1 sample trace.
- **Expected:** all sampled fixes verified by a successful assessment.

### 5.4 Policy Compliance / Policy Audit and compensating controls

#### PC-01 Policy library alignment
- **Objective:** O6. **Criteria:** V-13, F-03, F-02 CIS 4.
- **Read-only view:** PC/Policy Audit → Policies (view), Library/mandates (view).
- **Steps:** List active policies, source (CIS/DISA/Qualys library/custom), benchmark version vs current CIS version for each OS,
  profile level, last modification, lock status, assigned asset groups/tags, control count; identify controls removed or values
  changed from the library baseline and their justification.
- **Evidence:** EV-PC01-1 policy list and policy export (view/download); EV-PC01-2 version comparison.
- **Expected:** current benchmark versions (or approved lag); deviations documented.

#### PC-02 Compliance scan / agent coverage
- **Objective:** O3, O6. **Criteria:** V-13, V-01.
- **Read-only view:** PC scan schedules, agent PC module status, posture data.
- **Steps:** Confirm every in-scope asset class receives compliance assessment (scanner PC scan with auth, or agent PC module) at
  policy cadence; compute assets with no posture data in 30 days; check auth failures for PC.
- **Evidence:** EV-PC02-1 coverage analysis.
- **Expected:** ≥ 95 % in-scope assets with current posture.

#### PC-03 Posture and remediation of failed controls
- **Objective:** O5, O6. **Criteria:** M-01, F-01 A.8.9.
- **Read-only view:** posture views / existing compliance reports.
- **Steps:** Report pass rates per policy, BU and criticality; top failing controls; trend over `<PERIOD>`; sample 10 failed controls
  on critical assets and trace to remediation (CAR/script, change ticket) or exception.
- **Evidence:** EV-PC03-1 posture export; EV-PC03-2 sample trace.
- **Expected:** failed critical controls have remediation or exception.

#### PC-04 PC exceptions and compensating controls
- **Objective:** O5, O6. **Criteria:** M-02, M-05, A-07.
- **Read-only view:** PC → Exceptions (view), exception history.
- **Steps:** Export all exceptions (control, asset, status, requester, approver, reason, compensating control, expiry, comments
  history); test against M-02/A-07; confirm compensating controls are evidenced; identify expired-but-still-accepted posture.
- **Evidence:** EV-PC04-1 exception export; EV-PC04-2 test workbook.
- **Expected:** A-07 met.

#### PC-05 Compliance mapping to frameworks
- **Objective:** O6. **Criteria:** F-01–F-06.
- **Read-only view:** mandate mappings in PC library, existing mandate-based reports.
- **Steps:** Confirm `<ORG>`'s mandated frameworks are mapped (CIS, ISO 27001, PCI, regional); test that mandate reports can be
  reproduced from existing templates for audit evidence.
- **Evidence:** EV-PC05-1 mandate mapping screenshots.

### 5.5 Web Application Scanning and other modules

#### WA-01 WAS inventory, configuration and results
- **Objective:** O2, O3, O5. **Criteria:** V-17, F-02 CIS 16, F-05 6.4.
- **Read-only view:** WAS → Web Applications, Scans, Schedules, Option Profiles, Authentication, Detections (view).
- **Steps:** (1) Reconcile web apps to `<ORG>` application inventory / EASM (internet-facing apps). (2) For each app: authentication
  record configured and succeeding, crawl scope/exclusions, schedule cadence, scanner (external/internal), last scan status/duration,
  links crawled. (3) Open high/critical findings vs SLA; ignored findings with approval; retest evidence.
- **Evidence:** EV-WA01-1 web-app export; EV-WA01-2 scan status list; EV-WA01-3 findings/SLA workbook.
- **Expected:** all in-scope apps scanned authenticated at policy cadence.

#### MX-01 Other licensed modules (TotalCloud/CloudView, Container Security, EDR, FIM, CertView)
- **Objective:** O1–O3. **Criteria:** V-16 plus module-specific vendor guidance recorded in WP-00.
- **Read-only view:** each module's view permissions (4.3).
- **Steps (per module):** coverage (accounts/registries/hosts/certificates monitored vs inventory), policy/rule set currency, alert or
  finding backlog vs SLA, integration to ticketing/SIEM, exceptions.
- **Evidence:** EV-MX01-n per module.

### 5.6 Reporting and compliance

#### RC-01 Dashboard accuracy
- **Objective:** O7. **Criteria:** V-15.
- **Read-only view:** Unified Dashboard (dashboards shared to audit role or observed), widget QQL (view), underlying data.
- **Steps:** (1) Identify dashboards used for management/KPI reporting. (2) For 5 key widgets, record QQL/filters, then independently
  recompute the value from list views/API extracts. (3) Check for filters that silently exclude assets (tags, ignored vulns, severity,
  "confirmed only", date windows) or include decommissioned hosts. (4) Check refresh time.
- **Evidence:** EV-RC01-1 widget definition screenshots; EV-RC01-2 recomputation workbook.
- **Expected:** variance ≤ 2 % or explained.

#### RC-02 Executive and management reporting
- **Objective:** O7. **Criteria:** V-15, F-01 A.5.36.
- **Read-only view:** Report Share (existing reports), report templates (view), scheduled reports (view).
- **Steps:** Obtain last 3 executive VM reports/board packs; trace headline metrics (risk score trend, SLA %, coverage %, exception
  count) to Qualys data (RW-01, AM-01, RW-05). Confirm reports disclose coverage gaps, auth failure rates and excepted risk.
  Review templates for exclusions.
- **Evidence:** EV-RC02-1 report copies; EV-RC02-2 trace workbook.
- **Expected:** metrics reproducible; limitations disclosed.

#### RC-03 Report distribution and protection
- **Objective:** O8. **Criteria:** V-15.
- **Read-only view:** scheduled reports list (recipients, format, encryption), Report Share retention.
- **Steps:** Review recipients vs need-to-know, external recipients, secure PDF/encryption for sensitive reports, report share
  retention.
- **Evidence:** EV-RC03-1 scheduled report list.

#### RC-04 Compliance evidence packaging
- **Objective:** O6, O7. **Criteria:** F-01–F-06.
- **Read-only view:** existing scheduled compliance/VM reports, exports.
- **Steps:** Confirm `<ORG>` can produce, for an external assessor, a reproducible evidence pack: asset inventory & coverage, scan
  schedules & authenticated evidence (PCI 11.3.1.2), quarterly scan results, remediation evidence, exceptions with approvals,
  policy compliance posture, access review. Check evidence is retained per retention policy with integrity (date, source, hash).
- **Evidence:** EV-RC04-1 evidence pack index review.

#### RC-05 PCI ASV (if applicable)
- **Objective:** O6. **Criteria:** F-05 11.3.2.
- **Read-only view:** PCI Compliance module (view) / existing ASV reports.
- **Steps:** Confirm four passing quarterly external scans in the last 12 months, disputes/false-positive submissions with evidence,
  scope attestations.
- **Evidence:** EV-RC05-1 ASV attestation copies.

---

## 6. Roles and responsibilities

| Role | Responsibilities | Qualys access |
|---|---|---|
| **Audit sponsor (CISO / Head of Internal Audit)** | Approves scope, criteria and thresholds; receives report; owns escalation | None |
| **Audit lead** | Plans engagement, approves workpapers, manages timeline, ensures read-only constraint, issues report | Optional `<AUDIT-USER>` (read-only) |
| **Qualys SME auditor(s)** | Execute Section 5, maintain WP-00 vendor baseline register, evidence register | `<AUDIT-USER>` (read-only, named per person) |
| **Data analyst (optional)** | Reconciliation and SLA analytics (AM-01, RW-01) | No direct access; works on exported data |
| **Qualys platform owner (auditee)** | Provides context, policies, walkthroughs; performs observed exports (4.6); responds to findings | Manager |
| **Qualys administrator (auditee)** | Provisions `<AUDIT-USER>` and custom role; deprovisions at close | Manager |
| **IAM / IdP administrator** | Adds audit user to SSO/MFA; confirms leavers list | IdP |
| **CMDB / AD / cloud / EDR owners** | Provide authoritative inventories (AM-01, GV-05) | Read-only exports from their systems |
| **ITSM / patch owners** | Provide ticket and change evidence (RW-02, RW-03, GV-04) | Read-only ITSM reports |
| **Remediation owners / BU leads** | Explain overdue items and exceptions; own action plans | n/a |

**Independence:** auditors must not have held a Qualys Manager/Unit Manager/Scanner role in `<ORG>` during `<PERIOD>`.

---

## 7. Pre-audit access requests (prioritised)

Submit at least 10 working days before fieldwork. Priority 1 items block fieldwork.

| # | Priority | Request | To | Needed for | Read-only justification |
|---|---|---|---|---|---|
| 1 | **P1** | Create named user `<AUDIT-USER>` per auditor: **Reader** role, **BU = Unassigned**, **Asset Groups = All**, **"Allow user view access to all objects" enabled**, all other extended permissions disabled, GUI on | Qualys admin | All | Reader has no configuration write rights |
| 2 | **P1** | Create custom Administration role **`AUDIT_READ_ONLY_ALL_MODULES`** (view-only permissions per 4.3) and assign with **Full Scope** | Qualys admin | CSAM, Agent, PM, WAS, PC/Policy Audit, UD, other modules | View permissions only; explicit exclusion list in 4.3 |
| 3 | **P1** | SSO/MFA enrolment for audit users; IP allow-list entry for auditor workstations | IAM admin / Qualys admin | Login | Security control |
| 4 | **P1** | Visibility check session (PA-02): auditee Manager supplies object counts | Platform owner | PA-02 | Observation |
| 5 | **P1** | Licensed modules list and subscription details | Platform owner | Scope | Document |
| 6 | **P2** | Observed exports: user list, subscription security settings, activity log for `<PERIOD>`, purge/tracking settings | Qualys Manager (observed) | GV-01/02/04, AM-03 | Auditee performs; auditor observes |
| 7 | **P2** | Share management dashboards (Unified Dashboard) to the audit role, or schedule a walkthrough | Platform owner | RC-01 | Sharing is done by owner; auditor only views |
| 8 | **P2** | Read-only access to Report Share copies of last 3 months' scheduled executive/compliance reports | Platform owner | RC-02/04 | Existing reports |
| 9 | **P2** | Authoritative inventories: CMDB, AD computers, cloud account lists and inventories, EDR export, IPAM ranges, network diagram for scanner placement | Asset/cloud/network owners | AM-01, SD-04, GV-05 | Exports from other systems |
| 10 | **P2** | Policies: VM standard, patch SLA, exception policy, hardening standard, access policy, change policy | GRC | Criteria | Documents |
| 11 | **P3** | API access flag on `<AUDIT-USER>` (only if Appendix B used), IP-restricted | Qualys admin | Bulk exports | Read actions only (list/search/export) |
| 12 | **P3** | ITSM read-only report access (Qualys-originated tickets, changes for Qualys config) | ITSM owner | RW-03, GV-04 | Read-only report |
| 13 | **P3** | Patch/EDR tool compliance reports for SD-08 sample | Endpoint owner | SD-08 | Exports |
| 14 | **P3** | Calendar: walkthroughs with platform owner, PM owner, PC owner, WAS owner | Platform owner | All | n/a |

---

## 8. Reporting and follow-up

### 8.1 Finding format
Each finding records: **ID · Title · Condition** (what was found, with metrics) · **Criteria** (V/M/F/P/A IDs) · **Cause** ·
**Effect / risk** · **Recommendation** (aligned to Qualys vendor baseline where applicable) · **Management action plan** ·
**Owner** · **Target date** · **Evidence references**.

### 8.2 Rating
| Rating | Definition (example) |
|---|---|
| **Critical** | Material blind spot or control failure: e.g. large unscanned ranges, auth success < 70 % on critical assets, Manager accounts for leavers, disabled QIDs hiding KEVs |
| **High** | Significant weakness likely to cause missed or unremediated critical risk (SLA failure on KEVs, exceptions without approval/expiry) |
| **Medium** | Control operates but with gaps or inconsistencies (tag hygiene, stale assets, outdated benchmark versions) |
| **Low / Improvement** | Efficiency or best-practice alignment opportunities |

Overall opinion per objective O1–O8: *Effective / Effective with improvements / Partially effective / Ineffective*.

### 8.3 Reporting timeline
1. Daily/weekly status with the platform owner during fieldwork (issues log).
2. Exit meeting: draft findings validated for factual accuracy (≤ 5 working days after fieldwork).
3. Draft report with management responses due in 10 working days.
4. Final report to sponsor; executive summary with scorecard of A-01…A-10 metrics vs thresholds and vendor baseline alignment
   summary (V-01…V-18: aligned / partially / not aligned / not applicable).

### 8.4 Follow-up
- Action plans tracked in `<ORG>`'s GRC/issue tool.
- Follow-up review at target dates (or quarterly) using the **same read-only role** — re-request access via Section 7 items 1–3
  (do not leave the audit account enabled between reviews).
- Validation re-runs the relevant procedure's queries/exports; closure requires evidence from Qualys data, not attestation alone.

### 8.5 Close-out
- **PA-05 Deprovision:** auditee admin disables `<AUDIT-USER>` and removes the custom role assignment; screenshot retained.
- Evidence retained per audit retention policy; Qualys exports containing vulnerability data classified **Confidential** and
  stored encrypted.

---

## 9. Appendices

### Appendix A — Evidence register

**A.1 Register template**

| Evidence ID | Procedure | Description | Source (module / path / API call) | Obtained by (audit user / observed Manager) | Date-time (UTC) | Format | SHA-256 | Workpaper ref |
|---|---|---|---|---|---|---|---|---|
| EV-AM01-1 | AM-01 | Full asset export | CSAM → Inventory → Download | `<AUDIT-USER>` | | CSV | | WP-AM-01 |

**Evidence standards**
- Screenshots: full window, URL/module visible, filters visible, logged-in user visible, OS clock visible.
- Exports: original file retained unchanged; hash recorded at receipt; working copies separate.
- Observed evidence: note observer name, auditee performer, method (screen share/in person), file transfer route.

**A.2 Visibility reconciliation (PA-02)**

| Object class | Count reported by auditee Manager | Count visible to `<AUDIT-USER>` | Difference | Resolution |
|---|---|---|---|---|
| Assets (CSAM) | | | | |
| Asset groups | | | | |
| Tags | | | | |
| Scanner appliances | | | | |
| Scan schedules / map schedules | | | | |
| Option profiles | | | | |
| Authentication records | | | | |
| Cloud agents / activation keys / config profiles | | | | |
| PM jobs | | | | |
| PC policies / exceptions | | | | |
| VMDR exceptions | | | | |
| Web applications | | | | |
| Dashboards (management) | | | | |
| Connectors | | | | |

### Appendix B — Read-only API calls (optional)

Use only if item 11 (Section 7) is approved. These are **read** actions (list/search/export/download). Some Qualys read calls
use HTTP POST by design; POST to a `list`/`search`/`export` action does not change data. **Never** call `launch`, `add`,
`create`, `update`, `edit`, `delete`, `purge`, `cancel`, `pause`, `approve` or `activate` actions. Base URL: the `<POD>` API
server (e.g. `https://qualysapi.<pod>.apps.qualys.com`). Header `X-Requested-With` is required for the v2 FO API.

| Purpose | Endpoint (action) |
|---|---|
| Host list (tracking, last scan, OS) | `/api/2.0/fo/asset/host/?action=list&details=All` |
| Host detections (first/last found, fixed, QDS) | `/api/2.0/fo/asset/host/vm/detection/?action=list` |
| Asset groups | `/api/2.0/fo/asset/group/?action=list` |
| Scan history | `/api/2.0/fo/scan/?action=list` |
| Scan schedules | `/api/2.0/fo/schedule/scan/?action=list` |
| Option profiles (export) | `/api/2.0/fo/subscription/option_profile/vm/?action=export` |
| Scanner appliances | `/api/2.0/fo/appliance/?action=list&output_mode=full` |
| Authentication records | `/api/2.0/fo/auth/?action=list` |
| KnowledgeBase (incl. custom severity info) | `/api/2.0/fo/knowledge_base/vuln/?action=list` |
| Existing reports (list / fetch) | `/api/2.0/fo/report/?action=list`, `?action=fetch&id=…` |
| Compliance policies / exceptions | `/api/2.0/fo/compliance/policy/?action=list`, `/api/2.0/fo/compliance/exception/?action=list` |
| Tags (QPS) | `POST /qps/rest/2.0/search/am/tag` |
| Host assets incl. agent info (QPS) | `POST /qps/rest/2.0/search/am/hostasset` |
| WAS web apps / scans | `POST /qps/rest/3.0/search/was/webapp`, `POST /qps/rest/3.0/search/was/wasscan` |

Confirm in PA-02 that the Reader + custom role returns full results for each call; record any call refused for the role.

### Appendix C — Example QQL queries (validate token names in the QQL helper of each app)

| Purpose | Example QQL |
|---|---|
| Agents not checked in > 30 days (CSAM) | `agent.lastCheckedIn < now-30d` |
| Assets with no BU tag | `not tags.name:"BU-*"` *(adapt to tag taxonomy)* |
| Assets without criticality tag / default ACS | `asset.criticalityScore:1` *(token per release)* |
| Critical open vulnerabilities with active exploitation (VMDR) | `vulnerabilities.vulnerability.threatIntel.activeAttacks:true and vulnerabilities.status:[NEW, ACTIVE, REOPENED]` |
| CISA KEV open on critical assets | `vulnerabilities.vulnerability.threatIntel.cisaKnownExploitedVulns:true and asset.criticalityScore>=4` |
| Windows authentication failed | `vulnerabilities.vulnerability.qid:105015` |
| EOL operating systems (CSAM) | `operatingSystem.lifecycle.stage:EOL` |

### Appendix D — Procedure-to-criteria traceability (summary)

| Procedure | Objectives | Vendor baseline | Mitigation/comp. | Framework examples |
|---|---|---|---|---|
| GV-01–GV-05 | O1, O2, O8 | V-14, V-16, V-18 | — | ISO A.5.15, A.5.18, A.8.2, A.8.15, A.8.32; CIS 5, 6, 8 |
| AM-01–AM-07 | O2, O4 | V-02, V-07, V-08, V-09 | M-03 (EOL) | ISO A.5.9; CIS 1, 2; NIST CM-8 |
| SD-01–SD-09 | O1, O3, O4 | V-01–V-06, V-10 | — | CIS 7.5, 7.6; NIST RA-5; PCI 11.3.1, 11.3.1.2 |
| RW-01–RW-06 | O4, O5 | V-09, V-11, V-12 | M-03, M-04, M-05 | ISO A.8.8; NIST SI-2; PCI 6.3.3 |
| PC-01–PC-05 | O3, O5, O6 | V-13 | M-01, M-02, M-05 | CIS 4; CIS Benchmarks; ISO A.8.9 |
| WA-01, MX-01 | O2, O3, O5 | V-16, V-17 | — | CIS 16; PCI 6.4 |
| RC-01–RC-05 | O6, O7, O8 | V-15 | — | ISO A.5.36; PCI 11.3.2 |
