# 📌 Windows 11 STIG Remediation — Compliance Progression Report

## STIG Assessment Information

- **Name:** Ramzy Aboughlia 
- **Source:** Cyber Range SOC Challenge  
- **System:** Ramzy-Workstaion(IT Admin Workstation)

> **Context:** STIGs (Security Technical Implementation Guides) are DISA-published secure baseline configurations mandated for DoD-connected systems. Think of them as a health checklist — not for restaurants, but for OS hardening.
>
> - **CAT I** = Critical — fix immediately
> - **CAT II** = Medium
> - **CAT III** = Low

---

## 🧾 Overview

This document captures the end-to-end remediation of 10 DISA STIG findings on a Windows 11 virtual machine, verified through three Tenable scan cycles. The effort reduced failed checks from **152 → 140** (out of 264 total), increasing the pass count from **99 → 109**. Remediation was performed in two phases: manual Group Policy for critical CAT I and foundational CAT II controls, followed by a PowerShell automation script for the remaining five CAT II findings.

---

## 🎯 Objectives

- Reduce STIG failure count on a Windows 11 VM scanned by Tenable (`10.0.0.8`)
- Prioritize CAT I (critical) findings before advancing to CAT II
- Prefer Group Policy over direct registry edits for persistence and scalability
- Automate the second wave of CAT II fixes via `.ps1` script
- Document findings, rationale, and exact remediation paths for future reference

---

## 📊 Scan Results — Three Checkpoints

| Checkpoint | Failed | Warning | Passed | Total |
|---|---|---|---|---|
| Baseline | 152 | 13 | 99 | 264 |
| After 3 critical fixes | 150 | 13 | 101 | 264 |
| After all 10 STIGs fixed | **140** | 15 | **109** | 264 |

**Net improvement:** −12 failures, +10 passes across both phases.

> ⚠️ Warning count increased by 2 in the final scan — expected in some configurations. Should be reviewed but is not blocking.

---

## 🔍 Key Insights / Findings

- **Group Policy is superior to direct registry edits** — GPO reapplies every 90 minutes, making it resistant to drift from user action or application override.
- **WN11-CC-000190 and WN11-CC-000185 share a root cause** — both AutoPlay/AutoRun STIGs are resolved by a single Group Policy path; one fix closes two findings simultaneously.
- **Stateful firewall behavior** — the Windows Firewall + NSG inbound rule for the Tenable scan engine automatically permits return traffic; no explicit outbound rule is needed.
- **ICMP (ping) was blocked at the scan engine side**, not the VM — confirmed after adding both inbound and outbound ICMP rules on the VM without resolution.
- **NULL session / anonymous enumeration** (`WN11-SO-000150`) is a classic lateral movement vector. `RestrictAnonymous` enforcement via GPO closes this attack surface with minimal operational impact.
- **Log capacity settings** (AU-000500, AU-000505) prevent log rotation overwrites — critical for SOC visibility and forensic integrity.

---

## 🛠 Technical Details

### Scan Environment

| Component | Detail |
|---|---|
| Scan engine | Tenable — `10.0.0.8` |
| Target | Windows 11 VM |
| Firewall | Stateful (Windows Firewall + NSG) |
| Access method | Inbound rule permitting scan engine IP |
| Total checks | 264 |

---

### Phase 1 — Manual Group Policy Fixes (5 STIGs)

#### WN11-CC-000190 & WN11-CC-000185 — AutoPlay / AutoRun

Both resolved via a single Group Policy path:

```
gpedit.msc →
  Computer Configuration →
    Administrative Templates →
      Windows Components →
        AutoPlay Policies

  ├── Turn off AutoPlay = Enabled → All Drives          [WN11-CC-000190]
  └── Set the default behavior for AutoRun = Enabled    [WN11-CC-000185]
      → Do not execute any autorun commands
```

**Why this works:** Windows consults `NoDriveTypeAutoRun` in the registry when a drive is inserted. Setting this value to `255` via GPO prevents execution. Group Policy enforces this persistently — unlike a one-time registry edit, it cannot be silently overwritten by an application.

---

#### WN11-SO-000150 — Anonymous Enumeration of SAM / Shares

```
gpedit.msc →
  Computer Configuration →
    Windows Settings →
      Security Settings →
        Local Policies →
          Security Options →
            Network access: Do not allow anonymous enumeration of SAM accounts and shares = Enabled
```

**Background:** By default, Windows permits NULL sessions — unauthenticated connections used historically for legacy compatibility. Attackers abuse these to enumerate users, shares, and system info without credentials. The `RestrictAnonymous` registry value (set via GPO) blocks this.

**Key terms:**

| Term | Definition |
|---|---|
| SAM | Security Account Manager — Windows database storing user accounts and security info |
| NULL Session | Unauthenticated connection to Windows, historically allowed for legacy compatibility |
| `RestrictAnonymous` | Registry value controlling whether Windows responds to anonymous enumeration requests |

---

#### WN11-AU-000500 — Application Event Log Size

```
gpedit.msc →
  Computer Configuration →
    Administrative Templates →
      Windows Components →
        Event Log Service →
          Application →
            Specify the maximum log file size (KB) = Enabled → 32768 KB
```

#### WN11-AU-000505 — Security Event Log Size

```
gpedit.msc →
  Computer Configuration →
    Administrative Templates →
      Windows Components →
        Event Log Service →
          Security →
            Specify the maximum log file size (KB) = Enabled → 1024000 KB
```

---

### Phase 2 — PowerShell Automated Fixes (5 STIGs)

The following five STIGs were remediated via a `[View STIG Report](./Auto-fix.ps1)` automation script:

| STIG ID | Description | Policy Path |
|---|---|---|
| `WN11-AC-000005` | Account lockout duration ≥ 15 min | Account Lockout Policy |
| `WN11-AC-000010` | Account lockout threshold ≤ 3 (not 0) | Account Lockout Policy |
| `WN11-SO-000025` | Rename Guest account from default "Guest" | Local Policies → Security Options |
| `WN11-CC-000005` | Lock screen camera = Disabled | Control Panel → Personalization |
| `WN11-AU-000005` | Audit Credential Validation = Failure logged | Advanced Audit Policy → Account Logon |

**Full Group Policy paths:**

```
WN11-AC-000005:
  gpedit.msc → Computer Configuration → Windows Settings → Security Settings →
  Account Policies → Account Lockout Policy →
  Account lockout duration = 15 minutes or greater (or 0 to require admin unlock)

WN11-AC-000010:
  gpedit.msc → ... → Account Lockout Policy →
  Account lockout threshold = 3 or less (NOT 0)

WN11-SO-000025:
  gpedit.msc → ... → Local Policies → Security Options →
  Accounts: Rename guest account = <any name except "Guest">

WN11-CC-000005:
  gpedit.msc → ... → Administrative Templates → Control Panel →
  Personalization → Prevent enabling lock screen camera = Enabled

WN11-AU-000005:
  gpedit.msc → ... → Advanced Audit Policy Configuration →
  System Audit Policies → Account Logon →
  Audit Credential Validation = Failure
```

---

### Full STIG Remediation Reference

| STIG ID | Description | Category | Method | Phase |
|---|---|---|---|---|
| `WN11-CC-000190` | AutoPlay disabled for all drives | 🔴 CAT I | Group Policy | Phase 1 |
| `WN11-CC-000185` | Default AutoRun behavior — no execute | 🔴 CAT I | Group Policy | Phase 1 |
| `WN11-SO-000150` | Anonymous enumeration of SAM/shares restricted | 🔴 CAT I | Group Policy | Phase 1 |
| `WN11-AU-000500` | Application event log ≥ 32768 KB | 🟡 CAT II | Group Policy | Phase 1 |
| `WN11-AU-000505` | Security event log ≥ 1024000 KB | 🟡 CAT II | Group Policy | Phase 1 |
| `WN11-AC-000005` | Account lockout duration ≥ 15 min | 🟡 CAT II | Script (.ps1) | Phase 2 |
| `WN11-AC-000010` | Account lockout threshold ≤ 3 attempts | 🟡 CAT II | Script (.ps1) | Phase 2 |
| `WN11-SO-000025` | Guest account renamed from default | 🟡 CAT II | Script (.ps1) | Phase 2 |
| `WN11-CC-000005` | Lock screen camera disabled | 🟡 CAT II | Script (.ps1) | Phase 2 |
| `WN11-AU-000005` | Audit credential validation — Failure logged | 🟡 CAT II | Script (.ps1) | Phase 2 |

---

## ⚠️ Issues / Challenges

- **ICMP blocked at engine side** — ping tests to confirm connectivity failed even after adding VM-side firewall rules. Connectivity was confirmed indirectly via successful scan execution. No VM-side remediation needed.
- **Warning count increased by 2** in the final scan (13 → 15). Remediating certain settings may have exposed adjacent policy gaps. Requires review in the next scan cycle.
- **140 checks still failing** after this sprint — these likely include additional CAT II/III findings not yet in scope.

---

## ✅ Solutions / Recommendations

- **Always prefer Group Policy over direct registry edits** for STIG remediation. GPO is scalable, auditable, and self-healing via the 90-minute refresh cycle.
- **Batch related STIGs by category and method** — Phase 1 (manual critical), Phase 2 (scripted medium) — to keep the process manageable and auditable.
- **Version-control your `.ps1` remediation scripts** in this repository. Each script should be idempotent (safe to re-run) and include a comment header mapping it to its STIG ID(s).
- **Investigate the 2 new warnings** introduced in the final scan before proceeding to the next remediation sprint.
- **Triage the 140 remaining failures** by CAT level to plan Phase 3 scope.

---

## 🚀 Next Steps

1. **Review the 2 new warnings** — determine if they are expected artifacts of current fixes or new findings.
2. **Export remaining 140 failures** from Tenable and triage by CAT I → CAT II → CAT III priority.
3. **Expand the PowerShell script** to cover additional CAT II findings, following the same GPO-mapping pattern used in Phase 2.
4. **Run a clean verification scan** after a full GPO refresh cycle (90+ min post-remediation) to confirm all 10 fixes are stable.
5. **Document findings in a POAM** (Plan of Action & Milestones) if this system is on a path to ATO (Authority to Operate).
6. **Consider a SCAP benchmark run** alongside Tenable to cross-validate results.

---

*Report generated from raw remediation notes, scan screenshots, and Group Policy configuration logs.*  
*Scan engine: Tenable · Total checks: 264 · OS: Windows 11 · DISA STIG framework*
