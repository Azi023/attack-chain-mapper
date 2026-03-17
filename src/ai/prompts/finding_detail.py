"""Prompt template for AI finding detail generation.

Three reasoning modes based on evidence richness and chain position:
  Mode A — Rich evidence (>100 chars): Evidence-first analysis
  Mode B — Thin evidence (<100 chars or None): MITRE + chain context reasoning
  Mode C — Crown jewel (last node in primary path): Full attack narrative
"""
from __future__ import annotations

from src.ingestion.schema import Finding

# ---------------------------------------------------------------------------
# MITRE technique descriptions
# ---------------------------------------------------------------------------

MITRE_DESCRIPTIONS: dict[str, str] = {
    "T1557":     "Adversary-in-the-Middle — intercept and manipulate network communications",
    "T1557.001": "NTLM Relay — intercept NTLM authentication and relay it to gain unauthorized access",
    "T1557.002": "ARP Cache Poisoning — redirect network traffic by poisoning ARP tables",
    "T1552":     "Unsecured Credentials — find and access credentials stored insecurely",
    "T1552.001": "Credentials in Files — search file systems for credentials stored in plaintext",
    "T1552.004": "Private Keys — find and abuse private key material for authentication",
    "T1552.006": "Group Policy Preferences — recover credentials from GPP XML files in SYSVOL",
    "T1087":     "Account Discovery — enumerate user accounts to identify targets",
    "T1087.001": "Local Account Discovery — enumerate local accounts on a system",
    "T1087.002": "Domain Account Discovery — enumerate Active Directory accounts and groups",
    "T1558":     "Steal or Forge Kerberos Tickets — abuse Kerberos protocol for access",
    "T1558.001": "Golden Ticket — forge Kerberos TGTs using the KRBTGT hash",
    "T1558.002": "Silver Ticket — forge Kerberos service tickets using service account hashes",
    "T1558.003": "Kerberoasting — request TGS tickets for offline cracking of service account passwords",
    "T1558.004": "AS-REP Roasting — obtain TGT for accounts with Kerberos pre-auth disabled",
    "T1046":     "Network Service Discovery — scan hosts for open ports and running services",
    "T1595":     "Active Scanning — probe target infrastructure for vulnerabilities",
    "T1595.002": "Vulnerability Scanning — use scanners to identify exploitable weaknesses",
    "T1078":     "Valid Accounts — use legitimate credentials to authenticate and maintain access",
    "T1078.002": "Domain Accounts — abuse domain-level credentials for lateral movement",
    "T1110":     "Brute Force — attempt to guess or crack credentials through repeated attempts",
    "T1110.002": "Password Cracking — recover plaintext passwords from captured hashes",
    "T1110.003": "Password Spraying — try common passwords against many accounts to avoid lockout",
    "T1021":     "Remote Services — use legitimate remote access protocols for lateral movement",
    "T1021.002": "SMB/Windows Admin Shares — access network shares using SMB for lateral movement",
    "T1021.006": "Windows Remote Management — use WinRM for remote command execution",
    "T1047":     "Windows Management Instrumentation — use WMI for remote execution and discovery",
    "T1059":     "Command and Scripting Interpreter — execute commands via system interpreters",
    "T1059.001": "PowerShell — execute malicious PowerShell scripts or commands",
    "T1134":     "Access Token Manipulation — steal or forge security tokens to escalate privileges",
    "T1134.001": "Token Impersonation/Theft — steal and impersonate another user's access token",
    "T1068":     "Exploitation for Privilege Escalation — exploit software vulnerabilities to gain elevated rights",
    "T1190":     "Exploit Public-Facing Application — exploit internet-facing apps for initial access",
    "T1136":     "Create Account — create rogue accounts for persistence",
    "T1098":     "Account Manipulation — modify accounts to maintain access",
    "T1040":     "Network Sniffing — capture network traffic to extract credentials or data",
    "T1003":     "OS Credential Dumping — extract credential material from OS memory or files",
    "T1003.001": "LSASS Memory — dump credentials from the LSASS process memory",
    "T1003.006": "DCSync — simulate a domain controller to replicate credential data",
    "T1484":     "Domain Policy Modification — alter domain configuration for persistence or escalation",
    "T1484.001": "Group Policy Modification — modify GPOs to execute malicious code domain-wide",
    "T1207":     "Rogue Domain Controller — register a rogue DC using DCShadow to inject AD objects",
    "T1548":     "Abuse Elevation Control Mechanism — bypass or abuse privilege elevation controls",
    "T1548.002": "Bypass User Account Control — bypass Windows UAC to execute with elevated rights",
}


def _get_mitre_description(technique: str | None) -> str:
    if not technique:
        return "No MITRE technique recorded"
    desc = MITRE_DESCRIPTIONS.get(technique)
    if desc:
        return desc
    # Try parent technique (e.g. T1557.001 → T1557)
    parent = technique.split(".")[0]
    parent_desc = MITRE_DESCRIPTIONS.get(parent)
    if parent_desc:
        return f"{parent_desc} (sub-technique: {technique})"
    return f"Technique {technique} from MITRE ATT&CK framework"


# ---------------------------------------------------------------------------
# Prompt template
# ---------------------------------------------------------------------------

FINDING_DETAIL_PROMPT = """You are a senior penetration tester writing a finding analysis for a CISO.

FINDING:
Title: {title}
Severity: {severity_label} ({severity}/10)
MITRE Technique: {mitre_technique} — {mitre_description}
Step in engagement: {step_index} of {total_steps}
Time elapsed: {timestamp}
Target host: {host}

CHAIN CONTEXT:
This finding was enabled by: {enabled_by_titles}
This finding enabled: {enables_titles}
Position in chain: {chain_position}
{crown_jewel_context}

EVIDENCE:
{evidence_or_none}

INSTRUCTIONS:
Write a finding analysis that a CISO can act on immediately.

- If evidence is provided: Explain what the evidence proves, what the attacker could do next, and why the root cause exists.
- If evidence is thin or absent: Reason from the MITRE technique ({mitre_technique}) and the chain context. Describe how this vulnerability class typically manifests and what the chain position tells us about how it was actually used here.
- For crown jewel findings: Lead with the full attack narrative — what the attacker achieved, how they got there, and the blast radius.
- Never say "based on the evidence provided" or "according to the information given" — just state the analysis directly.
- Never write generic security advice. Every sentence must be specific to this finding's context in this chain.

Respond ONLY with valid JSON. No preamble, no markdown fences:
{{
    "detail": "3-4 sentences: what happened, why it matters, what it unlocked",
    "remediation": ["numbered actionable step 1", "step 2", "step 3"],
    "confidence": 0.0-1.0,
    "reasoning_mode": "rich_evidence|thin_evidence|crown_jewel"
}}"""


SYSTEM_PROMPT = (
    "You are a senior penetration testing expert writing CISO-grade security reports. "
    "Your finding details are technically precise, actionable, and suitable for board-level reporting. "
    "Never produce placeholder or generic text — every finding detail must be specific to the context provided."
)


# ---------------------------------------------------------------------------
# Builder function
# ---------------------------------------------------------------------------

def build_finding_detail_prompt(
    finding: Finding,
    chain_context: dict,
) -> str:
    """Build the enriched prompt for AI finding detail generation.

    chain_context keys:
      - enabled_by_titles: list[str]
      - enables_titles: list[str]
      - total_steps: int (total findings in engagement)
      - is_crown_jewel: bool (finding is last node in primary path)
    """
    enabled_by_titles = chain_context.get("enabled_by_titles", [])
    enables_titles = chain_context.get("enables_titles", [])
    total_steps = chain_context.get("total_steps", "?")
    is_crown_jewel = chain_context.get("is_crown_jewel", False)

    # Determine reasoning mode
    evidence_len = len(finding.evidence or "")
    if is_crown_jewel:
        reasoning_mode = "crown_jewel"
    elif evidence_len >= 100:
        reasoning_mode = "rich_evidence"
    else:
        reasoning_mode = "thin_evidence"

    # Chain position label
    step = finding.step_index
    if step is not None:
        position_label = f"Step {step} of {total_steps}"
    else:
        position_label = "Position unknown (no step_index)"

    if not enabled_by_titles:
        chain_position = f"{position_label} — entry point (no prerequisites)"
    elif not enables_titles:
        chain_position = f"{position_label} — terminal finding (nothing depends on this)"
    else:
        chain_position = f"{position_label} — mid-chain pivot"

    # Crown jewel context block
    if is_crown_jewel:
        enabled_by_str = " → ".join(enabled_by_titles) if enabled_by_titles else "direct access"
        crown_jewel_context = (
            f"⚠ CROWN JEWEL: This is the final objective in the primary attack chain. "
            f"Attack path to get here: {enabled_by_str} → {finding.title}. "
            f"Describe the full blast radius and business impact."
        )
    else:
        crown_jewel_context = ""

    # Evidence block
    if finding.evidence and len(finding.evidence.strip()) > 0:
        evidence_or_none = finding.evidence
    else:
        evidence_or_none = (
            f"No direct evidence recorded. Reason from MITRE {finding.mitre_technique or 'N/A'} "
            f"and chain position: {chain_position}."
        )

    timestamp_str = (
        f"{finding.timestamp_offset_s}s from engagement start"
        if finding.timestamp_offset_s is not None
        else "Not recorded"
    )

    return FINDING_DETAIL_PROMPT.format(
        title=finding.title,
        severity_label=finding.severity_label,
        severity=finding.severity,
        mitre_technique=finding.mitre_technique or "N/A",
        mitre_description=_get_mitre_description(finding.mitre_technique),
        step_index=finding.step_index if finding.step_index is not None else "?",
        total_steps=total_steps,
        timestamp=timestamp_str,
        host=finding.host or "Not recorded",
        enabled_by_titles=", ".join(enabled_by_titles) or "None (entry point)",
        enables_titles=", ".join(enables_titles) or "None (terminal finding)",
        chain_position=chain_position,
        crown_jewel_context=crown_jewel_context,
        evidence_or_none=evidence_or_none,
    )
