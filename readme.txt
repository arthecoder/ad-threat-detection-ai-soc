# Active Directory Attack & Detection Lab with Wazuh SIEM & AI SOAR

An end-to-end enterprise detection engineering and incident response lab simulating Active Directory identity attacks against a Windows Server Domain Controller (`corp.local`), ingesting Windows Security and Sysmon telemetry into **Wazuh SIEM**, and triaging high-severity alerts through an **AI SOC Analyst (Google Gemini + n8n)** with **Human-in-the-Loop SOAR** approval via Telegram.

---

## Architecture & Lab Topology

All virtual machines operate on an isolated VMware Workstation Pro NAT network (`192.168.70.0/24`):

```text
+-----------------------------------+       Kerberos / SMB Attacks        +-----------------------------------+

|         Kali Linux (Attacker)     |  (AS-REP Roast, Kerberoast, Spray)  |   Windows Server 2022 (DC01)      |
|         IP: 192.168.70.129        | ----------------------------------> |   Domain: corp.local              |
|                                   |                                     |   IP: 192.168.70.20               |
|  * Impacket / NetExec             |                                     |   * AD DS, DNS, Sysmon, Wazuh Agt |
|  * n8n SOAR + Google Gemini AI    | <----+                              +-----------------------------------+
+-----------------------------------+      |                                                |

                 |                         | Webhook (Level 10+ JSON Alert)                 | Windows Security + Sysmon
                 v                         |                                                | Logs (Port 1514)
+-----------------------------------+      |                              +-----------------------------------+

|   Telegram Human-in-the-Loop      |      +----------------------------- |   Ubuntu Server (Wazuh SIEM)      |
|   * AI Threat Summary             |                                     |   IP: 192.168.70.131              |
|   * Approve / Ignore Containment  |                                     |   * Custom Rules (100110, 100111) |
+-----------------------------------+                                     +-----------------------------------+
```

---

## Lab Environment & Vulnerable Targets

| Host | OS / Stack | Static IP | Role & Configuration |
| :--- | :--- | :--- | :--- |
| **`DC01`** | Windows Server 2022 | `192.168.70.20` | Active Directory Domain Controller (`corp.local`), Kerberos/Logon auditing enabled, Sysmon + Wazuh Agent |
| **`Ubuntu-SIEM`** | Ubuntu Server | `192.168.70.131` | Central Wazuh Manager, Indexer, Dashboard, custom detection rules, and `custom-n8n.py` webhook integration |
| **`Kali-SOC`** | Kali Linux | `192.168.70.129` | Adversary simulation (`impacket`, `netexec`) + containerized **n8n** SOAR orchestration & **Google Gemini** AI triage |

### Simulated Enterprise Misconfigurations (`corp.local`)
* **`svc_sql` (Kerberoastable Service Account):** Standard domain user registered with Service Principal Name `MSSQLSvc/dc01.corp.local:1433`.
* **`svc_backup` (AS-REP Roastable Account):** Domain account configured with `DoesNotRequirePreAuth = True` (`UF_DONT_REQUIRE_PREAUTH`).
* **`jdoe` (Standard Domain User):** Baseline user account used to request TGS tickets and test password spraying.

![Active Directory Target Setup](screenshots/01-dc01-ad-users.png)

---

## Attack Simulations & Detection Matrix

| Attack Scenario | Tool / Command | MITRE ATT&CK | Windows Event ID | Wazuh Rule ID & Level |
| :--- | :--- | :--- | :--- | :--- |
| **AS-REP Roasting** | `impacket-GetNPUsers` | `T1558.004` | `4768` (Pre-Auth Type `0`, RC4 `0x17`) | `100110` (Level 12) |
| **Kerberoasting** | `impacket-GetUserSPNs` | `T1558.003` | `4769` (TGS Request, RC4 `0x17`) | `100111` (Level 12) |
| **Password Spraying** | `netexec smb` | `T1110.003` | `4625` (Logon Failure) | `60122` (Level 5) / `60204` (Level 10) |

### 1. Offensive Execution (Kali Linux)
* **AS-REP Roasting (`svc_backup`):** Extracted `$krb5asrep$23$svc_backup@CORP.LOCAL` hash without valid domain credentials.
* **Kerberoasting (`svc_sql`):** Requested an RC4-encrypted TGS service ticket (`$krb5tgs$23$*svc_sql@CORP.LOCAL`) using a standard user account.
* **SMB Password Spraying:** Tested common credentials across `Administrator`, `jdoe`, and `svc_sql`.

![Kali Attack Execution](screenshots/02-kali-kerberos-attacks.png)

### 2. Custom Wazuh Detection Engineering (`local_rules.xml`)
By default, Windows Kerberos ticket events (`4768` and `4769`) log at informational severity (`Level 3`). Custom correlation rules were engineered in `/var/ossec/etc/rules/local_rules.xml` to detect RC4 downgrade requests (`0x17`) and elevate them to **Level 12** so they trigger automated AI SOC triage:

```xml
<group name="windows,sysmon,active_directory,">
  <rule id="100110" level="12">
    <if_sid>60103,60104</if_sid>
    <field name="win.system.eventID">^4768\$</field>
    <field name="win.eventdata.preAuthType">^0\$</field>
    <description>Possible AS-REP Roasting Attack Detected (Kerberos Pre-Auth Disabled)</description>
    <mitre>
      <id>T1558.004</id>
    </mitre>
  </rule>

  <rule id="100111" level="12">
    <if_sid>60103,60104</if_sid>
    <field name="win.system.eventID">^4769\$</field>
    <field name="win.eventdata.ticketEncryptionType">0x17</field>
    <description>Possible Kerberoasting Attack Detected (TGS Request with RC4 Encryption)</description>
    <mitre>
      <id>T1558.003</id>
    </mitre>
  </rule>
</group>
```

![Wazuh Security Events](screenshots/03-wazuh-alerts.png)

---

## AI SOC Triage & Human-in-the-Loop SOAR

When Wazuh triggers a **Level 10+** alert (`Rule 100110`, `Rule 100111`, or `Rule 60204`), `custom-n8n.py` forwards the JSON payload to an **n8n** workflow:
1. **Context Normalization (`Edit Fields`):** Extracts source IP, target user, service name, Windows Event ID, and MITRE ATT&CK ID.
2. **AI Analyst Triage (`Google Gemini`):** Evaluates the alert context, explains the attack vector, assesses severity, and recommends targeted identity or network remediation.
3. **Human-in-the-Loop Governance (`Telegram`):** Dispatches the AI summary to Telegram and pauses execution (`Send message and wait for response`) so an analyst can approve or ignore active containment—preventing automated false-positive lockouts on internal infrastructure.

![n8n Workflow Execution](screenshots/04-n8n-ai-soar-workflow.png)

---

## Remediation & Hardening

Following detection and triage, the Active Directory misconfigurations were remediated on `DC01`:
1. **Re-enable Kerberos Pre-Authentication:**
   ```powershell
   Set-ADAccountControl -Identity "svc_backup" -DoesNotRequirePreAuth \$false
   ```
2. **Enforce Strong Service Account Passwords & AES Encryption:** Rotate `svc_sql` to a 25+ character randomized password (or migrate to a Group Managed Service Account — gMSA) and enforce AES-128/AES-256 Kerberos encryption.
3. **Enable Account Lockout Policies:** Configure Domain Group Policy account lockout thresholds to mitigate SMB/Kerberos password spraying.
