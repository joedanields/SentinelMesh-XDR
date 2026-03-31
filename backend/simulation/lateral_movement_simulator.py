"""Lateral movement attack simulator."""

from __future__ import annotations

import random
from datetime import timedelta
from typing import Any, Dict, List, Optional

from .base_simulator import (
    BaseSimulator,
    _rand_internal_ip,
    _rand_hostname,
    _rand_username,
    _INTERNAL_SUBNETS,
)


# ---------------------------------------------------------------------------
# Data pools
# ---------------------------------------------------------------------------

_ADMIN_SHARES = ["C$", "ADMIN$", "IPC$", "SYSVOL", "NETLOGON"]
_SENSITIVE_FILES = [
    r"C:\Users\Administrator\Documents\passwords.xlsx",
    r"C:\Windows\NTDS\ntds.dit",
    r"C:\Windows\System32\config\SAM",
    r"\\dc-01\SYSVOL\domain\scripts\logon.bat",
    r"/etc/shadow", r"/etc/passwd", r"~/.ssh/id_rsa",
]
_PS_COMMANDS = [
    "Invoke-Mimikatz -DumpCreds",
    "Get-ADUser -Filter * -Properties *",
    "net user /domain",
    "net group 'Domain Admins' /domain",
    "Invoke-WMIMethod -Class Win32_Process -Name Create -ArgumentList 'cmd.exe /c whoami'",
    "Get-WmiObject Win32_ComputerSystem",
    "Set-MpPreference -DisableRealtimeMonitoring $true",
    "New-LocalUser -Name backdoor -Password (ConvertTo-SecureString 'P@ssw0rd' -AsPlainText -Force)",
]
_WMI_QUERIES = [
    "SELECT * FROM Win32_Process WHERE Name = 'lsass.exe'",
    "SELECT * FROM Win32_UserAccount",
    "SELECT * FROM Win32_NetworkAdapterConfiguration",
    "SELECT * FROM Win32_Share",
]
_MITRE_TECHNIQUES = {
    "smb_lateral": "T1021.002",
    "wmi_execution": "T1047",
    "pass_the_hash": "T1550.002",
    "pass_the_ticket": "T1550.003",
    "powershell": "T1059.001",
    "remote_service": "T1021",
}


class LateralMovementSimulator(BaseSimulator):
    """
    Simulates attacker lateral movement through a compromised network.

    Generates a multi-step attack chain:
    1. Initial host compromise logs
    2. Credential harvesting (Mimikatz / LSASS dump)
    3. SMB shares enumeration and access
    4. WMI remote execution on target hosts
    5. PowerShell execution (encoded commands)
    6. Pass-the-hash / Pass-the-ticket attempts
    7. Persistence establishment (new local user, scheduled task)
    """

    scenario_name = "lateral_movement"

    def __init__(
        self,
        *,
        initial_host: Optional[str] = None,
        attacker_ip: Optional[str] = None,
        internal_targets: Optional[List[str]] = None,
        num_hops: int = 3,
        start_time=None,
        seed: Optional[int] = None,
    ) -> None:
        super().__init__(
            target_host=initial_host,
            attacker_ip=attacker_ip,
            start_time=start_time,
            seed=seed,
        )
        self.initial_host = self.target_host
        self.internal_targets = internal_targets or [
            _rand_internal_ip() for _ in range(num_hops)
        ]
        self.num_hops = len(self.internal_targets)

    # ------------------------------------------------------------------

    def simulate(self, **params: Any) -> List[Dict[str, Any]]:
        logs: List[Dict[str, Any]] = []
        offset = 0.0

        # Step 1: Initial foothold signals
        logs.extend(self._initial_compromise(offset))
        offset += random.uniform(30, 120)

        # Step 2: Credential harvesting
        logs.extend(self._credential_harvest(offset))
        offset += random.uniform(60, 300)

        # Step 3: Lateral movement hops
        current_host = self.initial_host
        for hop_num, target in enumerate(self.internal_targets, 1):
            logs.extend(
                self._lateral_hop(
                    offset, current_host, target, hop_num
                )
            )
            offset += random.uniform(120, 600)
            current_host = _rand_hostname()  # attacker pivots

        # Step 4: Persistence
        logs.extend(self._establish_persistence(offset, current_host))

        return sorted(logs, key=lambda x: x["timestamp"])

    # ------------------------------------------------------------------
    # Individual simulation phases
    # ------------------------------------------------------------------

    def _initial_compromise(self, base_offset: float) -> List[Dict[str, Any]]:
        logs: List[Dict[str, Any]] = []
        timestamps = self._jittered_timestamps(5, max_interval=10)
        for i, ts in enumerate(timestamps):
            off = base_offset + (ts - self.start_time).total_seconds()
            if i == 0:
                msg = f"Unexpected outbound connection from {self.initial_host} to {self.attacker_ip}"
                ev_type = "network_connection"
            elif i == 1:
                msg = f"Process cmd.exe spawned by explorer.exe on {self.initial_host}"
                ev_type = "process_execution"
            elif i == 2:
                msg = f"Suspicious child process: powershell.exe -enc JABjAG..."
                ev_type = "process_execution"
            elif i == 3:
                msg = f"New scheduled task created: Windows_Update_Helper"
                ev_type = "scheduled_task"
            else:
                msg = f"Registry modification: HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
                ev_type = "registry_modification"

            logs.append(
                self._log_template(
                    offset_seconds=off,
                    event_type=ev_type,
                    source_ip=self.attacker_ip,
                    dest_ip=_rand_internal_ip(),
                    hostname=self.initial_host,
                    message=msg,
                    severity="high",
                    attack_vector="lateral_movement",
                    phase="initial_compromise",
                    mitre_technique="T1059",
                )
            )
        return logs

    def _credential_harvest(self, base_offset: float) -> List[Dict[str, Any]]:
        logs: List[Dict[str, Any]] = []
        timestamps = self._jittered_timestamps(6, max_interval=5)
        harvested_users = [_rand_username() for _ in range(3)]

        for i, ts in enumerate(timestamps):
            off = base_offset + (ts - self.start_time).total_seconds()
            if i == 0:
                msg = f"LSASS memory read by process mimikatz.exe (PID {random.randint(1000,9999)})"
                ev = "credential_access"
                sev = "critical"
            elif i == 1:
                ps_cmd = _PS_COMMANDS[0]  # Mimikatz invoke
                msg = f"PowerShell: {ps_cmd}"
                ev = "process_execution"
                sev = "critical"
            elif i < 5:
                user = harvested_users[i % len(harvested_users)]
                msg = f"Credential harvested for {user} (NTLM hash extracted)"
                ev = "credential_access"
                sev = "critical"
            else:
                msg = f"Windows event 4624 logon type 9 (NewCredentials) for {harvested_users[0]}"
                ev = "authentication"
                sev = "high"

            logs.append(
                self._log_template(
                    offset_seconds=off,
                    event_type=ev,
                    source_ip=_rand_internal_ip(),
                    dest_ip=_rand_internal_ip(),
                    hostname=self.initial_host,
                    username=harvested_users[i % len(harvested_users)],
                    message=msg,
                    severity=sev,
                    attack_vector="lateral_movement",
                    phase="credential_harvest",
                    mitre_technique="T1003.001",
                )
            )
        return logs

    def _lateral_hop(
        self,
        base_offset: float,
        source_host: str,
        target_ip: str,
        hop_num: int,
    ) -> List[Dict[str, Any]]:
        logs: List[Dict[str, Any]] = []
        technique = random.choice(["smb_lateral", "wmi_execution", "pass_the_hash"])
        mitre = _MITRE_TECHNIQUES[technique]
        timestamps = self._jittered_timestamps(8, max_interval=15)

        for i, ts in enumerate(timestamps):
            off = base_offset + (ts - self.start_time).total_seconds()
            username = _rand_username()

            if technique == "smb_lateral":
                share = random.choice(_ADMIN_SHARES)
                if i == 0:
                    msg = f"SMB connection established: {source_host} -> {target_ip} share={share}"
                    ev = "network_connection"
                    sev = "high"
                elif i == 1:
                    msg = f"File dropped via SMB: {share}\\malware.exe on {target_ip}"
                    ev = "file_write"
                    sev = "critical"
                else:
                    filepath = random.choice(_SENSITIVE_FILES)
                    msg = f"SMB file access: {filepath} on {target_ip}"
                    ev = "file_access"
                    sev = "high"

            elif technique == "wmi_execution":
                wmi_q = random.choice(_WMI_QUERIES)
                if i == 0:
                    msg = f"WMI remote query from {source_host} to {target_ip}: {wmi_q}"
                    ev = "wmi_activity"
                    sev = "high"
                elif i == 1:
                    msg = f"WMI process creation on {target_ip}: cmd.exe /c whoami > out.txt"
                    ev = "process_execution"
                    sev = "critical"
                else:
                    ps = random.choice(_PS_COMMANDS)
                    msg = f"Remote PowerShell via WMI on {target_ip}: {ps}"
                    ev = "process_execution"
                    sev = "critical"

            else:  # pass_the_hash
                if i == 0:
                    msg = (
                        f"Pass-the-Hash detected: {source_host} used NTLM hash for "
                        f"{username} to authenticate to {target_ip}"
                    )
                    ev = "authentication"
                    sev = "critical"
                elif i == 1:
                    msg = f"NTLM authentication with harvested hash - EventID 4624 type 3"
                    ev = "authentication"
                    sev = "critical"
                else:
                    ps = random.choice(_PS_COMMANDS[2:])
                    msg = f"Privileged command executed as {username} on {target_ip}: {ps}"
                    ev = "process_execution"
                    sev = "high"

            logs.append(
                self._log_template(
                    offset_seconds=off,
                    event_type=ev,
                    source_ip=_rand_internal_ip(),
                    dest_ip=target_ip,
                    hostname=source_host,
                    username=username,
                    message=msg,
                    severity=sev,
                    attack_vector="lateral_movement",
                    phase=f"hop_{hop_num}",
                    technique=technique,
                    mitre_technique=mitre,
                    hop_number=hop_num,
                )
            )

        return logs

    def _establish_persistence(
        self, base_offset: float, current_host: str
    ) -> List[Dict[str, Any]]:
        logs: List[Dict[str, Any]] = []
        timestamps = self._jittered_timestamps(4, max_interval=10)
        backdoor_user = "svc_update"

        persistence_events = [
            (
                "user_management",
                f"New user created: {backdoor_user} added to Administrators group",
                "critical",
                "T1136.001",
            ),
            (
                "scheduled_task",
                r"Scheduled task 'Windows_Telemetry_Helper' created - runs C:\Windows\Temp\update.exe",
                "high",
                "T1053.005",
            ),
            (
                "registry_modification",
                r"Registry persistence: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit modified",
                "critical",
                "T1547.004",
            ),
            (
                "service_installation",
                r"New service installed: 'WinHelperSvc' points to C:\Windows\Temp\svc.dll",
                "critical",
                "T1543.003",
            ),
        ]

        for ts, (ev, msg, sev, mitre) in zip(timestamps, persistence_events):
            off = base_offset + (ts - self.start_time).total_seconds()
            logs.append(
                self._log_template(
                    offset_seconds=off,
                    event_type=ev,
                    source_ip=_rand_internal_ip(),
                    dest_ip=_rand_internal_ip(),
                    hostname=current_host,
                    username=backdoor_user,
                    message=msg,
                    severity=sev,
                    attack_vector="lateral_movement",
                    phase="persistence",
                    mitre_technique=mitre,
                )
            )

        return logs
