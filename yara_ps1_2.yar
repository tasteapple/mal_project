rule PS1_Recon_Persistence_Firewall_Combo
{
    meta:
        description = "Detects PowerShell scripts combining reconnaissance, persistence, and firewall modification"
        author = "OpenAI"
        date = "2026-04-02"

    strings:
        $r1 = "Test-NetConnection" nocase
        $r2 = "Get-CimInstance" nocase
        $r3 = "AntiVirusProduct" nocase
        $r4 = "Register-ScheduledTask" nocase
        $r5 = "New-ScheduledTaskAction" nocase
        $r6 = "New-ScheduledTaskTrigger" nocase
        $r7 = "Set-NetFirewallProfile" nocase
        $r8 = "Out-File" nocase

    condition:
        (2 of ($r1,$r2,$r3)) and
        (2 of ($r4,$r5,$r6)) and
        1 of ($r7,$r8)
}