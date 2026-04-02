rule PS1_Training_Scenario_Stage_Persist_DisableFW
{
    meta:
        description = "Detects the training PowerShell scenario with staging, scheduled task persistence, security product enumeration, and firewall disable"
        author = "OpenAI"
        date = "2026-04-02"

    strings:
        $a1 = "Test-NetConnection" nocase
        $a2 = "Copy-Item" nocase
        $a3 = "Get-ChildItem" nocase
        $a4 = "Register-ScheduledTask" nocase
        $a5 = "New-ScheduledTaskAction" nocase
        $a6 = "New-ScheduledTaskTrigger" nocase
        $a7 = "root/SecurityCenter2" nocase
        $a8 = "AntiVirusProduct" nocase
        $a9 = "Set-NetFirewallProfile" nocase
        $a10 = "-Enabled False" nocase
        $a11 = "ps_execution_log.txt" nocase
        $a12 = "C:\\Temp\\Staging" nocase

    condition:
        6 of ($a*)
}