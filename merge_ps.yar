rule PS_Composite_Recon_Stage_Persist_DefenseEvasion
{
    meta:
        description = "Detects PowerShell scripts combining recon, staging, persistence, AV enumeration, and firewall modification"
        author = "OpenAI"
        date = "2026-04-02"
        version = "1.0"
        target = "PowerShell script text"

    strings:
        // Recon
        $recon1 = "Test-NetConnection" ascii wide nocase
        $recon2 = "-Port 445" ascii wide nocase
        $recon3 = "TcpTestSucceeded" ascii wide nocase
        $recon4 = "192.168." ascii wide nocase

        // Staging / File collection
        $stage1 = "$env:USERPROFILE\\Documents" ascii wide nocase
        $stage2 = "*.pdf" ascii wide nocase
        $stage3 = "*.docx" ascii wide nocase
        $stage4 = "*.txt" ascii wide nocase
        $stage5 = "Get-ChildItem" ascii wide nocase
        $stage6 = "Copy-Item" ascii wide nocase
        $stage7 = "Staging" ascii wide nocase
        $stage8 = "C:\\Temp\\Staging" ascii wide nocase
        $stage9 = "-Recurse" ascii wide nocase

        // Persistence
        $persist1 = "Register-ScheduledTask" ascii wide nocase
        $persist2 = "New-ScheduledTaskAction" ascii wide nocase
        $persist3 = "New-ScheduledTaskTrigger" ascii wide nocase
        $persist4 = "-User \"SYSTEM\"" ascii wide nocase
        $persist5 = "WindowsSecurityCheck" ascii wide nocase

        // Security product enumeration
        $sec1 = "Get-CimInstance" ascii wide nocase
        $sec2 = "root/SecurityCenter2" ascii wide nocase
        $sec3 = "AntiVirusProduct" ascii wide nocase
        $sec4 = "productState" ascii wide nocase

        // Firewall modification
        $fw1 = "Set-NetFirewallProfile" ascii wide nocase
        $fw2 = "-Enabled False" ascii wide nocase
        $fw3 = "Domain,Public,Private" ascii wide nocase

        // Logging / execution artifacts
        $log1 = "Out-File" ascii wide nocase
        $log2 = "C:\\Temp\\ps_execution_log.txt" ascii wide nocase

        // Sample-specific optional IOC
        $ioc1 = "yara_sample_ransomware_claude.exe" ascii wide nocase

    condition:
        filesize < 300KB and
        (
            (
                1 of ($recon*) and
                2 of ($stage*) and
                2 of ($persist*) and
                1 of ($sec*) and
                1 of ($fw*)
            )
            or
            (
                1 of ($log*) and
                1 of ($persist*) and
                1 of ($fw*) and
                1 of ($sec*)
            )
            or
            (
                1 of ($ioc*) and
                1 of ($persist*) and
                1 of ($recon*)
            )
        )
}