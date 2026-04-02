rule Detect_Recon_and_Persistence_Script {
    meta:
        description = "Detects project_test.ps1 based on specific logging and staging paths"
        author = "Gemini Security Analyst"
        date = "2026-04-02"

    strings:
        // 고유한 로그 및 스테이징 경로
        $path1 = "C:\\Temp\\ps_execution_log.txt" wide ascii
        $path2 = "C:\\Temp\\Staging" wide ascii
        
        // 악성 행위 관련 키워드
        $recon = "Test-NetConnection" wide ascii
        $recon_port = "-Port 445" wide ascii
        $persistence = "Register-ScheduledTask" wide ascii
        $task_name = "WindowsSecurityCheck" wide ascii
        
        // 특정 실행 파일 참조
        $target_exe = "yara_sample_ransomware_claude.exe" wide ascii

    condition:
        // 경로 문자열 중 하나와 행위 키워드 조합 시 탐지
        (any of ($path*)) and (2 of ($recon, $recon_port, $persistence, $task_name, $target_exe))
}