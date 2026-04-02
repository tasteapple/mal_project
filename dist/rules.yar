rule Malicious_VBA_Keywords {
    strings:
        $s1 = "Document_Open" nocase   // 파일 열 때 자동 실행
        $s2 = "Auto_Open" nocase       // 구버전 자동 실행
        $s3 = "Shell" nocase           // 시스템 명령어 실행
        $s4 = "URLDownloadToFile" nocase // 외부 파일 다운로드
        $s5 = "Environ" nocase         // 환경 변수 접근
        $s6 = "CreateObject(\"WScript.Shell\")" nocase
    condition:
        2 of them  // 위 키워드 중 2개 이상 발견 시 탐지
}