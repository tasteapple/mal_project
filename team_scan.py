import yara
import os
import sys

try:
    from oletools.olevba import VBA_Parser
    OLE_SUPPORT = True
except:
    OLE_SUPPORT = False

def get_base_path():
    # 현재 실행 중인 파일(EXE 또는 PY)의 절대 경로를 반환
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))

def run_scan():
    base_path = get_base_path()
    results = []
    
    # 1. 룰 파일 확인
    yar_files = [f for f in os.listdir(base_path) if f.endswith('.yar')]
    if not yar_files: return []

    try:
        rule_dict = {f: os.path.join(base_path, f) for f in yar_files}
        rules = yara.compile(filepaths=rule_dict)
        
        target_exts = ('.exe', '.xlsm', '.xlsx', '.xls', '.ps1')
        
        for file in os.listdir(base_path):
            if file.lower().endswith(target_exts):
                # 본체 프로그램만 제외 (확장자 포함하여 정확히 비교)
                if file.lower() == os.path.basename(sys.executable).lower(): continue
                if file.startswith("~$"): continue
                
                file_path = os.path.join(base_path, file)
                res = {"파일 이름": file, "수준": "정상", "탐지 여부": "미탐지", "상세내용": "분석 결과 이상 없음"}
                
                data = b""
                # VBA 추출 시도
                if OLE_SUPPORT and file.lower().endswith(('.xlsm', '.xls', '.xlsx')):
                    try:
                        vb = VBA_Parser(file_path)
                        if vb.detect_vba():
                            code = ""
                            for (_, _, _, txt) in vb.extract_macros(): code += txt
                            data = code.encode('utf-8', errors='ignore')
                        vb.close()
                    except: pass
                
                # VBA가 없으면 전체 파일 읽기
                if not data:
                    try:
                        with open(file_path, 'rb') as f: data = f.read()
                    except: continue

                # YARA 매칭
                if data:
                    matches = rules.match(data=data)
                    if matches:
                        res["수준"] = "심각"
                        res["탐지 여부"] = "탐지됨"
                        res["상세내용"] = f"패턴 탐지: {', '.join([str(m) for m in matches])}"
                
                results.append(res)
        return results
    except Exception as e:
        print(f"스캔 도중 치명적 에러: {e}")
        return []