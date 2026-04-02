import os
import sys
from pathlib import Path

import yara

try:
    from oletools.olevba import VBA_Parser
    OLE_SUPPORT = True
except Exception:
    OLE_SUPPORT = False

def base_dir() -> Path:
    if getattr(sys, 'frozen', False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent

def find_yara_rule_files():
    candidates = []
    folders = [base_dir(), Path.cwd(), base_dir() / "rules", Path.cwd() / "rules"]
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        folders.extend([Path(meipass), Path(meipass) / "rules"])
    seen = set()
    for folder in folders:
        if folder.exists():
            for p in list(folder.glob("*.yar")) + list(folder.glob("*.yara")):
                rp = str(p.resolve())
                if rp not in seen:
                    candidates.append(p)
                    seen.add(rp)
    return candidates

def read_target_data(file_path: Path) -> bytes:
    data = b""
    if OLE_SUPPORT and file_path.suffix.lower() in ('.xlsm', '.xls', '.xlsx'):
        try:
            vb = VBA_Parser(str(file_path))
            if vb.detect_vba():
                code = ""
                for (_, _, _, txt) in vb.extract_macros():
                    code += txt
                data = code.encode('utf-8', errors='ignore')
            vb.close()
        except Exception:
            data = b""
    if not data:
        with open(file_path, 'rb') as f:
            data = f.read()
    return data

def run_yara_scan(target_file):
    result = {"rule_files": [], "rows": [], "matched_count": 0, "loaded_count": 0, "error_count": 0}
    rule_files = find_yara_rule_files()
    result["rule_files"] = [str(p) for p in rule_files]
    if not rule_files:
        result["rows"].append({"rule_file": "(none)", "status": "skipped", "match_count": 0, "detail": "발견된 .yar/.yara 파일이 없습니다."})
        return result

    try:
        rule_dict = {p.name: str(p) for p in rule_files}
        compiled = yara.compile(filepaths=rule_dict)
        result["loaded_count"] = len(rule_files)
    except Exception as e:
        result["rows"].append({"rule_file": "(compile)", "status": "error", "match_count": 0, "detail": f"YARA 컴파일 실패: {e}"})
        result["error_count"] += 1
        return result

    try:
        data = read_target_data(Path(target_file))
    except Exception as e:
        result["rows"].append({"rule_file": "(target)", "status": "error", "match_count": 0, "detail": f"대상 파일 로드 실패: {e}"})
        result["error_count"] += 1
        return result

    try:
        matches = compiled.match(data=data, timeout=5)
    except Exception as e:
        result["rows"].append({"rule_file": "(match)", "status": "error", "match_count": 0, "detail": f"YARA 매칭 실패: {e}"})
        result["error_count"] += 1
        return result

    matched_by_ns = {}
    for m in matches:
        ns = getattr(m, "namespace", "") or "(unknown)"
        matched_by_ns.setdefault(ns, []).append(m.rule)

    for rf in rule_files:
        names = matched_by_ns.get(rf.name, [])
        if names:
            result["matched_count"] += len(names)
            result["rows"].append({
                "rule_file": rf.name,
                "status": "matched",
                "match_count": len(names),
                "detail": "매칭 룰: " + ", ".join(names[:10])
            })
        else:
            result["rows"].append({
                "rule_file": rf.name,
                "status": "loaded",
                "match_count": 0,
                "detail": "매칭 없음"
            })
    return result
