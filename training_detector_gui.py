import os
import sys
import json
import hashlib
import platform
import datetime as dt
import re
from pathlib import Path

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import makepdf  # [추가] PDF 변환 모듈 연결

from yara_helper import run_yara_scan, find_yara_rule_files

APP_TITLE = "Malware Training Detector"
APP_SUBTITLE = "훈련용 악성코드 탐지 · 분석 도구 | 내부 룰셋 + YARA 하이브리드 탐지"

DEFAULT_RULES = {
    "file_string_rules": [],
    "artifact_rules": [],
    "registry_rules": []
}

def app_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent

def load_rules():
    candidates = [app_dir() / "rules.json", Path.cwd() / "rules.json"]
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        candidates.append(Path(meipass) / "rules.json")
    for p in candidates:
        if p.exists():
            with open(p, "r", encoding="utf-8") as f:
                return json.load(f), str(p)
    return DEFAULT_RULES, "rules.json not found"

def sha_all(path: Path):
    hashes = {
        "MD5": hashlib.md5(),
        "SHA1": hashlib.sha1(),
        "SHA256": hashlib.sha256(),
    }
    with open(path, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            for h in hashes.values():
                h.update(chunk)
    return {k: v.hexdigest() for k, v in hashes.items()}

def file_size_fmt(size):
    units = ["B", "KB", "MB", "GB"]
    n = float(size)
    i = 0
    while n >= 1024 and i < len(units) - 1:
        n /= 1024.0
        i += 1
    return f"{n:.2f} {units[i]}"

def read_file_strings(path: Path, limit=4_000_000):
    ext = path.suffix.lower()

    if ext == ".ps1":
        for enc in ("utf-8-sig", "utf-8", "cp949", "euc-kr", "latin1"):
            try:
                return path.read_text(encoding=enc, errors="ignore")
            except Exception:
                continue
        return ""

    data = path.read_bytes()[:limit]

    text_ascii = []
    cur = bytearray()
    for b in data:
        if 32 <= b <= 126:
            cur.append(b)
        else:
            if len(cur) >= 4:
                text_ascii.append(cur.decode("ascii", errors="ignore"))
            cur = bytearray()
    if len(cur) >= 4:
        text_ascii.append(cur.decode("ascii", errors="ignore"))

    try:
        uni_raw = re.findall(r"(?:[\x20-\x7E]\x00){4,}", data.decode("latin1", errors="ignore"))
        text_uni = [s.replace("\x00", "") for s in uni_raw]
    except Exception:
        text_uni = []

    return "\n".join(text_ascii + text_uni)

def is_pe_file(path: Path):
    try:
        with open(path, "rb") as f:
            if f.read(2) != b"MZ":
                return False, None
            f.seek(0x3C)
            pe_offset = int.from_bytes(f.read(4), "little")
            f.seek(pe_offset)
            sig = f.read(4)
            return sig == b"PE\x00\x00", pe_offset
    except Exception:
        return False, None

class Scanner:
    def __init__(self, rules):
        self.rules = rules

    def scan_file(self, path: Path):
        findings = []
        score = 0
        ext = path.suffix.lower()

        if ext == ".exe":
            pe_ok, pe_offset = is_pe_file(path)
        else:
            pe_ok, pe_offset = False, None

        strings_blob = read_file_strings(path).lower()

        for rule in self.rules.get("file_string_rules", []):
            hits = []
            for p in rule.get("patterns", []):
                if p.lower() in strings_blob:
                    hits.append(p)

            matched = len(hits) == len(rule["patterns"]) if rule.get("all_required") else len(hits) > 0

            if matched:
                add_score = int(rule["score"])
                score += add_score
                findings.append({
                    "type": "파일 문자열",
                    "name": rule["name"],
                    "severity": rule.get("severity", "medium"),
                    "score": add_score,
                    "detail": ", ".join(hits[:12])
                })

        return {
            "file_name": path.name,
            "file_path": str(path),
            "file_type": ext,
            "size": path.stat().st_size,
            "size_text": file_size_fmt(path.stat().st_size),
            "modified": dt.datetime.fromtimestamp(path.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
            "is_pe": pe_ok,
            "pe_offset": pe_offset,
            "hashes": sha_all(path),
            "findings": findings,
            "score": score
        }

    def scan_artifacts(self):
        findings = []
        score = 0
        for rule in self.rules.get("artifact_rules", []):
            target = Path(rule["path"])
            if target.exists():
                add_score = int(rule["score"])
                score += add_score
                findings.append({
                    "type": "산출물 흔적",
                    "name": rule["name"],
                    "severity": rule.get("severity", "medium"),
                    "score": add_score,
                    "detail": str(target)
                })
        return findings, score

    def scan_registry(self):
        findings = []
        score = 0
        if platform.system() != "Windows":
            return findings, score, "레지스트리 검사는 Windows 환경에서만 수행됩니다."
        try:
            import winreg
        except Exception:
            return findings, score, "winreg 모듈을 로드하지 못했습니다."

        root_map = {"HKCU": winreg.HKEY_CURRENT_USER, "HKLM": winreg.HKEY_LOCAL_MACHINE}
        for rule in self.rules.get("registry_rules", []):
            try:
                with winreg.OpenKey(root_map[rule["root"]], rule["subkey"], 0, winreg.KEY_READ) as k:
                    val, _ = winreg.QueryValueEx(k, rule["value"])
                    expected = rule.get("expected", None)
                    matched = (val == expected) if expected is not None else True
                    if matched:
                        add_score = int(rule["score"])
                        score += add_score
                        findings.append({
                            "type": "레지스트리",
                            "name": rule["name"],
                            "severity": rule.get("severity", "high"),
                            "score": add_score,
                            "detail": f"{rule['root']}\\{rule['subkey']} -> {rule['value']} = {val}"
                        })
            except OSError:
                pass
        return findings, score, ""

def summarize_risk(score):
    if score >= 50:
        return "HIGH", "#ff6b6b"
    if score >= 20:
        return "MEDIUM", "#ffd166"
    return "LOW", "#7bd389"

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("1240x800")
        self.minsize(1120, 720)
        self.configure(bg="#0f172a")
        self.rules, self.rules_source = load_rules()
        self.scanner = Scanner(self.rules)
        self.selected_file = None
        self.last_result = None
        self._style()
        self._build_ui()

    def _style(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure(".", font=("맑은 고딕", 10))
        style.configure("Dark.TFrame", background="#0f172a")
        style.configure("Card.TFrame", background="#111827")
        style.configure("Title.TLabel", background="#0f172a", foreground="white", font=("맑은 고딕", 18, "bold"))
        style.configure("Sub.TLabel", background="#0f172a", foreground="#cbd5e1", font=("맑은 고딕", 10))
        style.configure("CardTitle.TLabel", background="#111827", foreground="white", font=("맑은 고딕", 12, "bold"))
        style.configure("CardBody.TLabel", background="#111827", foreground="#d1d5db", font=("맑은 고딕", 10))
        style.configure("Accent.TButton", font=("맑은 고딕", 10, "bold"))
        style.configure("Treeview", rowheight=28, font=("맑은 고딕", 10), fieldbackground="#f8fafc")
        style.configure("Treeview.Heading", font=("맑은 고딕", 10, "bold"))
        style.configure("TNotebook", background="#0f172a", borderwidth=0)
        style.configure("TNotebook.Tab", font=("맑은 고딕", 10, "bold"), padding=(12, 8))
        style.configure("TProgressbar", troughcolor="#1f2937", background="#22c55e", bordercolor="#1f2937")

    def _build_ui(self):
        root = ttk.Frame(self, style="Dark.TFrame", padding=16)
        root.pack(fill="both", expand=True)

        header = ttk.Frame(root, style="Dark.TFrame")
        header.pack(fill="x", pady=(0, 12))
        ttk.Label(header, text=APP_TITLE, style="Title.TLabel").pack(anchor="w")
        ttk.Label(header, text=APP_SUBTITLE, style="Sub.TLabel").pack(anchor="w", pady=(4, 0))

        top = ttk.Frame(root, style="Dark.TFrame")
        top.pack(fill="x", pady=(0, 12))

        left = ttk.Frame(top, style="Card.TFrame", padding=16)
        left.pack(side="left", fill="both", expand=True, padx=(0, 8))
        ttk.Label(left, text="검사 대상", style="CardTitle.TLabel").pack(anchor="w")
        self.file_label = ttk.Label(left, text="선택된 파일이 없습니다.", style="CardBody.TLabel")
        self.file_label.pack(anchor="w", pady=(8, 6))
        self.rules_label = ttk.Label(left, text=f"내부 룰: {self.rules_source}", style="CardBody.TLabel", wraplength=620)
        self.rules_label.pack(anchor="w", pady=(0, 4))
        self.yara_label = ttk.Label(left, text="YARA 룰: exe 폴더 / 현재 폴더 / rules 폴더 자동 검색", style="CardBody.TLabel")
        self.yara_label.pack(anchor="w", pady=(0, 10))

        btns = ttk.Frame(left, style="Card.TFrame")
        btns.pack(fill="x")
        ttk.Button(btns, text="파일 선택", command=self.pick_file, style="Accent.TButton").pack(side="left")
        ttk.Button(btns, text="전체 검사 시작", command=self.run_scan, style="Accent.TButton").pack(side="left", padx=8)
        ttk.Button(btns, text="결과 저장", command=self.export_report, style="Accent.TButton").pack(side="left")
        ttk.Button(btns, text="PDF 리포트", command=self.export_pdf, style="Accent.TButton").pack(side="left", padx=8)
        
        self.progress = ttk.Progressbar(left, mode="determinate", maximum=100)
        self.progress.pack(fill="x", pady=(14, 6))
        self.progress_label = ttk.Label(left, text="대기 중", style="CardBody.TLabel")
        self.progress_label.pack(anchor="w")

        right = ttk.Frame(top, style="Card.TFrame", padding=16)
        right.pack(side="left", fill="both", expand=True)
        ttk.Label(right, text="위험도 요약", style="CardTitle.TLabel").pack(anchor="w")
        self.risk_value = tk.Label(right, text="LOW", bg="#111827", fg="#7bd389", font=("맑은 고딕", 28, "bold"))
        self.risk_value.pack(anchor="w", pady=(8, 2))
        self.score_label = ttk.Label(right, text="점수: 0", style="CardBody.TLabel")
        self.score_label.pack(anchor="w")
        self.summary_label = ttk.Label(right, text="검사 결과가 여기에 표시됩니다.", style="CardBody.TLabel", wraplength=420, justify="left")
        self.summary_label.pack(anchor="w", pady=(10, 0))

        notebook = ttk.Notebook(root)
        notebook.pack(fill="both", expand=True)

        self.tab_overview = ttk.Frame(notebook, style="Dark.TFrame", padding=10)
        self.tab_findings = ttk.Frame(notebook, style="Dark.TFrame", padding=10)
        self.tab_artifacts = ttk.Frame(notebook, style="Dark.TFrame", padding=10)
        self.tab_yara = ttk.Frame(notebook, style="Dark.TFrame", padding=10)
        self.tab_report = ttk.Frame(notebook, style="Dark.TFrame", padding=10)

        notebook.add(self.tab_overview, text="개요")
        notebook.add(self.tab_findings, text="탐지 근거")
        notebook.add(self.tab_artifacts, text="시스템 흔적")
        notebook.add(self.tab_yara, text="YARA 결과")
        notebook.add(self.tab_report, text="리포트")

        self._build_overview_tab()
        self._build_findings_tab()
        self._build_artifacts_tab()
        self._build_yara_tab()
        self._build_report_tab()

    def _build_overview_tab(self):
        frame = ttk.Frame(self.tab_overview, style="Card.TFrame", padding=14)
        frame.pack(fill="both", expand=True)
        cols = ("항목", "값")
        self.info_tree = ttk.Treeview(frame, columns=cols, show="headings")
        for c in cols:
            self.info_tree.heading(c, text=c)
        self.info_tree.column("항목", width=180, anchor="w")
        self.info_tree.column("값", width=900, anchor="w")
        self.info_tree.pack(fill="both", expand=True)

    def _build_findings_tab(self):
        frame = ttk.Frame(self.tab_findings, style="Card.TFrame", padding=14)
        frame.pack(fill="both", expand=True)
        cols = ("구분", "탐지 항목", "위험도", "점수", "세부 내용")
        self.findings_tree = ttk.Treeview(frame, columns=cols, show="headings")
        widths = [120, 230, 100, 70, 650]
        for c, w in zip(cols, widths):
            self.findings_tree.heading(c, text=c)
            self.findings_tree.column(c, width=w, anchor="w")
        self.findings_tree.pack(fill="both", expand=True)

    def _build_artifacts_tab(self):
        wrap = ttk.Frame(self.tab_artifacts, style="Dark.TFrame")
        wrap.pack(fill="both", expand=True)
        top = ttk.Frame(wrap, style="Card.TFrame", padding=14)
        top.pack(fill="both", expand=True, pady=(0, 8))
        ttk.Label(top, text="시스템 흔적 검사 결과", style="CardTitle.TLabel").pack(anchor="w", pady=(0, 8))
        cols = ("구분", "탐지 항목", "위험도", "점수", "세부 내용")
        self.artifact_tree = ttk.Treeview(top, columns=cols, show="headings")
        widths = [120, 240, 100, 70, 620]
        for c, w in zip(cols, widths):
            self.artifact_tree.heading(c, text=c)
            self.artifact_tree.column(c, width=w, anchor="w")
        self.artifact_tree.pack(fill="both", expand=True)

        bottom = ttk.Frame(wrap, style="Card.TFrame", padding=14)
        bottom.pack(fill="x")
        ttk.Label(bottom, text="참고", style="CardTitle.TLabel").pack(anchor="w")
        self.registry_note = ttk.Label(bottom, text="Windows 환경에서 레지스트리 검사를 수행합니다.", style="CardBody.TLabel", wraplength=1050, justify="left")
        self.registry_note.pack(anchor="w", pady=(6, 0))

    def _build_yara_tab(self):
        frame = ttk.Frame(self.tab_yara, style="Card.TFrame", padding=14)
        frame.pack(fill="both", expand=True)
        cols = ("룰 파일", "상태", "매칭 수", "세부 내용")
        self.yara_tree = ttk.Treeview(frame, columns=cols, show="headings")
        widths = [330, 160, 80, 500]
        for c, w in zip(cols, widths):
            self.yara_tree.heading(c, text=c)
            self.yara_tree.column(c, width=w, anchor="w")
        self.yara_tree.pack(fill="both", expand=True)

    def _build_report_tab(self):
        frame = ttk.Frame(self.tab_report, style="Card.TFrame", padding=14)
        frame.pack(fill="both", expand=True)
        ttk.Label(frame, text="분석 리포트", style="CardTitle.TLabel").pack(anchor="w")
        self.report_text = tk.Text(frame, wrap="word", bg="#0b1220", fg="#e5e7eb", insertbackground="white", relief="flat", font=("Consolas", 10))
        self.report_text.pack(fill="both", expand=True, pady=(10, 0))

    def pick_file(self):
        path = filedialog.askopenfilename(
            title="검사 대상 파일 선택",
            filetypes=[
                ("Supported Files (*.exe, *.ps1)", ("*.exe", "*.ps1")),
                ("Executable Files (*.exe)", "*.exe"),
                ("PowerShell Files (*.ps1)", "*.ps1")
            ]
        )
        if path:
            self.selected_file = Path(path)
            self.file_label.config(text=str(self.selected_file))

    def set_progress(self, value, text):
        self.progress["value"] = value
        self.progress_label.config(text=text)
        self.update_idletasks()

    def clear_tables(self):
        for tree in [self.info_tree, self.findings_tree, self.artifact_tree, self.yara_tree]:
            for item in tree.get_children():
                tree.delete(item)
        self.report_text.delete("1.0", "end")

    def run_scan(self):
        if not self.selected_file:
            messagebox.showwarning("파일 필요", "먼저 검사할 EXE 파일을 선택하세요.")
            return
        if not self.selected_file.exists():
            messagebox.showerror("오류", "선택한 파일이 존재하지 않습니다.")
            return

        self.clear_tables()
        self.set_progress(10, "파일 기본 정보 수집 중...")
        file_result = self.scanner.scan_file(self.selected_file)

        self.set_progress(35, "산출물 흔적 검사 중...")
        artifact_findings, artifact_score = self.scanner.scan_artifacts()

        self.set_progress(55, "레지스트리 흔적 검사 중...")
        registry_findings, registry_score, note = self.scanner.scan_registry()

        self.set_progress(75, "YARA 스캔 중...")
        yara_result = run_yara_scan(self.selected_file)

        combined_findings = list(file_result["findings"])
        yara_score = 0
        for row in yara_result["rows"]:
            if row["status"] == "matched":
                add_score = 15 + (5 * min(row["match_count"], 3))
                yara_score += add_score
                combined_findings.append({
                    "type": "YARA",
                    "name": f"YARA 매칭 - {row['rule_file']}",
                    "severity": "high",
                    "score": add_score,
                    "detail": row["detail"]
                })

        total_score = file_result["score"] + artifact_score + registry_score + yara_score
        risk, color = summarize_risk(total_score)

        self.last_result = {
            "file": file_result,
            "artifact_findings": artifact_findings,
            "registry_findings": registry_findings,
            "yara": yara_result,
            "combined_findings": combined_findings,
            "total_score": total_score,
            "risk": risk,
            "note": note
        }

        self.set_progress(100, "검사 완료")
        self.render_result(color)

    def render_result(self, color):
        res = self.last_result
        f = res["file"]
        self.risk_value.config(text=res["risk"], fg=color)
        self.score_label.config(text=f"점수: {res['total_score']}")
        rule_count = len(find_yara_rule_files())
        self.summary_label.config(text=f"내부 룰 {len(f['findings'])}건, 시스템 흔적 {len(res['artifact_findings']) + len(res['registry_findings'])}건, YARA 매칭 {res['yara']['matched_count']}건 (룰 파일 {rule_count}개)")
        self.registry_note.config(text=res["note"] or "Windows 환경에서 레지스트리 검사를 완료했습니다.")

        overview_rows = [
            ("파일명", f["file_name"]),
            ("파일 경로", f["file_path"]),
            ("파일 유형", f.get("file_type", "unknown")),
            ("파일 크기", f["size_text"]),
            ("수정 시각", f["modified"]),
            ("PE 파일 여부", "예" if f["is_pe"] else "아니오"),
            ("PE 헤더 오프셋", str(f["pe_offset"])),
            ("MD5", f["hashes"]["MD5"]),
            ("SHA-1", f["hashes"]["SHA1"]),
            ("SHA-256", f["hashes"]["SHA256"]),
            ("내부 룰 파일", self.rules_source),
            ("YARA 룰 개수", str(rule_count))
        ]
        for row in overview_rows:
            self.info_tree.insert("", "end", values=row)

        for item in res["combined_findings"]:
            self.findings_tree.insert("", "end", values=(item["type"], item["name"], item["severity"], item["score"], item["detail"]))

        for item in res["artifact_findings"] + res["registry_findings"]:
            self.artifact_tree.insert("", "end", values=(item["type"], item["name"], item["severity"], item["score"], item["detail"]))

        for row in res["yara"]["rows"]:
            self.yara_tree.insert("", "end", values=(row["rule_file"], row["status"], row["match_count"], row["detail"]))

        self.report_text.insert("1.0", self.build_report_text())

    def build_report_text(self):
        res = self.last_result
        f = res["file"]
        lines = []
        lines.append("=" * 72)
        lines.append("훈련용 악성코드 탐지 결과 보고서")
        lines.append("=" * 72)
        lines.append(f"분석 시각 : {dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"대상 파일 : {f['file_name']}")
        lines.append(f"위험도    : {res['risk']} (점수 {res['total_score']})")
        lines.append("")
        lines.append("[파일 정보]")
        lines.append(f"- 경로      : {f['file_path']}")
        lines.append(f"- 크기      : {f['size_text']}")
        lines.append(f"- PE 여부   : {'예' if f['is_pe'] else '아니오'}")
        lines.append(f"- MD5       : {f['hashes']['MD5']}")
        lines.append(f"- SHA-1     : {f['hashes']['SHA1']}")
        lines.append(f"- SHA-256   : {f['hashes']['SHA256']}")
        lines.append("")
        lines.append("[정적 탐지 결과]")
        if res["combined_findings"]:
            for item in res["combined_findings"]:
                lines.append(f"- {item['type']} | {item['name']} | {item['severity']} | +{item['score']} | {item['detail']}")
        else:
            lines.append("- 탐지 없음")
        lines.append("")
        lines.append("[시스템 흔적 결과]")
        for item in res["artifact_findings"] + res["registry_findings"]:
            lines.append(f"- {item['name']} | {item['severity']} | +{item['score']} | {item['detail']}")
        if not (res["artifact_findings"] or res["registry_findings"]):
            lines.append("- 산출물/레지스트리 흔적 탐지 없음")
        lines.append("")
        lines.append("[YARA 결과]")
        for row in res["yara"]["rows"]:
            lines.append(f"- {row['rule_file']} | {row['status']} | {row['detail']}")
        return "\n".join(lines)
    def export_report(self):
        if not hasattr(self, 'last_result') or self.last_result is None:
            messagebox.showinfo("안내", "먼저 검사를 실행하여 분석 결과를 만드세요.")
            return
            
        path = filedialog.asksaveasfilename(
            title="텍스트 리포트 저장", 
            defaultextension=".txt", 
            filetypes=[("Text File", "*.txt")]
        )
        if not path: return
        
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(self.build_report_text())
            messagebox.showinfo("성공", f"텍스트 리포트가 저장되었습니다!\n경로: {path}")
        except Exception as e:
            messagebox.showerror("오류", f"저장 실패: {e}")
            
   # 파일 맨 마지막에 추가
    def export_pdf(self):
        # [강화] self.last_result가 실제로 생성되었는지 엄격히 체크
        if not hasattr(self, 'last_result') or self.last_result is None:
            messagebox.showinfo("안내", "먼저 검사를 실행하여 분석 결과를 만드세요.")
            return
            
        path = filedialog.asksaveasfilename(
            title="보안 리포트 PDF 저장", 
            defaultextension=".pdf", 
            filetypes=[("PDF File", "*.pdf")]
        )
        if not path: return
            
        # 3. makepdf.py의 전문 리포트 함수 호출
        # self.last_result 데이터를 그대로 넘겨줍니다.
        success, err = makepdf.create_training_report(self.last_result, path) 
               
        if success:
            messagebox.showinfo("성공", f"전문 PDF 리포트가 생성되었습니다!\n경로: {path}")
        else:
            messagebox.showerror("오류", f"PDF 생성 실패: {err}")

if __name__ == "__main__":
    App().mainloop()
