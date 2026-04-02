from fpdf import FPDF
import os
import sys
import socket
from datetime import datetime

def get_font_path():
    if getattr(sys, 'frozen', False):
        base_dir = os.path.dirname(sys.executable)
    else:
        base_dir = os.path.abspath(".")
        
    for name in ["font.ttf", "front.ttf"]:
        p = os.path.join(base_dir, name)
        if os.path.exists(p): return p
        
    try:
        base_dir2 = sys._MEIPASS
        for name in ["font.ttf", "front.ttf"]:
            p = os.path.join(base_dir2, name)
            if os.path.exists(p): return p
    except: pass
    return None

class SecurityReport(FPDF):
    def header(self):
        host_name = socket.gethostname()
        try: ip_addr = socket.gethostbyname(host_name)
        except: ip_addr = "127.0.0.1"
        
        self.set_font('Arial', 'B', 10)
        self.set_text_color(100, 100, 100)
        self.cell(0, 10, f"HOST: {host_name} | IP: {ip_addr} | Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}", align='R', new_x="LMARGIN", new_y="NEXT")
        
        self.set_draw_color(66, 133, 244)
        self.set_line_width(0.8)
        self.line(10, 18, 200, 18)
        self.cell(0, 5, "", new_x="LMARGIN", new_y="NEXT")

    def draw_section_title(self, title, font_name):
        self.cell(0, 5, "", new_x="LMARGIN", new_y="NEXT")
        self.set_font(font_name, 'B', 12) # 제목도 굵게 적용
        self.set_text_color(0, 0, 0)
        self.cell(0, 10, f"* {title}", new_x="LMARGIN", new_y="NEXT")
        self.cell(0, 2, "", new_x="LMARGIN", new_y="NEXT")

def create_training_report(res, output_path):
    try:
        pdf = SecurityReport()
        pdf.add_page()
        
        font_path = get_font_path()
        if not font_path:
            return False, "한글 폰트(font.ttf 또는 front.ttf)를 실행 파일과 같은 폴더에 놔주세요!"
        
        # [핵심 해결] 일반 폰트('')와 굵은 폰트('B')를 모두 등록해 줍니다!
        pdf.add_font('Korean', '', font_path)
        pdf.add_font('Korean', 'B', font_path)
        font_name = 'Korean'

        pdf.set_font(font_name, 'B', 20)
        pdf.cell(0, 20, '지능형 악성코드 분석 결과 보고서', align='C', new_x="LMARGIN", new_y="NEXT")

        def trim(txt, max_len=200):
            s = str(txt).replace('\n', ' ').replace('\r', '')
            return s[:max_len] + "..." if len(s) > max_len else s

        line_h = 7

        # 1. 진단 개요
        pdf.draw_section_title("진단 개요", font_name)
        f_info = res.get("file", {})
        overview_data = [
            ["파일명", trim(f_info.get("file_name", "-"))],
            ["파일 경로", trim(f_info.get("file_path", "-"))],
            ["SHA256", trim(f_info.get("hashes", {}).get("SHA256", "-"))],
            ["위험 수준", f"{res.get('risk', 'LOW')} ({res.get('total_score', 0)}점)"],
            ["분석 일시", datetime.now().strftime('%Y-%m-%d %H:%M:%S')]
        ]
        
        pdf.set_font(font_name, '', 9)
        col1_w = 40
        col2_w = 150

        for row in overview_data:
            pdf.set_fill_color(240, 240, 240)
            pdf.multi_cell(col1_w, line_h, row[0], border=1, fill=True, new_x="RIGHT", new_y="TOP")
            pdf.multi_cell(col2_w, line_h, row[1], border=1, new_x="LMARGIN", new_y="NEXT")

        # 2. 탐지 근거
        pdf.draw_section_title("탐지 근거", font_name)
        file_findings = f_info.get("findings", [])
        pdf.set_font(font_name, '', 9)
        if file_findings:
            pdf.set_fill_color(255, 235, 235)
            for f in file_findings:
                text = f"- [{f.get('severity', 'medium')}] {f.get('name', 'Unknown')}: {trim(f.get('detail', '-'))}"
                pdf.multi_cell(0, line_h, text, border=1, new_x="LMARGIN", new_y="NEXT")
        else:
            pdf.cell(0, line_h, "특이 탐지 내역 없음", border=1, align='C', new_x="LMARGIN", new_y="NEXT")

        # 3. 시스템 흔적
        pdf.draw_section_title("시스템 흔적 분석", font_name)
        all_artifacts = res.get("artifact_findings", []) + res.get("registry_findings", [])
        pdf.set_font(font_name, '', 9)
        if all_artifacts:
            for a in all_artifacts:
                pdf.set_fill_color(250, 250, 250)
                text = f"- [{a.get('severity', 'medium')}] {a.get('name', 'Unknown')}: {trim(a.get('detail', '-'))}"
                pdf.multi_cell(0, line_h, text, border=1, new_x="LMARGIN", new_y="NEXT")
        else:
            pdf.cell(0, line_h, "탐지된 시스템 흔적 없음", border=1, align='C', new_x="LMARGIN", new_y="NEXT")

        # 4. YARA 결과
        pdf.draw_section_title("YARA 패턴 분석 상세", font_name)
        yara_res = res.get("yara", {})
        
        if yara_res.get("rows"):
            with pdf.table(col_widths=(40, 30, 120), text_align=("LEFT", "CENTER", "LEFT")) as table:
                row = table.row()
                pdf.set_fill_color(230, 240, 255)
                # 이 부분이 에러의 원인이었음. 'B' 폰트를 추가했으므로 이제 에러 안 남.
                row.cell("룰 파일")
                row.cell("상태")
                row.cell("상세 내용")
                
                pdf.set_font(font_name, '', 8)
                for y in yara_res["rows"]:
                    row = table.row()
                    row.cell(trim(str(y.get('rule_file', '-')), 50))
                    row.cell(trim(str(y.get('status', '-')), 20))
                    row.cell(trim(str(y.get('detail', '-')), 150))
        else:
            pdf.set_font(font_name, '', 9)
            pdf.cell(0, line_h, "매칭된 YARA 시그니처 없음", border=1, align='C', new_x="LMARGIN", new_y="NEXT")

        pdf.output(output_path)
        return True, ""
    except Exception as e:
        import traceback
        return False, f"PDF 생성 에러:\n{str(e)}\n\n{traceback.format_exc()}"