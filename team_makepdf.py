from fpdf import FPDF
import os
import sys

def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

def create_report(df):
    try:
        # EXE 실행 위치 확인
        target_dir = os.path.dirname(sys.executable) if getattr(sys, 'frozen', False) else os.getcwd()
        output_path = os.path.join(target_dir, "Diagnosis_Report.pdf")

        # [필독] 기존 PDF가 열려 있는지 확인 시도
        if os.path.exists(output_path):
            try:
                with open(output_path, 'ab') as f: pass
            except PermissionError:
                print("PDF 파일이 다른 프로그램에서 열려 있습니다.")
                return False

        pdf = FPDF()
        pdf.add_page()
        
        font_path = resource_path("font.ttf")
        if os.path.exists(font_path):
            pdf.add_font('Korean', '', font_path, unicode=True)
            pdf.set_font('Korean', '', 14)
        else:
            pdf.set_font('Arial', 'B', 14)

        pdf.cell(0, 15, '악성코드 다중 진단 결과 보고서', ln=True, align='C')
        pdf.ln(10)

        # 헤더
        pdf.set_font('Korean', '', 10) if os.path.exists(font_path) else pdf.set_font('Arial', '', 10)
        pdf.cell(50, 10, '파일명', 1)
        pdf.cell(20, 10, '수준', 1)
        pdf.cell(20, 10, '탐지여부', 1)
        pdf.cell(100, 10, '상세 내용', 1)
        pdf.ln()

        if df.empty:
            pdf.cell(190, 10, '탐지 내역 없음', 1, 1, 'C')
        else:
            for _, row in df.iterrows():
                pdf.cell(50, 10, str(row.get('파일 이름', '-'))[:25], 1)
                pdf.cell(20, 10, str(row.get('수준', '정상')), 1, 0, 'C')
                pdf.cell(20, 10, str(row.get('탐지 여부', '미탐지')), 1, 0, 'C')
                pdf.cell(100, 10, str(row.get('상세내용', '-'))[:50], 1, 1)

        pdf.output(output_path)
        return True
    except Exception as e:
        print(f"PDF 에러: {e}")
        return False