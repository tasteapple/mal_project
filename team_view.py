import sys
import os
# [필독] 이 클래스가 모든 import보다 가장 위에 있어야 에러가 나지 않습니다.
class DummyStream:
    def write(self, data): pass
    def flush(self): pass
    def isatty(self): return False
    @property
    def encoding(self): return "utf-8"

# 콘솔이 없는 환경(--noconsole)에서 표준 출력을 가짜 스트림으로 대체합니다.
if sys.stdout is None: sys.stdout = DummyStream()
if sys.stderr is None: sys.stderr = DummyStream()
import pandas as pd
import socket
import platform
from datetime import datetime
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QPushButton, QTableWidget, QTableWidgetItem, 
                             QLabel, QHeaderView, QFrame, QMessageBox)
from PyQt6.QtCore import Qt, QThread, pyqtSignal

# 팀원 모듈 연결
import scan
import makepdf


if sys.stdout is None: sys.stdout = DummyStream()
if sys.stderr is None: sys.stderr = DummyStream()

if getattr(sys, 'frozen', False):
    os.chdir(os.path.dirname(sys.executable))

class AnalysisWorker(QThread):
    finished = pyqtSignal(list)
    def run(self):
        try:
            results = scan.run_scan()
            self.finished.emit(results)
        except Exception as e:
            self.finished.emit([]) 

class ScannerApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SK Shieldus Rookies 다중 진단 도구")
        self.setMinimumSize(1100, 800)
        self.current_results = []
        self.is_analyzed = False  
        self.init_ui()

    def init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        header_layout = QHBoxLayout()
        title_label = QLabel("〈  다중 진단")
        title_label.setStyleSheet("font-size: 20px; font-weight: bold;")
        
        self.start_btn = QPushButton("▶ 분석시작")
        self.start_btn.setFixedSize(120, 40)
        self.start_btn.clicked.connect(self.start_analysis)
        
        self.pdf_btn = QPushButton("📄 PDF 생성")
        self.pdf_btn.setFixedSize(120, 40)
        self.pdf_btn.clicked.connect(self.generate_pdf_clicked)
        
        header_layout.addWidget(title_label); header_layout.addStretch()
        header_layout.addWidget(self.start_btn); header_layout.addWidget(self.pdf_btn)
        main_layout.addLayout(header_layout)

        mid_layout = QHBoxLayout()
        left_box = QVBoxLayout()
        left_box.addWidget(QLabel("분석 대상 파일"))
        self.target_table = QTableWidget(0, 1)
        self.target_table.setHorizontalHeaderLabels(["결과파일 이름"])
        self.target_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        left_box.addWidget(self.target_table)
        
        right_box = QVBoxLayout()
        right_box.addWidget(QLabel("적용 룰 파일 (YARA)"))
        self.rule_table = QTableWidget(0, 2)
        self.rule_table.setHorizontalHeaderLabels(["룰 파일 이름", "상태"])
        self.rule_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        right_box.addWidget(self.rule_table)
        
        mid_layout.addLayout(left_box, 1); mid_layout.addLayout(right_box, 1)
        main_layout.addLayout(mid_layout)

        main_layout.addWidget(QLabel("상세 정보"))
        detail_frame = QFrame()
        detail_frame.setFrameShape(QFrame.Shape.Box)
        detail_frame.setStyleSheet("background-color: #f8f9fa; border: 1px solid #dee2e6;")
        detail_layout = QVBoxLayout(detail_frame)

        self.host_info_label = QLabel(f"호스트 이름 : {socket.gethostname()} | OS 정보 : {platform.system()} | OS 설치시점 : -")
        detail_layout.addWidget(self.host_info_label)

        badge_layout = QHBoxLayout()
        self.risk_badge = QLabel(" 위험도 ● 정상 ")
        self.risk_badge.setStyleSheet("background-color: #e6f4ea; color: #1e7e34; border-radius: 10px; padding: 5px; font-weight: bold;")
        badge_layout.addWidget(self.risk_badge)
        
        self.count_normal = QLabel("● 정상 : 0"); self.count_serious = QLabel("● 심각 : 0")
        badge_layout.addWidget(self.count_normal); badge_layout.addWidget(self.count_serious); badge_layout.addStretch()
        detail_layout.addLayout(badge_layout)

        self.log_table = QTableWidget(0, 4)
        self.log_table.setHorizontalHeaderLabels(["파일명", "수준", "탐지", "상세내용"])
        self.log_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        detail_layout.addWidget(self.log_table)

        main_layout.addWidget(detail_frame)
        self.load_all_files()

    def load_all_files(self):
        all_files = os.listdir('.')
        targets = [f for f in all_files if f.lower().endswith(('.exe', '.xlsm', '.xlsx', '.xls', '.ps1'))]
        self.target_table.setRowCount(len(targets))
        for i, f in enumerate(targets): self.target_table.setItem(i, 0, QTableWidgetItem(f))
            
        self.yar_files = [f for f in all_files if f.endswith('.yar')]
        self.rule_table.setRowCount(len(self.yar_files))
        for i, f in enumerate(self.yar_files):
            self.rule_table.setItem(i, 0, QTableWidgetItem(f))
            self.rule_table.setItem(i, 1, QTableWidgetItem("적용됨"))

    def start_analysis(self):
        if not self.yar_files:
            QMessageBox.critical(self, "오류", "폴더 내에 .yar 파일이 없습니다!")
            return
        self.start_btn.setEnabled(False)
        self.start_btn.setText("분석 중...")
        self.worker = AnalysisWorker()
        self.worker.finished.connect(self.on_analysis_finished)
        self.worker.start()

    def on_analysis_finished(self, results):
        self.start_btn.setEnabled(True)
        self.start_btn.setText("▶ 분석시작")
        self.current_results = results
        self.is_analyzed = True
        
        # [중요] 리스트가 비어있을 경우 알림
        if not results:
            QMessageBox.warning(self, "알림", "분석 대상 파일을 찾지 못했습니다.\n폴더에 .exe나 .xlsm 파일이 있는지 확인하세요.")
            return

        self.log_table.setRowCount(len(results))
        serious_count = 0
        
        for i, res in enumerate(results):
            self.log_table.setItem(i, 0, QTableWidgetItem(res.get("파일 이름", "-")))
            self.log_table.setItem(i, 1, QTableWidgetItem(res.get("수준", "정상")))
            self.log_table.setItem(i, 2, QTableWidgetItem(res.get("탐지 여부", "미탐지")))
            self.log_table.setItem(i, 3, QTableWidgetItem(res.get("상세내용", "이상 없음")))
            if res.get("수준") == "심각": serious_count += 1

        # 상단 통계 업데이트
        self.count_normal.setText(f"● 정상 : {len(results) - serious_count}")
        self.count_serious.setText(f"● 심각 : {serious_count}")
        
        # [추가] 배지 색상 업데이트
        if serious_count > 0:
            self.risk_badge.setText(" 위험도 ● 심각 ")
            self.risk_badge.setStyleSheet("background-color: #fce8e6; color: #d93025; border-radius: 10px; padding: 5px; font-weight: bold;")
        else:
            self.risk_badge.setText(" 위험도 ● 정상 ")
            self.risk_badge.setStyleSheet("background-color: #e6f4ea; color: #1e7e34; border-radius: 10px; padding: 5px; font-weight: bold;")
        
        QMessageBox.information(self, "완료", f"분석이 완료되었습니다. (총 {len(results)}건)")

    def generate_pdf_clicked(self):
        if not self.is_analyzed:
            QMessageBox.warning(self, "알림", "분석을 먼저 실행해 주세요."); return
        try:
            if makepdf.create_report(pd.DataFrame(self.current_results)):
                QMessageBox.information(self, "성공", "PDF 리포트가 생성되었습니다.")
            else:
                QMessageBox.critical(self, "오류", "PDF 저장 실패 (파일이 열려있는지 확인)")
        except Exception as e:
            QMessageBox.critical(self, "오류", f"PDF 생성 중 에러: {e}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = ScannerApp()
    window.show()
    sys.exit(app.exec())