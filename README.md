# merged_training_detector_v2

포함 파일
- training_detector_gui.py : 메인 다크 테마 GUI
- yara_helper.py : 팀원이 수정한 scan.py 방식을 반영한 YARA 헬퍼
- rules.json : 최종 내부 룰셋
- team_scan.py / team_view.py / team_makepdf.py : 팀원 원본 백업본

실행
```bash
python -m pip install -r requirements.txt
python training_detector_gui.py
```

빌드
```bash
python -m PyInstaller --noconsole --onefile --hidden-import=yara --add-data "rules.json;." training_detector_gui.py
```

권장 배치
- 빌드 후 dist 폴더에 .yar 파일과 rules.json을 exe 옆에 둡니다.
