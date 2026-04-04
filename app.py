import requests
from flask import Flask, render_template, request, jsonify

# ⭐️ 우리가 방금 만든 '주방장' 모듈에서 핵심 기능만 불러옵니다!
from scanner_engine import scan_target

app = Flask(__name__)

# 웹 메인 화면 서빙
@app.route('/')
def index():
    return render_template('index.html')

# 프론트엔드 통신 담당 (사전 검증 + 스캔 지시)
@app.route('/scan', methods=['POST'])
def scan():
    url = request.json.get('url')
    
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
        
    # [사전 검증 로직] 잘못된 주소 필터링
    try:
        print(f"[*] 대상 서버 접속 테스트 중: {url}")
        test_req = requests.get(url, timeout=3)
        
        if test_req.status_code >= 400:
            error_msg = f"서버가 에러 코드를 반환했습니다. (상태 코드: {test_req.status_code})"
            print(f"[-] 접속 실패: {error_msg}")
            return jsonify({'error': error_msg})
            
    except requests.exceptions.RequestException:
        error_msg = "해당 URL에 접속할 수 없습니다. 주소를 다시 확인해 주세요."
        print(f"[-] 접속 실패: {error_msg}")
        return jsonify({'error': error_msg})
        
    print("[*] 서버 정상 작동 확인 완료. 본격적인 스캔을 시작합니다.")
    
    # ⭐️ 복잡했던 코드가 이 단 한 줄로 깔끔하게 정리되었습니다!
    results = scan_target(url)
    
    return jsonify({'results': results})

if __name__ == '__main__':
    app.run(debug=True, port=5000)