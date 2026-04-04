import os
import yaml
import requests
from urllib.parse import urljoin
from bs4 import BeautifulSoup

# AI 모듈 불러오기
try:
    from ai_analyzer import CodeBERTScanner
    print("[*] AI 엔진을 로드합니다...")
    ai_scanner = CodeBERTScanner()
    print("[*] AI 엔진 로드 완료!")
except ImportError:
    print("[!] 경고: ai_analyzer.py 파일을 찾을 수 없거나 관련 라이브러리가 설치되지 않았습니다.")
    ai_scanner = None

def load_rules():
    rules = []
    # 현재 파일(scanner_engine.py)이 있는 경로를 기준으로 rules 폴더를 찾습니다.
    base_dir = os.path.dirname(os.path.abspath(__file__))
    rule_dir = os.path.join(base_dir, 'rules')
    
    if not os.path.exists(rule_dir):
        os.makedirs(rule_dir) 
        
    for file in os.listdir(rule_dir):
        if file.endswith('.yaml'):
            with open(os.path.join(rule_dir, file), 'r', encoding='utf-8') as f:
                rules.append(yaml.safe_load(f))
    return rules

def scan_target(target_url):
    rules = load_rules()
    found_vulns = []
    forms_to_test = []

    try:
        res = requests.get(target_url, timeout=5)
        soup = BeautifulSoup(res.text, 'html.parser')
        
        # 1. [AI 기반] 웹페이지 소스 코드 검사 (시연용 출력 모드 포함)
        if ai_scanner:
            script_tags = soup.find_all('script')
            ai_analyzed = False
            
            for script in script_tags:
                code_content = script.string
                if code_content and len(code_content.strip()) > 10: 
                    ai_analyzed = True
                    print(f"[*] AI 모델이 자바스크립트를 분석 중입니다... (길이: {len(code_content)}자)")
                    is_vuln, prob = ai_scanner.analyze_snippet(code_content)
                    
                    found_vulns.append({
                        'name': 'AI 자바스크립트 분석 (CodeBERT)',
                        'url': target_url,
                        'payload': f'스크립트 길이: {len(code_content)}자',
                        'word': f'위험 확률: {prob}%'
                    })

            if not ai_analyzed:
                print("[*] 스크립트가 없어서 HTML 소스코드를 AI에게 분석시킵니다...")
                html_snippet = res.text[:500] 
                is_vuln, prob = ai_scanner.analyze_snippet(html_snippet)
                
                found_vulns.append({
                    'name': 'AI 구조 분석 (CodeBERT)',
                    'url': target_url,
                    'payload': f'분석된 HTML 길이: {len(html_snippet)}자',
                    'word': f'위험 확률: {prob}%'
                })

        # 2. [템플릿 기반] 입력 폼 크롤링 및 수집
        for form in soup.find_all('form'):
            action = form.get('action', '')
            method = form.get('method', 'get').lower()
            inputs = [tag.get('name') for tag in form.find_all(['input', 'textarea']) if tag.get('name')]
            
            if inputs:
                forms_to_test.append({
                    'url': urljoin(target_url, action),
                    'method': method,
                    'inputs': inputs
                })
                
    except Exception as e:
        print(f"[-] 타겟 접근 실패 또는 크롤링 에러: {e}")
        return found_vulns

    # 3. [템플릿 기반] YAML 규칙 기반 공격 수행
    for rule in rules:
        payloads = rule['http'][0].get('payloads', [])
        matchers = rule['http'][0].get('matchers', [])

        for form in forms_to_test:
            for payload in payloads:
                test_data = {inp: payload for inp in form['inputs']}
                try:
                    if form['method'] == 'post':
                        r = requests.post(form['url'], data=test_data, timeout=5)
                    else:
                        r = requests.get(form['url'], params=test_data, timeout=5)

                    for matcher in matchers:
                        for word in matcher['words']:
                            if word.lower() in r.text.lower():
                                found_vulns.append({
                                    'name': rule['info']['name'],
                                    'url': form['url'],
                                    'payload': payload,
                                    'word': word
                                })
                                break 
                except:
                    pass

    return found_vulns