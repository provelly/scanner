import torch
import re
from transformers import AutoTokenizer, AutoModelForSequenceClassification

class CodeBERTScanner:
    def __init__(self):
        print("[*] CodeBERT 모델을 메모리에 로드하는 중입니다...")
        self.model_name = "microsoft/codebert-base" 
        self.tokenizer = AutoTokenizer.from_pretrained(self.model_name)
        self.model = AutoModelForSequenceClassification.from_pretrained(self.model_name, num_labels=2)
        self.model.eval()

    def clean_code(self, code_text):
        if not code_text: return ""
        code_text = re.sub(r'/\*[\s\S]*?\*/', '', code_text)
        code_text = re.sub(r'//.*', '', code_text)
        code_text = re.sub(r'\s+', ' ', code_text)
        return code_text.strip()

    def chunk_code(self, code_text, chunk_size=400):
        chunks = []
        for i in range(0, len(code_text), chunk_size):
            chunks.append(code_text[i:i + chunk_size])
        return chunks

    # ⭐️ [새로 추가된 핵심 로직] 위험한 코드를 분석해서 문장으로 설명해주는 함수
    def generate_explanation(self, risky_code):
        reasons = []
        # 자바스크립트의 대표적인 위험 패턴들을 검사하여 설명 생성
        if "eval(" in risky_code or "setTimeout(" in risky_code:
            reasons.append("문자열을 코드로 강제 실행하는 함수(eval 등)가 포함되어 있어 원격 코드 실행 위험이 있습니다.")
        if "innerHTML" in risky_code or "document.write" in risky_code:
            reasons.append("화면(DOM)을 직접 조작하는 로직이 있어 XSS(크로스사이트 스크립팅) 공격에 노출될 수 있습니다.")
        if "document.cookie" in risky_code or "localStorage" in risky_code:
            reasons.append("사용자의 쿠키나 로컬 저장소에 접근하고 있어 세션 및 개인정보 탈취 위험이 존재합니다.")
        if "XMLHttpRequest" in risky_code or "fetch(" in risky_code:
            reasons.append("외부와 통신하는 비동기 요청이 포함되어 있어 데이터 유출이나 CSRF 공격에 악용될 수 있습니다.")
        
        # 명확한 패턴이 없는데도 AI가 위험하다고 한 경우
        if not reasons:
            reasons.append("명확한 취약점 패턴은 보이지 않으나, 코드가 난독화되어 있거나 복잡한 로직이 포함되어 있어 AI 모델이 구조적으로 위험하다고 판단했습니다.")
            
        return " ".join(reasons)

    def analyze_snippet(self, raw_code_text):
        cleaned_code = self.clean_code(raw_code_text)
        if len(cleaned_code) < 10:
            return False, 0.0, "코드가 너무 짧습니다."

        chunks = self.chunk_code(cleaned_code)
        highest_prob = 0.0
        riskiest_chunk = "" # ⭐️ 가장 위험한 코드 덩어리를 기억할 변수
        
        for chunk in chunks:
            try:
                inputs = self.tokenizer(chunk, return_tensors="pt", truncation=True, max_length=512)
                with torch.no_grad():
                    outputs = self.model(**inputs)
                
                probabilities = torch.nn.functional.softmax(outputs.logits, dim=-1)
                vuln_prob = probabilities[0][1].item()
                
                if vuln_prob > highest_prob:
                    highest_prob = vuln_prob
                    riskiest_chunk = chunk # 가장 위험한 점수를 냈을 때의 코드를 저장
                    
            except Exception as e:
                continue

        is_vulnerable = highest_prob > 0.10
        
        # ⭐️ 위험하다고 판단되면 설명문을 생성, 아니면 안전하다고 표시
        explanation = self.generate_explanation(riskiest_chunk) if is_vulnerable else "AI 분석 결과 특이사항이 없습니다."
        
        # 리턴값이 2개에서 3개(설명 포함)로 늘어났습니다!
        return is_vulnerable, round(highest_prob * 100, 2), explanation