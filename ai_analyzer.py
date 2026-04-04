import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification

class CodeBERTScanner:
    def __init__(self):
        print("[*] CodeBERT 모델을 메모리에 로드하는 중입니다... (최초 1회 다운로드 필요)")
        
        # 캡스톤 고도화 시 보안 취약점 전용 파인튜닝 모델로 변경하면 성능이 대폭 상승합니다.
        self.model_name = "microsoft/codebert-base" 
        
        self.tokenizer = AutoTokenizer.from_pretrained(self.model_name)
        self.model = AutoModelForSequenceClassification.from_pretrained(self.model_name, num_labels=2)
        self.model.eval() # 평가 모드 설정

    def analyze_snippet(self, code_text):
        """소스 코드 조각을 입력받아 취약점 확률을 반환합니다."""
        # 코드가 너무 짧으면 분석하지 않음 (최소 10자 이상)
        if not code_text or len(code_text.strip()) < 10:
            return False, 0.0

        try:
            # 1. 텍스트를 AI가 이해할 수 있는 토큰으로 변환 (최대 512 길이)
            inputs = self.tokenizer(code_text, return_tensors="pt", truncation=True, max_length=512)

            # 2. AI 모델 추론
            with torch.no_grad():
                outputs = self.model(**inputs)

            # 3. 결과 확률 계산 (Softmax)
            probabilities = torch.nn.functional.softmax(outputs.logits, dim=-1)
            
            # 클래스 1(취약점 있음)에 해당하는 확률 추출
            vuln_prob = probabilities[0][1].item()

            # ⭐️ [테스트용 설정] 확률이 10%만 넘어도 화면에 출력하도록 커트라인 하향 조정
            # 캡스톤 최종 제출 시에는 이 값을 0.75 나 0.80 으로 올리시는 것을 추천합니다.
            is_vulnerable = vuln_prob > 0.10
            
            return is_vulnerable, round(vuln_prob * 100, 2)
            
        except Exception as e:
            print(f"[-] AI 분석 중 에러 발생: {e}")
            return False, 0.0