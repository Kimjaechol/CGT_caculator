"""
2025 양도소득세 AI 전문 컨설팅 플랫폼 - Backend API
Railway 배포용
"""

import os
import sqlite3
import json
from datetime import datetime
from typing import Optional, List, Dict, Any
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from dotenv import load_dotenv

import google.generativeai as genai

# 환경변수 로드
load_dotenv()

# === 설정 ===
app = FastAPI(
    title="2025 양도소득세 AI API",
    description="양도소득세 계산 및 AI 세무상담 API",
    version="1.0.0"
)

# CORS 설정 - Vercel 프론트엔드 허용
FRONTEND_URL = os.getenv("FRONTEND_URL", "*")
ALLOWED_ORIGINS = [
    FRONTEND_URL,
    "http://localhost:3000",
    "http://localhost:5173",
    "http://127.0.0.1:3000",
    "http://127.0.0.1:5173",
]

# 모든 Vercel 도메인 허용
if FRONTEND_URL == "*":
    ALLOWED_ORIGINS = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Gemini API 설정
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
if GEMINI_API_KEY and GEMINI_API_KEY != "your_gemini_api_key_here":
    genai.configure(api_key=GEMINI_API_KEY)

# Railway에서는 /tmp 디렉토리 사용
DB_PATH = os.getenv("DB_PATH", "/tmp/tax_knowledge.db")


# === 2025년 양도소득세 세율표 ===
TAX_BRACKETS_2023 = [
    (14_000_000, 0.06, 0),
    (50_000_000, 0.15, 1_260_000),
    (88_000_000, 0.24, 5_760_000),
    (150_000_000, 0.35, 15_440_000),
    (300_000_000, 0.38, 19_940_000),
    (500_000_000, 0.40, 25_940_000),
    (1_000_000_000, 0.42, 35_940_000),
    (float('inf'), 0.45, 65_940_000),
]

TAX_BRACKETS_NON_BIZ_LAND = [
    (14_000_000, 0.16, 0),
    (50_000_000, 0.25, 1_260_000),
    (88_000_000, 0.34, 5_760_000),
    (150_000_000, 0.45, 15_440_000),
    (300_000_000, 0.48, 19_940_000),
    (500_000_000, 0.50, 25_940_000),
    (1_000_000_000, 0.52, 35_940_000),
    (float('inf'), 0.55, 65_940_000),
]

LTHSD_TABLE1 = {
    3: 0.06, 4: 0.08, 5: 0.10, 6: 0.12, 7: 0.14, 8: 0.16, 9: 0.18, 10: 0.20,
    11: 0.22, 12: 0.24, 13: 0.26, 14: 0.28, 15: 0.30
}

LTHSD_TABLE2_HOLDING = {
    3: 0.12, 4: 0.16, 5: 0.20, 6: 0.24, 7: 0.28, 8: 0.32, 9: 0.36, 10: 0.40
}

LTHSD_TABLE2_RESIDENCE = {
    2: 0.08, 3: 0.12, 4: 0.16, 5: 0.20, 6: 0.24, 7: 0.28, 8: 0.32, 9: 0.36, 10: 0.40
}


# === Pydantic 모델 ===
class CalcRequest(BaseModel):
    transfer_date: str = Field(..., description="양도일자 (YYYY-MM-DD)")
    acquisition_date: str = Field(..., description="취득일자 (YYYY-MM-DD)")
    transfer_price: int = Field(..., description="양도가액 (원)")
    acquisition_price: int = Field(..., description="취득가액 (원)")
    necessary_expenses: int = Field(0, description="필요경비 (원)")
    asset_type: str = Field("housing", description="자산유형")
    is_1h1h: bool = Field(False, description="1세대1주택 여부")
    residence_years: int = Field(0, description="거주기간 (년)")
    is_adjusted_area: bool = Field(False, description="조정대상지역 여부")
    housing_count: int = Field(1, description="보유주택수")
    reduction_type: str = Field("none", description="감면유형")
    is_registered: bool = Field(True, description="등기 여부")


class ConsultRequest(BaseModel):
    query: str = Field(..., description="상담 질문")
    context_data: Optional[Dict[str, Any]] = Field(None, description="계산 결과 컨텍스트")


# === 데이터베이스 ===
def init_db():
    os.makedirs(os.path.dirname(DB_PATH) if os.path.dirname(DB_PATH) else ".", exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE VIRTUAL TABLE IF NOT EXISTS tax_knowledge
        USING fts5(category, title, content, keywords)
    """)

    cursor.execute("SELECT count(*) FROM tax_knowledge")
    if cursor.fetchone()[0] == 0:
        knowledge_data = [
            ("비과세", "1세대1주택 비과세",
             "1세대가 양도일 현재 국내에 1주택을 보유하고 2년 이상 보유(조정대상지역 2017.8.3. 이후 취득분은 2년 거주 필요)한 경우 비과세. 고가주택 기준: 12억원 초과 시 초과분에 대해서만 과세.",
             "1세대1주택 비과세 고가주택 12억 2년보유 2년거주"),
            ("비과세", "일시적 2주택 비과세",
             "종전주택을 보유한 상태에서 신규주택을 취득하고 3년 이내에 종전주택을 양도하는 경우 비과세. 조정대상지역 내 신규주택 취득 시: 1년 이내 전입 + 1년 이상 거주 요건.",
             "일시적2주택 이사 신규주택 종전주택 3년"),
            ("공제", "장기보유특별공제",
             "표1(일반자산): 3년 이상 보유 시 연 2%, 최대 30%(15년). 표2(1세대1주택): 보유기간 연 4%(최대 40%) + 거주기간 연 4%(최대 40%) = 최대 80%. 다주택자도 2022.5.10.~2026.5.9. 양도분은 기본세율 및 장특공제 적용.",
             "장기보유특별공제 장특공제 표1 표2 보유기간 거주기간"),
            ("세율", "다주택자 중과세율",
             "조정대상지역 2주택: 기본세율 + 20%, 3주택 이상: 기본세율 + 30%. 2022.5.10.~2026.5.9. 양도분: 보유기간 2년 이상 주택은 중과 배제.",
             "다주택 중과 조정대상지역 2주택 3주택 중과유예"),
            ("세율", "단기양도 세율",
             "1년 미만: 50% (주택/입주권/분양권 70%). 1년 이상 2년 미만: 40% (주택/입주권/분양권 60%).",
             "단기양도 1년미만 2년미만 70% 60%"),
            ("세율", "비사업용 토지",
             "비사업용 토지: 기본세율 + 10%. 장기보유특별공제 적용 가능.",
             "비사업용토지 농지 재촌 자경 10%"),
            ("감면", "8년 자경농지 감면",
             "8년 이상 재촌·자경 농지 양도세 100% 감면. 한도: 1과세기간 1억원, 5년간 2억원. 농특세: 감면세액의 20%.",
             "8년자경 농지감면 자경농지 재촌자경"),
            ("감면", "공익사업 수용 감면",
             "사업인정고시일 2년 이전 취득 토지 수용 시 감면. 현금보상: 10%, 채권보상(3년): 40%, 채권보상(5년): 15%. 2025년 이후 연간 한도 2억원.",
             "공익사업 수용 보상 현금보상 채권보상"),
            ("세율", "미등기 양도자산",
             "미등기 양도자산: 70% 단일세율. 장기보유특별공제 적용 배제. 기본공제 적용 배제.",
             "미등기 70%"),
            ("세율", "2025년 기본세율",
             "1,400만원 이하: 6%, 5,000만원 이하: 15%(누진공제 126만), 8,800만원 이하: 24%(576만), 1.5억원 이하: 35%(1,544만), 3억원 이하: 38%(1,994만), 5억원 이하: 40%(2,594만), 10억원 이하: 42%(3,594만), 10억원 초과: 45%(6,594만)",
             "기본세율 누진세율 누진공제"),
            ("공제", "양도소득기본공제",
             "연간 250만원 공제. 미등기양도자산: 기본공제 적용 배제.",
             "기본공제 250만원"),
            ("비과세", "상속주택 특례",
             "상속받은 주택과 일반주택 보유 시 일반주택 양도 시 상속주택은 주택수 제외.",
             "상속주택 특례 주택수제외"),
        ]
        cursor.executemany(
            "INSERT INTO tax_knowledge(category, title, content, keywords) VALUES (?, ?, ?, ?)",
            knowledge_data
        )
        conn.commit()
    conn.close()


def search_knowledge(query: str, limit: int = 5) -> str:
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        search_query = ' OR '.join(query.split())
        cursor.execute("""
            SELECT title, content FROM tax_knowledge
            WHERE tax_knowledge MATCH ?
            ORDER BY rank LIMIT ?
        """, (search_query, limit))
        results = cursor.fetchall()
        conn.close()
        if results:
            return "\n\n".join([f"### {t}\n{c}" for t, c in results])
        return "관련 법령 정보를 찾을 수 없습니다."
    except Exception as e:
        return f"검색 오류: {str(e)}"


# === 계산 엔진 ===
def calculate_holding_period(acquisition_date: str, transfer_date: str) -> tuple:
    acq = datetime.strptime(acquisition_date, "%Y-%m-%d")
    trans = datetime.strptime(transfer_date, "%Y-%m-%d")
    total_days = (trans - acq).days
    years = total_days // 365
    months = (total_days % 365) // 30
    return years, months, total_days


def get_lthsd_rate(holding_years: int, residence_years: int, is_1h1h: bool, asset_type: str) -> tuple:
    if holding_years < 3:
        return 0, "보유기간 3년 미만"
    if is_1h1h and residence_years >= 2:
        holding_rate = LTHSD_TABLE2_HOLDING.get(min(holding_years, 10), 0.40)
        residence_rate = LTHSD_TABLE2_RESIDENCE.get(min(residence_years, 10), 0.40)
        total_rate = min(holding_rate + residence_rate, 0.80)
        return total_rate, f"1세대1주택 표2: {total_rate*100:.0f}%"
    else:
        capped_years = min(holding_years, 15)
        rate = LTHSD_TABLE1.get(capped_years, min(capped_years * 0.02, 0.30))
        return rate, f"일반자산 표1: {rate*100:.0f}%"


def calculate_tax_amount(tax_base: int, brackets: list) -> tuple:
    for threshold, rate, deduction in brackets:
        if tax_base <= threshold:
            return max(int(tax_base * rate - deduction), 0), rate, deduction
    _, rate, deduction = brackets[-1]
    return max(int(tax_base * rate - deduction), 0), rate, deduction


def calculate_cgt(data: CalcRequest) -> Dict[str, Any]:
    result = {
        "status": "success",
        "input": data.dict(),
        "calculation": {},
        "breakdown": [],
        "warnings": [],
        "summary": {}
    }

    try:
        years, months, total_days = calculate_holding_period(data.acquisition_date, data.transfer_date)
        result["calculation"]["holding_period"] = {
            "years": years, "months": months, "total_days": total_days,
            "display": f"{years}년 {months}개월"
        }

        gross_gain = data.transfer_price - data.acquisition_price - data.necessary_expenses
        result["calculation"]["gross_gain"] = gross_gain
        result["breakdown"].append({
            "step": "양도차익 계산",
            "formula": f"{data.transfer_price:,} - {data.acquisition_price:,} - {data.necessary_expenses:,}",
            "value": gross_gain
        })

        if gross_gain <= 0:
            result["status"] = "no_tax"
            result["summary"] = {"message": "양도차익이 없거나 손실입니다.", "total_tax": 0}
            return result

        taxable_gain = gross_gain
        if data.is_1h1h and data.housing_count == 1 and years >= 2:
            if data.transfer_price <= 1_200_000_000:
                result["status"] = "exempt"
                result["summary"] = {
                    "message": "1세대 1주택 비과세 (12억원 이하)",
                    "total_tax": 0,
                    "legal_basis": "소득세법 제89조 제1항 제3호"
                }
                return result
            else:
                ratio = (data.transfer_price - 1_200_000_000) / data.transfer_price
                taxable_gain = int(gross_gain * ratio)
                result["warnings"].append("고가주택(12억 초과분 과세)")

        result["calculation"]["taxable_gain"] = taxable_gain

        lthsd_amount = 0
        lthsd_rate = 0
        lthsd_note = ""
        if not data.is_registered:
            lthsd_note = "미등기: 장특공제 배제"
            result["warnings"].append(lthsd_note)
        elif data.asset_type in ["housing", "land", "land_nonbiz", "building"]:
            lthsd_rate, lthsd_note = get_lthsd_rate(years, data.residence_years, data.is_1h1h, data.asset_type)
            lthsd_amount = int(taxable_gain * lthsd_rate)

        result["calculation"]["lthsd"] = {"rate": lthsd_rate, "amount": lthsd_amount, "note": lthsd_note}

        transfer_income = taxable_gain - lthsd_amount
        basic_deduction = 2_500_000 if data.is_registered else 0
        tax_base = max(transfer_income - basic_deduction, 0)
        result["calculation"]["basic_deduction"] = basic_deduction
        result["calculation"]["tax_base"] = tax_base

        if tax_base <= 0:
            result["status"] = "no_tax"
            result["summary"] = {"message": "과세표준이 0 이하입니다.", "total_tax": 0}
            return result

        calc_tax = 0
        applied_rate = 0
        rate_note = ""

        if not data.is_registered:
            calc_tax = int(tax_base * 0.70)
            applied_rate = 0.70
            rate_note = "미등기: 70%"
        elif years < 2:
            if data.asset_type in ["housing", "right", "share_right"]:
                if years < 1:
                    calc_tax, applied_rate = int(tax_base * 0.70), 0.70
                    rate_note = "단기(1년 미만 주택): 70%"
                else:
                    calc_tax, applied_rate = int(tax_base * 0.60), 0.60
                    rate_note = "단기(1~2년 주택): 60%"
            else:
                if years < 1:
                    calc_tax, applied_rate = int(tax_base * 0.50), 0.50
                    rate_note = "단기(1년 미만): 50%"
                else:
                    calc_tax, applied_rate = int(tax_base * 0.40), 0.40
                    rate_note = "단기(1~2년): 40%"
        elif data.is_adjusted_area and data.housing_count >= 2 and data.asset_type == "housing":
            trans_date = datetime.strptime(data.transfer_date, "%Y-%m-%d")
            if datetime(2022, 5, 10) <= trans_date <= datetime(2026, 5, 9) and years >= 2:
                calc_tax, applied_rate, _ = calculate_tax_amount(tax_base, TAX_BRACKETS_2023)
                rate_note = f"다주택 중과유예: 기본세율 {applied_rate*100:.0f}%"
            else:
                base_tax, base_rate, _ = calculate_tax_amount(tax_base, TAX_BRACKETS_2023)
                surcharge_rate = 0.20 if data.housing_count == 2 else 0.30
                calc_tax = base_tax + int(tax_base * surcharge_rate)
                applied_rate = base_rate + surcharge_rate
                rate_note = f"다주택 중과: +{surcharge_rate*100:.0f}%"
        elif data.asset_type == "land_nonbiz":
            calc_tax, applied_rate, _ = calculate_tax_amount(tax_base, TAX_BRACKETS_NON_BIZ_LAND)
            rate_note = f"비사업용 토지: {applied_rate*100:.0f}%"
        else:
            calc_tax, applied_rate, _ = calculate_tax_amount(tax_base, TAX_BRACKETS_2023)
            rate_note = f"기본세율: {applied_rate*100:.0f}%"

        result["calculation"]["calc_tax"] = calc_tax
        result["calculation"]["applied_rate"] = applied_rate

        reduction = 0
        rural_tax = 0
        if data.reduction_type == "farming_8yr":
            reduction = min(calc_tax, 100_000_000)
            rural_tax = int(reduction * 0.20)
        elif data.reduction_type == "public_cash":
            reduction = min(int(calc_tax * 0.10), 200_000_000)
        elif data.reduction_type == "public_bond_3yr":
            reduction = min(int(calc_tax * 0.40), 200_000_000)
        elif data.reduction_type == "public_bond_5yr":
            reduction = min(int(calc_tax * 0.15), 200_000_000)

        result["calculation"]["reduction"] = reduction

        final_tax = max(calc_tax - reduction, 0)
        local_tax = int(final_tax * 0.10)
        total_tax = final_tax + local_tax + rural_tax

        result["calculation"]["final_tax"] = final_tax
        result["calculation"]["local_tax"] = local_tax
        result["calculation"]["rural_tax"] = rural_tax
        result["calculation"]["total_tax"] = total_tax

        result["summary"] = {
            "gross_gain": gross_gain,
            "taxable_gain": taxable_gain,
            "lthsd_amount": lthsd_amount,
            "tax_base": tax_base,
            "calc_tax": calc_tax,
            "reduction": reduction,
            "final_tax": final_tax,
            "local_tax": local_tax,
            "rural_tax": rural_tax,
            "total_tax": total_tax,
            "effective_rate": round(total_tax / gross_gain * 100, 2) if gross_gain > 0 else 0,
            "holding_display": f"{years}년 {months}개월",
            "rate_note": rate_note
        }
        return result

    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)
        return result


# === AI 상담 ===
async def get_ai_consultation(query: str, context: Optional[Dict] = None) -> str:
    knowledge = search_knowledge(query)

    system_prompt = f"""당신은 30년 경력의 양도소득세 전문 세무사입니다.

## 지식베이스
{knowledge}

## 답변 형식
반드시 다음 5단계 구조로 답변하세요:

<div class="report-section">
<h3>1. 문의 개요</h3>
<p>귀하의 문의는 [질문 요약]에 관한 내용입니다.</p>
</div>

<div class="report-section">
<h3>2. 핵심 답변 (결론)</h3>
<div class="conclusion-box">
<p><strong>[명확한 결론]</strong></p>
</div>
</div>

<div class="report-section">
<h3>3. 상세 검토 및 법적 근거</h3>
<ul><li>관련 법령과 실무 기준</li></ul>
</div>

<div class="report-section">
<h3>4. 주의사항 및 리스크</h3>
<ul><li>신고 기한, 가산세 등</li></ul>
</div>

<div class="report-section">
<h3>5. 종합 의견</h3>
<p>실무적 조언</p>
</div>

<div class="report-footer">
<p>본 보고서는 일반적인 세무 상담 자료입니다.</p>
<p>작성일: {datetime.now().strftime('%Y년 %m월 %d일')}</p>
</div>
"""

    user_message = query
    if context:
        user_message += f"\n\n[계산 데이터]\n{json.dumps(context, ensure_ascii=False, indent=2)}"

    try:
        if not GEMINI_API_KEY or GEMINI_API_KEY == "your_gemini_api_key_here":
            return generate_fallback_response(query, knowledge)

        model = genai.GenerativeModel('gemini-1.5-pro')
        response = model.generate_content(
            [system_prompt, user_message],
            generation_config=genai.GenerationConfig(temperature=0.3, max_output_tokens=4096)
        )
        return response.text
    except Exception as e:
        return generate_fallback_response(query, knowledge, str(e))


def generate_fallback_response(query: str, knowledge: str, error: str = None) -> str:
    today = datetime.now().strftime('%Y년 %m월 %d일')
    error_note = f"<p class='error-note'>AI 오류: {error}</p>" if error else ""
    return f"""
<div class="report-section">
<h3>1. 문의 개요</h3>
<p>"{query}"에 관한 문의입니다.</p>
{error_note}
</div>
<div class="report-section">
<h3>2. 관련 법령 정보</h3>
<div class="knowledge-box">{knowledge.replace(chr(10), '<br>')}</div>
</div>
<div class="report-section">
<h3>3. 안내</h3>
<p>AI 상담을 위해 GEMINI_API_KEY를 설정해 주세요.</p>
</div>
<div class="report-footer"><p>작성일: {today}</p></div>
"""


# === API 라우터 ===
@app.on_event("startup")
async def startup_event():
    init_db()


@app.get("/")
async def root():
    return {"status": "healthy", "service": "2025 양도소득세 AI API", "version": "1.0.0"}


@app.get("/api/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}


@app.post("/api/calculate")
async def calculate_endpoint(req: CalcRequest):
    result = calculate_cgt(req)
    return JSONResponse(content=result)


@app.post("/api/consult")
async def consult_endpoint(req: ConsultRequest):
    try:
        report_html = await get_ai_consultation(req.query, req.context_data)
        return JSONResponse(content={
            "status": "success",
            "html": report_html,
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# === 실행 ===
if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port)
