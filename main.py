"""
2025 양도소득세 AI 전문 컨설팅 플랫폼
- 정밀 양도세 계산 엔진
- Google Gemini 기반 AI 세무 상담
- PDF 보고서 자동 생성
"""

import os
import sqlite3
import json
import re
from datetime import datetime, date
from typing import Optional, List, Dict, Any
from pathlib import Path

from fastapi import FastAPI, Request, HTTPException, Response
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from dotenv import load_dotenv

import google.generativeai as genai

# 환경변수 로드
load_dotenv()

# === 설정 ===
app = FastAPI(
    title="2025 양도소득세 AI 전문 컨설팅",
    description="공인중개사를 위한 실시간 양도세 계산 및 AI 세무상담 플랫폼",
    version="1.0.0"
)

# CORS 설정
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Static files & Templates
BASE_DIR = Path(__file__).resolve().parent
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

# Gemini API 설정
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
if GEMINI_API_KEY and GEMINI_API_KEY != "your_gemini_api_key_here":
    genai.configure(api_key=GEMINI_API_KEY)

DB_PATH = os.getenv("DB_PATH", "./data/tax_knowledge.db")


# === 2025년 양도소득세 세율표 (정확한 법령 기준) ===
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

# 비사업용 토지 세율 (기본세율 + 10%)
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

# 장기보유특별공제율 (표1: 일반, 표2: 1세대1주택)
LTHSD_TABLE1 = {  # 일반자산 (연 2%, 최대 30%)
    3: 0.06, 4: 0.08, 5: 0.10, 6: 0.12, 7: 0.14, 8: 0.16, 9: 0.18, 10: 0.20,
    11: 0.22, 12: 0.24, 13: 0.26, 14: 0.28, 15: 0.30
}

LTHSD_TABLE2_HOLDING = {  # 1세대1주택 보유기간 (연 4%, 최대 40%)
    3: 0.12, 4: 0.16, 5: 0.20, 6: 0.24, 7: 0.28, 8: 0.32, 9: 0.36, 10: 0.40
}

LTHSD_TABLE2_RESIDENCE = {  # 1세대1주택 거주기간 (연 4%, 최대 40%)
    2: 0.08, 3: 0.12, 4: 0.16, 5: 0.20, 6: 0.24, 7: 0.28, 8: 0.32, 9: 0.36, 10: 0.40
}


# === Pydantic 모델 ===
class CalcRequest(BaseModel):
    """양도세 계산 요청 모델"""
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
    """AI 상담 요청 모델"""
    query: str = Field(..., description="상담 질문")
    context_data: Optional[Dict[str, Any]] = Field(None, description="계산 결과 컨텍스트")


class ReportRequest(BaseModel):
    """보고서 생성 요청 모델"""
    calc_result: Dict[str, Any]
    consult_history: Optional[List[Dict[str, str]]] = None


# === 데이터베이스 초기화 ===
def init_db():
    """SQLite FTS5 데이터베이스 초기화"""
    os.makedirs(os.path.dirname(DB_PATH) if os.path.dirname(DB_PATH) else ".", exist_ok=True)

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # FTS5 가상 테이블 생성
    cursor.execute("""
        CREATE VIRTUAL TABLE IF NOT EXISTS tax_knowledge
        USING fts5(category, title, content, keywords)
    """)

    # 초기 데이터 확인 및 적재
    cursor.execute("SELECT count(*) FROM tax_knowledge")
    if cursor.fetchone()[0] == 0:
        knowledge_data = [
            # 1세대1주택 비과세
            ("비과세", "1세대1주택 비과세",
             """1세대가 양도일 현재 국내에 1주택을 보유하고 2년 이상 보유(조정대상지역 2017.8.3. 이후 취득분은 2년 거주 필요)한 경우 비과세.
             고가주택 기준: 12억원 초과 시 초과분에 대해서만 과세.
             고가주택 과세표준 = 양도차익 × (양도가액 - 12억원) / 양도가액""",
             "1세대1주택 비과세 고가주택 12억 2년보유 2년거주 조정대상지역"),

            # 일시적 2주택
            ("비과세", "일시적 2주택 비과세",
             """종전주택을 보유한 상태에서 신규주택을 취득하고 3년 이내에 종전주택을 양도하는 경우 비과세.
             2023.1.12. 이후 양도분: 신규주택 취득 후 3년 이내 종전주택 양도.
             조정대상지역 내 신규주택 취득 시: 1년 이내 전입 + 1년 이상 거주 요건 충족 필요.""",
             "일시적2주택 이사 신규주택 종전주택 3년 비과세"),

            # 장기보유특별공제
            ("공제", "장기보유특별공제",
             """표1(일반자산): 3년 이상 보유 시 연 2%, 최대 30%(15년).
             표2(1세대1주택): 보유기간 연 4%(최대 40%) + 거주기간 연 4%(최대 40%) = 최대 80%.
             2022.5.10.~2026.5.9. 양도분: 다주택자도 기본세율 및 장기보유특별공제 적용(중과 유예).
             비사업용 토지: 장기보유특별공제 적용 가능.""",
             "장기보유특별공제 장특공제 표1 표2 보유기간 거주기간"),

            # 다주택자 중과
            ("세율", "다주택자 중과세율",
             """조정대상지역 2주택: 기본세율 + 20%, 3주택 이상: 기본세율 + 30%.
             2022.5.10.~2026.5.9. 양도분: 보유기간 2년 이상 주택은 중과 배제, 기본세율 적용.
             분양권: 2021.1.1. 이후 취득분부터 주택수 포함.""",
             "다주택 중과 조정대상지역 2주택 3주택 중과유예"),

            # 단기양도
            ("세율", "단기양도 세율",
             """2021.6.1. 이후 양도분:
             1년 미만: 50% (주택/입주권/분양권 70%)
             1년 이상 2년 미만: 40% (주택/입주권/분양권 60%)
             분양권: 지역 불문 1년 미만 70%, 1년 이상 60%.""",
             "단기양도 1년미만 2년미만 70% 60% 분양권"),

            # 비사업용 토지
            ("세율", "비사업용 토지",
             """비사업용 토지: 기본세율 + 10%.
             농지 비사업용 판정: 재촌·자경 요건 미충족 시 비사업용.
             장기보유특별공제 적용 가능.
             토지투기지역(현재 없음): 비사업용 토지 세율 + 10%.""",
             "비사업용토지 농지 재촌 자경 10% 중과"),

            # 8년 자경 감면
            ("감면", "8년 자경농지 감면",
             """8년 이상 재촌·자경 농지 양도세 100% 감면.
             한도: 1과세기간 1억원, 5년간 2억원.
             농특세: 감면세액의 20% (비과세 아님).
             요건: 거주지에서 30km 이내 소재, 1/2 이상 자기 노동력으로 경작.""",
             "8년자경 농지감면 자경농지 재촌자경 100%감면"),

            # 공익사업 수용
            ("감면", "공익사업 수용 감면",
             """사업인정고시일 2년 이전 취득 토지 수용 시 감면.
             현금보상: 10% 감면, 채권보상(5년): 15%, 채권보상(3년): 40%.
             2025년 이후: 연간 한도 2억원.""",
             "공익사업 수용 보상 현금보상 채권보상 감면"),

            # 미등기 양도
            ("세율", "미등기 양도자산",
             """미등기 양도자산: 70% 단일세율.
             장기보유특별공제 적용 배제.
             예외: 장기할부조건, 법원경매, 상속등기 전 양도 등은 미등기 제외.""",
             "미등기 70% 미등기양도 등기"),

            # 기본세율
            ("세율", "2025년 기본세율",
             """2023년 이후 양도소득세 기본세율:
             1,400만원 이하: 6%
             1,400~5,000만원: 15% (누진공제 126만원)
             5,000~8,800만원: 24% (누진공제 576만원)
             8,800~1.5억원: 35% (누진공제 1,544만원)
             1.5~3억원: 38% (누진공제 1,994만원)
             3~5억원: 40% (누진공제 2,594만원)
             5~10억원: 42% (누진공제 3,594만원)
             10억원 초과: 45% (누진공제 6,594만원)""",
             "기본세율 누진세율 누진공제 6% 15% 24% 35% 38% 40% 42% 45%"),

            # 양도소득기본공제
            ("공제", "양도소득기본공제",
             """연간 250만원 공제.
             부동산, 부동산에 관한 권리, 기타자산 각각 적용.
             미등기양도자산: 기본공제 적용 배제.""",
             "기본공제 250만원 연간공제"),

            # 상속주택 특례
            ("비과세", "상속주택 특례",
             """상속받은 주택과 일반주택 보유 시:
             일반주택 양도 시 상속주택은 주택수 제외(비과세 판정 시).
             단, 상속개시 당시 피상속인과 동거한 상속인에게 상속된 주택에 한함.
             상속주택 먼저 양도 시 일반 양도세율 적용.""",
             "상속주택 특례 주택수제외 피상속인 상속개시"),
        ]

        cursor.executemany(
            "INSERT INTO tax_knowledge(category, title, content, keywords) VALUES (?, ?, ?, ?)",
            knowledge_data
        )
        conn.commit()

    conn.close()


def search_knowledge(query: str, limit: int = 5) -> str:
    """지식베이스 검색"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        # FTS5 검색
        search_query = ' OR '.join(query.split())
        cursor.execute("""
            SELECT title, content FROM tax_knowledge
            WHERE tax_knowledge MATCH ?
            ORDER BY rank
            LIMIT ?
        """, (search_query, limit))

        results = cursor.fetchall()
        conn.close()

        if results:
            formatted = []
            for title, content in results:
                formatted.append(f"### {title}\n{content}")
            return "\n\n".join(formatted)

        return "관련 법령 정보를 찾을 수 없습니다."
    except Exception as e:
        return f"검색 오류: {str(e)}"


# === 계산 엔진 ===
def calculate_holding_period(acquisition_date: str, transfer_date: str) -> tuple:
    """보유기간 계산 (년, 월, 일)"""
    acq = datetime.strptime(acquisition_date, "%Y-%m-%d")
    trans = datetime.strptime(transfer_date, "%Y-%m-%d")

    total_days = (trans - acq).days
    years = total_days // 365
    months = (total_days % 365) // 30
    days = (total_days % 365) % 30

    return years, months, days, total_days


def get_lthsd_rate(holding_years: int, residence_years: int, is_1h1h: bool, asset_type: str) -> tuple:
    """장기보유특별공제율 계산"""
    if holding_years < 3:
        return 0, "보유기간 3년 미만으로 장기보유특별공제 적용 불가"

    if is_1h1h and residence_years >= 2:
        # 표2 적용 (1세대1주택)
        holding_rate = LTHSD_TABLE2_HOLDING.get(min(holding_years, 10), 0.40)
        residence_rate = LTHSD_TABLE2_RESIDENCE.get(min(residence_years, 10), 0.40)
        total_rate = min(holding_rate + residence_rate, 0.80)
        return total_rate, f"1세대1주택 표2 적용: 보유 {holding_rate*100:.0f}% + 거주 {residence_rate*100:.0f}% = {total_rate*100:.0f}%"
    else:
        # 표1 적용 (일반)
        capped_years = min(holding_years, 15)
        rate = LTHSD_TABLE1.get(capped_years, min(capped_years * 0.02, 0.30))
        return rate, f"일반자산 표1 적용: {holding_years}년 보유 = {rate*100:.0f}%"


def calculate_tax_amount(tax_base: int, brackets: list) -> tuple:
    """누진세율 적용 세액 계산"""
    for threshold, rate, deduction in brackets:
        if tax_base <= threshold:
            tax = int(tax_base * rate - deduction)
            return max(tax, 0), rate, deduction

    # 최고구간
    _, rate, deduction = brackets[-1]
    return max(int(tax_base * rate - deduction), 0), rate, deduction


def calculate_cgt(data: CalcRequest) -> Dict[str, Any]:
    """양도소득세 계산 메인 로직"""
    result = {
        "status": "success",
        "input": data.dict(),
        "calculation": {},
        "breakdown": [],
        "warnings": [],
        "summary": {}
    }

    try:
        # 1. 보유기간 계산
        years, months, days, total_days = calculate_holding_period(
            data.acquisition_date, data.transfer_date
        )
        result["calculation"]["holding_period"] = {
            "years": years,
            "months": months,
            "days": days,
            "total_days": total_days,
            "display": f"{years}년 {months}개월"
        }

        # 2. 양도차익 계산
        gross_gain = data.transfer_price - data.acquisition_price - data.necessary_expenses
        result["calculation"]["gross_gain"] = gross_gain
        result["breakdown"].append({
            "step": "양도차익 계산",
            "formula": f"양도가액({data.transfer_price:,}) - 취득가액({data.acquisition_price:,}) - 필요경비({data.necessary_expenses:,})",
            "value": gross_gain
        })

        if gross_gain <= 0:
            result["status"] = "no_tax"
            result["summary"] = {
                "message": "양도차익이 없거나 손실이므로 납부할 세금이 없습니다.",
                "total_tax": 0
            }
            return result

        # 3. 비과세 판정 (1세대1주택)
        taxable_gain = gross_gain
        exempt_amount = 0
        high_value_ratio = 1.0

        if data.is_1h1h and data.housing_count == 1:
            if years >= 2 or (not data.is_adjusted_area and years >= 2):
                if data.transfer_price <= 1_200_000_000:
                    result["status"] = "exempt"
                    result["summary"] = {
                        "message": "1세대 1주택 비과세 적용 (양도가액 12억원 이하)",
                        "total_tax": 0,
                        "legal_basis": "소득세법 제89조 제1항 제3호"
                    }
                    return result
                else:
                    # 고가주택 과세
                    high_value_ratio = (data.transfer_price - 1_200_000_000) / data.transfer_price
                    taxable_gain = int(gross_gain * high_value_ratio)
                    exempt_amount = gross_gain - taxable_gain
                    result["breakdown"].append({
                        "step": "고가주택 과세표준 조정",
                        "formula": f"양도차익 × (양도가액 - 12억) / 양도가액 = {gross_gain:,} × {high_value_ratio:.4f}",
                        "value": taxable_gain,
                        "note": "12억 초과분에 대해서만 과세"
                    })
                    result["warnings"].append("고가주택(12억 초과)으로 초과분 과세")

        result["calculation"]["taxable_gain"] = taxable_gain
        result["calculation"]["exempt_amount"] = exempt_amount

        # 4. 장기보유특별공제
        lthsd_amount = 0
        lthsd_rate = 0
        lthsd_note = ""

        # 미등기 또는 특정 조건에서 장특공제 배제
        if not data.is_registered:
            lthsd_note = "미등기 양도자산: 장기보유특별공제 적용 배제"
            result["warnings"].append(lthsd_note)
        elif data.asset_type in ["housing", "land", "land_nonbiz", "building"]:
            lthsd_rate, lthsd_note = get_lthsd_rate(
                years, data.residence_years, data.is_1h1h, data.asset_type
            )
            lthsd_amount = int(taxable_gain * lthsd_rate)

        result["calculation"]["lthsd"] = {
            "rate": lthsd_rate,
            "amount": lthsd_amount,
            "note": lthsd_note
        }
        result["breakdown"].append({
            "step": "장기보유특별공제",
            "formula": f"과세양도차익({taxable_gain:,}) × {lthsd_rate*100:.0f}%",
            "value": lthsd_amount,
            "note": lthsd_note
        })

        # 5. 양도소득금액
        transfer_income = taxable_gain - lthsd_amount
        result["calculation"]["transfer_income"] = transfer_income

        # 6. 과세표준 (양도소득기본공제 250만원)
        basic_deduction = 2_500_000
        if not data.is_registered:
            basic_deduction = 0  # 미등기는 기본공제 배제

        tax_base = max(transfer_income - basic_deduction, 0)
        result["calculation"]["basic_deduction"] = basic_deduction
        result["calculation"]["tax_base"] = tax_base
        result["breakdown"].append({
            "step": "과세표준 계산",
            "formula": f"양도소득금액({transfer_income:,}) - 기본공제({basic_deduction:,})",
            "value": tax_base
        })

        if tax_base <= 0:
            result["status"] = "no_tax"
            result["summary"] = {
                "message": "과세표준이 0 이하로 납부할 세금이 없습니다.",
                "total_tax": 0
            }
            return result

        # 7. 세율 결정 및 산출세액
        calc_tax = 0
        applied_rate = 0
        rate_note = ""

        # 미등기 양도
        if not data.is_registered:
            calc_tax = int(tax_base * 0.70)
            applied_rate = 0.70
            rate_note = "미등기 양도: 70%"
            result["warnings"].append("미등기 양도자산으로 70% 세율 적용")

        # 단기양도 (1년 미만, 1~2년 미만)
        elif years < 2:
            if data.asset_type in ["housing", "right", "share_right"]:
                if years < 1:
                    calc_tax = int(tax_base * 0.70)
                    applied_rate = 0.70
                    rate_note = "단기양도(1년 미만 주택/입주권): 70%"
                else:
                    calc_tax = int(tax_base * 0.60)
                    applied_rate = 0.60
                    rate_note = "단기양도(1~2년 미만 주택/입주권): 60%"
            else:
                if years < 1:
                    calc_tax = int(tax_base * 0.50)
                    applied_rate = 0.50
                    rate_note = "단기양도(1년 미만): 50%"
                else:
                    calc_tax = int(tax_base * 0.40)
                    applied_rate = 0.40
                    rate_note = "단기양도(1~2년 미만): 40%"

        # 다주택자 중과 (2022.5.10~2026.5.9 유예기간 체크)
        elif data.is_adjusted_area and data.housing_count >= 2 and data.asset_type == "housing":
            trans_date = datetime.strptime(data.transfer_date, "%Y-%m-%d")
            suspension_start = datetime(2022, 5, 10)
            suspension_end = datetime(2026, 5, 9)

            if suspension_start <= trans_date <= suspension_end and years >= 2:
                # 중과 유예: 기본세율 적용
                calc_tax, applied_rate, deduction = calculate_tax_amount(tax_base, TAX_BRACKETS_2023)
                rate_note = f"다주택 중과 유예기간: 기본세율 {applied_rate*100:.0f}% 적용"
                result["breakdown"].append({
                    "step": "중과 유예 적용",
                    "note": "2022.5.10~2026.5.9 양도, 보유 2년 이상으로 중과 배제"
                })
            else:
                # 중과 적용
                base_tax, base_rate, deduction = calculate_tax_amount(tax_base, TAX_BRACKETS_2023)
                surcharge_rate = 0.20 if data.housing_count == 2 else 0.30
                surcharge = int(tax_base * surcharge_rate)
                calc_tax = base_tax + surcharge
                applied_rate = base_rate + surcharge_rate
                rate_note = f"다주택 중과: 기본세율 + {surcharge_rate*100:.0f}%"
                result["warnings"].append(f"조정대상지역 {data.housing_count}주택 중과세율 적용")

        # 비사업용 토지
        elif data.asset_type == "land_nonbiz":
            calc_tax, applied_rate, deduction = calculate_tax_amount(tax_base, TAX_BRACKETS_NON_BIZ_LAND)
            rate_note = f"비사업용 토지: 기본세율 + 10% = {applied_rate*100:.0f}%"
            result["warnings"].append("비사업용 토지로 기본세율에 10% 가산")

        # 기본세율
        else:
            calc_tax, applied_rate, deduction = calculate_tax_amount(tax_base, TAX_BRACKETS_2023)
            rate_note = f"기본세율: {applied_rate*100:.0f}%"

        result["calculation"]["calc_tax"] = calc_tax
        result["calculation"]["applied_rate"] = applied_rate
        result["breakdown"].append({
            "step": "산출세액 계산",
            "formula": f"과세표준({tax_base:,}) × 세율",
            "value": calc_tax,
            "note": rate_note
        })

        # 8. 세액감면
        reduction = 0
        reduction_note = ""
        rural_tax = 0  # 농어촌특별세

        if data.reduction_type == "farming_8yr":
            reduction = min(calc_tax, 100_000_000)  # 연간 한도 1억원
            reduction_note = "8년 자경농지 감면 (100% 감면, 연 한도 1억원)"
            rural_tax = int(reduction * 0.20)  # 농특세 20%
            result["breakdown"].append({
                "step": "8년 자경농지 감면",
                "value": reduction,
                "note": "농어촌특별세 별도 부과"
            })

        elif data.reduction_type == "public_cash":
            reduction = min(int(calc_tax * 0.10), 200_000_000)  # 2025년 기준 연 한도 2억원
            reduction_note = "공익사업 수용 감면 (현금보상 10%)"
            result["breakdown"].append({
                "step": "공익사업 수용 감면",
                "value": reduction,
                "note": "현금보상 10% 감면"
            })

        elif data.reduction_type == "public_bond_3yr":
            reduction = min(int(calc_tax * 0.40), 200_000_000)
            reduction_note = "공익사업 수용 감면 (3년 만기 채권보상 40%)"

        elif data.reduction_type == "public_bond_5yr":
            reduction = min(int(calc_tax * 0.15), 200_000_000)
            reduction_note = "공익사업 수용 감면 (5년 만기 채권보상 15%)"

        result["calculation"]["reduction"] = reduction
        result["calculation"]["reduction_note"] = reduction_note

        # 9. 결정세액
        final_tax = max(calc_tax - reduction, 0)
        result["calculation"]["final_tax"] = final_tax

        # 10. 지방소득세 (10%)
        local_tax = int(final_tax * 0.10)
        result["calculation"]["local_tax"] = local_tax

        # 11. 농어촌특별세
        result["calculation"]["rural_tax"] = rural_tax

        # 12. 총 납부세액
        total_tax = final_tax + local_tax + rural_tax
        result["calculation"]["total_tax"] = total_tax

        # 요약
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
    """Gemini를 사용한 AI 세무 상담"""

    # 지식베이스 검색
    knowledge = search_knowledge(query)

    # 시스템 프롬프트 (세무사 보고서 양식)
    system_prompt = f"""당신은 30년 경력의 양도소득세 전문 세무사입니다. 국세청 자문위원 출신으로 실무에 정통합니다.

## 역할
- 사용자의 양도소득세 관련 질문에 정확하고 상세하게 답변합니다.
- 반드시 아래 [지식베이스]의 내용을 근거로 답변해야 합니다.
- 최신 세법(2025년 귀속 기준)을 적용합니다.

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
<p><strong>[명확한 결론을 1-2문장으로]</strong></p>
</div>
</div>

<div class="report-section">
<h3>3. 상세 검토 및 법적 근거</h3>
<p>관련 법령과 실무 기준을 상세히 설명합니다.</p>
<ul>
<li>법령 근거: 소득세법 제XX조</li>
<li>적용 요건 및 계산 방법</li>
</ul>
</div>

<div class="report-section">
<h3>4. 주의사항 및 리스크</h3>
<ul>
<li>신고 기한, 가산세 등 주의사항</li>
<li>흔히 실수하는 부분</li>
</ul>
</div>

<div class="report-section">
<h3>5. 종합 의견</h3>
<p>실무적 조언과 권고사항을 포함합니다.</p>
</div>

<div class="report-footer">
<p>본 보고서는 일반적인 세무 상담 자료이며, 개별 사안에 대한 최종 판단은 관할 세무서 또는 세무사와 상담하시기 바랍니다.</p>
<p>작성일: {datetime.now().strftime('%Y년 %m월 %d일')}</p>
</div>
"""

    user_message = query
    if context:
        user_message += f"\n\n[참고: 사용자 계산 데이터]\n{json.dumps(context, ensure_ascii=False, indent=2)}"

    try:
        if not GEMINI_API_KEY or GEMINI_API_KEY == "your_gemini_api_key_here":
            # API 키가 없으면 기본 응답
            return generate_fallback_response(query, knowledge)

        model = genai.GenerativeModel('gemini-1.5-pro')

        response = model.generate_content(
            [system_prompt, user_message],
            generation_config=genai.GenerationConfig(
                temperature=0.3,
                max_output_tokens=4096,
            )
        )

        return response.text

    except Exception as e:
        return generate_fallback_response(query, knowledge, str(e))


def generate_fallback_response(query: str, knowledge: str, error: str = None) -> str:
    """API 키가 없거나 오류 시 기본 응답"""
    today = datetime.now().strftime('%Y년 %m월 %d일')

    error_note = ""
    if error:
        error_note = f"<p class='error-note'>AI 서비스 연결 오류: {error}</p>"

    return f"""
<div class="report-section">
<h3>1. 문의 개요</h3>
<p>귀하의 문의는 "{query}"에 관한 내용입니다.</p>
{error_note}
</div>

<div class="report-section">
<h3>2. 관련 법령 정보</h3>
<div class="knowledge-box">
{knowledge.replace(chr(10), '<br>')}
</div>
</div>

<div class="report-section">
<h3>3. 안내</h3>
<p>보다 정확한 상담을 위해 Gemini API 키를 설정해 주세요.</p>
<p>.env 파일의 GEMINI_API_KEY 값을 입력하시면 AI 기반 상세 상담이 가능합니다.</p>
</div>

<div class="report-footer">
<p>본 내용은 지식베이스 검색 결과입니다.</p>
<p>작성일: {today}</p>
</div>
"""


# === API 라우터 ===
@app.on_event("startup")
async def startup_event():
    """서버 시작 시 DB 초기화"""
    init_db()


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    """메인 페이지"""
    return templates.TemplateResponse("index.html", {"request": request})


@app.post("/api/calculate")
async def calculate_endpoint(req: CalcRequest):
    """양도세 계산 API"""
    result = calculate_cgt(req)
    return JSONResponse(content=result)


@app.post("/api/consult")
async def consult_endpoint(req: ConsultRequest):
    """AI 상담 API"""
    try:
        report_html = await get_ai_consultation(req.query, req.context_data)
        return JSONResponse(content={
            "status": "success",
            "html": report_html,
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/health")
async def health_check():
    """헬스체크"""
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}


# === 실행 ===
if __name__ == "__main__":
    import uvicorn
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", 8000))
    debug = os.getenv("DEBUG", "false").lower() == "true"

    uvicorn.run("main:app", host=host, port=port, reload=debug)
