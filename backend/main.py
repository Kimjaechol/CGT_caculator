"""
2025 양도소득세 AI 전문 컨설팅 플랫폼 - Backend API
- 사용자 인증 (카카오 OAuth + JWT)
- 관리자 기능 (회원관리, 파일업로드, 내역조회)
- 상담내역 RAG 재활용
"""

import os
import sqlite3
import json
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from pathlib import Path

from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, Form, Header
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from dotenv import load_dotenv
import httpx
import jwt

import google.generativeai as genai

# 환경변수 로드
load_dotenv()

# === 설정 ===
app = FastAPI(
    title="2025 양도소득세 AI API",
    description="양도소득세 계산 및 AI 세무상담 API",
    version="2.0.0"
)

# CORS 설정
FRONTEND_URL = os.getenv("FRONTEND_URL", "*")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if FRONTEND_URL == "*" else [FRONTEND_URL, "http://localhost:3000", "http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# JWT 설정
JWT_SECRET = os.getenv("JWT_SECRET", secrets.token_hex(32))
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 24 * 7  # 7일

# 카카오 OAuth 설정
KAKAO_CLIENT_ID = os.getenv("KAKAO_CLIENT_ID", "")
KAKAO_CLIENT_SECRET = os.getenv("KAKAO_CLIENT_SECRET", "")
KAKAO_REDIRECT_URI = os.getenv("KAKAO_REDIRECT_URI", "")

# Gemini API 설정
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
if GEMINI_API_KEY and GEMINI_API_KEY != "your_gemini_api_key_here":
    genai.configure(api_key=GEMINI_API_KEY)

# 관리자 설정
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin1234")

# DB 경로
DB_PATH = os.getenv("DB_PATH", "/tmp/tax_app.db")

security = HTTPBearer(auto_error=False)


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
    transfer_date: str
    acquisition_date: str
    transfer_price: int
    acquisition_price: int
    necessary_expenses: int = 0
    asset_type: str = "housing"
    is_1h1h: bool = False
    residence_years: int = 0
    is_adjusted_area: bool = False
    housing_count: int = 1
    reduction_type: str = "none"
    is_registered: bool = True


class ConsultRequest(BaseModel):
    query: str
    context_data: Optional[Dict[str, Any]] = None


class KakaoLoginRequest(BaseModel):
    code: str
    redirect_uri: Optional[str] = None


class UserUpdateRequest(BaseModel):
    phone: Optional[str] = None
    email: Optional[str] = None


class RegisterRequest(BaseModel):
    email: str
    password: str
    name: str
    phone: Optional[str] = None


class LoginRequest(BaseModel):
    email: str
    password: str


class AdminLoginRequest(BaseModel):
    password: str


# === 데이터베이스 초기화 ===
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    os.makedirs(os.path.dirname(DB_PATH) if os.path.dirname(DB_PATH) else ".", exist_ok=True)
    conn = get_db()
    cursor = conn.cursor()

    # 사용자 테이블
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            kakao_id TEXT UNIQUE,
            email TEXT UNIQUE,
            password_hash TEXT,
            name TEXT,
            phone TEXT,
            profile_image TEXT,
            is_admin INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # 계산 내역 테이블
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS calc_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            input_data TEXT,
            result_data TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    # 상담 내역 테이블
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS consult_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            query TEXT,
            response_html TEXT,
            context_data TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    # 지식베이스 FTS5 테이블
    cursor.execute("""
        CREATE VIRTUAL TABLE IF NOT EXISTS tax_knowledge
        USING fts5(category, title, content, keywords)
    """)

    # 상담내역 RAG용 FTS5 테이블
    cursor.execute("""
        CREATE VIRTUAL TABLE IF NOT EXISTS consult_rag
        USING fts5(query, response, created_at)
    """)

    # 업로드 파일 메타데이터 테이블
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS uploaded_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT,
            file_type TEXT,
            file_size INTEGER,
            storage_type TEXT,
            gemini_store_name TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # 초기 지식베이스 데이터 확인
    cursor.execute("SELECT count(*) FROM tax_knowledge")
    if cursor.fetchone()[0] == 0:
        _init_knowledge_base(cursor)

    conn.commit()
    conn.close()


def _init_knowledge_base(cursor):
    """초기 지식베이스 데이터 삽입"""
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
    ]
    cursor.executemany(
        "INSERT INTO tax_knowledge(category, title, content, keywords) VALUES (?, ?, ?, ?)",
        knowledge_data
    )


# === JWT 인증 ===
def create_jwt_token(user_id: int, is_admin: bool = False) -> str:
    payload = {
        "user_id": user_id,
        "is_admin": is_admin,
        "exp": datetime.utcnow() + timedelta(hours=JWT_EXPIRATION_HOURS)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def verify_jwt_token(token: str) -> Optional[Dict]:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> Optional[Dict]:
    if not credentials:
        return None
    payload = verify_jwt_token(credentials.credentials)
    return payload


async def require_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> Dict:
    if not credentials:
        raise HTTPException(status_code=401, detail="로그인이 필요합니다")
    payload = verify_jwt_token(credentials.credentials)
    if not payload:
        raise HTTPException(status_code=401, detail="유효하지 않은 토큰입니다")
    return payload


async def require_admin(credentials: HTTPAuthorizationCredentials = Depends(security)) -> Dict:
    payload = await require_user(credentials)
    if not payload.get("is_admin"):
        raise HTTPException(status_code=403, detail="관리자 권한이 필요합니다")
    return payload


# === 카카오 OAuth ===
async def get_kakao_token(code: str, redirect_uri: str) -> Dict:
    async with httpx.AsyncClient() as client:
        response = await client.post(
            "https://kauth.kakao.com/oauth/token",
            data={
                "grant_type": "authorization_code",
                "client_id": KAKAO_CLIENT_ID,
                "client_secret": KAKAO_CLIENT_SECRET,
                "redirect_uri": redirect_uri,
                "code": code
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )
        if response.status_code != 200:
            raise HTTPException(status_code=400, detail="카카오 토큰 발급 실패")
        return response.json()


async def get_kakao_user_info(access_token: str) -> Dict:
    async with httpx.AsyncClient() as client:
        response = await client.get(
            "https://kapi.kakao.com/v2/user/me",
            headers={"Authorization": f"Bearer {access_token}"}
        )
        if response.status_code != 200:
            raise HTTPException(status_code=400, detail="카카오 사용자 정보 조회 실패")
        return response.json()


# === 지식베이스 검색 ===
def search_knowledge(query: str, limit: int = 5) -> str:
    try:
        conn = get_db()
        cursor = conn.cursor()

        # 기본 지식베이스 검색
        search_query = ' OR '.join(query.split())
        cursor.execute("""
            SELECT title, content FROM tax_knowledge
            WHERE tax_knowledge MATCH ?
            ORDER BY rank LIMIT ?
        """, (search_query, limit))
        kb_results = cursor.fetchall()

        # 상담 RAG 검색
        cursor.execute("""
            SELECT query, response FROM consult_rag
            WHERE consult_rag MATCH ?
            ORDER BY rank LIMIT 3
        """, (search_query,))
        rag_results = cursor.fetchall()

        conn.close()

        formatted = []
        if kb_results:
            for row in kb_results:
                formatted.append(f"### {row['title']}\n{row['content']}")

        if rag_results:
            formatted.append("\n### [이전 상담 사례]")
            for row in rag_results:
                formatted.append(f"Q: {row['query'][:100]}...")

        return "\n\n".join(formatted) if formatted else "관련 법령 정보를 찾을 수 없습니다."
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
        if not data.is_registered:
            result["warnings"].append("미등기: 장특공제 배제")
        elif data.asset_type in ["housing", "land", "land_nonbiz", "building"]:
            lthsd_rate, _ = get_lthsd_rate(years, data.residence_years, data.is_1h1h, data.asset_type)
            lthsd_amount = int(taxable_gain * lthsd_rate)

        result["calculation"]["lthsd"] = {"rate": lthsd_rate, "amount": lthsd_amount}

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
async def get_ai_consultation(query: str, context: Optional[Dict] = None, user_id: Optional[int] = None) -> str:
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

        response_text = response.text

        # 상담 내역을 RAG에 저장
        save_consult_to_rag(query, response_text)

        return response_text
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


def save_consult_to_rag(query: str, response: str):
    """상담 내역을 RAG FTS5에 저장"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        # HTML 태그 제거한 텍스트만 저장
        import re
        clean_response = re.sub(r'<[^>]+>', '', response)[:2000]
        cursor.execute(
            "INSERT INTO consult_rag (query, response, created_at) VALUES (?, ?, ?)",
            (query[:500], clean_response, datetime.now().isoformat())
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"RAG 저장 오류: {e}")


# === API 라우터 ===
@app.on_event("startup")
async def startup_event():
    init_db()


@app.get("/")
async def root():
    return {"status": "healthy", "service": "2025 양도소득세 AI API", "version": "2.0.0"}


@app.get("/api/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}


# --- 인증 API ---
@app.post("/api/auth/kakao")
async def kakao_login(req: KakaoLoginRequest):
    """카카오 OAuth 로그인"""
    redirect_uri = req.redirect_uri or KAKAO_REDIRECT_URI

    # 카카오 토큰 발급
    token_data = await get_kakao_token(req.code, redirect_uri)
    access_token = token_data.get("access_token")

    # 카카오 사용자 정보 조회
    kakao_user = await get_kakao_user_info(access_token)
    kakao_id = str(kakao_user.get("id"))

    kakao_account = kakao_user.get("kakao_account", {})
    profile = kakao_account.get("profile", {})

    name = profile.get("nickname", "")
    profile_image = profile.get("profile_image_url", "")
    email = kakao_account.get("email", "")
    phone = kakao_account.get("phone_number", "")

    # DB에서 사용자 조회 또는 생성
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM users WHERE kakao_id = ?", (kakao_id,))
    user = cursor.fetchone()

    if user:
        # 기존 사용자
        user_id = user["id"]
        needs_additional_info = not user["email"] or not user["phone"]
    else:
        # 신규 사용자 생성
        cursor.execute("""
            INSERT INTO users (kakao_id, email, name, phone, profile_image)
            VALUES (?, ?, ?, ?, ?)
        """, (kakao_id, email, name, phone, profile_image))
        conn.commit()
        user_id = cursor.lastrowid
        needs_additional_info = not email or not phone

    conn.close()

    # JWT 토큰 생성
    token = create_jwt_token(user_id)

    return {
        "status": "success",
        "token": token,
        "user": {
            "id": user_id,
            "name": name,
            "email": email,
            "phone": phone,
            "profile_image": profile_image
        },
        "needs_additional_info": needs_additional_info
    }


@app.post("/api/auth/register")
async def register(req: RegisterRequest):
    """이메일 회원가입"""
    conn = get_db()
    cursor = conn.cursor()

    # 이메일 중복 확인
    cursor.execute("SELECT id FROM users WHERE email = ?", (req.email,))
    if cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=400, detail="이미 가입된 이메일입니다")

    # 비밀번호 해시
    password_hash = hashlib.sha256(req.password.encode()).hexdigest()

    cursor.execute("""
        INSERT INTO users (email, password_hash, name, phone)
        VALUES (?, ?, ?, ?)
    """, (req.email, password_hash, req.name, req.phone))
    conn.commit()
    user_id = cursor.lastrowid
    conn.close()

    token = create_jwt_token(user_id)

    return {
        "status": "success",
        "token": token,
        "user": {"id": user_id, "name": req.name, "email": req.email}
    }


@app.post("/api/auth/login")
async def login(req: LoginRequest):
    """이메일 로그인"""
    conn = get_db()
    cursor = conn.cursor()

    password_hash = hashlib.sha256(req.password.encode()).hexdigest()

    cursor.execute("""
        SELECT id, name, email, phone, profile_image, is_admin
        FROM users WHERE email = ? AND password_hash = ?
    """, (req.email, password_hash))
    user = cursor.fetchone()
    conn.close()

    if not user:
        raise HTTPException(status_code=401, detail="이메일 또는 비밀번호가 올바르지 않습니다")

    token = create_jwt_token(user["id"], bool(user["is_admin"]))

    return {
        "status": "success",
        "token": token,
        "user": {
            "id": user["id"],
            "name": user["name"],
            "email": user["email"],
            "phone": user["phone"],
            "profile_image": user["profile_image"],
            "is_admin": bool(user["is_admin"])
        }
    }


@app.put("/api/auth/update")
async def update_user(req: UserUpdateRequest, user: Dict = Depends(require_user)):
    """사용자 정보 업데이트 (휴대폰, 이메일)"""
    conn = get_db()
    cursor = conn.cursor()

    updates = []
    values = []

    if req.phone:
        updates.append("phone = ?")
        values.append(req.phone)
    if req.email:
        updates.append("email = ?")
        values.append(req.email)

    if updates:
        values.append(user["user_id"])
        cursor.execute(
            f"UPDATE users SET {', '.join(updates)}, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
            values
        )
        conn.commit()

    conn.close()

    return {"status": "success", "message": "정보가 업데이트되었습니다"}


@app.get("/api/auth/me")
async def get_me(user: Dict = Depends(require_user)):
    """현재 사용자 정보 조회"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, name, email, phone, profile_image, is_admin, created_at
        FROM users WHERE id = ?
    """, (user["user_id"],))
    row = cursor.fetchone()
    conn.close()

    if not row:
        raise HTTPException(status_code=404, detail="사용자를 찾을 수 없습니다")

    return {
        "id": row["id"],
        "name": row["name"],
        "email": row["email"],
        "phone": row["phone"],
        "profile_image": row["profile_image"],
        "is_admin": bool(row["is_admin"]),
        "created_at": row["created_at"]
    }


# --- 계산기 API ---
@app.post("/api/calculate")
async def calculate_endpoint(req: CalcRequest, user: Optional[Dict] = Depends(get_current_user)):
    """양도세 계산"""
    result = calculate_cgt(req)

    # 로그인한 사용자면 내역 저장
    if user:
        try:
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO calc_history (user_id, input_data, result_data)
                VALUES (?, ?, ?)
            """, (user["user_id"], json.dumps(req.dict()), json.dumps(result)))
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"계산 내역 저장 오류: {e}")

    return JSONResponse(content=result)


# --- 상담 API ---
@app.post("/api/consult")
async def consult_endpoint(req: ConsultRequest, user: Optional[Dict] = Depends(get_current_user)):
    """AI 세무 상담"""
    try:
        user_id = user["user_id"] if user else None
        report_html = await get_ai_consultation(req.query, req.context_data, user_id)

        # 로그인한 사용자면 내역 저장
        if user:
            try:
                conn = get_db()
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO consult_history (user_id, query, response_html, context_data)
                    VALUES (?, ?, ?, ?)
                """, (user["user_id"], req.query, report_html, json.dumps(req.context_data) if req.context_data else None))
                conn.commit()
                conn.close()
            except Exception as e:
                print(f"상담 내역 저장 오류: {e}")

        return JSONResponse(content={
            "status": "success",
            "html": report_html,
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# --- 사용자 내역 API ---
@app.get("/api/history/calc")
async def get_calc_history(user: Dict = Depends(require_user), limit: int = 20):
    """계산 내역 조회"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, input_data, result_data, created_at
        FROM calc_history WHERE user_id = ?
        ORDER BY created_at DESC LIMIT ?
    """, (user["user_id"], limit))
    rows = cursor.fetchall()
    conn.close()

    return [{
        "id": row["id"],
        "input": json.loads(row["input_data"]),
        "result": json.loads(row["result_data"]),
        "created_at": row["created_at"]
    } for row in rows]


@app.get("/api/history/consult")
async def get_consult_history(user: Dict = Depends(require_user), limit: int = 20):
    """상담 내역 조회"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, query, response_html, created_at
        FROM consult_history WHERE user_id = ?
        ORDER BY created_at DESC LIMIT ?
    """, (user["user_id"], limit))
    rows = cursor.fetchall()
    conn.close()

    return [{
        "id": row["id"],
        "query": row["query"],
        "response_html": row["response_html"],
        "created_at": row["created_at"]
    } for row in rows]


# --- 관리자 API ---
@app.post("/api/admin/login")
async def admin_login(req: AdminLoginRequest):
    """관리자 로그인 (비밀번호)"""
    if req.password != ADMIN_PASSWORD:
        raise HTTPException(status_code=401, detail="잘못된 비밀번호입니다")

    # 관리자 전용 토큰 생성 (user_id=0, is_admin=True)
    token = create_jwt_token(0, is_admin=True)
    return {"status": "success", "token": token}


@app.get("/api/admin/users")
async def get_all_users(admin: Dict = Depends(require_admin), page: int = 1, limit: int = 50):
    """전체 회원 목록 조회"""
    offset = (page - 1) * limit
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM users")
    total = cursor.fetchone()[0]

    cursor.execute("""
        SELECT id, kakao_id, email, name, phone, is_admin, created_at
        FROM users ORDER BY created_at DESC LIMIT ? OFFSET ?
    """, (limit, offset))
    rows = cursor.fetchall()
    conn.close()

    return {
        "total": total,
        "page": page,
        "limit": limit,
        "users": [dict(row) for row in rows]
    }


@app.get("/api/admin/calc-history")
async def get_all_calc_history(admin: Dict = Depends(require_admin), page: int = 1, limit: int = 50):
    """전체 계산 내역 조회"""
    offset = (page - 1) * limit
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM calc_history")
    total = cursor.fetchone()[0]

    cursor.execute("""
        SELECT ch.id, ch.user_id, u.name, u.email, ch.input_data, ch.result_data, ch.created_at
        FROM calc_history ch
        LEFT JOIN users u ON ch.user_id = u.id
        ORDER BY ch.created_at DESC LIMIT ? OFFSET ?
    """, (limit, offset))
    rows = cursor.fetchall()
    conn.close()

    return {
        "total": total,
        "page": page,
        "limit": limit,
        "history": [{
            "id": row["id"],
            "user_id": row["user_id"],
            "user_name": row["name"],
            "user_email": row["email"],
            "input": json.loads(row["input_data"]) if row["input_data"] else None,
            "result": json.loads(row["result_data"]) if row["result_data"] else None,
            "created_at": row["created_at"]
        } for row in rows]
    }


@app.get("/api/admin/consult-history")
async def get_all_consult_history(admin: Dict = Depends(require_admin), page: int = 1, limit: int = 50):
    """전체 상담 내역 조회"""
    offset = (page - 1) * limit
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM consult_history")
    total = cursor.fetchone()[0]

    cursor.execute("""
        SELECT ch.id, ch.user_id, u.name, u.email, ch.query, ch.response_html, ch.created_at
        FROM consult_history ch
        LEFT JOIN users u ON ch.user_id = u.id
        ORDER BY ch.created_at DESC LIMIT ? OFFSET ?
    """, (limit, offset))
    rows = cursor.fetchall()
    conn.close()

    return {
        "total": total,
        "page": page,
        "limit": limit,
        "history": [dict(row) for row in rows]
    }


@app.post("/api/admin/upload-knowledge")
async def upload_knowledge_file(
    file: UploadFile = File(...),
    category: str = Form("일반"),
    title: str = Form(""),
    admin: Dict = Depends(require_admin)
):
    """지식베이스 파일 업로드 (FTS5)"""
    content = await file.read()
    filename = file.filename

    # 텍스트 파일인지 확인
    try:
        text_content = content.decode('utf-8')
    except UnicodeDecodeError:
        text_content = f"Binary File: {filename} (Content not indexed)"

    title = title or filename

    conn = get_db()
    cursor = conn.cursor()

    # FTS5에 저장
    cursor.execute("""
        INSERT INTO tax_knowledge (category, title, content, keywords)
        VALUES (?, ?, ?, ?)
    """, (category, title, text_content[:10000], filename))

    # 파일 메타데이터 저장
    cursor.execute("""
        INSERT INTO uploaded_files (filename, file_type, file_size, storage_type)
        VALUES (?, ?, ?, ?)
    """, (filename, file.content_type, len(content), "fts5"))

    conn.commit()
    conn.close()

    return {"status": "success", "message": f"'{filename}' 업로드 완료", "storage": "FTS5"}


@app.get("/api/admin/uploaded-files")
async def get_uploaded_files(admin: Dict = Depends(require_admin)):
    """업로드된 파일 목록 조회"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, filename, file_type, file_size, storage_type, created_at
        FROM uploaded_files ORDER BY created_at DESC
    """)
    rows = cursor.fetchall()
    conn.close()

    return [dict(row) for row in rows]


@app.get("/api/admin/stats")
async def get_admin_stats(admin: Dict = Depends(require_admin)):
    """관리자 대시보드 통계"""
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM users")
    total_users = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM calc_history")
    total_calcs = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM consult_history")
    total_consults = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM uploaded_files")
    total_files = cursor.fetchone()[0]

    # 오늘 통계
    today = datetime.now().strftime("%Y-%m-%d")
    cursor.execute("SELECT COUNT(*) FROM users WHERE created_at LIKE ?", (f"{today}%",))
    today_users = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM calc_history WHERE created_at LIKE ?", (f"{today}%",))
    today_calcs = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM consult_history WHERE created_at LIKE ?", (f"{today}%",))
    today_consults = cursor.fetchone()[0]

    conn.close()

    return {
        "total_users": total_users,
        "total_calcs": total_calcs,
        "total_consults": total_consults,
        "total_files": total_files,
        "today_users": today_users,
        "today_calcs": today_calcs,
        "today_consults": today_consults
    }


# === 실행 ===
if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port)
