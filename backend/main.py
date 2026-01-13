"""
2025 양도소득세 AI 전문 컨설팅 플랫폼 - Backend API
Railway 배포용 - 확장 버전 (카카오 로그인, 관리자 페이지, Gemini File Search)
"""

import os
import sqlite3
import json
import secrets
import tempfile
import time
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

from jose import jwt, JWTError
import bcrypt

import google.generativeai as genai

# 환경변수 로드
load_dotenv()

# === 설정 ===
app = FastAPI(
    title="2025 양도소득세 AI API",
    description="양도소득세 계산 및 AI 세무상담 API",
    version="2.0.0"
)

# CORS 설정 - 프론트엔드 허용
FRONTEND_URL = os.getenv("FRONTEND_URL", "https://cgt.lawith.kr")

# Vercel 서브도메인 패턴을 허용하는 정규식
CORS_ORIGIN_REGEX = r"https://cgt-caculator(-[a-z0-9]+)?\.vercel\.app"

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        FRONTEND_URL,
        "https://cgt.lawith.kr",
        "https://cgt-caculator.vercel.app",
        "http://localhost:3000",
        "http://localhost:5173",
        "http://localhost:8000",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:8000",
    ],
    allow_origin_regex=CORS_ORIGIN_REGEX,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Gemini API 설정
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
if GEMINI_API_KEY and GEMINI_API_KEY != "your_gemini_api_key_here":
    genai.configure(api_key=GEMINI_API_KEY)

# 카카오 OAuth 설정
KAKAO_CLIENT_ID = os.getenv("KAKAO_CLIENT_ID", "")
KAKAO_CLIENT_SECRET = os.getenv("KAKAO_CLIENT_SECRET", "")
KAKAO_REDIRECT_URI = os.getenv("KAKAO_REDIRECT_URI", f"{FRONTEND_URL}/callback")

# JWT 설정
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", secrets.token_hex(32))
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_HOURS = 24

# 관리자 설정
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin1234")
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")

# Railway에서는 /tmp 디렉토리 사용
DB_PATH = os.getenv("DB_PATH", "/tmp/tax_knowledge.db")
USER_DB_PATH = os.getenv("USER_DB_PATH", "/tmp/users.db")

# 비밀번호 해싱 함수
def hash_password(password: str) -> str:
    """비밀번호를 bcrypt로 해싱"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    """비밀번호 검증"""
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

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


class KakaoAuthRequest(BaseModel):
    code: str = Field(..., description="카카오 인증 코드")


class UserInfoUpdate(BaseModel):
    name: Optional[str] = None
    birthdate: Optional[str] = None
    gender: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None


class AdminLoginRequest(BaseModel):
    username: str
    password: str


class UserRegisterRequest(BaseModel):
    email: str = Field(..., description="이메일 (아이디)")
    phone: str = Field(..., description="전화번호 (비밀번호)")
    name: str = Field(..., description="이름")
    birthdate: Optional[str] = Field(None, description="생년월일")
    gender: Optional[str] = Field(None, description="성별")
    agree_terms: bool = Field(..., description="약관 동의")
    agree_privacy: bool = Field(..., description="개인정보처리방침 동의")


class UserLoginRequest(BaseModel):
    email: str = Field(..., description="이메일 (아이디)")
    phone: str = Field(..., description="전화번호 (비밀번호)")


class KnowledgeEntry(BaseModel):
    category: str
    title: str
    content: str
    keywords: str


class ConsultationRequestModel(BaseModel):
    type: str = Field(..., description="상담 유형 (tax: 세무사, lawyer: 변호사)")
    name: str = Field(..., description="신청자 이름")
    phone: str = Field(..., description="연락처")
    email: Optional[str] = Field(None, description="이메일")
    preferred_date: str = Field(..., description="희망 상담일")
    content: str = Field(..., description="상담 내용")


class WebPushSubscription(BaseModel):
    endpoint: str
    keys: Dict[str, str]


# === 카카오 알림톡/메시지 설정 ===
KAKAO_ADMIN_KEY = os.getenv("KAKAO_ADMIN_KEY", "")
KAKAO_SENDER_KEY = os.getenv("KAKAO_SENDER_KEY", "")
KAKAO_TEMPLATE_CODE = os.getenv("KAKAO_TEMPLATE_CODE", "consultation_request")
ADMIN_PHONE = os.getenv("ADMIN_PHONE", "")


# === 데이터베이스 초기화 ===
def init_tax_db():
    """세무 지식 데이터베이스 초기화"""
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
        ]
        cursor.executemany(
            "INSERT INTO tax_knowledge(category, title, content, keywords) VALUES (?, ?, ?, ?)",
            knowledge_data
        )
        conn.commit()
    conn.close()


def init_user_db():
    """사용자/관리자/상담내역 데이터베이스 초기화"""
    os.makedirs(os.path.dirname(USER_DB_PATH) if os.path.dirname(USER_DB_PATH) else ".", exist_ok=True)
    conn = sqlite3.connect(USER_DB_PATH)
    cursor = conn.cursor()

    # 사용자 테이블
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            kakao_id TEXT UNIQUE,
            name TEXT,
            birthdate TEXT,
            gender TEXT,
            email TEXT,
            phone TEXT,
            nickname TEXT,
            profile_image TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # 기존 테이블에 새 컬럼 추가 (마이그레이션)
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN name TEXT")
    except:
        pass
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN birthdate TEXT")
    except:
        pass
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN gender TEXT")
    except:
        pass
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN password_hash TEXT")
    except:
        pass
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN agree_terms INTEGER DEFAULT 0")
    except:
        pass
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN agree_privacy INTEGER DEFAULT 0")
    except:
        pass

    # 관리자 테이블
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # 기본 관리자 계정 생성
    cursor.execute("SELECT count(*) FROM admins WHERE username = ?", (ADMIN_USERNAME,))
    if cursor.fetchone()[0] == 0:
        hashed = hash_password(ADMIN_PASSWORD)
        cursor.execute("INSERT INTO admins (username, password_hash) VALUES (?, ?)", (ADMIN_USERNAME, hashed))

    # 상담 내역 테이블
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS consultations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            query TEXT NOT NULL,
            context_data TEXT,
            response_html TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    # Gemini File Search Store 정보 테이블
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS file_search_stores (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            store_name TEXT NOT NULL,
            display_name TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # 업로드된 파일 정보 테이블
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS uploaded_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            file_type TEXT,
            destination TEXT,
            store_name TEXT,
            status TEXT DEFAULT 'pending',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # 대면상담 신청 테이블
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS consultation_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            type TEXT NOT NULL,
            name TEXT NOT NULL,
            phone TEXT NOT NULL,
            email TEXT,
            preferred_date TEXT NOT NULL,
            content TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            admin_note TEXT,
            kakao_sent INTEGER DEFAULT 0,
            push_sent INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    # 웹 푸시 구독 테이블
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS push_subscriptions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            endpoint TEXT NOT NULL UNIQUE,
            p256dh_key TEXT NOT NULL,
            auth_key TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    conn.commit()
    conn.close()


def search_knowledge(query: str, limit: int = 5) -> str:
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        # FTS5 특수문자 제거 (알파벳, 숫자, 한글만 유지)
        import re
        clean_query = re.sub(r'[^\w\s가-힣]', ' ', query)
        words = [w.strip() for w in clean_query.split() if w.strip()]
        if not words:
            return "검색어가 없습니다."
        search_query = ' OR '.join(words)
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


# === JWT 토큰 관리 ===
def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(hours=JWT_EXPIRE_HOURS))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def verify_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload
    except JWTError:
        return None


async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if not credentials:
        return None
    payload = verify_token(credentials.credentials)
    if not payload:
        return None
    return payload


async def require_admin(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if not credentials:
        raise HTTPException(status_code=401, detail="인증이 필요합니다")
    payload = verify_token(credentials.credentials)
    if not payload or payload.get("role") != "admin":
        raise HTTPException(status_code=403, detail="관리자 권한이 필요합니다")
    return payload


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
async def get_ai_consultation(query: str, context: Optional[Dict] = None, user_id: int = None) -> str:
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

    response_html = ""
    try:
        if not GEMINI_API_KEY or GEMINI_API_KEY == "your_gemini_api_key_here":
            response_html = generate_fallback_response(query, knowledge)
        else:
            model = genai.GenerativeModel('gemini-1.5-pro')
            response = model.generate_content(
                [system_prompt, user_message],
                generation_config=genai.GenerationConfig(temperature=0.3, max_output_tokens=4096)
            )
            response_html = response.text
    except Exception as e:
        response_html = generate_fallback_response(query, knowledge, str(e))

    # 상담 내역 저장
    try:
        conn = sqlite3.connect(USER_DB_PATH)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO consultations (user_id, query, context_data, response_html) VALUES (?, ?, ?, ?)",
            (user_id, query, json.dumps(context) if context else None, response_html)
        )
        conn.commit()
        conn.close()
    except Exception:
        pass

    return response_html


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
    init_tax_db()
    init_user_db()


@app.get("/")
async def root():
    return {"status": "healthy", "service": "2025 양도소득세 AI API", "version": "2.0.0"}


@app.get("/api/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}


@app.post("/api/calculate")
async def calculate_endpoint(req: CalcRequest):
    result = calculate_cgt(req)
    return JSONResponse(content=result)


@app.post("/api/consult")
async def consult_endpoint(req: ConsultRequest, user: dict = Depends(get_current_user)):
    try:
        user_id = user.get("user_id") if user else None
        report_html = await get_ai_consultation(req.query, req.context_data, user_id)
        return JSONResponse(content={
            "status": "success",
            "html": report_html,
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# === 카카오 OAuth ===
@app.get("/api/auth/kakao/url")
async def get_kakao_auth_url():
    """카카오 로그인 URL 반환"""
    if not KAKAO_CLIENT_ID:
        raise HTTPException(status_code=500, detail="카카오 클라이언트 ID가 설정되지 않았습니다")

    auth_url = f"https://kauth.kakao.com/oauth/authorize?client_id={KAKAO_CLIENT_ID}&redirect_uri={KAKAO_REDIRECT_URI}&response_type=code&scope=profile_nickname,account_email"
    return {"auth_url": auth_url}


@app.post("/api/auth/kakao/callback")
async def kakao_callback(req: KakaoAuthRequest):
    """카카오 인증 코드로 로그인/회원가입 처리"""
    if not KAKAO_CLIENT_ID:
        raise HTTPException(status_code=500, detail="카카오 설정이 완료되지 않았습니다")

    async with httpx.AsyncClient() as client:
        # 토큰 발급
        token_response = await client.post(
            "https://kauth.kakao.com/oauth/token",
            data={
                "grant_type": "authorization_code",
                "client_id": KAKAO_CLIENT_ID,
                "client_secret": KAKAO_CLIENT_SECRET,
                "redirect_uri": KAKAO_REDIRECT_URI,
                "code": req.code,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )

        if token_response.status_code != 200:
            raise HTTPException(status_code=400, detail="카카오 토큰 발급 실패")

        tokens = token_response.json()
        access_token = tokens.get("access_token")

        # 사용자 정보 조회
        user_response = await client.get(
            "https://kapi.kakao.com/v2/user/me",
            headers={"Authorization": f"Bearer {access_token}"}
        )

        if user_response.status_code != 200:
            raise HTTPException(status_code=400, detail="카카오 사용자 정보 조회 실패")

        kakao_user = user_response.json()
        kakao_id = str(kakao_user.get("id"))
        kakao_account = kakao_user.get("kakao_account", {})
        profile = kakao_account.get("profile", {})

        nickname = profile.get("nickname", "")
        profile_image = profile.get("profile_image_url", "")
        email = kakao_account.get("email", "")

        # DB에 사용자 저장/업데이트
        conn = sqlite3.connect(USER_DB_PATH)
        cursor = conn.cursor()

        cursor.execute("SELECT id, email, phone FROM users WHERE kakao_id = ?", (kakao_id,))
        existing = cursor.fetchone()

        if existing:
            user_id = existing[0]
            cursor.execute(
                "UPDATE users SET nickname = ?, profile_image = ?, updated_at = ? WHERE id = ?",
                (nickname, profile_image, datetime.now().isoformat(), user_id)
            )
            email = existing[1] or email
            phone = existing[2]
        else:
            cursor.execute(
                "INSERT INTO users (kakao_id, email, nickname, profile_image) VALUES (?, ?, ?, ?)",
                (kakao_id, email, nickname, profile_image)
            )
            user_id = cursor.lastrowid
            phone = None

        conn.commit()
        conn.close()

        # JWT 토큰 발급
        jwt_token = create_access_token({
            "user_id": user_id,
            "kakao_id": kakao_id,
            "nickname": nickname,
            "role": "user"
        })

        # 추가 정보 필요 여부 확인
        needs_additional_info = not email or not phone

        return {
            "status": "success",
            "token": jwt_token,
            "user": {
                "id": user_id,
                "nickname": nickname,
                "profile_image": profile_image,
                "email": email,
                "phone": phone,
                "needs_additional_info": needs_additional_info
            }
        }


@app.post("/api/auth/register")
async def register_user(req: UserRegisterRequest):
    """일반 회원가입 (이메일 + 전화번호)"""
    if not req.agree_terms or not req.agree_privacy:
        raise HTTPException(status_code=400, detail="약관 및 개인정보처리방침에 동의해야 합니다")

    conn = sqlite3.connect(USER_DB_PATH)
    cursor = conn.cursor()

    # 이메일 중복 확인
    cursor.execute("SELECT id FROM users WHERE email = ?", (req.email,))
    if cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=400, detail="이미 등록된 이메일입니다")

    # 비밀번호 해싱 (전화번호를 비밀번호로 사용)
    password_hash = hash_password(req.phone)

    # 사용자 등록
    cursor.execute("""
        INSERT INTO users (email, phone, name, birthdate, gender, nickname, password_hash, agree_terms, agree_privacy)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (req.email, req.phone, req.name, req.birthdate, req.gender, req.name, password_hash, 1, 1))

    user_id = cursor.lastrowid
    conn.commit()
    conn.close()

    # JWT 토큰 발급
    jwt_token = create_access_token({
        "user_id": user_id,
        "email": req.email,
        "nickname": req.name,
        "role": "user"
    })

    return {
        "status": "success",
        "message": "회원가입이 완료되었습니다",
        "token": jwt_token,
        "user": {
            "id": user_id,
            "email": req.email,
            "name": req.name,
            "nickname": req.name,
            "phone": req.phone,
            "birthdate": req.birthdate,
            "gender": req.gender
        }
    }


@app.post("/api/auth/login")
async def login_user(req: UserLoginRequest):
    """일반 로그인 (이메일 + 전화번호)"""
    conn = sqlite3.connect(USER_DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, email, name, nickname, phone, birthdate, gender, password_hash, profile_image
        FROM users WHERE email = ?
    """, (req.email,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        raise HTTPException(status_code=401, detail="등록되지 않은 이메일입니다")

    user_id, email, name, nickname, phone, birthdate, gender, password_hash, profile_image = row

    # 비밀번호 확인 (전화번호)
    if not password_hash:
        # 카카오로 가입한 사용자 - 전화번호 직접 비교
        if phone != req.phone:
            raise HTTPException(status_code=401, detail="전화번호가 일치하지 않습니다")
    else:
        # 일반 회원가입 사용자 - 해시 비교
        if not verify_password(req.phone, password_hash):
            raise HTTPException(status_code=401, detail="전화번호가 일치하지 않습니다")

    # JWT 토큰 발급
    jwt_token = create_access_token({
        "user_id": user_id,
        "email": email,
        "nickname": nickname or name,
        "role": "user"
    })

    return {
        "status": "success",
        "token": jwt_token,
        "user": {
            "id": user_id,
            "email": email,
            "name": name,
            "nickname": nickname or name,
            "phone": phone,
            "birthdate": birthdate,
            "gender": gender,
            "profile_image": profile_image
        }
    }


@app.put("/api/user/info")
async def update_user_info(req: UserInfoUpdate, user: dict = Depends(get_current_user)):
    """사용자 정보 업데이트"""
    if not user:
        raise HTTPException(status_code=401, detail="로그인이 필요합니다")

    user_id = user.get("user_id")

    conn = sqlite3.connect(USER_DB_PATH)
    cursor = conn.cursor()

    updates = []
    values = []
    if req.name:
        updates.append("name = ?")
        values.append(req.name)
    if req.birthdate:
        updates.append("birthdate = ?")
        values.append(req.birthdate)
    if req.gender:
        updates.append("gender = ?")
        values.append(req.gender)
    if req.email:
        updates.append("email = ?")
        values.append(req.email)
    if req.phone:
        updates.append("phone = ?")
        values.append(req.phone)

    if updates:
        updates.append("updated_at = ?")
        values.append(datetime.now().isoformat())
        values.append(user_id)

        cursor.execute(f"UPDATE users SET {', '.join(updates)} WHERE id = ?", values)
        conn.commit()

    conn.close()

    return {"status": "success", "message": "회원정보가 업데이트되었습니다"}


@app.get("/api/user/me")
async def get_my_info(user: dict = Depends(get_current_user)):
    """현재 로그인한 사용자 정보 조회"""
    if not user:
        raise HTTPException(status_code=401, detail="로그인이 필요합니다")

    user_id = user.get("user_id")

    conn = sqlite3.connect(USER_DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id, kakao_id, name, birthdate, gender, email, phone, nickname, profile_image FROM users WHERE id = ?", (user_id,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        raise HTTPException(status_code=404, detail="사용자를 찾을 수 없습니다")

    return {
        "id": row[0],
        "kakao_id": row[1],
        "name": row[2],
        "birthdate": row[3],
        "gender": row[4],
        "email": row[5],
        "phone": row[6],
        "nickname": row[7],
        "profile_image": row[8]
    }


# === 관리자 API ===
@app.post("/api/admin/login")
async def admin_login(req: AdminLoginRequest):
    """관리자 로그인"""
    conn = sqlite3.connect(USER_DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id, password_hash FROM admins WHERE username = ?", (req.username,))
    row = cursor.fetchone()
    conn.close()

    if not row or not verify_password(req.password, row[1]):
        raise HTTPException(status_code=401, detail="아이디 또는 비밀번호가 올바르지 않습니다")

    token = create_access_token({
        "admin_id": row[0],
        "username": req.username,
        "role": "admin"
    })

    return {"status": "success", "token": token}


@app.get("/api/admin/users")
async def get_users(admin: dict = Depends(require_admin)):
    """회원 목록 조회"""
    conn = sqlite3.connect(USER_DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, kakao_id, name, birthdate, gender, email, phone, nickname, profile_image, created_at
        FROM users ORDER BY created_at DESC
    """)
    rows = cursor.fetchall()
    conn.close()

    return {
        "users": [
            {
                "id": r[0], "kakao_id": r[1], "name": r[2], "birthdate": r[3], "gender": r[4],
                "email": r[5], "phone": r[6], "nickname": r[7], "profile_image": r[8], "created_at": r[9]
            }
            for r in rows
        ]
    }


@app.get("/api/admin/consultations")
async def get_consultations(admin: dict = Depends(require_admin), limit: int = 100):
    """상담 내역 조회"""
    conn = sqlite3.connect(USER_DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT c.id, c.user_id, u.nickname, c.query, c.response_html, c.created_at
        FROM consultations c
        LEFT JOIN users u ON c.user_id = u.id
        ORDER BY c.created_at DESC
        LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    conn.close()

    return {
        "consultations": [
            {
                "id": r[0], "user_id": r[1], "nickname": r[2] or "비회원",
                "query": r[3], "response_html": r[4], "created_at": r[5]
            }
            for r in rows
        ]
    }


@app.get("/api/admin/knowledge")
async def get_knowledge_entries(admin: dict = Depends(require_admin)):
    """지식 데이터베이스 목록 조회"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT rowid, category, title, content, keywords FROM tax_knowledge")
    rows = cursor.fetchall()
    conn.close()

    return {
        "entries": [
            {"id": r[0], "category": r[1], "title": r[2], "content": r[3], "keywords": r[4]}
            for r in rows
        ]
    }


@app.post("/api/admin/knowledge")
async def add_knowledge_entry(entry: KnowledgeEntry, admin: dict = Depends(require_admin)):
    """지식 데이터베이스에 항목 추가"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO tax_knowledge (category, title, content, keywords) VALUES (?, ?, ?, ?)",
        (entry.category, entry.title, entry.content, entry.keywords)
    )
    entry_id = cursor.lastrowid
    conn.commit()
    conn.close()

    return {"status": "success", "id": entry_id}


@app.delete("/api/admin/knowledge/{entry_id}")
async def delete_knowledge_entry(entry_id: int, admin: dict = Depends(require_admin)):
    """지식 데이터베이스 항목 삭제"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM tax_knowledge WHERE rowid = ?", (entry_id,))
    conn.commit()
    conn.close()

    return {"status": "success"}


@app.post("/api/admin/knowledge/upload")
async def upload_knowledge_file(
    file: UploadFile = File(...),
    admin: dict = Depends(require_admin)
):
    """마크다운/텍스트 파일을 FTS5에 업로드"""
    filename = file.filename
    content = await file.read()

    # 텍스트 파일인지 확인
    try:
        text_content = content.decode('utf-8')
    except UnicodeDecodeError:
        return {
            "status": "error",
            "message": "텍스트 파일만 FTS5에 업로드할 수 있습니다. 바이너리 파일은 Gemini File Search를 사용해주세요."
        }

    # FTS5에 저장
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # 파일명에서 카테고리 추출 (예: "비과세_일시적2주택.md" -> "비과세")
    category = filename.split('_')[0] if '_' in filename else "일반"
    title = filename.rsplit('.', 1)[0]  # 확장자 제거

    cursor.execute(
        "INSERT INTO tax_knowledge (category, title, content, keywords) VALUES (?, ?, ?, ?)",
        (category, title, text_content, title.replace('_', ' '))
    )
    conn.commit()
    conn.close()

    # 업로드 기록 저장
    conn = sqlite3.connect(USER_DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO uploaded_files (filename, file_type, destination, status) VALUES (?, ?, ?, ?)",
        (filename, "text", "fts5", "completed")
    )
    conn.commit()
    conn.close()

    return {"status": "success", "message": f"'{filename}'이(가) FTS5에 추가되었습니다."}


@app.post("/api/admin/gemini/upload")
async def upload_to_gemini_file_search(
    file: UploadFile = File(...),
    store_name: str = Form("Lawith_Tax_Store"),
    admin: dict = Depends(require_admin)
):
    """Gemini File Search Store에 파일 업로드"""
    if not GEMINI_API_KEY or GEMINI_API_KEY == "your_gemini_api_key_here":
        raise HTTPException(status_code=500, detail="Gemini API Key가 설정되지 않았습니다")

    filename = file.filename
    content = await file.read()

    # 파일 크기 체크 (100MB 제한)
    if len(content) > 100 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="파일 크기는 100MB를 초과할 수 없습니다")

    # 임시 파일로 저장
    with tempfile.NamedTemporaryFile(delete=False, suffix=f"_{filename}") as tmp:
        tmp.write(content)
        tmp_path = tmp.name

    try:
        # google-genai 패키지 사용 (새로운 API)
        try:
            from google import genai as genai_new
            from google.genai import types

            client = genai_new.Client(api_key=GEMINI_API_KEY)

            # File Search Store 생성 또는 기존 것 사용
            file_search_store = client.file_search_stores.create(
                config={'display_name': store_name}
            )

            # 파일 업로드
            operation = client.file_search_stores.upload_to_file_search_store(
                file=tmp_path,
                file_search_store_name=file_search_store.name,
                config={'display_name': filename}
            )

            # 업로드 완료 대기
            max_wait = 60  # 최대 60초 대기
            waited = 0
            while not operation.done and waited < max_wait:
                time.sleep(2)
                operation = client.operations.get(operation)
                waited += 2

            gemini_store_name = file_search_store.name

        except ImportError:
            # google-genai가 없으면 기존 방식으로 파일 업로드만 수행
            uploaded_file = genai.upload_file(tmp_path, display_name=filename)
            gemini_store_name = f"legacy_{uploaded_file.name}"

        # 업로드 기록 저장
        conn = sqlite3.connect(USER_DB_PATH)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO uploaded_files (filename, file_type, destination, store_name, status) VALUES (?, ?, ?, ?, ?)",
            (filename, file.content_type or "unknown", "gemini", gemini_store_name, "completed")
        )

        # Store 정보 저장
        cursor.execute(
            "INSERT OR IGNORE INTO file_search_stores (store_name, display_name) VALUES (?, ?)",
            (gemini_store_name, store_name)
        )
        conn.commit()
        conn.close()

        return {
            "status": "success",
            "message": f"'{filename}'이(가) Gemini File Search Store에 업로드되었습니다.",
            "store_name": gemini_store_name
        }

    except Exception as e:
        # 실패 기록
        conn = sqlite3.connect(USER_DB_PATH)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO uploaded_files (filename, file_type, destination, status) VALUES (?, ?, ?, ?)",
            (filename, file.content_type or "unknown", "gemini", f"failed: {str(e)}")
        )
        conn.commit()
        conn.close()

        raise HTTPException(status_code=500, detail=f"Gemini 업로드 실패: {str(e)}")

    finally:
        # 임시 파일 삭제
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)


@app.get("/api/admin/gemini/stores")
async def get_gemini_stores(admin: dict = Depends(require_admin)):
    """Gemini File Search Store 목록 조회"""
    conn = sqlite3.connect(USER_DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT store_name, display_name, created_at FROM file_search_stores ORDER BY created_at DESC")
    rows = cursor.fetchall()
    conn.close()

    return {
        "stores": [
            {"store_name": r[0], "display_name": r[1], "created_at": r[2]}
            for r in rows
        ]
    }


@app.get("/api/admin/uploads")
async def get_uploaded_files(admin: dict = Depends(require_admin)):
    """업로드된 파일 목록 조회"""
    conn = sqlite3.connect(USER_DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, filename, file_type, destination, store_name, status, created_at
        FROM uploaded_files ORDER BY created_at DESC
    """)
    rows = cursor.fetchall()
    conn.close()

    return {
        "files": [
            {
                "id": r[0], "filename": r[1], "file_type": r[2], "destination": r[3],
                "store_name": r[4], "status": r[5], "created_at": r[6]
            }
            for r in rows
        ]
    }


# === 대면상담 신청 API ===
async def send_kakao_alimtalk(phone: str, name: str, consultation_type: str, preferred_date: str, content: str) -> bool:
    """카카오 알림톡 발송"""
    if not KAKAO_ADMIN_KEY or not KAKAO_SENDER_KEY:
        print("카카오 알림톡 설정이 없습니다. 발송을 건너뜁니다.")
        return False

    type_name = "세무사" if consultation_type == "tax" else "변호사"
    message = f"""[대면상담 신청 알림]

신청자: {name}
상담유형: {type_name} 대면상담
희망일자: {preferred_date}
연락처: {phone}
상담내용: {content[:100]}{'...' if len(content) > 100 else ''}

빠른 시일 내에 연락드리겠습니다."""

    try:
        async with httpx.AsyncClient() as client:
            # 카카오 알림톡 API 호출
            response = await client.post(
                "https://kapi.kakao.com/v2/api/talk/memo/default/send",
                headers={
                    "Authorization": f"KakaoAK {KAKAO_ADMIN_KEY}",
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                data={
                    "template_object": json.dumps({
                        "object_type": "text",
                        "text": message,
                        "link": {
                            "web_url": FRONTEND_URL,
                            "mobile_web_url": FRONTEND_URL
                        }
                    })
                }
            )
            return response.status_code == 200
    except Exception as e:
        print(f"카카오 알림톡 발송 실패: {e}")
        return False


async def send_kakao_message_to_admin(name: str, consultation_type: str, preferred_date: str, phone: str, content: str) -> bool:
    """관리자에게 카카오톡 메시지 발송"""
    if not KAKAO_ADMIN_KEY:
        print("카카오 관리자 키가 설정되지 않았습니다.")
        return False

    type_name = "세무사" if consultation_type == "tax" else "변호사"
    message = f"""🔔 새 대면상담 신청

📋 유형: {type_name} 상담
👤 신청자: {name}
📞 연락처: {phone}
📅 희망일: {preferred_date}
📝 내용: {content[:80]}{'...' if len(content) > 80 else ''}

관리자 페이지에서 확인하세요."""

    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                "https://kapi.kakao.com/v2/api/talk/memo/default/send",
                headers={
                    "Authorization": f"KakaoAK {KAKAO_ADMIN_KEY}",
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                data={
                    "template_object": json.dumps({
                        "object_type": "text",
                        "text": message,
                        "link": {
                            "web_url": f"{FRONTEND_URL}/admin.html",
                            "mobile_web_url": f"{FRONTEND_URL}/admin.html"
                        }
                    })
                }
            )
            return response.status_code == 200
    except Exception as e:
        print(f"카카오 메시지 발송 실패: {e}")
        return False


async def send_web_push_to_admins(title: str, body: str, url: str = None) -> int:
    """관리자에게 웹 푸시 알림 발송"""
    conn = sqlite3.connect(USER_DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT endpoint, p256dh_key, auth_key FROM push_subscriptions WHERE is_admin = 1")
    subscriptions = cursor.fetchall()
    conn.close()

    if not subscriptions:
        print("등록된 관리자 푸시 구독이 없습니다.")
        return 0

    success_count = 0
    payload = json.dumps({
        "title": title,
        "body": body,
        "icon": "/favicon.ico",
        "url": url or f"{FRONTEND_URL}/admin.html"
    })

    # 웹 푸시는 pywebpush 라이브러리가 필요하지만,
    # 간단한 구현을 위해 여기서는 기록만 남김
    print(f"웹 푸시 발송 대상: {len(subscriptions)}명")
    for sub in subscriptions:
        try:
            # pywebpush 사용 시:
            # from pywebpush import webpush
            # webpush(
            #     subscription_info={"endpoint": sub[0], "keys": {"p256dh": sub[1], "auth": sub[2]}},
            #     data=payload,
            #     vapid_private_key=VAPID_PRIVATE_KEY,
            #     vapid_claims={"sub": f"mailto:{ADMIN_EMAIL}"}
            # )
            success_count += 1
        except Exception as e:
            print(f"푸시 발송 실패: {e}")

    return success_count


@app.post("/api/consultation/request")
async def request_consultation(req: ConsultationRequestModel, user: dict = Depends(get_current_user)):
    """대면상담 신청"""
    user_id = user.get("user_id") if user else None

    # 데이터베이스에 저장
    conn = sqlite3.connect(USER_DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO consultation_requests (user_id, type, name, phone, email, preferred_date, content)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (user_id, req.type, req.name, req.phone, req.email, req.preferred_date, req.content))
    request_id = cursor.lastrowid
    conn.commit()

    # 알림 발송 상태
    kakao_sent = False
    push_sent = 0

    # 1. 신청자에게 카카오 알림톡 발송
    kakao_sent = await send_kakao_alimtalk(
        phone=req.phone,
        name=req.name,
        consultation_type=req.type,
        preferred_date=req.preferred_date,
        content=req.content
    )

    # 2. 관리자에게 카카오 메시지 발송
    await send_kakao_message_to_admin(
        name=req.name,
        consultation_type=req.type,
        preferred_date=req.preferred_date,
        phone=req.phone,
        content=req.content
    )

    # 3. 관리자에게 웹 푸시 발송
    type_name = "세무사" if req.type == "tax" else "변호사"
    push_sent = await send_web_push_to_admins(
        title=f"새 {type_name} 상담 신청",
        body=f"{req.name}님이 {req.preferred_date} 상담을 신청했습니다.",
        url=f"{FRONTEND_URL}/admin.html"
    )

    # 발송 상태 업데이트
    cursor.execute("""
        UPDATE consultation_requests SET kakao_sent = ?, push_sent = ? WHERE id = ?
    """, (1 if kakao_sent else 0, push_sent, request_id))
    conn.commit()
    conn.close()

    return {
        "status": "success",
        "message": "상담 신청이 완료되었습니다.",
        "request_id": request_id,
        "notifications": {
            "kakao_sent": kakao_sent,
            "push_sent": push_sent
        }
    }


@app.get("/api/admin/consultation-requests")
async def get_consultation_requests(admin: dict = Depends(require_admin), limit: int = 100):
    """대면상담 신청 목록 조회"""
    conn = sqlite3.connect(USER_DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, user_id, type, name, phone, email, preferred_date, content,
               status, admin_note, kakao_sent, push_sent, created_at
        FROM consultation_requests
        ORDER BY created_at DESC
        LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    conn.close()

    return {
        "requests": [
            {
                "id": r[0], "user_id": r[1], "type": r[2], "name": r[3],
                "phone": r[4], "email": r[5], "preferred_date": r[6],
                "content": r[7], "status": r[8], "admin_note": r[9],
                "kakao_sent": bool(r[10]), "push_sent": r[11], "created_at": r[12]
            }
            for r in rows
        ]
    }


@app.put("/api/admin/consultation-requests/{request_id}")
async def update_consultation_request(
    request_id: int,
    status: str = Form(...),
    admin_note: str = Form(None),
    admin: dict = Depends(require_admin)
):
    """대면상담 신청 상태 업데이트"""
    conn = sqlite3.connect(USER_DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE consultation_requests
        SET status = ?, admin_note = ?, updated_at = ?
        WHERE id = ?
    """, (status, admin_note, datetime.now().isoformat(), request_id))
    conn.commit()
    conn.close()

    return {"status": "success", "message": "상담 신청이 업데이트되었습니다."}


@app.post("/api/push/subscribe")
async def subscribe_push(subscription: WebPushSubscription, user: dict = Depends(get_current_user)):
    """웹 푸시 구독 등록"""
    user_id = user.get("user_id") if user else None
    is_admin = 1 if user and user.get("role") == "admin" else 0

    conn = sqlite3.connect(USER_DB_PATH)
    cursor = conn.cursor()

    try:
        cursor.execute("""
            INSERT OR REPLACE INTO push_subscriptions (user_id, endpoint, p256dh_key, auth_key, is_admin)
            VALUES (?, ?, ?, ?, ?)
        """, (user_id, subscription.endpoint, subscription.keys.get("p256dh", ""), subscription.keys.get("auth", ""), is_admin))
        conn.commit()
    except Exception as e:
        conn.close()
        raise HTTPException(status_code=500, detail=f"구독 등록 실패: {str(e)}")

    conn.close()
    return {"status": "success", "message": "푸시 알림이 등록되었습니다."}


# === 실행 ===
if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port)
