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

# Perplexity AI API 설정
PERPLEXITY_API_KEY = os.getenv("PERPLEXITY_API_KEY", "")

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


# ============================================
# === 검색 파이프라인 2.0 (Search Pipeline 2.0) ===
# ============================================
# 3가지 검색을 병렬 실행:
# 1. FTS5 스마트 키워드 검색 (Multi-Query)
# 2. Gemini File Search 시멘틱 검색
# 3. Perplexity AI 웹검색 (법령 검증)

# 토큰 제한 설정 (Transient Context Buffer)
MAX_CONTEXT_CHARS = 30000  # 최대 문맥 버퍼 크기


def search_knowledge(query: str, limit: int = 5) -> str:
    """FTS5 키워드 검색 (기본)"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        import re
        clean_query = re.sub(r'[^\w\s가-힣]', ' ', query)
        words = [w.strip() for w in clean_query.split() if w.strip()]
        if not words:
            return ""
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
        return ""
    except Exception as e:
        return f"검색 오류: {str(e)}"


def search_fts5_with_optimized_query(query_string: str, limit: int = 10) -> List[tuple]:
    """
    FTS5 최적화 쿼리로 검색 (OR, NEAR, 접두사 지원)
    """
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT title, content FROM tax_knowledge
            WHERE tax_knowledge MATCH ?
            ORDER BY rank LIMIT ?
        """, (query_string, limit))
        results = cursor.fetchall()
        conn.close()
        return results
    except Exception as e:
        print(f"FTS5 검색 오류: {e}")
        return []


def search_knowledge_multi_query(queries: List[str], limit: int = 10) -> str:
    """
    Multi-Query FTS5 검색: 여러 쿼리를 실행하고 결과를 중복 제거 후 통합
    Transient Context Buffer 방식으로 메모리에서 처리
    """
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        import re

        # 중복 제거를 위한 Set (title 기준)
        seen_titles = set()
        all_results = []
        total_chars = 0

        for query in queries:
            # 특수문자 제거 (FTS5 연산자 제외)
            clean_query = re.sub(r'[^\w\s가-힣*]', ' ', query)
            words = [w.strip() for w in clean_query.split() if w.strip()]
            if not words:
                continue

            # OR 연산자로 결합
            search_query = ' OR '.join(words)

            try:
                cursor.execute("""
                    SELECT title, content FROM tax_knowledge
                    WHERE tax_knowledge MATCH ?
                    ORDER BY rank LIMIT ?
                """, (search_query, limit // len(queries) + 2))
                results = cursor.fetchall()

                for title, content in results:
                    # 중복 제거
                    if title in seen_titles:
                        continue

                    # 토큰 제한 체크
                    content_len = len(content)
                    if total_chars + content_len > MAX_CONTEXT_CHARS:
                        break

                    seen_titles.add(title)
                    all_results.append((title, content))
                    total_chars += content_len

            except Exception as e:
                print(f"쿼리 '{search_query}' 검색 오류: {e}")
                continue

            # 토큰 제한 도달 시 중단
            if total_chars >= MAX_CONTEXT_CHARS:
                break

        conn.close()

        if all_results:
            return "\n\n".join([f"### {t}\n{c}" for t, c in all_results[:limit]])
        return ""
    except Exception as e:
        return f"검색 오류: {str(e)}"


async def generate_optimized_queries(query: str, time_context: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    [1단계] AI 쿼리 최적화 - Multi-Query 생성
    - 사용자 질문을 분석하여 3~5개의 최적화된 검색 쿼리 생성
    - 동의어 확장, 법률용어 확장, 시점 분석 포함
    """
    if not GEMINI_API_KEY or GEMINI_API_KEY == "your_gemini_api_key_here":
        import re
        words = [w for w in re.sub(r'[^\w\s가-힣]', ' ', query).split() if w.strip()]
        return {
            "original_query": query,
            "intent": "양도소득세 관련 문의",
            "issues": [query],
            "reformulated_query": query,
            "time_context": {"applicable_date": None, "law_version": "현행법"},
            "fts5_queries": [' OR '.join(words[:5])],
            "semantic_query": query,
            "perplexity_query": query,
            "keywords": words[:5],
            "expanded_keywords": words[:5]
        }

    analysis_prompt = """당신은 양도소득세 전문 법률 검색 분석가입니다.
이용자의 질문을 분석하여 최적의 검색 전략을 수립하세요.

## 핵심 분석 항목

### 1. 시점 분석 (매우 중요!)
- 양도일, 취득일이 언제인지 파악
- 어느 시점의 법령을 적용해야 하는지 확정
- 해당 기간에 법령 개정이 있었는지 확인 필요 여부

### 2. 의도 및 쟁점 분석
- 이용자가 원하는 목적과 궁금한 점
- 핵심 쟁점들 (최대 3개)
- 명확하게 정리된 질문

### 3. FTS5 최적화 쿼리 생성 (3~5개)
각 쿼리는 다른 각도에서 검색하도록 설계:
- 쿼리1: 핵심 법률용어 조합 (예: "비과세 OR 면세 OR 과세제외")
- 쿼리2: 구체적 정황 기반 (예: "1세대1주택 OR 1가구1주택 OR 단독주택")
- 쿼리3: 관련 조문/규정 (예: "소득세법 OR 시행령 OR 제89조")
- 쿼리4: 동의어/유사어 확장 (예: "장특공제 OR 장기보유특별공제 OR 보유공제")
- 쿼리5: 특수 상황/예외 (예: "조정대상지역 OR 투기과열지구 OR 중과")

### 4. Perplexity 웹검색 쿼리
- 법령 검증을 위한 검색어 (시점 정보 포함)
- 예: "2024년 양도소득세 1세대1주택 비과세 요건 소득세법 개정"

## 양도소득세 핵심 동의어 사전
- 비과세: 면세, 세금면제, 과세제외, 비과세요건
- 1세대1주택: 1가구1주택, 단독주택자, 1주택자, 단일주택
- 장기보유특별공제: 장특공제, 장기보유공제, 보유기간공제
- 양도차익: 양도차액, 양도이익, 매매차익, 시세차익
- 취득가액: 취득원가, 매입가, 구입가격, 취득비용
- 조정대상지역: 투기과열지구, 조정지역, 규제지역
- 다주택자: 2주택자, 3주택자, 다주택, 복수주택
- 일시적2주택: 이사목적, 대체취득, 종전주택, 신규주택
- 중과세: 중과, 추가세율, 가산세율, 중과배제

## 응답 형식 (JSON만 출력)
```json
{
  "intent": "이용자의 목적 (2-3문장)",
  "issues": ["쟁점1", "쟁점2", "쟁점3"],
  "reformulated_query": "정리된 질문",
  "time_context": {
    "applicable_date": "적용 기준일 (YYYY-MM-DD 또는 null)",
    "law_version": "적용 법령 버전 설명",
    "needs_amendment_check": true/false
  },
  "fts5_queries": [
    "쿼리1 (핵심 법률용어)",
    "쿼리2 (구체적 정황)",
    "쿼리3 (관련 조문)",
    "쿼리4 (동의어 확장)",
    "쿼리5 (특수 상황)"
  ],
  "semantic_query": "시멘틱 검색용 자연어 질문",
  "perplexity_query": "웹검색용 쿼리 (시점+법령+핵심어)",
  "keywords": ["키워드1", "키워드2"],
  "expanded_keywords": ["확장키워드1", "확장키워드2", ...]
}
```

이용자 질문: """ + query

    if time_context:
        analysis_prompt += f"\n\n추가 시점 정보: {json.dumps(time_context, ensure_ascii=False)}"

    try:
        model = genai.GenerativeModel('gemini-1.5-flash')
        response = model.generate_content(
            analysis_prompt,
            generation_config=genai.GenerationConfig(
                temperature=0.1,
                max_output_tokens=2048
            )
        )

        response_text = response.text
        import re
        json_match = re.search(r'```json\s*(.*?)\s*```', response_text, re.DOTALL)
        if json_match:
            json_str = json_match.group(1)
        else:
            json_match = re.search(r'\{.*\}', response_text, re.DOTALL)
            json_str = json_match.group(0) if json_match else "{}"

        analysis = json.loads(json_str)
        analysis["original_query"] = query
        return analysis

    except Exception as e:
        print(f"쿼리 최적화 오류: {e}")
        import re
        words = [w for w in re.sub(r'[^\w\s가-힣]', ' ', query).split() if w.strip()]
        return {
            "original_query": query,
            "intent": "양도소득세 관련 문의",
            "issues": [query],
            "reformulated_query": query,
            "time_context": {"applicable_date": None, "law_version": "현행법"},
            "fts5_queries": [' OR '.join(words[:5])],
            "semantic_query": query,
            "perplexity_query": query,
            "keywords": words[:5],
            "expanded_keywords": words[:5]
        }


async def search_perplexity(query: str, time_context: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Perplexity AI 웹검색 API 호출
    - 최신 법령 정보 검색 및 검증
    - 시점별 법령 개정 여부 확인
    """
    if not PERPLEXITY_API_KEY:
        return {
            "status": "skip",
            "message": "Perplexity API 키가 설정되지 않았습니다",
            "result": ""
        }

    # 시점 정보를 쿼리에 포함
    enhanced_query = query
    if time_context and time_context.get("applicable_date"):
        date = time_context["applicable_date"]
        enhanced_query = f"{query} (적용 시점: {date}, 해당 시점의 법령과 세율 기준으로 검색)"

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                "https://api.perplexity.ai/chat/completions",
                headers={
                    "Authorization": f"Bearer {PERPLEXITY_API_KEY}",
                    "Content-Type": "application/json"
                },
                json={
                    "model": "llama-3.1-sonar-small-128k-online",
                    "messages": [
                        {
                            "role": "system",
                            "content": """당신은 한국 양도소득세 법령 전문가입니다.
질문에 대해 다음을 반드시 확인하고 답변하세요:
1. 적용되는 법령의 시점 (언제의 법령을 적용해야 하는지)
2. 해당 시점에 법령 개정이 있었는지 여부
3. 현행 법령과의 차이점
4. 관련 법령 조문 번호 (소득세법, 시행령, 시행규칙)
5. 명확한 결론과 법적 근거

반드시 출처와 법령 조문을 인용하세요."""
                        },
                        {
                            "role": "user",
                            "content": enhanced_query
                        }
                    ],
                    "temperature": 0.1,
                    "max_tokens": 2000
                }
            )

            if response.status_code == 200:
                data = response.json()
                result_text = data.get("choices", [{}])[0].get("message", {}).get("content", "")
                return {
                    "status": "success",
                    "result": result_text,
                    "citations": data.get("citations", [])
                }
            else:
                return {
                    "status": "error",
                    "message": f"API 오류: {response.status_code}",
                    "result": ""
                }

    except Exception as e:
        return {
            "status": "error",
            "message": f"Perplexity 검색 오류: {str(e)}",
            "result": ""
        }


async def analyze_query_with_ai(query: str) -> Dict[str, Any]:
    """
    [1단계] AI가 이용자 질문을 분석하여 의도, 쟁점, 키워드를 추출
    - 이용자가 원하는 목적 파악
    - 핵심 쟁점 확정
    - 질문을 명확한 문장으로 정리
    - 키워드 추출 및 동의어 확장
    """
    if not GEMINI_API_KEY or GEMINI_API_KEY == "your_gemini_api_key_here":
        import re
        words = [w for w in re.sub(r'[^\w\s가-힣]', ' ', query).split() if w.strip()]
        return {
            "original_query": query,
            "intent": "양도소득세 관련 문의",
            "issues": [query],
            "reformulated_query": query,
            "keywords": words[:5],
            "expanded_keywords": words[:5]
        }

    analysis_prompt = """당신은 양도소득세 전문 분석가입니다.
이용자의 질문을 분석하여 다음 정보를 JSON 형식으로 추출하세요.

## 분석 항목
1. intent: 이용자가 원하는 목적과 궁금한 점 (2-3문장으로 상세히)
2. issues: 핵심 쟁점들 (리스트, 최대 3개)
3. reformulated_query: 명확하게 정리된 질문 (한 문장)
4. keywords: 검색에 사용할 핵심 키워드 (리스트, 최대 5개)
5. expanded_keywords: 동의어와 관련어를 포함한 확장 키워드 (리스트, 최대 15개)

## 양도소득세 관련 주요 동의어/관련어 참고
- 비과세: 면세, 세금면제, 과세제외, 비과세요건, 세금안냄
- 1세대1주택: 1가구1주택, 단독주택자, 1주택자, 단일주택, 일주택
- 장기보유특별공제: 장특공제, 장기보유공제, 보유기간공제, 장기공제
- 양도차익: 양도차액, 양도이익, 매매차익, 시세차익
- 취득가액: 취득원가, 매입가, 구입가격, 취득비용
- 필요경비: 취득세, 중개수수료, 법무비용, 부대비용
- 조정대상지역: 투기과열지구, 조정지역, 규제지역, 투기지역
- 다주택자: 2주택자, 3주택자, 다주택, 다가구, 복수주택
- 일시적2주택: 이사목적, 대체취득, 종전주택, 신규주택
- 거주기간: 실거주, 거주요건, 거주년수
- 보유기간: 보유년수, 소유기간
- 중과세: 중과, 추가세율, 가산세율
- 양도세: 양도소득세, 부동산세금

## 응답 형식 (반드시 아래 JSON 형식만 출력)
```json
{
  "intent": "이용자의 목적 설명...",
  "issues": ["쟁점1", "쟁점2"],
  "reformulated_query": "정리된 질문",
  "keywords": ["키워드1", "키워드2"],
  "expanded_keywords": ["키워드1", "동의어1", "관련어1", ...]
}
```

이용자 질문: """ + query

    try:
        model = genai.GenerativeModel('gemini-1.5-flash')
        response = model.generate_content(
            analysis_prompt,
            generation_config=genai.GenerationConfig(
                temperature=0.1,
                max_output_tokens=1024
            )
        )

        response_text = response.text
        import re
        json_match = re.search(r'```json\s*(.*?)\s*```', response_text, re.DOTALL)
        if json_match:
            json_str = json_match.group(1)
        else:
            json_match = re.search(r'\{.*\}', response_text, re.DOTALL)
            json_str = json_match.group(0) if json_match else "{}"

        analysis = json.loads(json_str)
        analysis["original_query"] = query
        return analysis

    except Exception as e:
        print(f"질문 분석 오류: {e}")
        import re
        words = [w for w in re.sub(r'[^\w\s가-힣]', ' ', query).split() if w.strip()]
        return {
            "original_query": query,
            "intent": "양도소득세 관련 문의",
            "issues": [query],
            "reformulated_query": query,
            "keywords": words[:5],
            "expanded_keywords": words[:5]
        }


async def search_gemini_file_store(query: str) -> str:
    """Gemini File Search Store를 사용한 의미론적 검색 (시멘틱 벡터 검색)"""
    if not GEMINI_API_KEY or GEMINI_API_KEY == "your_gemini_api_key_here":
        return ""

    try:
        from google import genai as genai_new
        from google.genai import types

        client = genai_new.Client(api_key=GEMINI_API_KEY)

        conn = sqlite3.connect(USER_DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT store_name FROM file_search_stores ORDER BY created_at DESC LIMIT 5")
        stores = cursor.fetchall()
        conn.close()

        if not stores:
            return ""

        all_results = []

        for (store_name,) in stores:
            try:
                response = client.models.generate_content(
                    model='gemini-2.0-flash',
                    contents=query,
                    config=types.GenerateContentConfig(
                        tools=[types.Tool(
                            file_search=types.FileSearch(
                                file_search_store=store_name
                            )
                        )],
                        temperature=0.1,
                        max_output_tokens=2048
                    )
                )

                if response.text:
                    all_results.append(response.text)

            except Exception as e:
                print(f"File Search Store '{store_name}' 검색 실패: {e}")
                continue

        return "\n\n".join(all_results) if all_results else ""

    except ImportError:
        return ""
    except Exception as e:
        print(f"Gemini File Search 오류: {e}")
        return ""


async def parallel_search_pipeline(query_analysis: Dict[str, Any]) -> Dict[str, Any]:
    """
    [2단계] 3가지 검색 병렬 실행 (Search Pipeline 2.0)
    1. FTS5 Multi-Query 스마트 키워드 검색
    2. Gemini File Search 시멘틱 벡터 검색
    3. Perplexity AI 웹검색 (법령 검증)

    모든 검색을 병렬로 실행하여 성능 최적화
    """
    import asyncio

    results = {
        "fts5_results": "",
        "semantic_results": "",
        "perplexity_results": {},
        "query_analysis": query_analysis
    }

    # FTS5 검색 (동기 함수이므로 executor로 실행)
    def run_fts5_search():
        fts5_queries = query_analysis.get("fts5_queries", [])
        if fts5_queries:
            return search_knowledge_multi_query(fts5_queries, limit=10)
        else:
            expanded_keywords = query_analysis.get("expanded_keywords", [])
            if expanded_keywords:
                return search_knowledge_multi_query(
                    [' OR '.join(expanded_keywords)],
                    limit=10
                )
            return search_knowledge(query_analysis.get("original_query", ""))

    # 비동기 검색 태스크 정의
    async def gemini_search():
        semantic_query = query_analysis.get("semantic_query",
                        query_analysis.get("reformulated_query",
                        query_analysis.get("original_query", "")))
        return await search_gemini_file_store(semantic_query)

    async def perplexity_search():
        perplexity_query = query_analysis.get("perplexity_query",
                          query_analysis.get("reformulated_query",
                          query_analysis.get("original_query", "")))
        time_context = query_analysis.get("time_context", {})
        return await search_perplexity(perplexity_query, time_context)

    # 병렬 실행
    loop = asyncio.get_event_loop()

    # FTS5 검색 (동기 -> 비동기 변환)
    fts5_task = loop.run_in_executor(None, run_fts5_search)
    gemini_task = gemini_search()
    perplexity_task = perplexity_search()

    # 모든 태스크 동시 실행
    fts5_result, gemini_result, perplexity_result = await asyncio.gather(
        fts5_task, gemini_task, perplexity_task,
        return_exceptions=True
    )

    # 결과 처리
    results["fts5_results"] = fts5_result if isinstance(fts5_result, str) else ""
    results["semantic_results"] = gemini_result if isinstance(gemini_result, str) else ""
    results["perplexity_results"] = perplexity_result if isinstance(perplexity_result, dict) else {"status": "error", "result": ""}

    return results


async def cross_validate_results(
    internal_results: str,
    perplexity_results: Dict[str, Any],
    query_analysis: Dict[str, Any]
) -> Dict[str, Any]:
    """
    [3단계] 교차검증 - 내부 RAG 결과와 Perplexity 웹검색 결과 비교
    - 두 결과 사이에 차이가 있으면 분석
    - 법적 근거에 기초하여 정확한 결론 도출
    """
    validation = {
        "has_discrepancy": False,
        "discrepancy_analysis": "",
        "final_conclusion": "",
        "confidence": "high"
    }

    perplexity_text = perplexity_results.get("result", "")
    if not perplexity_text or perplexity_results.get("status") != "success":
        # Perplexity 결과가 없으면 검증 생략
        validation["confidence"] = "medium"
        validation["final_conclusion"] = "웹검색 결과가 없어 내부 지식베이스 결과만으로 답변합니다."
        return validation

    if not GEMINI_API_KEY or GEMINI_API_KEY == "your_gemini_api_key_here":
        return validation

    # AI를 사용하여 두 결과 비교 분석
    validation_prompt = f"""두 가지 검색 결과를 비교하여 교차검증하세요.

## 질문
{query_analysis.get('reformulated_query', query_analysis.get('original_query', ''))}

## 시점 정보
{json.dumps(query_analysis.get('time_context', {}), ensure_ascii=False)}

## 내부 지식베이스 검색 결과 (RAG)
{internal_results[:5000] if internal_results else '결과 없음'}

## 웹검색 결과 (Perplexity)
{perplexity_text[:5000]}

## 분석 요청
1. 두 결과 사이에 법적 결론이나 요건에 차이가 있는지 확인
2. 차이가 있다면 그 원인 분석 (법령 개정, 시점 차이, 해석 차이 등)
3. 법적 근거에 기초하여 어느 결과가 정확한지 판단
4. 최종 결론 및 신뢰도 평가

## 응답 형식 (JSON)
```json
{{
  "has_discrepancy": true/false,
  "discrepancy_analysis": "차이점 분석 (차이 없으면 빈 문자열)",
  "correct_source": "internal/perplexity/both (정확한 출처)",
  "legal_basis": "판단의 법적 근거",
  "final_conclusion": "최종 결론",
  "confidence": "high/medium/low"
}}
```"""

    try:
        model = genai.GenerativeModel('gemini-1.5-flash')
        response = model.generate_content(
            validation_prompt,
            generation_config=genai.GenerationConfig(
                temperature=0.1,
                max_output_tokens=1500
            )
        )

        import re
        json_match = re.search(r'```json\s*(.*?)\s*```', response.text, re.DOTALL)
        if json_match:
            validation = json.loads(json_match.group(1))
        else:
            json_match = re.search(r'\{.*\}', response.text, re.DOTALL)
            if json_match:
                validation = json.loads(json_match.group(0))

    except Exception as e:
        print(f"교차검증 오류: {e}")

    return validation


async def hybrid_rag_search(query_analysis: Dict[str, Any]) -> Dict[str, str]:
    """
    [호환성 유지] 기존 함수 호환을 위한 래퍼
    새로운 parallel_search_pipeline을 호출
    """
    results = await parallel_search_pipeline(query_analysis)
    return {
        "fts5_results": results.get("fts5_results", ""),
        "semantic_results": results.get("semantic_results", ""),
        "query_analysis": query_analysis
    }


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


# === AI 상담 (검색 파이프라인 2.0) ===
async def get_ai_consultation(query: str, context: Optional[Dict] = None, user_id: int = None) -> str:
    """
    검색 파이프라인 2.0 기반 AI 상담:
    1단계: AI 쿼리 최적화 - Multi-Query 생성, 시점 분석
    2단계: 3가지 검색 병렬 실행 (FTS5 + Gemini + Perplexity)
    3단계: 교차검증 - 내부 RAG vs 웹검색 결과 비교
    4단계: 결과 통합 - 보고서 형식 답변 생성
    """

    # 시점 정보 추출 (계산 데이터에서)
    time_context = None
    if context:
        time_context = {
            "transfer_date": context.get("transfer_date"),
            "acquisition_date": context.get("acquisition_date")
        }

    # ============================================
    # [1단계] AI 쿼리 최적화 - Multi-Query 생성
    # ============================================
    query_analysis = await generate_optimized_queries(query, time_context)

    # ============================================
    # [2단계] 3가지 검색 병렬 실행
    # - FTS5: Multi-Query 스마트 키워드 검색
    # - Gemini: 시멘틱 벡터 검색
    # - Perplexity: 웹검색 (법령 검증)
    # ============================================
    search_results = await parallel_search_pipeline(query_analysis)

    fts5_knowledge = search_results.get("fts5_results", "")
    semantic_knowledge = search_results.get("semantic_results", "")
    perplexity_results = search_results.get("perplexity_results", {})
    perplexity_text = perplexity_results.get("result", "")

    # 내부 RAG 결과 통합
    internal_knowledge = ""
    if fts5_knowledge:
        internal_knowledge += f"## 관련 법령 및 세무 지식 (FTS5 키워드 검색)\n{fts5_knowledge}\n\n"
    if semantic_knowledge:
        internal_knowledge += f"## 문서 검색 결과 (시멘틱 검색)\n{semantic_knowledge}\n\n"

    # ============================================
    # [3단계] 교차검증 - 내부 RAG vs Perplexity
    # ============================================
    validation = await cross_validate_results(
        internal_knowledge,
        perplexity_results,
        query_analysis
    )

    # 최종 지식베이스 구성
    combined_knowledge = internal_knowledge
    if perplexity_text and perplexity_results.get("status") == "success":
        combined_knowledge += f"## 웹검색 결과 (Perplexity - 최신 법령 검증)\n{perplexity_text}\n\n"

    if validation.get("has_discrepancy"):
        combined_knowledge += f"""## 교차검증 결과 (주의)
- 내부 검색과 웹검색 결과에 차이가 발견되었습니다.
- 차이 분석: {validation.get('discrepancy_analysis', '')}
- 법적 근거: {validation.get('legal_basis', '')}
- 최종 판단: {validation.get('final_conclusion', '')}
- 신뢰도: {validation.get('confidence', 'medium')}
"""

    if not combined_knowledge:
        combined_knowledge = "관련 정보를 찾을 수 없습니다. 일반적인 양도소득세 지식을 바탕으로 답변합니다."

    # ============================================
    # [4단계] 보고서 형식 답변 생성
    # ============================================
    today = datetime.now().strftime('%Y년 %m월 %d일')
    time_context_info = query_analysis.get("time_context", {})

    system_prompt = f"""당신은 30년 경력의 양도소득세 전문 세무사입니다.
아래의 [질문 분석 결과]와 [검색된 지식베이스]를 참고하여 이용자의 질문에 답변하세요.

## 질문 분석 결과
- 이용자 원본 질문: {query_analysis.get('original_query', query)}
- 이용자의 의도: {query_analysis.get('intent', '양도소득세 관련 문의')}
- 핵심 쟁점: {', '.join(query_analysis.get('issues', []))}
- 정리된 질문: {query_analysis.get('reformulated_query', query)}
- FTS5 검색 쿼리: {query_analysis.get('fts5_queries', [])}

## 시점 분석 (중요!)
- 적용 기준일: {time_context_info.get('applicable_date', '현재')}
- 적용 법령: {time_context_info.get('law_version', '현행법')}
- 법령 개정 확인 필요: {time_context_info.get('needs_amendment_check', False)}

## 검색된 지식베이스 (3가지 검색 통합)
{combined_knowledge}

## 교차검증 결과
- 결과 일치 여부: {'불일치 - 주의 필요' if validation.get('has_discrepancy') else '일치 또는 검증 생략'}
- 신뢰도: {validation.get('confidence', 'medium')}

## 답변 작성 지침
1. **시점 분석 우선**: 반드시 어느 시점의 법령을 적용해야 하는지 먼저 확정하세요.
2. **법령 개정 확인**: 해당 기간에 법령 개정이 있었는지 확인하고 명시하세요.
3. 질문 분석 결과의 "핵심 쟁점"을 중심으로 답변하세요.
4. 검색된 지식베이스의 내용을 근거로 답변하되, 없는 내용은 추측하지 마세요.
5. 교차검증에서 불일치가 있으면 그 내용을 반영하여 정확한 결론을 도출하세요.
6. 명확한 결론을 먼저 제시하고, 상세 설명을 뒤에 배치하세요.
7. 관련 법령(소득세법, 시행령 등)과 조문 번호를 반드시 인용하세요.

## 답변 형식 (HTML)
반드시 다음 6단계 구조로 답변하세요:

<div class="report-section">
<h3>1. 문의 개요</h3>
<p>귀하의 문의는 <strong>[분석된 질문의 핵심]</strong>에 관한 내용입니다.</p>
<p><em>핵심 쟁점: [쟁점 나열]</em></p>
</div>

<div class="report-section time-analysis">
<h3>2. 시점 분석 및 적용 법령</h3>
<ul>
<li><strong>적용 기준일:</strong> [양도일/취득일 등]</li>
<li><strong>적용 법령:</strong> [해당 시점의 소득세법/시행령 버전]</li>
<li><strong>법령 개정 여부:</strong> [개정 사항이 있다면 명시]</li>
</ul>
</div>

<div class="report-section">
<h3>3. 핵심 답변 (결론)</h3>
<div class="conclusion-box">
<p><strong>[명확하고 구체적인 결론 - 2~3문장]</strong></p>
</div>
</div>

<div class="report-section">
<h3>4. 상세 검토 및 법적 근거</h3>
<ul>
<li><strong>관련 법령:</strong> 소득세법 제○○조, 시행령 제○○조 등</li>
<li><strong>적용 요건:</strong> 구체적인 요건 설명</li>
<li><strong>계산 방법:</strong> 해당되는 경우 계산 예시</li>
</ul>
</div>

<div class="report-section">
<h3>5. 주의사항 및 리스크</h3>
<ul>
<li>신고 기한 및 납부 기한</li>
<li>가산세 등 불이익</li>
<li>실무상 주의점</li>
</ul>
</div>

<div class="report-section">
<h3>6. 종합 의견</h3>
<p>전문가로서의 종합적인 조언과 권고사항</p>
</div>

<div class="report-footer">
<p>본 보고서는 일반적인 세무 상담 자료이며, 개별 사안에 따라 결과가 달라질 수 있습니다.</p>
<p>정확한 세금 계산과 신고를 위해서는 세무사와의 개별 상담을 권장합니다.</p>
<p>검색 신뢰도: {validation.get('confidence', 'medium').upper()}</p>
<p>작성일: {today}</p>
</div>
"""

    user_message = query
    if context:
        user_message += f"\n\n[계산 데이터]\n{json.dumps(context, ensure_ascii=False, indent=2)}"

    response_html = ""
    try:
        if not GEMINI_API_KEY or GEMINI_API_KEY == "your_gemini_api_key_here":
            response_html = generate_fallback_response(query, combined_knowledge)
        else:
            model = genai.GenerativeModel('gemini-1.5-pro')
            response = model.generate_content(
                [system_prompt, user_message],
                generation_config=genai.GenerationConfig(temperature=0.3, max_output_tokens=4096)
            )
            response_html = response.text
    except Exception as e:
        response_html = generate_fallback_response(query, combined_knowledge, str(e))

    # 상담 내역 저장 (분석 결과 포함)
    try:
        conn = sqlite3.connect(USER_DB_PATH)
        cursor = conn.cursor()
        context_with_analysis = {
            "calculation_context": context,
            "query_analysis": query_analysis,
            "search_results": {
                "fts5_queries": query_analysis.get("fts5_queries", []),
                "perplexity_status": perplexity_results.get("status"),
                "validation": validation
            }
        }
        cursor.execute(
            "INSERT INTO consultations (user_id, query, context_data, response_html) VALUES (?, ?, ?, ?)",
            (user_id, query, json.dumps(context_with_analysis, ensure_ascii=False) if context_with_analysis else None, response_html)
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
        # 토큰 발급 요청 데이터 구성
        token_data = {
            "grant_type": "authorization_code",
            "client_id": KAKAO_CLIENT_ID,
            "redirect_uri": KAKAO_REDIRECT_URI,
            "code": req.code,
        }
        # Client Secret이 있는 경우에만 추가 (선택사항)
        if KAKAO_CLIENT_SECRET:
            token_data["client_secret"] = KAKAO_CLIENT_SECRET

        token_response = await client.post(
            "https://kauth.kakao.com/oauth/token",
            data=token_data,
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )

        if token_response.status_code != 200:
            error_detail = token_response.json() if token_response.text else {}
            print(f"카카오 토큰 오류: {error_detail}")
            raise HTTPException(status_code=400, detail=f"카카오 토큰 발급 실패: {error_detail.get('error_description', '알 수 없는 오류')}")

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


@app.put("/api/admin/knowledge/{entry_id}")
async def update_knowledge_entry(
    entry_id: int,
    category: str = Form(...),
    title: str = Form(...),
    content: str = Form(...),
    keywords: str = Form(""),
    admin: dict = Depends(require_admin)
):
    """지식 데이터베이스 항목 수정"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE tax_knowledge
        SET category = ?, title = ?, content = ?, keywords = ?
        WHERE rowid = ?
    """, (category, title, content, keywords, entry_id))
    conn.commit()
    conn.close()

    return {"status": "success", "message": "항목이 수정되었습니다."}


@app.get("/api/admin/knowledge/{entry_id}")
async def get_knowledge_entry(entry_id: int, admin: dict = Depends(require_admin)):
    """지식 데이터베이스 항목 조회"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT rowid, category, title, content, keywords FROM tax_knowledge WHERE rowid = ?", (entry_id,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        raise HTTPException(status_code=404, detail="항목을 찾을 수 없습니다")

    return {
        "id": row[0],
        "category": row[1],
        "title": row[2],
        "content": row[3],
        "keywords": row[4]
    }


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


@app.post("/api/admin/rag/test")
async def test_rag_search(
    query: str = Form(...),
    admin: dict = Depends(require_admin)
):
    """
    3단계 RAG 파이프라인 테스트
    1단계: 질문 분석 (의도, 쟁점, 키워드 확장)
    2단계: 하이브리드 검색 (FTS5 + Gemini File Search)
    3단계: 결과 통합
    """
    results = {
        "query": query,
        "step1_analysis": {},
        "step2_fts5_result": "",
        "step2_gemini_result": "",
        "step3_combined": ""
    }

    # [1단계] 질문 분석
    try:
        query_analysis = await analyze_query_with_ai(query)
        results["step1_analysis"] = {
            "intent": query_analysis.get("intent", ""),
            "issues": query_analysis.get("issues", []),
            "reformulated_query": query_analysis.get("reformulated_query", ""),
            "keywords": query_analysis.get("keywords", []),
            "expanded_keywords": query_analysis.get("expanded_keywords", [])
        }
    except Exception as e:
        results["step1_analysis"] = {"error": f"질문 분석 오류: {str(e)}"}
        query_analysis = {"original_query": query, "expanded_keywords": [], "reformulated_query": query}

    # [2단계] 하이브리드 RAG 검색
    try:
        search_results = await hybrid_rag_search(query_analysis)
        results["step2_fts5_result"] = search_results.get("fts5_results", "") or "FTS5 검색 결과 없음"
        results["step2_gemini_result"] = search_results.get("semantic_results", "") or "Gemini File Search 결과 없음 (파일이 업로드되지 않았거나 관련 정보가 없습니다)"
    except Exception as e:
        results["step2_fts5_result"] = f"FTS5 검색 오류: {str(e)}"
        results["step2_gemini_result"] = f"Gemini 검색 오류: {str(e)}"

    # [3단계] 결과 통합
    combined = ""
    if results["step2_fts5_result"] and "결과 없음" not in results["step2_fts5_result"] and "오류" not in results["step2_fts5_result"]:
        combined += f"## 키워드 검색 결과 (FTS5)\n{results['step2_fts5_result']}\n\n"
    if results["step2_gemini_result"] and "결과 없음" not in results["step2_gemini_result"] and "오류" not in results["step2_gemini_result"]:
        combined += f"## 시멘틱 검색 결과 (Gemini)\n{results['step2_gemini_result']}"
    results["step3_combined"] = combined if combined else "검색 결과가 없습니다."

    return {
        "status": "success",
        "results": results
    }


@app.get("/api/admin/rag/status")
async def get_rag_status(admin: dict = Depends(require_admin)):
    """RAG 시스템 상태 확인"""
    status = {
        "fts5": {"status": "unknown", "count": 0},
        "gemini": {"status": "unknown", "stores": [], "api_key_set": False}
    }

    # FTS5 상태 확인
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM tax_knowledge")
        count = cursor.fetchone()[0]
        conn.close()
        status["fts5"] = {"status": "ok", "count": count}
    except Exception as e:
        status["fts5"] = {"status": "error", "message": str(e)}

    # Gemini 상태 확인
    status["gemini"]["api_key_set"] = bool(GEMINI_API_KEY and GEMINI_API_KEY != "your_gemini_api_key_here")

    try:
        conn = sqlite3.connect(USER_DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT store_name, display_name, created_at FROM file_search_stores")
        stores = cursor.fetchall()

        cursor.execute("SELECT COUNT(*) FROM uploaded_files WHERE destination = 'gemini' AND status = 'completed'")
        gemini_file_count = cursor.fetchone()[0]
        conn.close()

        status["gemini"]["status"] = "ok"
        status["gemini"]["stores"] = [{"store_name": s[0], "display_name": s[1], "created_at": s[2]} for s in stores]
        status["gemini"]["file_count"] = gemini_file_count
    except Exception as e:
        status["gemini"]["status"] = "error"
        status["gemini"]["message"] = str(e)

    return {"status": "success", "rag_status": status}


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
