# 배포 가이드

Railway(백엔드)와 Vercel(프론트엔드) 분리 배포 가이드입니다.

## 프로젝트 구조

```
CGT_caculator/
├── backend/              # Railway 배포용 (FastAPI)
│   ├── main.py
│   ├── requirements.txt
│   ├── Procfile
│   ├── railway.json
│   └── .env.example
│
├── frontend/             # Vercel 배포용 (Static HTML)
│   ├── index.html
│   ├── env.js
│   ├── vercel.json
│   ├── package.json
│   └── .env.example
│
└── [양도세 관련 문서들]   # 참고 자료
```

---

## 1. Railway 백엔드 배포

### 1.1 Railway 프로젝트 생성

1. [Railway](https://railway.app) 접속 후 로그인
2. **New Project** → **Deploy from GitHub repo** 선택
3. GitHub 저장소 연결

### 1.2 배포 설정

Railway 대시보드에서:

1. **Settings** → **Root Directory**: `backend` 입력
2. **Variables** 탭에서 환경변수 추가:

```
GEMINI_API_KEY=your_gemini_api_key_here
FRONTEND_URL=https://your-app.vercel.app
```

### 1.3 도메인 확인

배포 완료 후 Railway가 제공하는 URL 확인:
- 예: `https://cgt-calculator-production.up.railway.app`

---

## 2. Vercel 프론트엔드 배포

### 2.1 Vercel 프로젝트 생성

1. [Vercel](https://vercel.com) 접속 후 로그인
2. **Add New** → **Project** → GitHub 저장소 선택

### 2.2 배포 설정

1. **Root Directory**: `frontend` 입력
2. **Framework Preset**: `Other` 선택
3. **Build Command**: 비워두기 (정적 사이트)
4. **Output Directory**: `.` (현재 디렉토리)

### 2.3 API URL 설정

**중요!** `frontend/env.js` 파일을 Railway URL로 수정:

```javascript
// frontend/env.js
window.ENV_API_URL = 'https://your-railway-app.up.railway.app';
```

또는 Vercel 환경변수로 관리하려면:

1. Vercel 대시보드 → **Settings** → **Environment Variables**
2. 추가: `VITE_API_URL` = `https://your-railway-app.up.railway.app`

---

## 3. CORS 설정

Railway 백엔드에서 Vercel 프론트엔드를 허용하도록 환경변수 설정:

```
FRONTEND_URL=https://your-app.vercel.app
```

---

## 4. 배포 확인

### 백엔드 헬스체크
```bash
curl https://your-railway-app.up.railway.app/api/health
```

응답 예시:
```json
{"status": "healthy", "timestamp": "2025-01-12T..."}
```

### 프론트엔드 확인
브라우저에서 Vercel URL 접속:
```
https://your-app.vercel.app
```

---

## 5. 문제 해결

### CORS 오류
- Railway 환경변수에 `FRONTEND_URL` 정확히 설정했는지 확인
- Vercel 도메인이 `https://`로 시작하는지 확인

### API 연결 실패
- `frontend/env.js`의 URL이 Railway URL과 일치하는지 확인
- Railway 서비스가 정상 동작하는지 확인

### Gemini API 오류
- `GEMINI_API_KEY` 환경변수가 올바르게 설정되었는지 확인
- [Google AI Studio](https://aistudio.google.com/app/apikey)에서 API 키 상태 확인

---

## 6. 로컬 개발

### 백엔드
```bash
cd backend
pip install -r requirements.txt
cp .env.example .env  # GEMINI_API_KEY 설정
python main.py
```

### 프론트엔드
```bash
cd frontend
# env.js에서 API_URL을 localhost:8000으로 변경
npx serve .
```

---

## 환경변수 요약

### Railway (백엔드)
| 변수명 | 설명 | 예시 |
|--------|------|------|
| `GEMINI_API_KEY` | Google Gemini API 키 | `AIza...` |
| `FRONTEND_URL` | Vercel 프론트엔드 URL | `https://your-app.vercel.app` |
| `PORT` | (자동 설정) 서버 포트 | - |

### Vercel (프론트엔드)
| 파일/변수 | 설명 | 예시 |
|-----------|------|------|
| `env.js` 내 `ENV_API_URL` | Railway 백엔드 URL | `https://xxx.up.railway.app` |
