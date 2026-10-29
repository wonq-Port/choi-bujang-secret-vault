# 내 보안 Agent 시작 틀 0.2.11

이 보안 Agent는 회사 직원이 자기 로그인 상태, 업무 앱 접속 결과, 최근 접속 기록과 보안 경보를 보는 보안 앱입니다. 13단계부터 22단계까지 이 프로젝트 하나로 화면을 채워 가며 완성합니다. 처음이라면 docs/GETTING_STARTED_STUDENT.md부터 읽습니다. 무엇을 왜 만드는지와 단계별 순서가 그 문서에 있습니다.

이 시작 틀을 받은 것만으로 단계를 통과하지 않습니다. 단계마다 docs/STUDENT_PROMPTS.md의 안내를 수업용 AI에 붙여 넣어 student/extension.mjs를 고치고, 화면에서 확인하고, 커밋한 뒤 ALEPH에 제출합니다. 제출하면 서버가 그 커밋의 코드를 받아 AI가 단계 과제 기준으로 읽고 판정합니다. 코드를 실행해서 판정하지 않습니다.

## 기능과 구성

- **보호 현황**: 로그인·기기·세션 상태, 상태·알림 표시, 도움정보, AI 연결 상태, 설치 패키지·취약점 조회.
- **업무 앱**: 현재 사용자에게 표시되는 업무 앱 목록, 앱별 접근 판정 요청과 결과.
- **보안 기록**: 사용자 범위의 접속/XDR 기록, 기록 상세, AI 설명과 조치 요청 결과 표시. 실제 원천 집행은 별도 연결·권한이 있어야 하며, 기본 실행에서 지원된다고 가정하지 않습니다.
- **주요 파일 경계**: `public/index.html`, `public/app.js`, `public/style.css`, `src/server.mjs`는 제공 UI·서버이고, `student/extension.mjs`는 학생 표시 구현입니다. 엔진 연결은 `src/engine.mjs`와 `student/engine-adapter.mjs` 등 서버 측 코드가 담당합니다.
- **흐름 요약**: 브라우저 → 로컬 앱 서버(`/api/...`) → 설정된 엔진·SDP/XDR 연결. AI 기능은 브라우저에서 게이트웨이에 직접 연결하지 않고 로컬 서버의 `src/ai/`·`src/connection/`을 거칩니다. 기본 실행은 연결 없음 상태입니다. 글로 쓴 구성도와 데이터 계약은 [docs/STUDENT_RUNBOOK.md](docs/STUDENT_RUNBOOK.md)를 참고하세요.
- **이름**: 과제에서 사용하는 Agent 이름이 별도로 지정되어도 이 시작 틀의 브라우저 제목과 실행 안내는 기본 이름 `케셰브`를 사용합니다. 이름을 바꾸는 UI 변경은 이번 문서 단계의 범위가 아닙니다.

## 켜기

검수 환경은 Node.js 24.19.0이며 외부 npm 의존성이 없습니다. `package.json`의 프로젝트 버전은 0.2.11이고, `tools/start-alekov.ps1`은 Node.js 22~24를 허용하되 24.19.0을 권장합니다. 실행 스크립트가 사용하는 Windows PowerShell 절차 외의 환경은 여기서 검증하지 않았습니다. 이 폴더의 PowerShell에서 아래를 실행하고 PC 브라우저로 http://127.0.0.1:5189 를 엽니다. 자세한 켜기·끄기·다시 켜기는 docs/STUDENT_LAUNCH_GUIDE.md에 있습니다.

    powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\start-alekov.ps1

npm start도 같은 서버를 켭니다. 기본 실행은 실제 회사 시스템(기존 엔진)에 연결되지 않은 상태입니다. npm run demo는 예제 자료로 화면을 보여 줄 뿐이며 실제 연결이나 성취가 아닙니다. npm run check는 student/extension.mjs의 문법만 확인합니다.

## 지킬 것

- 기존 1~3차 프로젝트와 학생 파일은 지우거나 덮어쓰지 않습니다. 새 폴더에서 시작하거나, 이미 하던 프로젝트를 이어 씁니다.
- AI 열쇠·비밀번호·토큰을 코드, 커밋, 캡처, 도움정보에 넣지 않습니다. 주소나 열쇠를 직접 입력하는 칸도 만들지 않습니다.
- .env.example에는 비밀 없는 설정만 있습니다.

## 더 읽을 곳

- 학생용 실행 설명서와 시스템 구성도: docs/STUDENT_RUNBOOK.md
- 단계별 안내와 AI에 붙여 넣을 문장: docs/STUDENT_PROMPTS.md
- 단계별 확인 항목: docs/CURRICULUM.json, docs/IMPLEMENTATION_CONTRACT.md
- 오류 코드별 해결: docs/CONNECTION_TROUBLESHOOT.md
- 시작 틀 업데이트(내 파일 보존): docs/STARTER_UPDATE.md
- 실제 회사 시스템(SDP)·앱 안 AI 연결은 담당자가 따로 안내할 때만 씁니다: docs/SDP_HOST_CONNECTION.md, docs/AI_SETUP_GUIDE.md. 이 연결은 앱을 처음 켜고 13~16단계 화면을 만들거나 공식 AI 코드 판정을 받기 위한 전제 조건은 아닙니다. 다만 17단계 이후의 실제 연결과 새 환경 재현은 해당 단계의 기준에 따라 따로 확인합니다.
