# 가디언.XDR (BYTE BACK & 케셰브) 실전 활용 및 UI 업그레이드 완벽 가이드

이 문서는 `https://aleph-omega.vercel.app/defense`의 모든 방어전 활동(1~22단계 및 보너스 XDR 6종)을 수료한 뒤, **기존 프로젝트를 세련된 와인색 XDR 대시보드 앱으로 업그레이드**하고 **내 컴퓨터에서 실제로 일상 보안 도구로 활용하는 방법**을 총정리한 매뉴얼입니다.

---

## 1. Git 저장소(`aleph-defense-starter`) 구조 구분: 어떤 걸 내 컴퓨터에서 쓸 수 있나요?

현재 Git과 연결된 `aleph-defense-starter` 폴더 안에는 **크게 3가지 영역**이 공존하고 있습니다. 무엇이 클라우드용이고 무엇이 내 PC용인지 명확히 구분해야 헷갈리지 않습니다.

| 구분 | 폴더 및 핵심 파일 | 배포·실행 위치 | 실제 정체와 내가 쓸 수 있는 방법 |
|---|---|---|---|
| **① 클라우드 보호 자료실 & 탈환 작전실** (1~12단계) | • 루트 `public/index.html`, `public/manifest.json`<br>• `api/login.js`, `api/memos.js`<br>• `src/decider.mjs`, `src/detect.mjs`, `src/verify-login.mjs`<br>• `vercel.json` | **Vercel 클라우드 서버**<br>(`https://본인주소.vercel.app`) | • 인터넷 어디서나 접속 가능한 **나만의 암호화·전자서명 클라우드 보안 메모장(PWA)**이자 **자동 보안 점검 작전실**입니다.<br>• 내 PC나 스마트폰 크롬/엣지에서 배포 주소 접속 후 주소창 우측 **「앱 설치」**를 누르면 바탕화면 독립 앱으로 설치해 일상 비밀 메모장으로 쓸 수 있습니다. |
| **② 내 PC 로컬 보안 Agent (`케셰브`)** (13~22단계) | • `on-client/src/server.mjs`<br>• `on-client/public/index.html`, `app.js`, `style.css`<br>• `on-client/student/extension.mjs`<br>• `on-client/src/vulnerabilities/osv.mjs` | **내 컴퓨터 로컬 전용**<br>(`http://127.0.0.1:5189`) | • **내 컴퓨터에서 직접 띄워 쓰는 핵심 로컬 보안 에이전트**입니다.<br>• **수료용 도구(`keshev-portable-tools-0.1.1`)**를 설치하면 학원 서버/포털 없이도 평생 내 PC에서 작동하며, **내 개인 AI 키를 연결해 보안 로그를 분석**하거나 **내가 개발하는 프로젝트(`package-lock.json`)의 오픈소스 취약점(OSV)을 실시간 스캔**할 수 있습니다. |
| **③ XDR 6대 위협 판정 엔진** (보너스) | • `xdr/fixtures/*.json`<br>• `xdr/<모듈명>/decide.mjs`<br>• `scripts/xdr-run.mjs` | **내 컴퓨터 터미널(Node.js)**<br>(`npm run xdr:run -- <모듈>`) | • Wazuh SIEM/XDR 형태의 6가지 보안 경보(`brute-force`, `web-injection`, `known-cve`, `persistence`, `privilege`, `exfiltration`)를 분석해 차단(`block`)·경고(`alert`)·기록(`record`)을 자동 판정하는 로컬 상관분석 엔진입니다. |
| **④ 클라우드 확장 뼈대** (3차 패키징) | • `api/ai.js`, `api/threat-intel.js`<br>• `package/*.md` | **Vercel 클라우드 서버** | • 시작 틀에서는 기본적으로 `501 Not Implemented`를 반환하는 확장용 빈 뼈대입니다. 원할 때 내 OpenAI 키나 NVD/CISA KEV API를 연결해 클라우드 위협 인텔리전스 포털로 확장할 수 있습니다. |

---

## 2. 방어전(1~22단계) 기능의 정확한 실제 보안 용어 매핑 & 일상 활용법

수업에서는 이해하기 쉬운 비유(점령된 자료실, 검문소, 도플갱어 등)로 배웠지만, 각 기능은 실제 엔터프라이즈 보안 솔루션(CrowdStrike Falcon, Palo Alto Cortex XDR, Zscaler ZTNA, Okta 등)의 핵심 기술을 정확히 구현한 것입니다.

| 방어전 단계 및 코드 | 실제 가리키는 엔터프라이즈 보안 기술 | 일상에서 내가 실제로 활용하는 방법 |
|---|---|---|
| **1~5단계**: `/data.json` 제거, `api/login.js`, `src/verify-login.mjs` | **Secret Isolation & API Gateway JWT 검증**<br>(정적 빌드 아티팩트 내 민감 데이터 제거 및 서버 집중형 토큰 서명 검증) | • 개인 토이 프로젝트나 포트폴리오 사이트를 Vercel에 배포할 때 API 키·개인 데이터를 프론트엔드 번들에서 분리하고 Supabase 인증 게이트를 두는 표준 보안 템플릿으로 재사용합니다. |
| **6~8단계**: `src/decider.mjs` (`device_registered`, `step_up_required`, `zone_access`) | **ZTNA 정책 결정 지점 (PDP, Policy Decision Point) & 적응형 인증 (Adaptive MFA) & 마이크로세그멘테이션** | • 단순히 "로그인 성공=모든 권한"이 아니라, **내 등록된 기기인지**, **평소와 다른 시간대/IP/대량 요청(이상 징후)인지**, **허용된 경로(Zone)인지**를 18개 필드로 계산하는 제로트러스트 엔진입니다. 개인 웹앱의 미들웨어로 그대로 붙일 수 있습니다. |
| **9~10단계**: `src/detect.mjs` (`burst_read`) & `/api/restore` | **UEBA (사용자 행위 기반 이상 탐지) + SOAR 자동 세션 회수 + 랜섬웨어 대비 불변 백업(SHA-256 무결성 복구)** | • 10분 내 120건 초과 조회 시 크롤러/세션 탈취(도플갱어)로 판단해 즉시 권한을 회수하고, 데이터가 훼손됐을 때 백업 사본의 `ID`·`owner_id`·`SHA-256 해시`를 대조해 안전할 때만 복원하는 무결성 롤백 로직입니다. |
| **11~12단계**: `public/index.html` Web Crypto ECDSA P-256 서명 & 탈환 작전실 | **FIDO2 / DPoP (시연 증명 전자서명) & BAS (Breach and Attack Simulation, 침해 시뮬레이션 대시보드)** | • 브라우저 저장소(`localStorage`)에 키를 저장하지 않고 메모리에서만 유지되는 비추출(`extractable: false`) ECDSA 개인키로 `메서드+경로+본문해시+시각`을 전자서명합니다.<br>• **탈환 작전실**의 「1~11단계 실측 점검 실행」 버튼은 내 서버에 실제 공격(무인증, 미등록 기기, 서명 누락, 경로 변조)을 쏘아 방어 여부를 실시간 검증하는 **자동 보안 헬스체크 도구**입니다. |
| **13~19단계**: `on-client/` (`student/extension.mjs`) | **엔드포인트 XDR 에이전트 UI + Security Copilot (근거 기반 AI 분석) + Human-in-the-Loop SOAR** | • AI가 환각(Hallucination)으로 근거 없는 설명을 하거나 멋대로 시스템을 조작하지 못하도록, **사건 근거(`evidence`)와 규칙(`rules`) 바인딩 검증** 후 **사람의 명시적 승인(`confirmationId` 및 만료 기한)**을 거쳐서만 조치를 실행하는 안전한 AI 보안 관제 패턴입니다. |
| **20단계**: `on-client/src/vulnerabilities/osv.mjs` | **SCA (Software Composition Analysis, 오픈소스 공급망 취약점 스캐너 — Snyk / Dependabot 역할)** | • 내 컴퓨터의 `package-lock.json`에 설치된 실제 패키지 버전을 구글 OSV(Open Source Vulnerabilities) 데이터베이스와 대조해 취약점 유무를 검사합니다. **내가 개발하는 다른 Node.js 프로젝트의 취약점 점검기**로 일상에서 바로 쓸 수 있습니다. |

---

## 3. 보내주신 2가지 실전 키트의 정체와 단계별 사용법

### A. 케셰브 수료용 도구 (`keshev-portable-tools-0.1.1.zip`)
- **무엇인가요?**: 수업 중 사용하던 워크벤치나 ALEPH 포털 연결이 끊긴 수료 후에도, 내가 만든 `on-client` 에이전트를 **내 PC에서 평생 독립 실행(`standalone-server.mjs`)**하고, **내 개인 AI API 키(OpenAI, OpenRouter, xAI)를 연결해 보안 이벤트를 분석(`/personal/`)**하며, 비밀키나 불필요한 캐시를 걸러내고 **깨끗한 포트폴리오용 패키지 폴더로 내보내는(`export-student-package.mjs`)** 공식 독립화 키트입니다.
- **실제 내 컴퓨터에서 사용하는 순서 (Windows PowerShell)**:
  1. **압축 풀기**: `keshev-portable-tools-0.1.1.zip`을 기존 프로젝트 폴더 **바깥**(예: `C:\keshev-portable-tools`)에 풉니다.
  2. **내 `on-client`에 수료용 도구 설치 (미리보기 → 적용)**:
     ```powershell
     cd C:\keshev-portable-tools\keshev-portable-tools-0.1.1
     # 1) 먼저 파일 충돌이 없는지 미리보기(dry-run) 실행
     node tools/install-portable-tools.mjs --bundle . --project "C:\내작업\aleph-defense-starter\on-client"
     # 2) 이상이 없으면 --apply 를 붙여 실제 설치
     node tools/install-portable-tools.mjs --bundle . --project "C:\내작업\aleph-defense-starter\on-client" --apply
     ```
  3. **나만의 앱 이름(예: 가디언 XDR) 및 개인 AI 설정 파일 만들기**:
     설정은 Git에 올라가지 않도록 내 PC의 `%LOCALAPPDATA%\KeshevSettings\personal.json`에 만듭니다.
     ```powershell
     cd "C:\내작업\aleph-defense-starter\on-client"
     $settingsFolder = Join-Path $env:LOCALAPPDATA 'KeshevSettings'
     New-Item -ItemType Directory -Path $settingsFolder -Force | Out-Null
     $settingsFile = Join-Path $settingsFolder 'personal.json'
     Copy-Item -LiteralPath .\tools\portable\personal-config.example.json -Destination $settingsFile
     notepad $settingsFile
     ```
     열린 메모장에서 `"appName": "가디언 XDR"`로 바꾸고 저장합니다. (개인 AI를 쓰려면 `"enabled": true`, `"provider": "openai"` (또는 `"openrouter"`, `"xai"`), `"model": "본인계정지원모델ID"` 입력)
  4. **수료 후 독립 모드로 실행하기**:
     ```powershell
     # 기본 실행 (또는 예제 데이터로 화면 전체 기능을 체험하려면 끝에 -Demo 추가)
     powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\start-standalone.ps1 -PersonalConfig $settingsFile -Demo

     # 개인 AI API 키를 안전하게(메모리 전용) 입력하며 실행할 때
     powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\start-standalone.ps1 -PersonalConfig $settingsFile -PromptPersonalKey
     ```
     - 메인 에이전트 화면: `http://127.0.0.1:5189/`
     - 개인 AI 보안 이벤트 분석실: `http://127.0.0.1:5189/personal/`
  5. **영구 보관 및 포트폴리오용 클린 패키지 내보내기**:
     ```powershell
     node tools/export-student-package.mjs --source . --out ..\..\guardian-xdr-package --app-name "가디언 XDR"
     ```

---

### B. 케셰브 AI 보안 도우미 키트 (`keshev-ai-security-kit-1.0.zip`)
- **무엇인가요?**: 내 실제 Windows PC의 건강 상태와 보안 설정(Defender 실시간 보호, 방화벽 3종, 전체 대역 `0.0.0.0` 열린 포트와 프로세스명, 시작 프로그램, 디스크 여유 공간, CPU·메모리 상위 프로세스, 최근 3일 시스템/앱 오류 이벤트 로그, 네트워크/DNS 상태, 그리고 실행 중인 케셰브 앱의 상태)을 **100% 읽기 전용으로 수집·익명화(`<사용자>`, `<IP>`, `<가림>`)**한 뒤, 내가 쓰는 **Claude Code (`claude`), Codex CLI (`codex`), Gemini CLI (`gemini`)**를 **'내 PC 전담 보안 주치의'**로 만들어 주는 일상 보안 점검 도구입니다.
- **실제 내 컴퓨터에서 사용하는 순서 (Windows PowerShell)**:
  1. **압축 풀기**: 프로젝트 폴더 밖의 새 폴더(예: `C:\AI보안도우미`)에 압축을 풉니다.
  2. **내 PC 보안 스냅샷 수집 (1분 이내, 관리자 권한 불필요)**:
     ```powershell
     cd C:\AI보안도우미\keshev-ai-security-kit-1.0
     powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\collect-pc-snapshot.ps1
     ```
     실행하면 `reports\snapshot-날짜-시각.md` 와 `.json` 파일이 생성됩니다. (케셰브 앱을 `127.0.0.1:5189`에 켜 두고 실행하면 앱 상태도 함께 수집합니다.)
  3. **AI 보안 주치의와 대화하며 내 PC 진단하기**:
     **반드시 키트 폴더(`CLAUDE.md`, `AGENTS.md`, `GEMINI.md`가 있는 위치) 안에서** AI CLI를 실행합니다:
     ```powershell
     claude   # 또는 codex 또는 gemini
     ```
     그다음 `prompts/` 폴더에 있는 7가지 프롬프트 중 지금 필요한 것을 복사해 붙여 넣습니다:
     - `01-전체-보안-점검.md`: 한 달에 한 번 내 PC 정기 보안 감사 (상태: 정상/주의/위험 판정 및 급한 조치 3가지 안내)
     - `02-느려진-PC-원인-찾기.md`: CPU·메모리 과다 점유 프로세스, 디스크 부족, 업타임 분석으로 버벅임 원인 진단
     - `03-인터넷-연결-문제-해결.md`: 공유기 → 랜카드 → DNS → HTTPS 순으로 인터넷 먹통 구간 정밀 추적
     - `04-시작-프로그램과-열린-포트-점검.md`: 부팅 시 몰래 켜지는 수상한 프로그램이나 외부(`0.0.0.0`)로 열려 있는 포트 정체 파악
     - `05-Windows-오류-기록-해석.md`: 이벤트 뷰어의 반복 오류나 강제 종료(이벤트 41, 6008)를 쉬운 한국어로 번역·해석
     - `06-케셰브-앱-화면-해석.md`: 내가 만든 케셰브 앱의 수치와 실제 PC 수집값 비교 해석
     - `07-점검-보고서-쓰기.md`: 깔끔한 1장짜리 PC 보안 점검 리포트 생성
  4. **매일 정해진 시각에 자동 보안 점검 & 위험 시 메모장 알림 받기 (선택)**:
     ```powershell
     # 매일 낮 12:30에 자동 점검 (평소엔 조용히 기록만 남기고, '주의'나 '위험'일 때만 메모장이 자동으로 열림!)
     powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\register-daily-check.ps1 -Agent codex -Time 12:30

     # 자동 점검을 끄고 싶을 때
     powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\unregister-daily-check.ps1
     ```

---

## 4. 와인색 XDR 보안 대시보드 UI 적용 방법 (동봉된 파일 덮어쓰기)

이 압축 파일(`aleph-wine-xdr-upgrade-pack.zip`)에는 보내주신 **「와인색 XDR 보안 대시보드」**의 에디토리얼 디자인(`#741f3a` 딥 와인, `#f4f0eb` 한지 아이보리 배경, 비대칭 라디우스 카드, 사이드바 관제 레이아웃)을 기존 기능 손실 없이 100% 이식한 3개의 파일이 들어 있습니다.

> **중요 순서**: `on-client`에 수료용 도구(`keshev-portable-tools-0.1.1`)를 설치할 예정이라면, **먼저 위의 `install-portable-tools.mjs --apply`를 실행한 뒤에** 아래 CSS 파일들을 덮어쓰세요! (`export-student-package.mjs`로 내보낼 때는 수정된 디자인 파일들이 `provided-modified`로 정상 인식되어 깔끔하게 패키징됩니다.)

1. **Vercel 클라우드 웹앱 & 통합 대시보드 적용**:
   - 동봉된 `public/index.html`을 내 저장소의 `public/index.html`에 덮어씁니다.
   - 기존 1~12단계의 모든 ID, Web Crypto ECDSA P-256 전자서명, 기기 승인, 41종 실측 점검, 메모 작성/수정/삭제 API가 **가디언.XDR 대시보드 레이아웃** 안에서 그대로 작동합니다.
2. **`on-client` 로컬 에이전트 와인색 XDR 테마 적용**:
   - 동봉된 `on-client/public/style.css`를 내 저장소의 `on-client/public/style.css`에 덮어씁니다.
   - `on-client` 서버의 엄격한 보안 정책(`Content-Security-Policy: style-src 'self'`)을 100% 준수하도록 외부 폰트나 CDN 없이 순수 로컬 CSS만으로 와인색 XDR 디자인을 구현했으며, `student/extension.mjs`의 모든 슬롯과 `data-testid`가 그대로 유지됩니다.
3. **수료 후 개인 AI 화면(`/personal/`) 와인색 XDR 테마 적용**:
   - 수료용 도구 설치 후 생성된 `on-client/public/portable/personal.css`에 동봉된 `on-client/public/portable/personal.css`를 덮어씁니다.
