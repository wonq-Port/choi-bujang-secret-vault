# 수료 후 사용 패키지 계약 (KESHEV-PORTABLE-20261018-A)

학생의 누적 Alekov 프로젝트를 워크벤치·ALEPH 포털 없이 실행할 수 있는 폴더로 내보내는 도구의 계약입니다. 학생용 설명은 [AFTER_COURSE_GUIDE.md](AFTER_COURSE_GUIDE.md)에 있습니다.

## 1. 구성

| 파일 | 역할 |
|---|---|
| `tools/export-student-package.mjs` | 내보내기(`--source --out [--app-name]`)와 확인(`--verify`) |
| `tools/portable/START_HERE.template.md` | 패키지 첫 안내 틀. `{{APP_NAME}}`, `{{CREATED_AT}}`, `{{STARTER_VERSION}}`, `{{FILE_COUNT}}`만 바꿉니다 |
| `test/student-portable-package.test.mjs` | 임시 관리 fixture 시험 |

출력은 원본의 학생 파일과 런타임, 고정 도구·안내 보충본, `START_HERE.md`, `PACKAGE_MANIFEST.json`으로 구성합니다. 실제 0.2.10에도 없는 `docs/AFTER_COURSE_GUIDE.md`, `docs/FINAL_PACKAGE.md`를 보충합니다. 동명 원본 파일이 보충본과 다르면 `EXPORT_SUPPLIED_CONFLICT`로 전체 중단해 학생 문서를 보존합니다. 최종 릴리스 template이 도구에 있으면 template을 넣고, `FINAL_RELEASE_CHECKLIST.md`가 없을 때만 틀에서 생성합니다. 이미 작성한 학생 체크리스트는 내용을 바꾸지 않고 복사합니다.

설치된 원본에 `src/standalone-server.mjs`가 있으면 개인 모듈3개·개인 화면4개·독립 launcher·개인 설정 안내가 모두 있는지 확인하고 이를 기본 entry로 기록합니다. 일부만 있으면 `EXPORT_STANDALONE_INCOMPLETE`로 중단합니다. 새 entry가 없는 고정0.2.10은 기존 src/server.mjs를 그대로 사용하며 새 아키텍처를 자동 추가하지 않습니다. 개인 설정 안내는 도구에 제공된 경우 고정0.2.10 내보내기에도 보충합니다.

## 2. 원본 확인

- `--source`는 실제 폴더여야 합니다. 경로 자체가 링크이거나 실제 경로(realpath)와 다르면 `EXPORT_LINK_REFUSED`입니다.
- `package.json`(name `alekov-client-starter`), `src/server.mjs`, `student/extension.mjs`가 있어야 합니다. 없으면 `EXPORT_SOURCE_NOT_ALEKOV`입니다.
- `package.json`에 `dependencies`·`optionalDependencies`·`peerDependencies`가 있으면 `EXPORT_DEPENDENCY_PRESENT`입니다. 현재 런타임은 외부 의존성 없이 실행하는 구조만 지원합니다.
- 원본은 읽기만 합니다. 시험에서 원본 전체 파일 해시를 내보내기 전후로 대조합니다.

## 3. 포함·제외 규칙

- 원본 안의 모든 항목을 `lstat`으로 확인합니다. 심볼릭 링크·junction이 하나라도 있으면 전체 거절(`EXPORT_LINK_REFUSED`, 경로만 알림)합니다. 일반 파일·폴더가 아닌 항목도 거절합니다.
- 이름이 정확히 같은 폴더는 제외합니다: `.git`, `node_modules`, `.local`, `receipts`, `.cache`, `.npm`, `.parcel-cache`, `.vercel`, `coverage`, `.idea`, `.vscode`. 제외한 경로는 목록에 남깁니다.
- 비밀 파일 이름은 제외하고 경로만 목록에 남깁니다: `.env`, `.env.*`(`.env.example`은 포함), `*.pem *.key *.p12 *.pfx *.jks *.keystore *.kdbx *.ppk *.der`, `id_rsa` 계열, `.npmrc .netrc .git-credentials .pypirc`.
- 텍스트 파일 내용에 GitHub 토큰, 개인키 머리글, AWS 접근 키, AI 서비스 키(`sk-`), Slack 토큰, Supabase 토큰 형태가 있으면 내보내기 전체를 거절(`EXPORT_SECRET_CONTENT`)합니다. 학생 코드를 몰래 빼지 않기 위해서입니다. 메시지와 오류 정보에는 경로와 종류만 넣고 값은 넣지 않습니다.
- 자격 보관함·연결 등록부(`.credentials`, `.connections`, credentials, vault, registry, native-vault, native-registry), DB·로그·세션/토큰 설정 자료, `src/learning`, 시험·격리 실행기는 기본 제외합니다. runtime 코드의 credential-vault.mjs 같은 모듈 이름만으로 제외하지 않습니다. 모든 바이너리·임의 이름의 비밀을 완전히 탐지한다고 주장하지 않습니다.
- 개인 실행 파일(`src/standalone-server.mjs`, `src/portable/`, `public/portable/`)과 전달 도구·template·개인 설정 안내는 원본에 있으면 보존합니다. 비밀 없는 런타임만 포함하며 개인 설정 자료는 제외합니다.
- 상한: 파일 하나 10MB, 전체 60MB, 2,000개이며 보충 파일까지 최종 합계를 확인합니다. 넘으면 거절합니다.
- 원본 맨 위의 `PACKAGE_MANIFEST.json`·`START_HERE.md`는 다시 내보낼 때 새로 만들므로 복사하지 않습니다.

## 4. 출력 폴더 규칙

- `--out`이 이미 있으면(빈 폴더 포함) `EXPORT_OUTPUT_EXISTS`로 거절합니다. 덮어쓰지 않습니다.
- 상위 폴더가 없거나 링크이면 `EXPORT_OUTPUT_PARENT_MISSING`입니다.
- 출력이 원본 안쪽이거나 원본을 품으면 `EXPORT_OUTPUT_OVERLAP`입니다.
- 같은 상위 폴더의 임시 폴더에 `wx`로 쓰고 검증 후 마지막에 이름을 바꿉니다. 실패한 부분 결과는 재귀 삭제하지 않으며 오류의 partialDirectory/written으로 경로를 남깁니다.
- source·verify root와 모든 부모의 realpath·링크·identity, 파일의 단일 hard link와 fd/path identity·변경 시각·크기·SHA를 대조합니다. 복사 직전 source를 다시 확인하고 완성한 임시 패키지도 검증합니다. Node 경로 재검증만으로 같은 SID의 모든 경합을 원자적으로 차단한다고 주장하지 않습니다.

## 5. PACKAGE_MANIFEST.json

정확한 top-level shape는 schema/createdAt/appName/appNameNote/starter/runtime/totals/files/excluded입니다. runtime.node는 원본 package.json의 engines.node(없으면 null), exporterNode는 내보내기 실행의 process.version입니다. 다른 Node 버전의 실행 성공을 뜻하지 않습니다. 앱 이름은 안내문에만 쓰며 PowerShell 명령에는 보간하지 않습니다. 기존 길이32/NFC·제어 문자 검사는 유지합니다.

`files[].origin`은 `.on-starter-manifest.json`의 `sourceHashes`로 판정합니다.

| origin | 뜻 |
|---|---|
| `student` | `student/` 아래 파일 |
| `provided` | 시작 틀 해시와 같은 제공 파일, 또는 `.on-starter-manifest.json` |
| `provided-modified` | 시작 틀 목록에 있지만 해시가 다른 파일(학생이 16단계 이후 고친 화면·서버 등) |
| `student-added` | 시작 틀 목록에 없는 파일 |
| `package` | 이 도구가 넣은 파일(`START_HERE.md`, 도구 자신, 안내 틀) |

`.on-starter-manifest.json`이 없거나 깨졌으면 `student/` 밖의 파일은 모두 `student-added`로 적습니다.

origin은 위치와 기존 목록의 해시를 비교한 분류이며 작성자나 학생 성취를 인증하지 않습니다. 특히 새 개인 AI 제공 파일이 이전0.2.10 sourceHashes에 없어 student-added로 분류돼도 학생이 작성했거나 공식 단계를 통과했다는 근거가 아닙니다.

## 6. --verify

목록의 정확한 shape·정규 상대경로·대소문자 중복·해시·유한 정수·필수 파일·totals를 먼저 확인하고 실제 파일과 대조합니다. 빈 files·잘못된 합계·링크 root는 정상으로 인정하지 않습니다. 쓰기는 하지 않습니다. changed/missing/extra/link 중 하나라도 있으면 종료 코드2입니다. 목록 형식 오류는 코드1입니다. 목록 SHA는 파일 대조 기준이며 배포 주체를 인증하지 않습니다.

## 7. 지원 범위와 하지 않는 것

- 지원: 현재 시작 틀 0.2.10 런타임의 독립 실행(`node src/server.mjs`, 127.0.0.1, `ON_PORT`), 기본 `disconnected`, `--demo` 예제. 시험에서 출력 폴더로 실제 서버를 띄워 `GET /` 200, `/api/diagnostics`의 `engine.mode`가 기본 `disconnected`, `--demo`에서 `demo`, `ai.authorized:false`, `workbenchRequiredAtRuntime:false`를 확인합니다.
- 하지 않는 것: ZIP 출력, 시작 틀 재빌드, 워크벤치·포털 연동, 학생 앱 이름을 앱 코드·화면 제목에 반영, 외부 AI·SDP·XDR 연결 설정 생성, 비밀값 이전.
- 도구는 기존 공식 다운로드 사이트의 수료용 도구 묶음으로 전달합니다. 기존0.2.10 ZIP을 바꾸거나 학생 파일 위에 새 시작 틀을 덮지 않습니다.
- 학원 AI API·계정·권한이 수료 후 유지된다고 약속하지 않습니다. 19단계 실제 조치 처리와 21·22단계 공식 접수는 과정 안에서도 미완료입니다.
