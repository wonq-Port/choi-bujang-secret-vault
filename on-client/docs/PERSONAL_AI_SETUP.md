# 수료 후 독립 실행과 개인 AI 설정

수료용 도구 묶음은 내가 만든 `student/` 코드와 기존 앱을 보존하면서 **새 독립 실행 방식**을 추가합니다. 학원 계정·워크벤치·ALEPH 포털 없이 내 PC에서 실행할 수 있습니다. Node.js는 PC에 별도로 설치돼 있어야 합니다. 확인한 실행 버전은 **24.19.0**입니다. Node가 설치된 뒤 미연결 기본 실행과 예제 화면에는 인터넷이 필요하지 않습니다. 개인 AI와 실제 서버 연결에는 각각 네트워크와 본인의 이용 권한이 필요합니다.

## 1. 실행 방식을 먼저 구분하세요

| 실행 방법 | 용도 | AI·서버 상태 |
|---|---|---|
| `node src/server.mjs` | 기존 수업용 앱 | 기존 수업용 연결 계약을 유지합니다. 수료 후 권한이 유지된다고 보장하지 않습니다. |
| `node src/standalone-server.mjs` | 수료 후 독립 실행 | 기본은 서버 미연결·개인 AI 꺼짐입니다. |
| `node src/standalone-server.mjs --demo` | 예제 화면 확인 | 예제 자료입니다. 실제 사용자·접근 판정·보안 이벤트가 아닙니다. |

새 독립 실행에서도 기존 세 메뉴와 학생 구현은 그대로 사용합니다. 사이드바의 **개인 AI · 보안 이벤트 설명**에서 수료 후 개인 AI를 별도로 이용합니다. 이 기능은 학원 AI 이용 권한이나 공식 과제 판정을 대신하지 않습니다. AI가 설명하거나 대응 방안을 제안해도 실제 보안 조치를 실행하지 않습니다.

## 2. 기존 프로젝트에 도구 추가하기

공식 안내의 수료용 도구 ZIP과 SHA-256을 확인한 뒤 **기존 프로젝트 밖의 새 폴더**에 압축을 풉니다. 도구 묶음 폴더에서 PowerShell을 실행하고 아래 경로를 자신의 실제 `on-client` 폴더로 바꿉니다.

```powershell
node tools/install-portable-tools.mjs --bundle . --project "C:\내작업\on-client"
```

먼저 파일 목록의 `add`(새로 추가)와 `skip`(동일 파일)을 확인합니다. 이 명령은 파일을 쓰지 않습니다. 확인한 뒤에만 같은 명령 끝에 `--apply`를 붙입니다.

```powershell
node tools/install-portable-tools.mjs --bundle . --project "C:\내작업\on-client" --apply
```

다른 내용의 기존 파일이 있으면 `INSTALL_TARGET_CONFLICT`로 중단합니다. 원래 파일을 지워서 통과시키지 않습니다. 도구 묶음과 대상 경로가 맞는지 확인하고, 기존 파일이 학생이 수정한 파일이면 별도로 보관한 뒤 변경 내용을 비교합니다. 중간 실패 시 추가된 파일은 지우지 않으며, 오류의 `written` 목록에 남깁니다. 같은 바이트의 파일은 재실행 때 건너뜁니다. `.git`, `student/`, 기존 `src/server.mjs`·`public/app.js`·`package.json`은 덮어쓰지 않습니다.

## 3. AI를 끈 상태로 먼저 실행하기

학생 프로젝트의 `on-client` 폴더에서 실행합니다.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\start-standalone.ps1
```

브라우저에서 `http://127.0.0.1:5189/`를 엽니다. 기본 화면이 보이고 연결되지 않은 항목에 미연결·확인 불가가 표시되는지 확인합니다. 이 상태에서는 AI를 호출하지 않습니다. 개인 AI 화면은 `http://127.0.0.1:5189/personal/`입니다. 끝낼 때는 PowerShell에서 `Ctrl+C`를 누릅니다.

포트가 사용 중이면 다른 프로그램을 종료하지 말고 명령 끝에 `-Port 5190`을 붙입니다. 브라우저 주소도 `:5190`으로 바꿉니다. 예제 화면은 같은 명령에 `-Demo`를 붙여 별도로 확인합니다.

## 4. 내 앱 이름과 개인 설정 파일 만들기

설정 파일은 프로젝트·Git 저장소·패키지 밖에 보관합니다. 아래 명령은 기존 파일이 있으면 중단하며 덮어쓰지 않습니다. API 키는 이 JSON에 적지 않습니다.

```powershell
$settingsFolder = Join-Path $env:LOCALAPPDATA 'KeshevSettings'
New-Item -ItemType Directory -Path $settingsFolder -Force | Out-Null
$settingsFile = Join-Path $settingsFolder 'personal.json'
if (Test-Path -LiteralPath $settingsFile) { throw '기존 개인 설정이 있습니다. 파일을 직접 확인하세요.' }
Copy-Item -LiteralPath .\tools\portable\personal-config.example.json -Destination $settingsFile
notepad $settingsFile
```

`appName`을 원하는 이름으로 바꿉니다. 1~32자이며 앞뒤 공백은 제거합니다. 이름을 비워 두면 케셰브가 됩니다. 이 설정으로 새 독립 실행 방식을 시작하면 실제 앱 제목과 개인 AI 화면 이름에 반영됩니다. 포털에서 저장한 이름은 이 파일을 자동 변경하지 않습니다.

AI를 끈 채 이름만 적용하려면 다음처럼 실행합니다.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\start-standalone.ps1 -PersonalConfig $settingsFile
```

설정 파일은 UTF-8 JSON으로 저장합니다. 링크·junction·공유 경로·프로젝트 내부 설정 파일은 받지 않습니다. 설정 이름을 임의로 추가하거나 키를 JSON에 적으면 `PERSONAL_CONFIG_INVALID`로 중단합니다.

## 5. 개인 AI를 사용할 때만 설정하기

학원 AI 키를 복사하지 않습니다. 이미 본인이 이용 권한을 가진 공급자의 API 계정과 사용 한도를 먼저 확인합니다. 이 도구는 계정이나 키를 발급하지 않습니다.

1. 개인 설정 JSON의 `ai.enabled`를 `true`로 바꿉니다.
2. `provider`에는 `openai`, `openrouter`, `xai` 중 실제 본인 공급자를 적습니다. 임의 URL과 다른 주소로 이동하는 응답은 받지 않습니다.
3. `model`에는 그 계정에서 이용할 수 있는 **정확한 모델 ID**를 적습니다. 견본의 모델이 내 계정에서 제공된다는 뜻은 아닙니다. 자동 모델 선택과 대체 모델 호출은 하지 않습니다. 요청한 모델과 공급자 응답의 모델 ID가 다르면 결과를 표시하지 않습니다.
4. 아래처럼 실행합니다. API 키는 화면에 보이지 않는 입력창에서 입력하고, 서버 프로세스의 메모리와 환경 변수에만 둡니다. 파일·명령 기록·브라우저에 저장하지 않습니다.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\start-standalone.ps1 -PersonalConfig $settingsFile -PromptPersonalKey
```

이 기능은 Astra·Flash 모델 ID를 허용하지 않습니다. 다른 모델로 임의 대체하지 않으며, 지원되지 않거나 응답 형식이 다른 모델은 설정을 확인해야 합니다.

개인 AI 화면에서 **설정됨**은 설정이 준비됐다는 뜻입니다. 실제 요청 성공을 뜻하지 않습니다. 페이지를 열거나 상태를 확인하는 동작으로 유료 요청을 보내지 않습니다.

실제 연결된 본인 보안 이벤트를 선택하고, 화면에 나온 근거·규칙·상태와 외부 전송 안내를 읽습니다. 전송 및 본인 사용량·비용을 확인한 뒤 **선택한 보안 이벤트 설명 요청**을 누를 때만 공급자에게 보냅니다. 예제 모드에서 요청하면 예제 근거가 전송되며 실제 연결 검증으로 인정하지 않습니다. 취소해도 공급자가 이미 처리한 사용량은 발생할 수 있습니다. 자동 재시도는 하지 않습니다.

## 6. 실제 접근 제어·XDR 서버는 별도 연결입니다

개인 AI 키를 설정해도 회사 서버·본인 기기·접근 기록이 자동 연결되지는 않습니다. 기본은 미연결입니다. 기존 서버가 제공하는 API와 본인 범위의 조회 권한을 확인하고 `docs/IMPLEMENTATION_CONTRACT.md`에 맞는 어댑터가 있어야 합니다. `ON_ENGINE_ADAPTER`는 PC 실행자가 지정하는 모듈 경로이며, 브라우저에서 선택하지 않습니다. 다른 직원의 기록이나 관리자 전체 조회를 연결하지 않습니다.

실제 연결 어댑터는 현재 사용자의 활성 세션과 프로젝트를 확인하고 본인 기록에 `subjectId`·`projectId`를 붙여 반환해야 합니다. 세션·근거가 바뀌면 AI 설명을 중단하고 최신 기록을 확인합니다. 실제 조치 집행·인증서 발급·서버 계정 준비는 개인 AI 기능에 포함되지 않습니다. 연결하지 않은 기능을 정상이나 완료로 표시하지 않습니다.

## 7. 오류별 확인 방법

| 코드·상태 | 확인할 내용 |
|---|---|
| `STANDALONE_PORT_IN_USE` | 다른 프로그램이 해당 포트를 사용 중입니다. `-Port`를 바꿉니다. |
| `STANDALONE_CONFIGURATION_INVALID` | JSON 형식·절대경로·프로젝트 밖 위치·파일 링크·Node 버전을 확인합니다. |
| `PERSONAL_ACCESS_BLOCKED` | 개인 키와 공급자 계정의 이용 권한을 확인합니다. 키를 대화창에 붙이지 않습니다. |
| `PERSONAL_LIMIT_REACHED` | 공급자 계정의 사용 한도와 남은 사용량을 확인합니다. |
| `PERSONAL_MODEL_MISMATCH` | 요청 모델과 실제 응답 모델이 달랐습니다. 공급자의 정확한 모델 ID를 확인합니다. |
| `PERSONAL_INVALID_OUTPUT` | 근거·조치·응답 형식을 확인할 수 없습니다. 해당 결과를 실행 지시로 사용하지 않습니다. |
| `REQUEST_TIMEOUT`, `PERSONAL_TIMEOUT` | 응답 시간이 초과됐습니다. 사용량과 현재 상태를 확인하고 필요할 때만 직접 재요청합니다. |
| `EVENT_CHANGED`, `SUBJECT_SCOPE_UNVERIFIED` | 로그인 상태나 이벤트 근거가 바뀌었습니다. 상태를 다시 조회한 뒤 근거를 확인합니다. |
| `ENGINE_NOT_CONNECTED` | 실제 기록 서버가 미연결입니다. 개인 키 오류나 정상 빈 목록과 구분합니다. |

## 8. 최종 패키지와 검증 범위

`docs/AFTER_COURSE_GUIDE.md`를 따라 **내가 수정한 누적 프로젝트**를 새 폴더로 내보냅니다. 도구 묶음 자체에는 내 학생 코드가 들어 있지 않습니다. 개인 설정·키·DB·로그를 내보내지 않습니다. `FINAL_RELEASE_CHECKLIST.md`로 21단계 설명서와 22단계 새 폴더 실행·재시작·누적 기능을 확인합니다.

현재 제공 도구는 Node24.19.0 기본 실행·예제·파일 보존과 모의 HTTP에서 개인 AI 성공·실패·취소·모델 검증을 확인했습니다. 실제 개인 공급자의 유료 추론·실제 회사 서버 연결·19단계 조치 집행·21/22 공식 접수는 이 확인에 포함되지 않습니다. 사용한 모델·사용량·응답 시간은 실제 요청이 성공한 경우에만 공급자 응답과 함께 표시합니다.
