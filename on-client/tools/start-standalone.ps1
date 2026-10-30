param(
  [string]$PersonalConfig,
  [ValidateRange(1024,65535)][int]$Port = 5189,
  [switch]$Demo,
  [switch]$PromptPersonalKey
)
$ErrorActionPreference = 'Stop'
$projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$entry = Join-Path $projectRoot 'src/standalone-server.mjs'
if (-not (Test-Path -LiteralPath $entry -PathType Leaf)) { throw '독립 실행 도구가 없습니다. 수료용 도구 묶음을 먼저 확인하세요.' }
if ($PromptPersonalKey -and [string]::IsNullOrWhiteSpace($PersonalConfig)) { throw '개인 설정 파일의 절대경로를 -PersonalConfig로 지정하세요.' }
$nodePath = (Get-Command node -ErrorAction Stop).Source
$oldPort = [Environment]::GetEnvironmentVariable('ON_PORT','Process')
$oldKey = [Environment]::GetEnvironmentVariable('KESHEV_PERSONAL_API_KEY','Process')
$secret = $null
try {
  if ($PromptPersonalKey) {
    $secret = Read-Host '본인 AI 공급자의 기존 API 키를 입력하세요(화면과 파일에 저장하지 않음)' -AsSecureString
    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secret)
    try { $env:KESHEV_PERSONAL_API_KEY = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }
  }
  $env:ON_PORT = [string]$Port
  $nodeArgs = @($entry)
  if (-not [string]::IsNullOrWhiteSpace($PersonalConfig)) { $nodeArgs += @('--personal-config',$PersonalConfig) }
  if ($Demo) { $nodeArgs += '--demo' }
  Write-Host '종료하려면 Ctrl+C를 누르세요. 개인 AI 설명은 화면에서 직접 요청할 때만 전송합니다.'
  & $nodePath @nodeArgs
  if ($LASTEXITCODE -ne 0) { throw '독립 실행을 시작하지 못했습니다. 위 오류 코드와 수료 후 설정 안내를 확인하세요.' }
}
finally {
  [Environment]::SetEnvironmentVariable('ON_PORT',$oldPort,'Process')
  [Environment]::SetEnvironmentVariable('KESHEV_PERSONAL_API_KEY',$oldKey,'Process')
  if ($null -ne $secret) { $secret.Dispose() }
}
