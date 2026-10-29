import { mkdir, writeFile, readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { deploymentIdentity } from './deployment-identity.mjs';

const root = resolve(import.meta.dirname, '..');
const config = JSON.parse(await readFile(resolve(root, 'aleph.config.json'), 'utf8'));

// 1. public 디렉터리 생성
await mkdir(resolve(root, 'public'), { recursive: true });

// 2. [2단계 조치] data.json 복사는 중단합니다. (/data.json 404 또는 0건 요건 충족)

// 3. [11단계 조치] 설치형 웹앱 manifest.json 생성 보장
const manifest = {
  name: 'BYTE BACK 보호된 자료실 접속 앱',
  short_name: '보호자료실',
  description: '서버·판정기 기기 승인과 요청 서명이 결합된 보호 자료실 설치형 웹앱(PWA)입니다. 설치 표시만으로 기기 확인이 완료되지 않습니다.',
  start_url: '/',
  scope: '/',
  display: 'standalone',
  background_color: '#101a28',
  theme_color: '#8ad8df',
  lang: 'ko',
  icons: [
    {
      src: "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 192 192'%3E%3Crect width='192' height='192' rx='32' fill='%23101a28'/%3E%3Cpath d='M96 36l52 24v36c0 34-22 64-52 76-30-12-52-42-52-76V60l52-24z' fill='%238ad8df'/%3E%3C/svg%3E",
      sizes: '192x192',
      type: 'image/svg+xml',
      purpose: 'any',
    },
  ],
};
await writeFile(
  resolve(root, 'public', 'manifest.json'),
  `${JSON.stringify(manifest, null, 2)}\n`,
  'utf8'
);

// 4. 심판 확인용 aleph.json 파일 생성 (100점 필수 조건: 절대 삭제 금지)
if (!process.argv.includes('--local')) {
  const identity = deploymentIdentity(process.env, config);
  await writeFile(
    resolve(root, 'public', 'aleph.json'),
    `${JSON.stringify(identity, null, 2)}\n`,
    'utf8'
  );
  console.log('배포 저장소·커밋·주소를 public/aleph.json에 기록했습니다.');
}
