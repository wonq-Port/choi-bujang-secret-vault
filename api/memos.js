// api/memos.js
import fs from 'node:fs';
import path from 'node:path';
import { createLoginVerifier } from '../src/verify-login.mjs';

// aleph.config.json 읽기
const configPath = path.resolve(process.cwd(), 'aleph.config.json');
const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));

let verifier;
function getVerifier() {
  if (!verifier) {
    verifier = createLoginVerifier({
      config,
      supabaseSecretKey: process.env.SUPABASE_SECRET_KEY,
    });
  }
  return verifier;
}

export default async function handler(req, res) {
  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method Not Allowed' });
  }

  // 1. 요청 헤더에서 토큰 추출 및 검증 (클라이언트의 userId, role은 무시)
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res.status(401).json({ error: 'Unauthorized: missing authorization header' });
  }

  let user;
  try {
    const verify = getVerifier();
    user = await verify(authHeader);
  } catch (err) {
    return res.status(401).json({ error: 'Unauthorized: invalid verification' });
  }

  // 2. 검증 실패(토큰 위조, 만료 등) 시 자료 없이 401 반환
  if (!user) {
    return res.status(401).json({ error: 'Unauthorized: invalid token' });
  }

  // 3. 정상 로그인(A 계정 또는 심판 토큰) 검증 완료 시 자료 조회
  const supabaseUrl = process.env.SUPABASE_URL;
  const supabaseSecretKey = process.env.SUPABASE_SECRET_KEY;

  if (!supabaseUrl || !supabaseSecretKey) {
    return res.status(500).json({ error: 'Server configuration missing' });
  }

  try {
    const response = await fetch(`${supabaseUrl}/rest/v1/memos?select=id,title,content,created_at`, {
      headers: {
        'apikey': supabaseSecretKey,
        'Authorization': `Bearer ${supabaseSecretKey}`,
        'Content-Type': 'application/json'
      }
    });

    if (!response.ok) {
      return res.status(response.status).json({ error: 'Failed to fetch memos' });
    }

    const data = await response.json();
    return res.status(200).json({ notes: data });
  } catch (err) {
    return res.status(500).json({ error: 'Internal Server Error' });
  }
}
