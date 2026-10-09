// api/login.js
import { createClient } from '@supabase/supabase-js';

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method Not Allowed' });
  }

  const { email, password } = req.body || {};
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password required' });
  }

  const supabaseUrl = process.env.SUPABASE_URL;
  const supabaseKey = process.env.SUPABASE_SECRET_KEY;

  if (!supabaseUrl || !supabaseKey) {
    return res.status(500).json({ error: 'Server configuration missing' });
  }

  try {
    const supabase = createClient(supabaseUrl, supabaseKey, {
      auth: { autoRefreshToken: false, persistSession: false }
    });

    const { data, error } = await supabase.auth.signInWithPassword({
      email,
      password
    });

    if (error || !data.session) {
      return res.status(401).json({ error: error ? error.message : 'Login failed' });
    }

    // 브라우저에는 토큰과 사용자 정보만 돌려줌 (Supabase URL/키는 노출 안 됨)
    return res.status(200).json({
      access_token: data.session.access_token,
      user: {
        id: data.user.id,
        email: data.user.email
      }
    });
  } catch (err) {
    return res.status(500).json({ error: 'Internal Server Error' });
  }
}
