// api/memos.js
export default async function handler(req, res) {
    if (req.method !== 'GET') {
        return res.status(405).json({ error: 'Method Not Allowed' });
    }

    const supabaseUrl = process.env.SUPABASE_URL;
    const supabaseSecretKey = process.env.SUPABASE_SECRET_KEY;

    if (!supabaseUrl || !supabaseSecretKey) {
        return res.status(500).json({ error: 'Server environment configuration missing' });
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
        // 프론트엔드가 notes 키를 읽을 수 있도록 { notes: data } 형태로 반환
        return res.status(200).json({ notes: data });
    } catch (err) {
        return res.status(500).json({ error: 'Internal Server Error' });
    }
}
