
const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" }
  });

export default async (req) => {
  const env = (key) => process.env[key];

  const url = env("SUPABASE_URL")?.replace(/\/+$/, "");
  const anon = env("SUPABASE_ANON_KEY");
  const service = env("SUPABASE_SERVICE_ROLE_KEY");
  const openai = env("OPENAI_API_KEY");

  if (req.method === "GET") {
    if (!url || !anon) return json({ error: "Supabase configuration missing" }, 500);
    return json({ supabaseUrl: url, supabaseAnonKey: anon });
  }

  if (req.method !== "POST") return json({ error: "Method not allowed" }, 405);

  try {
    if (!url || !anon || !service || !openai)
      return json({ error: "Server configuration incomplete" }, 500);

    const token = (req.headers.get("Authorization") || "").replace(/^Bearer /, "");
    if (!token) return json({ error: "Sign in required" }, 401);

    const auth = await fetch(`${url}/auth/v1/user`, {
      headers: { apikey: anon, Authorization: `Bearer ${token}` }
    });

    if (!auth.ok) return json({ error: "Invalid session" }, 401);

    const user = await auth.json();
    const userId = user.id;

    const db = async (table, query = "", method = "GET", body = null, prefer = "") => {
      const response = await fetch(`${url}/rest/v1/${table}${query}`, {
        method,
        headers: {
          apikey: service,
          Authorization: `Bearer ${service}`,
          "Content-Type": "application/json",
          ...(prefer ? { Prefer: prefer } : {})
        },
        ...(body ? { body: JSON.stringify(body) } : {})
      });

      const text = await response.text();
      if (!response.ok) {
        console.error("Database error:", response.status, text);
        throw new Error("Database operation failed");
      }
      return text ? JSON.parse(text) : null;
    };

    const data = await req.json();
    let conversationId = data.conversation_id || null;

    if (conversationId) {
      const owned = await db(
        "conversations",
        `?id=eq.${conversationId}&user_id=eq.${userId}&select=id`
      );
      if (!owned.length) return json({ error: "Conversation not found" }, 404);
    }

    if (data.action === "load") {
      if (!conversationId)
        return json({ messages: [], memories: [] });

      const [messages, memories] = await Promise.all([
        db("messages", `?conversation_id=eq.${conversationId}&user_id=eq.${userId}&select=role,content&order=created_at.asc&limit=100`),
        db("user_memories", `?user_id=eq.${userId}&select=memory_key,memory_value&order=updated_at.desc&limit=30`)
      ]);

      return json({ conversation_id: conversationId, messages, memories });
    }

    const message = (data.message || "").trim();
    if (!message) return json({ error: "Message is empty" }, 400);

    if (!conversationId) {
      const created = await db(
        "conversations",
        "?select=id",
        "POST",
        [{ user_id: userId, title: message.slice(0, 70) }],
        "return=representation"
      );
      conversationId = created[0].id;
    }

    let memorySaved = false;
    const match = message.match(/^(?:please\s+)?remember(?:\s+that)?\s+([\s\S]+)$/i);

    if (match) {
      await db(
        "user_memories",
        "",
        "POST",
        [{
          user_id: userId,
          memory_key: `note_${Date.now()}_${crypto.randomUUID()}`,
          memory_value: match[1].slice(0, 4000)
        }],
        "return=minimal"
      );
      memorySaved = true;
    }

    await db("messages", "", "POST", [{
      conversation_id: conversationId,
      user_id: userId,
      role: "user",
      content: message
    }], "return=minimal");

    const [history, memories] = await Promise.all([
      db("messages", `?conversation_id=eq.${conversationId}&user_id=eq.${userId}&select=role,content&order=created_at.desc&limit=12`),
      db("user_memories", `?user_id=eq.${userId}&select=memory_value&order=updated_at.desc&limit=30`)
    ]);

    const memoryContext = memories.length
      ? "\n\nSaved user memories:\n" + memories.map(m => "- " + m.memory_value).join("\n")
      : "";

    const ai = await fetch("https://api.openai.com/v1/responses", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${openai}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        model: "gpt-5-mini",
        instructions:
          "You are Nyra, the AI assistant created by AstropicAI. Be helpful, intelligent, friendly and honest. Use saved memories only when relevant." +
          memoryContext,
        input: history.reverse().map(m => ({
          role: m.role,
          content: m.content
        }))
      })
    });

    const result = await ai.json();
    if (!ai.ok) {
      console.error("OpenAI error:", result);
      return json({ error: "AI service failed" }, 502);
    }

    const reply = result.output_text ||
      result.output?.flatMap(x => x.content || [])
        .filter(x => x.type === "output_text")
        .map(x => x.text).join("\n") ||
      "I couldn't generate a response.";

    await db("messages", "", "POST", [{
      conversation_id: conversationId,
      user_id: userId,
      role: "assistant",
      content: reply
    }], "return=minimal");

    await db(
      "conversations",
      `?id=eq.${conversationId}&user_id=eq.${userId}`,
      "PATCH",
      { updated_at: new Date().toISOString() },
      "return=minimal"
    );

    return json({
      reply,
      conversation_id: conversationId,
      memory_saved: memorySaved
    });

  } catch (error) {
    console.error("Nyra error:", error);
    return json({ error: "Nyra encountered a server error" }, 500);
  }
};
