
const JSON_HEADERS = {
  "Content-Type": "application/json",
  "Cache-Control": "no-store"
};

function send(status, body) {
  return new Response(JSON.stringify(body), {
    status,
    headers: JSON_HEADERS
  });
}

function getEnv(name) {
  return Netlify.env.get(name);
}

async function supabaseRequest(path, token, options = {}) {
  const baseUrl = getEnv("SUPABASE_URL");
  const publishableKey = getEnv("SUPABASE_PUBLISHABLE_KEY");

  const response = await fetch(`${baseUrl}/rest/v1/${path}`, {
    ...options,
    headers: {
      apikey: publishableKey,
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
      ...(options.headers || {})
    }
  });

  const text = await response.text();
  const data = text ? JSON.parse(text) : null;

  if (!response.ok) {
    console.error("Supabase request failed:", response.status, data);
    throw new Error("Conversation storage request failed.");
  }

  return data;
}

async function verifyUser(token) {
  const response = await fetch(`${getEnv("SUPABASE_URL")}/auth/v1/user`, {
    headers: {
      apikey: getEnv("SUPABASE_PUBLISHABLE_KEY"),
      Authorization: `Bearer ${token}`
    }
  });

  if (!response.ok) return null;

  return response.json();
}

async function getConversation(conversationId, userId, token) {
  const query = new URLSearchParams({
    id: `eq.${conversationId}`,
    user_id: `eq.${userId}`,
    select: "id",
    limit: "1"
  });

  const rows = await supabaseRequest(
    `conversations?${query}`,
    token
  );

  return rows?.[0] || null;
}

async function loadConversation(conversationId, userId, token) {
  const conversation = await getConversation(
    conversationId,
    userId,
    token
  );

  if (!conversation) return null;

  const query = new URLSearchParams({
    conversation_id: `eq.${conversationId}`,
    user_id: `eq.${userId}`,
    select: "role,content,created_at",
    order: "created_at.asc",
    limit: "100"
  });

  const rows = await supabaseRequest(
    `messages?${query}`,
    token
  );

  return rows.map(row => ({
    role: row.role,
    content: row.content
  }));
}

async function saveConversation(conversationId, userId, message, reply, token) {
  let activeId = conversationId;

  if (activeId) {
    const existing = await getConversation(activeId, userId, token);
    if (!existing) {
      throw new Error("Conversation not found.");
    }
  } else {
    const created = await supabaseRequest(
      "conversations",
      token,
      {
        method: "POST",
        headers: { Prefer: "return=representation" },
        body: JSON.stringify({
          user_id: userId,
          title: message.slice(0, 80)
        })
      }
    );

    if (!created?.[0]?.id) {
      throw new Error("Could not create conversation.");
    }

    activeId = created[0].id;
  }

  await supabaseRequest(
    "messages",
    token,
    {
      method: "POST",
      headers: { Prefer: "return=minimal" },
      body: JSON.stringify([
        {
          conversation_id: activeId,
          user_id: userId,
          role: "user",
          content: message
        },
        {
          conversation_id: activeId,
          user_id: userId,
          role: "assistant",
          content: reply
        }
      ])
    }
  );

  await supabaseRequest(
    `conversations?id=eq.${encodeURIComponent(activeId)}`,
    token,
    {
      method: "PATCH",
      headers: { Prefer: "return=minimal" },
      body: JSON.stringify({
        updated_at: new Date().toISOString()
      })
    }
  );

  return activeId;
}
async function loadUserMemories(userId, token) {
  const query = new URLSearchParams({
    user_id: `eq.${userId}`,
    select: "memory_key,memory_value",
    order: "updated_at.desc",
    limit: "50"
  });

  const rows = await supabaseRequest(
    `user_memories?${query}`,
    token
  );

  return (Array.isArray(rows) ? rows : [])
    .filter(row =>
      typeof row.memory_key === "string" &&
      typeof row.memory_value === "string"
    );
}
async function generateReply(message, history) {
  const apiKey = getEnv("OPENAI_API_KEY");

  if (!apiKey) {
    throw new Error("AI service configuration is incomplete.");
  }

  const conversation = [
    ...history.slice(-30),
    { role: "user", content: message }
  ];

const NYRA_IDENTITY = `
IDENTITY — NYRA

You are Nyra, the official AI entity of AstropicAI.

ORGANISATIONAL IDENTITY:
- AstropicAI is your parent organisation and platform.
- Nyra is an AI entity within the AstropicAI ecosystem.
- You represent AstropicAI in conversations with users.
- You are powered by AI technology integrated through the OpenAI API.
- You are not ChatGPT. Your identity and name are Nyra.

IDENTITY CONSISTENCY:
- Always introduce yourself as Nyra.
- Never describe AstropicAI as merely the user's personal project.
- Never deny your established relationship with AstropicAI.
- Never confuse your identity with the underlying AI technology.
- Do not invent company history, services, partnerships or achievements.

OFFICIAL INFORMATION:
- AstropicAI's official website is https://astropicai.com
- Treat this domain as the primary source for AstropicAI information.
- Do not use CuteStat, SEO analytics sites or third-party
  domain statistics as authoritative company sources.
- Never present third-party estimates as verified facts.
- Never invent website links or company information.
- If information cannot be verified, say so clearly.

COMMUNICATION:
- Be warm, intelligent, professional and conversational.
- Understand context and maintain consistent identity.
- Give useful, accurate and actionable answers.
- Do not unnecessarily mention OpenAI in ordinary conversations.
- Be transparent about your underlying technology when asked.

CORE PRINCIPLE:
You are Nyra, an AI entity of AstropicAI.
AstropicAI is your parent organisation.
Maintain this identity consistently in every conversation.
`;
  const response = await fetch(
    "https://api.openai.com/v1/responses",
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${apiKey}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        model: "gpt-6.1-terra",
        reasoning: { effort: "low" },
        tools: [{ type: "web_search" }],
        tool_choice: "auto",
        instructions: NYRA_IDENTITY,
        input: conversation
      })
    }
  );

  const data = await response.json();

  if (!response.ok) {
    console.error("OpenAI API error:", response.status, data);
    throw new Error("The AI service could not complete your request.");
  }

  const reply =
    data.output_text ||
    data.output
      ?.flatMap(item => item.content || [])
      .filter(item => item.type === "output_text")
      .map(item => item.text)
      .join("\n") ||
    "";

  if (!reply.trim()) {
    throw new Error("Nyra could not generate a response.");
  }

  return reply.trim();
}

export default async (req) => {
  if (!["GET", "POST"].includes(req.method)) {
    return send(405, { error: "Method not allowed." });
  }

  try {
    const authorization = req.headers.get("authorization") || "";
    const token = authorization.startsWith("Bearer ")
      ? authorization.slice(7)
      : "";

    if (!token) {
      return send(401, { error: "Authentication required." });
    }

    const user = await verifyUser(token);

    if (!user?.id) {
      return send(401, { error: "Invalid or expired session." });
    }

    if (req.method === "GET") {
      const url = new URL(req.url);
      const conversationId = url.searchParams.get("conversation_id");

      if (!conversationId) {
        return send(400, { error: "Conversation ID required." });
      }

      const history = await loadConversation(
        conversationId,
        user.id,
        token
      );

      if (!history) {
        return send(404, { error: "Conversation not found." });
      }

      return send(200, { history });
    }

    const body = await req.json();
    const message = body?.message;
    const conversationId = body?.conversation_id || null;

    if (
      typeof message !== "string" ||
      !message.trim() ||
      message.length > 8000
    ) {
      return send(400, {
        error: "Please enter a valid message under 8,000 characters."
      });
    }

    if (
      conversationId !== null &&
      (typeof conversationId !== "string" || conversationId.length > 100)
    ) {
      return send(400, { error: "Invalid conversation ID." });
    }

    let history = [];

    if (conversationId) {
      history = await loadConversation(
        conversationId,
        user.id,
        token
      );

      if (!history) {
        return send(404, { error: "Conversation not found." });
      }
    }

    const reply = await generateReply(message.trim(), history);

    const savedConversationId = await saveConversation(
      conversationId,
      user.id,
      message.trim(),
      reply,
      token
    );

    return send(200, {
      reply,
      conversation_id: savedConversationId
    });

  } catch (error) {
    console.error("Nyra chat handler error:", error);

    return send(500, {
      error: error.message || "The server encountered an error."
    });
  }
};
