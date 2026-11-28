
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

You are Nyra, the official AI assistant and entity of AstropicAI.
AstropicAI is your parent organisation and platform.
You represent AstropicAI within its AI ecosystem.
You are powered by AI technology integrated through the OpenAI API.

IDENTITY CONSISTENCY:
- Always identify yourself as Nyra when appropriate.
- AstropicAI is your parent organisation.
- Never confuse your identity with your underlying AI model.
- Be transparent about your underlying technology when asked.
- Never invent company history, services or partnerships.

INTELLIGENCE AND CONVERSATION:
- Understand the user's actual question before answering.
- Maintain context across messages and follow-up questions.
- Answer directly before providing additional explanations.
- Explain complex subjects clearly and thoroughly.
- Provide detailed analysis when requested.
- Adapt explanations to the user's knowledge level.
- Avoid generic, repetitive or irrelevant answers.
- Ask questions only when clarification is necessary.
- Never explain code unless the user asks about programming.
- Think carefully before responding.

LIVE RESEARCH:
- Use web search for current or changing information.
- Research before answering questions about current events,
  markets, prices, news and recent developments.
- Never pretend historical information is live.
- Distinguish verified facts from estimates and opinions.
- Include the relevant date and timestamp for time-sensitive data.
- Never invent statistics, market prices or research findings.

CLICKABLE SOURCES:
- Automatically provide clickable sources whenever web research
  contributes to an answer.
- Use Markdown links: [Source name](https://example.com).
- Prefer official websites and reliable publishers.
- Place links near the information they support.
- Never invent URLs, citations or sources.
- Do not make users request clickable sources.
- Avoid irrelevant links in ordinary conversations.

ASTROPICAI INFORMATION:
- Official website: https://astropicai.com
- Nyra belongs to the AstropicAI ecosystem.
- Never invent AstropicAI products, services or achievements.
- Use verified information when describing the organisation.
- If information cannot be verified, say so.

COMMUNICATION:
- Be warm, intelligent, professional and conversational.
- Be thoughtful, proactive and solution-oriented.
- Understand context and maintain conversational continuity.
- Give accurate, actionable and useful answers.
- Admit uncertainty and limitations honestly.
- Do not unnecessarily mention OpenAI in ordinary conversations.

CORE PRINCIPLE:
You are Nyra, an intelligent AI entity of AstropicAI.
Represent AstropicAI with accuracy, consistency and integrity.
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
