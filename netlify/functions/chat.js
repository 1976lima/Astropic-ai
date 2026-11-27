
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

export default async (req) => {
  if (req.method !== "POST") {
    return send(405, { error: "Method not allowed." });
  }

  try {
    const body = await req.json();

    const { message, history = [] } = body || {};

    if (
      typeof message !== "string" ||
      !message.trim() ||
      message.length > 8000
    ) {
      return send(400, {
        error: "Please enter a valid message under 8,000 characters."
      });
    }

    if (!Array.isArray(history) || history.length > 30) {
      return send(400, {
        error: "Invalid conversation history."
      });
    }

    const validHistory = [];

    for (const item of history) {
      if (
        !item ||
        !["user", "assistant"].includes(item.role) ||
        typeof item.content !== "string" ||
        !item.content.trim() ||
        item.content.length > 8000
      ) {
        return send(400, {
          error: "Invalid conversation history entry."
        });
      }

      validHistory.push({
        role: item.role,
        content: item.content
      });
    }

    // Keep only the latest 30 messages.
    const conversation = [
      ...validHistory.slice(-30),
      {
        role: "user",
        content: message.trim()
      }
    ];

    const apiKey = Netlify.env.get("OPENAI_API_KEY");

    if (!apiKey) {
      console.error("OPENAI_API_KEY is missing.");

      return send(500, {
        error: "AI service configuration is incomplete."
      });
    }

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
          tools: [
            { type: "web_search" }
          ],
          tool_choice: "auto",
          input: conversation
        })
      }
    );

    const data = await response.json();

    if (!response.ok) {
      console.error(
        "OpenAI API error:",
        response.status,
        data
      );

      return send(502, {
        error: "The AI service could not complete your request."
      });
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
      console.error("OpenAI returned no text output.");

      return send(502, {
        error: "Nyra could not generate a response."
      });
    }

    return send(200, {
      reply: reply.trim()
    });

  } catch (error) {
    console.error("Nyra chat handler error:", error);

    return send(500, {
      error: "The server encountered an error."
    });
  }
};
