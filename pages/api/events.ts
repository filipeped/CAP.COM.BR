import type { NextApiRequest, NextApiResponse } from "next";
import crypto from "crypto";

const PIXEL_ID = "1142320931265624";
const ACCESS_TOKEN = "EAAQfmxkTTZCcBPJqdYzaTyZB5WWFIMaXGDF9WhWWbgbO4jhifEM5l25TvjYzaBPT3QoZBiYG5cIxJnpHIQrxZCX7HUOlXcXX5yrCbdJIOD8fBcZAIpM9QSwiGo4gYTZA3AAtdrM5V38LLt4td6oW6ou6eCGzecRZBfSIev4yH258aQEZBdR3gBrgFrQZBAOoJTQZDZD";
const META_URL = `https://graph.facebook.com/v19.0/${PIXEL_ID}/events`;

function hashSHA256(value: string): string {
  return crypto.createHash("sha256").update(value.toLowerCase().trim()).digest("hex");
}

// Validação básica do payload recebido
function validatePayload(payload: any): boolean {
  if (!payload || !payload.data || !Array.isArray(payload.data) || payload.data.length === 0) {
    return false;
  }
  // Pode adicionar validações mais específicas para cada evento, se necessário
  return true;
}

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "*");

  if (req.method === "OPTIONS") return res.status(200).end();
  if (req.method !== "POST") return res.status(405).json({ error: "Method Not Allowed" });

  if (!PIXEL_ID || !ACCESS_TOKEN) {
    console.error("❌ Variáveis META_PIXEL_ID ou META_ACCESS_TOKEN não configuradas.");
    return res.status(500).json({ error: "Configuração do servidor incompleta." });
  }

  try {
    if (!validatePayload(req.body)) {
      console.log("❌ Payload inválido:", req.body);
      return res.status(400).json({ error: "Payload inválido - campo 'data' deve ser um array e não pode ser vazio" });
    }

    const { session_id, email, phone, first_name, last_name, fbp, fbc } = req.body;

    const getUserData = () => ({
      em: email ? hashSHA256(email) : undefined,
      ph: phone ? hashSHA256(phone.replace(/\D/g, "")) : undefined, // Higienização do telefone
      fn: first_name ? hashSHA256(first_name) : undefined,
      ln: last_name ? hashSHA256(last_name) : undefined,
      external_id: session_id ? hashSHA256(session_id) : undefined,
      client_ip_address: Array.isArray(req.headers["x-forwarded-for"])
        ? req.headers["x-forwarded-for"][0]
        : typeof req.headers["x-forwarded-for"] === "string"
          ? req.headers["x-forwarded-for"].split(",")[0].trim()
          : req.socket?.remoteAddress || undefined,
      client_user_agent: req.headers["user-agent"] || undefined,
      fbp: fbp || undefined,
      fbc: fbc || undefined,
    });

    const getEventSourceUrl = (event: any) => {
      if (event.event_source_url) return event.event_source_url;
      if (req.headers.referer) return req.headers.referer;
      if (req.headers.origin) return req.headers.origin;
      return "https://www.digitalpaisagismo.com.br"; // URL padrão de fallback
    };

    const getEnhancedPayload = (event: any) => ({
      ...event,
      event_source_url: getEventSourceUrl(event),
      action_source: "website",
      event_id: event.event_id || `ev-${session_id || Date.now()}-${event.event_name}`,
      event_time: event.event_time || Math.floor(Date.now() / 1000),
      user_data: getUserData()
    });

    const enhancedPayload = {
      data: req.body.data.map(getEnhancedPayload)
    };

    console.log("🔄 Enviando evento para Meta...");
    // Para debug detalhado, descomente a linha abaixo:
    // console.log(JSON.stringify(enhancedPayload, null, 2));

    const fbResponse = await fetch(`${META_URL}?access_token=${ACCESS_TOKEN}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(enhancedPayload)
    });

    const result = await fbResponse.json();
    
    if (fbResponse.ok) {
      console.log("✅ Resposta da Meta:", result);
      res.status(fbResponse.status).json(result);
    } else {
      console.error("❌ Erro da API da Meta:", result);
      res.status(fbResponse.status).json({ error: "Erro da API da Meta", details: result });
    }

  } catch (err) {
    console.error("❌ Erro interno:", err);
    res.status(500).json({ error: "Erro interno no servidor CAPI." });
  }
}
