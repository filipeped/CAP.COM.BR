// ✅ DIGITAL PAISAGISMO CAPI V6.1 - LEAD CORRIGIDO E OTIMIZADO
// Corrigido: event_name fixo, event_source_url dinâmico, user_data em arrays para máxima compatibilidade

import type { NextApiRequest, NextApiResponse } from "next";
import crypto from "crypto";
import zlib from "zlib";

const PIXEL_ID = "1142320931265624";
const ACCESS_TOKEN = "EAAQfmxkTTZCcBPLhKvYsZALHTMSuDkSuOZCBoaIbPepL6jnlIU1nME7WQKM1z3z7HRkQZCCjWNBtN8aDEvZBtXei5bVYgYsjrWKDGhxLCoMDLNr4i0WXDmruHXbgr8z5P4ZBzJWCceb1d3M0mFSrzu1qZBm2yKs3IlsSTTh14MiiGD546da2rcePNWNMZCtZAjQZDZD";
const META_URL = `https://graph.facebook.com/v19.0/${PIXEL_ID}/events`;

function hashSHA256(value: string) {
  return crypto.createHash("sha256").update(value.trim().toLowerCase()).digest("hex");
}

const RATE_LIMIT = 30;
const rateLimitMap = new Map();

function rateLimit(ip: string): boolean {
  const now = Date.now();
  const windowMs = 60000;
  if (!rateLimitMap.has(ip)) rateLimitMap.set(ip, []);
  const timestamps = rateLimitMap.get(ip)!.filter((t: number) => now - t < windowMs);
  if (timestamps.length >= RATE_LIMIT) return false;
  timestamps.push(now);
  rateLimitMap.set(ip, timestamps);
  if (rateLimitMap.size > 1000) {
    const oldestKey = rateLimitMap.keys().next().value;
    rateLimitMap.delete(oldestKey);
  }
  return true;
}

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const startTime = Date.now();
  const ip = (req.headers["x-forwarded-for"] as string)?.split(",")[0]?.trim() || req.socket.remoteAddress || "unknown";
  const userAgent = req.headers["user-agent"] || "";
  const origin = req.headers.origin;

  const ALLOWED_ORIGINS = [
    "https://www.digitalpaisagismo.com.br",
    "https://cap.digitalpaisagismo.com.br",
    "https://atendimento.digitalpaisagismo.com.br",
    "http://localhost:3000"
  ];
  res.setHeader("Access-Control-Allow-Origin", ALLOWED_ORIGINS.includes(origin!) ? origin! : "https://www.digitalpaisagismo.com.br");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With");
  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("X-Robots-Tag", "noindex, nofollow");
  res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");

  if (req.method === "OPTIONS") return res.status(200).end();
  if (req.method !== "POST") return res.status(405).json({ error: "Method Not Allowed" });
  if (!rateLimit(ip)) return res.status(429).json({ error: "Limite de requisições excedido", retry_after: 60 });

  try {
    if (!req.body?.data || !Array.isArray(req.body.data)) {
      return res.status(400).json({ error: "Payload inválido - campo 'data' obrigatório" });
    }

    const enrichedData = req.body.data.map((event: any) => {
      const sessionId = event.session_id || "";
      const externalId = sessionId ? hashSHA256(sessionId) : "";
      const eventId = event.event_id || `evt_${Date.now()}_${Math.random().toString(36).substring(2, 10)}`;
      const eventName = event.event_name || "Lead";
      const eventSourceUrl = event.event_source_url || origin || req.headers.referer || "https://www.digitalpaisagismo.com.br";
      const eventTime = event.event_time || Math.floor(Date.now() / 1000);
      const actionSource = event.action_source || "website";

      const email = event.user_data?.email || "";
      const phone = event.user_data?.phone || "";
      const first_name = event.user_data?.first_name || "";
      const last_name = event.user_data?.last_name || "";

      const customData = {
        value: event.custom_data?.value ?? 0,
        currency: event.custom_data?.currency ?? "BRL",
        ...event.custom_data
      };

      return {
        event_name: eventName,
        event_id: eventId,
        event_time: eventTime,
        event_source_url: eventSourceUrl,
        action_source: actionSource,
        custom_data: customData,
        user_data: {
          external_id: externalId ? [externalId] : undefined,
          em: email ? [hashSHA256(email)] : undefined,
          ph: phone ? [hashSHA256(phone.replace(/\D/g, ""))] : undefined,
          fn: first_name ? [hashSHA256(first_name)] : undefined,
          ln: last_name ? [hashSHA256(last_name)] : undefined,
          client_ip_address: ip,
          client_user_agent: userAgent,
          fbp: typeof event.user_data?.fbp === "string" && event.user_data.fbp.startsWith("fb.") ? event.user_data.fbp : undefined,
          fbc: typeof event.user_data?.fbc === "string" && event.user_data.fbc.startsWith("fb.") ? event.user_data.fbc : undefined
        }
      };
    });

    const payload = { data: enrichedData };
    const shouldCompress = Buffer.byteLength(JSON.stringify(payload)) > 2048;
    const body = shouldCompress ? zlib.gzipSync(JSON.stringify(payload)) : JSON.stringify(payload);
    const headers = {
      "Content-Type": "application/json",
      "Connection": "keep-alive",
      "User-Agent": "DigitalPaisagismo-CAPI-Proxy/1.0",
      ...(shouldCompress && { "Content-Encoding": "gzip" })
    };

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8000);

    const response = await fetch(`${META_URL}?access_token=${ACCESS_TOKEN}`, {
      method: "POST",
      headers,
      body,
      signal: controller.signal
    });

    clearTimeout(timeout);
    const data = await response.json();
    const responseTime = Date.now() - startTime;

    if (!response.ok) {
      return res.status(response.status).json({
        error: "Erro da Meta",
        details: data,
        processing_time_ms: responseTime
      });
    }

    res.status(200).json({
      ...data,
      proxy_metadata: {
        processing_time_ms: responseTime,
        events_processed: enrichedData.length,
        compression_used: shouldCompress,
        timestamp: new Date().toISOString()
      }
    });

  } catch (error: any) {
    console.error("❌ Erro no Proxy CAPI:", error);
    if (error.name === "AbortError") {
      return res.status(408).json({ error: "Timeout ao enviar evento para a Meta", timeout_ms: 8000 });
    }
    res.status(500).json({ error: "Erro interno no servidor CAPI." });
  }
}
