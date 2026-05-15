const OTX_BASE_URL = "https://otx.alienvault.com/api/v1";
const REQUEST_TIMEOUT_MS = Number(process.env.THREAT_INTEL_TIMEOUT_MS || 5000);

const buildHeaders = () => {
  const headers = { Accept: "application/json" };
  const apiKey = process.env.OTX_API_KEY;

  if (apiKey) {
    headers["X-OTX-API-KEY"] = apiKey;
  }

  return headers;
};

const fetchJson = async (url) => {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

  try {
    const response = await fetch(url, { headers: buildHeaders(), signal: controller.signal });
    const payload = await response.json().catch(() => ({}));

    if (!response.ok) {
      throw new Error(
        payload?.detail ||
          payload?.error ||
          `OTX request failed with status ${response.status}`
      );
    }

    return payload;
  } catch (err) {
    if (err.name === "AbortError") {
      throw new Error("OTX request timed out");
    }
    throw err;
  } finally {
    clearTimeout(timeout);
  }
};

const fetchSection = async (ipAddress, section) => {
  const url = `${OTX_BASE_URL}/indicators/IPv4/${encodeURIComponent(ipAddress)}/${section}`;
  return fetchJson(url);
};

const checkIpThreatIntel = async (ipAddress) => {
  try {
    const [general, reputation] = await Promise.allSettled([
      fetchSection(ipAddress, "general"),
      fetchSection(ipAddress, "reputation"),
    ]);

    const result = {
      configured: Boolean(process.env.OTX_API_KEY),
      general: general.status === "fulfilled" ? general.value : null,
      reputation: reputation.status === "fulfilled" ? reputation.value : null,
      errors: [],
    };

    if (general.status === "rejected") result.errors.push(general.reason.message);
    if (reputation.status === "rejected") result.errors.push(reputation.reason.message);

    return result;
  } catch (err) {
    return {
      configured: Boolean(process.env.OTX_API_KEY),
      general: null,
      reputation: null,
      errors: [err.message],
    };
  }
};

const getSubscribedPulseIndicators = async ({ limit = 5 } = {}) => {
  if (!process.env.OTX_API_KEY) {
    return {
      configured: false,
      error: "OTX_API_KEY is not configured",
      data: [],
    };
  }

  const maxIndicators = Math.min(Math.max(Number(limit) || 5, 1), 25);
  const url = new URL(`${OTX_BASE_URL}/pulses/subscribed`);
  url.searchParams.set("limit", String(Math.min(maxIndicators, 10)));
  url.searchParams.set("page", "1");

  try {
    const payload = await fetchJson(url.toString());
    const pulses = Array.isArray(payload.results) ? payload.results : [];
    const seen = new Set();
    const indicators = [];

    for (const pulse of pulses) {
      const pulseIndicators = Array.isArray(pulse.indicators) ? pulse.indicators : [];

      for (const indicator of pulseIndicators) {
        if (indicator.type !== "IPv4" || !indicator.indicator || seen.has(indicator.indicator)) continue;
        seen.add(indicator.indicator);
        indicators.push({
          value: indicator.indicator,
          type: "ip",
          source: "otx-subscribed-pulse",
          pulse_id: pulse.id,
          pulse_name: pulse.name,
          adversary: pulse.adversary,
          tags: Array.isArray(pulse.tags) ? pulse.tags : [],
          modified: pulse.modified,
          created: pulse.created,
        });

        if (indicators.length >= maxIndicators) break;
      }

      if (indicators.length >= maxIndicators) break;
    }

    return {
      configured: true,
      data: indicators,
      pulse_count: pulses.length,
    };
  } catch (err) {
    return {
      configured: true,
      error: err.message,
      data: [],
    };
  }
};

module.exports = { checkIpThreatIntel, getSubscribedPulseIndicators };
