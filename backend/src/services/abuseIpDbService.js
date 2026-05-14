const ABUSEIPDB_CHECK_URL = "https://api.abuseipdb.com/api/v2/check";
const REQUEST_TIMEOUT_MS = Number(process.env.THREAT_INTEL_TIMEOUT_MS || 5000);

const parseMaxAge = () => {
  const value = Number.parseInt(process.env.ABUSEIPDB_MAX_AGE_DAYS || "90", 10);
  if (Number.isNaN(value)) return 90;
  return Math.min(Math.max(value, 1), 365);
};

const checkIpReputation = async (ipAddress) => {
  const apiKey = process.env.ABUSEIPDB_API_KEY;

  if (!apiKey) {
    return {
      configured: false,
      error: "ABUSEIPDB_API_KEY is not configured",
    };
  }

  const url = new URL(ABUSEIPDB_CHECK_URL);
  url.searchParams.set("ipAddress", ipAddress);
  url.searchParams.set("maxAgeInDays", String(parseMaxAge()));
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

  try {
    const response = await fetch(url, {
      headers: {
        Accept: "application/json",
        Key: apiKey,
      },
      signal: controller.signal,
    });

    const payload = await response.json().catch(() => ({}));

    if (!response.ok) {
      return {
        configured: true,
        error:
          payload?.errors?.[0]?.detail ||
          payload?.message ||
          `AbuseIPDB request failed with status ${response.status}`,
      };
    }

    return {
      configured: true,
      data: payload.data,
    };
  } catch (err) {
    return {
      configured: true,
      error: err.name === "AbortError" ? "AbuseIPDB request timed out" : err.message,
    };
  } finally {
    clearTimeout(timeout);
  }
};

module.exports = { checkIpReputation };
