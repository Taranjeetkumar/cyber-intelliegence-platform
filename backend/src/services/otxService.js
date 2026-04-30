const OTX_BASE_URL = "https://otx.alienvault.com/api/v1";

const buildHeaders = () => {
  const headers = { Accept: "application/json" };
  const apiKey = process.env.OTX_API_KEY;

  if (apiKey) {
    headers["X-OTX-API-KEY"] = apiKey;
  }

  return headers;
};

const fetchSection = async (ipAddress, section) => {
  const url = `${OTX_BASE_URL}/indicators/IPv4/${encodeURIComponent(ipAddress)}/${section}`;
  const response = await fetch(url, { headers: buildHeaders() });
  const payload = await response.json().catch(() => ({}));

  if (!response.ok) {
    throw new Error(
      payload?.detail ||
        payload?.error ||
        `OTX ${section} request failed with status ${response.status}`
    );
  }

  return payload;
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

module.exports = { checkIpThreatIntel };
