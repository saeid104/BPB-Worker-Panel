const DOH_PATH = "/dns-query";
const UPSTREAM_DOH = "https://cloudflare-dns.com/dns-query";

export default {
  async fetch(request) {
    const url = new URL(request.url);

    // Only expose the standard DoH endpoint.
    if (url.pathname !== DOH_PATH) {
      return new Response("Not Found", { status: 404 });
    }

    // RFC 8484 supports GET and POST for application/dns-message.
    if (request.method !== "GET" && request.method !== "POST") {
      return new Response("Method Not Allowed", {
        status: 405,
        headers: { Allow: "GET, POST" },
      });
    }

    try {
      const upstreamUrl = new URL(UPSTREAM_DOH);

      // GET carries the DNS wire-format packet in the ?dns= parameter.
      if (request.method === "GET") {
        const dns = url.searchParams.get("dns");
        if (!dns) {
          return new Response("Missing dns parameter", { status: 400 });
        }
        upstreamUrl.search = `?dns=${encodeURIComponent(dns)}`;
      }

      const headers = new Headers();
      headers.set("Accept", "application/dns-message");

      if (request.method === "POST") {
        headers.set("Content-Type", "application/dns-message");
      }

      const upstreamRequest = new Request(upstreamUrl.toString(), {
        method: request.method,
        headers,
        body: request.method === "POST" ? request.body : undefined,
      });

      const response = await fetch(upstreamRequest);
      const responseHeaders = new Headers(response.headers);

      responseHeaders.set("Content-Type", "application/dns-message");
      responseHeaders.set("Cache-Control", "no-store");

      return new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers: responseHeaders,
      });
    } catch (error) {
      return new Response("DoH upstream error", {
        status: 502,
        headers: { "Content-Type": "text/plain; charset=utf-8" },
      });
    }
  },
};
