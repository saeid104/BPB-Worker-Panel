import { initializeParams } from './helpers/init';
import { vlessOverWSHandler } from './protocols/vless';
import { trojanOverWSHandler } from './protocols/trojan';
import { updateWarpConfigs } from './kv/handlers';
import { logout, resetPassword, login } from './authentication/auth';
import { renderErrorPage } from './pages/error';
import { getXrayCustomConfigs, getXrayWarpConfigs } from './cores-configs/xray';
import { getSingBoxCustomConfig, getSingBoxWarpConfig } from './cores-configs/sing-box';
import { getClashNormalConfig, getClashWarpConfig } from './cores-configs/clash';
import { getNormalConfigs } from './cores-configs/normalConfigs';
import { fallback, getMyIP, handlePanel } from './helpers/helpers';
import { renderSecretsPage } from './pages/secrets';

const DOH_PATH = '/dns-query';
const UPSTREAM_DOH = 'https://cloudflare-dns.com/dns-query';

async function handleDoH(request) {
    if (request.method !== 'GET' && request.method !== 'POST') {
        return new Response('Method Not Allowed', { status: 405, headers: { Allow: 'GET, POST' } });
    }

    const url = new URL(request.url);
    const upstream = new URL(UPSTREAM_DOH);
    const headers = new Headers({ Accept: 'application/dns-message' });

    if (request.method === 'GET') {
        const dns = url.searchParams.get('dns');
        if (!dns) return new Response('Missing dns parameter', { status: 400 });
        upstream.searchParams.set('dns', dns);
    } else {
        headers.set('Content-Type', 'application/dns-message');
    }

    try {
        const upstreamRequest = new Request(upstream, {
            method: request.method,
            headers,
            body: request.method === 'POST' ? request.body : undefined
        });
        const response = await fetch(upstreamRequest);
        const responseHeaders = new Headers(response.headers);
        responseHeaders.set('Content-Type', 'application/dns-message');
        responseHeaders.set('Cache-Control', 'no-store');
        return new Response(response.body, {
            status: response.status,
            statusText: response.statusText,
            headers: responseHeaders
        });
    } catch {
        return new Response('DoH upstream error', { status: 502 });
    }
}

export default {
    async fetch(request, env) {
        try {
            const url = new URL(request.url);

            // DoH is intentionally handled before BPB initialization because
            // it does not require UUID/TROJAN/KV credentials.
            if (url.pathname === DOH_PATH) return await handleDoH(request);

            initializeParams(request, env);
            const upgradeHeader = request.headers.get('Upgrade');
            if (!upgradeHeader || upgradeHeader !== 'websocket') {
                switch (globalThis.pathName) {
                    case '/update-warp':
                        return await updateWarpConfigs(request, env);
                    case `/sub/${globalThis.userID}`:
                        if (globalThis.client === 'sfa') return await getSingBoxCustomConfig(request, env, false);
                        if (globalThis.client === 'clash') return await getClashNormalConfig(request, env);
                        if (globalThis.client === 'xray') return await getXrayCustomConfigs(request, env, false);
                        return await getNormalConfigs(request, env);
                    case `/fragsub/${globalThis.userID}`:
                        return globalThis.client === 'hiddify'
                            ? await getSingBoxCustomConfig(request, env, true)
                            : await getXrayCustomConfigs(request, env, true);
                    case `/warpsub/${globalThis.userID}`:
                        if (globalThis.client === 'clash') return await getClashWarpConfig(request, env);
                        if (globalThis.client === 'singbox' || globalThis.client === 'hiddify') return await getSingBoxWarpConfig(request, env, globalThis.client);
                        return await getXrayWarpConfigs(request, env, globalThis.client);
                    case '/panel':
                        return await handlePanel(request, env);
                    case '/login':
                        return await login(request, env);
                    case '/logout':
                        return logout();
                    case '/panel/password':
                        return await resetPassword(request, env);
                    case '/my-ip':
                        return await getMyIP(request);
                    case '/secrets':
                        return await renderSecretsPage();
                    default:
                        return await fallback(request);
                }
            }
            return globalThis.pathName.startsWith('/tr')
                ? await trojanOverWSHandler(request)
                : await vlessOverWSHandler(request);
        } catch (err) {
            return await renderErrorPage(err);
        }
    }
};
