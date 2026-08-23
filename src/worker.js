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

const dohHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'content-type',
};

async function handleDoH(request) {
    if (request.method === 'OPTIONS') {
        return new Response(null, { status: 204, headers: dohHeaders });
    }

    if (request.method !== 'GET' && request.method !== 'POST') {
        return new Response('Method Not Allowed', {
            status: 405,
            headers: { ...dohHeaders, Allow: 'GET, POST, OPTIONS' },
        });
    }

    const url = new URL(request.url);
    const upstream = new URL(UPSTREAM_DOH);
    const headers = new Headers({ Accept: 'application/dns-message' });

    if (request.method === 'GET') {
        const dns = url.searchParams.get('dns');
        if (!dns) return new Response('Missing dns parameter', { status: 400, headers: dohHeaders });
        upstream.searchParams.set('dns', dns);
    } else {
        const contentType = request.headers.get('Content-Type')?.split(';')[0].trim().toLowerCase();
        if (contentType !== 'application/dns-message') {
            return new Response('Content-Type must be application/dns-message', {
                status: 415,
                headers: dohHeaders,
            });
        }
        headers.set('Content-Type', 'application/dns-message');
    }

    try {
        const upstreamRequest = new Request(upstream, {
            method: request.method,
            headers,
            body: request.method === 'POST' ? request.body : undefined,
        });
        const response = await fetch(upstreamRequest);
        const responseHeaders = new Headers(dohHeaders);
        responseHeaders.set('Content-Type', 'application/dns-message');
        responseHeaders.set('Cache-Control', 'no-store');
        return new Response(response.body, {
            status: response.status,
            statusText: response.statusText,
            headers: responseHeaders,
        });
    } catch {
        return new Response('DoH upstream error', {
            status: 502,
            headers: { ...dohHeaders, 'Content-Type': 'text/plain; charset=utf-8' },
        });
    }
}

export default {
    async fetch(request, env) {
        try {
            const url = new URL(request.url);

            // DoH is handled before BPB initialization, so /dns-query works
            // independently of UUID, TROJAN_PASS, or the bpb KV binding.
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
                        return await getXrayWarpConfigs(request, env);
                    case '/panel':
                        return await handlePanel(request, env);
                    case '/login':
                        return await login(request, env);
                    case '/logout':
                        return await logout(request, env);
                    case '/reset-password':
                        return await resetPassword(request, env);
                    case '/secrets':
                        return await renderSecretsPage(request, env);
                    default:
                        return await fallback(request, env);
                }
            }

            if (globalThis.pathName === `/tr/${globalThis.userID}`) {
                return await trojanOverWSHandler(request, env);
            }
            return await vlessOverWSHandler(request, env);
        } catch (err) {
            return await renderErrorPage(err);
        }
    },
};
