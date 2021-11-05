import { sha256 } from "../utils/sha256";

/**
 * This method attempts to obtain a token in an On-Behalf-Of (OBO) flow and cache it using Cloudflare worker's cache for 60 seconds.
 */
export async function getOboTokenCached(tenant: string, token: string, event: FetchEvent): Promise<any> {
    const oboRequest = new Request(`https://login.microsoftonline.com/${tenant}/oauth2/v2.0/token`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
            grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
            client_id: OBO_CLIENT_ID,
            client_secret: OBO_CLIENT_SECRET,
            assertion: token,
            scope: 'https://graph.microsoft.com/.default',
            requested_token_use: 'on_behalf_of'
        })
    });

    const body = await oboRequest.clone().text();
    const hash = await sha256(body);
    const cacheUrl = new URL(oboRequest.url);
    cacheUrl.pathname = cacheUrl.pathname + "/" + hash;
    const cacheKey = new Request(cacheUrl.toString(), {
        headers: oboRequest.headers,
        method: "GET",
    });

    const cache = caches.default;
    const result = await cache.match(cacheKey);
    if (result) {
        return result.json();
    } else {
        const response = await fetch(oboRequest);

        if (response.ok) {
            const cacheReposponse = new Response(await response.clone().blob(), {
                status: response.status,
                ok: response.ok,
                headers: {
                    'Cache-Control': `Max-Age=60`
                }
            });
            event.waitUntil(cache.put(cacheKey, cacheReposponse.clone()));

            return response.json();
        } else {
            throw new Error(`Unable to obtain OBO token: ${response.status}: ${response.statusText}`);
        }
    }
}