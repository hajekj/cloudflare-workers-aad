declare global {
    const AUTHORITY: string;
    const AUDIENCE: string;
    const OBO_CLIENT_ID: string;
    const OBO_CLIENT_SECRET: string;
}

import { getOboTokenCached } from './authentication/getOboTokenCached';
import { isTokenValid } from './authentication/isTokenValid';

export async function handleRequest(request: Request, event: FetchEvent): Promise<Response> {
    const authHeader = request.headers.get('Authorization');
    const jwt = authHeader?.split(' ').pop() ?? null;

    const authenticationResult = await isTokenValid(jwt);
    if (jwt !== null && authenticationResult[0]) {
        try {
            const tenant = authenticationResult[1]?.['tid'];
            if (!tenant) {
                return new Response(`Unable to obtain tenant from token`, {
                    status: 403,
                    statusText: 'Forbidden'
                });
            }
            const url = new URL(request.url);
            switch (url.pathname) {
                case '/graph/me':
                    const authResponse = await getOboTokenCached(tenant, jwt, event);

                    const graphResponse = await fetch(`https://graph.microsoft.com/v1.0/me`, {
                        headers: {
                            "Authorization": `Bearer ${authResponse.access_token}`
                        }
                    });

                    if (graphResponse && graphResponse.ok) {
                        const data = await graphResponse.json();
                        return new Response(`${JSON.stringify({ claims: authenticationResult[1], graphResponse: data })}`, {
                            headers: {
                                'Content-Type': 'application/json, charset=utf-8'
                            }
                        });
                    }
                    else {
                        return graphResponse;
                    }
                default:
                    return new Response(`${JSON.stringify({ claims: authenticationResult[1] })}`, {
                        headers: {
                            'Content-Type': 'application/json, charset=utf-8'
                        }
                    });
            }
        }
        catch (err) {
            return new Response(`Something went wrong!\n\n${JSON.stringify(err)}`);
        }
    }
    else {
        return new Response(`Unauthorized`);
    }
}
