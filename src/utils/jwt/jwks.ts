import { DecodedJwt, JsonWebKeyset } from "@cfworker/jwt/dist/types";

interface JsonWebKey {
    x5c?: string[];
    kid?: string;
    x5t?: string;
    n?: string;
}
interface OidcMetadata {
    jwks_uri: string;
}

export async function getOidcMetadata(issuer: string): Promise<OidcMetadata> {
    const url = new URL(issuer);
    if (!url.pathname.endsWith('/')) {
        url.pathname += '/';
    }
    url.pathname += '.well-known/openid-configuration';
    const response = await fetch(url.href);
    if (!response.ok) {
        throw new Error(
            `Error loading oidc metadata at ${url.href}. ${response.status} ${response.statusText}`
        );
    }
    return response.json();
}
/**
 * Fetch a json web keyset.
 */
export async function getJwks(jwks_uri: string): Promise<JsonWebKeyset> {
    const response = await fetch(jwks_uri);
    if (!response.ok) {
        throw new Error(
            `Error loading jwks at ${jwks_uri}. ${response.status} ${response.statusText}`
        );
    }
    return response.json();
}

const importedKeys: Record<string, Record<string, CryptoKey>> = {};

/**
 * Import and cache a JsonWebKeyset
 * @param iss The issuer. Serves as the first-level cache key.
 * @param jwks The JsonWebKeyset to import.
 */
export async function importKey(iss: string, jwk: JsonWebKey): Promise<void> {
    const input = {
        kty: 'RSA',
        e: 'AQAB',
        n: jwk.n,
        alg: 'RS256',
        ext: true
    };
    const key = await crypto.subtle.importKey(
        'jwk',
        input,
        { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
        false,
        ['verify']
    );
    importedKeys[iss] = importedKeys[iss] || {};
    importedKeys[iss][jwk.kid || 'default'] = key;
}

/**
 * Get the CryptoKey associated with the JWT's issuer.
 */
export async function getKey(decoded: DecodedJwt): Promise<CryptoKey> {
    const {
        header: { kid = 'default' },
        payload: { iss }
    } = decoded;

    if (!importedKeys[iss]) {
        const metadata = await getOidcMetadata(iss);
        const jwks = await getJwks(metadata.jwks_uri);
        await Promise.all(jwks.keys.map(jwk => importKey(iss, jwk)));
    }

    const key = importedKeys[iss][kid];

    if (!key) {
        throw new Error(`Error jwk not found. iss: ${iss}; kid: ${kid};`);
    }

    return key;
}