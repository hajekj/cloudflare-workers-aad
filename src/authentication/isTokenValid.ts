import { decodeJwt } from "@cfworker/jwt/dist/decode";
import { DecodedJwt } from "@cfworker/jwt/dist/types";
import { IClaims } from "../interfaces/IClaims";
import { parseJwt } from "../utils/jwt/parse";

export async function isTokenValid(token?: string | null): Promise<[authenticated: boolean, claims: IClaims | null]> {
    if (token !== undefined && token !== null) {
        let decodedJwt: DecodedJwt;
        try {
            decodedJwt = decodeJwt(token);
        } catch {
            return [false, null];
        }

        // TODO: Validate issuer

        const validatedJwt = await parseJwt(token, decodedJwt.payload.iss, AUDIENCE);
        if (!validatedJwt.valid) {
            return [false, null];
        } else {
            return [true, validatedJwt.payload as any];
        }
    }
    else {
        return [false, null];
    }
}