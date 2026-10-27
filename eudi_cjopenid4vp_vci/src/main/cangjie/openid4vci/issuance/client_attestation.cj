/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * client_attestation.cj — Client attestation PoP JWT generation.
 *
 * Ported from iOS:
 *   - Sources/Main/AttestationBasedClient/ClientAttestationPoPJWT.swift
 *   - Sources/Main/AttestationBasedClient/ClientAttestationPoPJWTSpec.swift
 *   - Sources/Main/AttestationBasedClient/ClientAttestationPoPBuilder.swift
 *   - Sources/Main/AttestationBasedClient/ClientAttestation.swift
 *   - Sources/Main/AttestationBasedClient/ClientAuthenticationMethod.swift
 *   - Sources/Main/AttestationBasedClient/ClientAttestationError.swift
 *
 * iOS async throws → sync throws.
 * iOS JOSESwift JWS → Cangjie: JoseJws.signEs256 (from eudi_cjjose).
 *
 * The attestation PoP JWT is used in authorization requests for ClientKind.Attested
 * clients (OAuth 2.0 Attestation-Based Client Authentication draft).
 *
 * Structure:
 *   Header: { "alg": "<alg>", "typ": "<typ>" }
 *   Payload: { "iss": <clientId>, "jti": <random>, "exp": <now+duration>,
 *              "iat": <now>, "aud": <authServerId>, "cnf": <jwkCnf>, "nonce": <challenge> }
 *   Signature: ES256 over header.payload
 *
 * Known Limitation:
 *   - The `ClientAttestationJWT` validation (cnf/jwk) requires a full JWS verify path;
 *     only structural parsing is implemented here (no signature verification of the
 *     attestation JWT itself — verification is the issuer's responsibility).
 *   - Only ES256 signing is implemented (matching the EUDI wallet spec).
 */
package ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.issuance

import std.collection.*
import std.time.DateTime
import stdx.encoding.json.*
import stdx.crypto.keys.ECDSAPrivateKey
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.util.JWTClaimNames
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.error.{ValidationError, CredentialIssuanceError}
import ohos_app_cangjie_eudi_cjjose.jose.JoseJws
import eudi_lib_core_crypto.{Rng, Base64Url}

// ---------------------------------------------------------------------------
// ClientAttestationError
// ---------------------------------------------------------------------------

public class ClientAttestationError <: Exception {
    public init(msg: String) {
        super(msg)
    }

    public static func InvalidClient(): ClientAttestationError {
        ClientAttestationError("Invalid client kind for attestation PoP: expected Attested")
    }
    public static func InvalidPayload(): ClientAttestationError {
        ClientAttestationError("ClientAttestation: invalid JWT payload")
    }
    public static func MissingIssuerClaim(): ClientAttestationError {
        ClientAttestationError("ClientAttestation: missing 'iss' claim")
    }
    public static func MissingExpClaim(): ClientAttestationError {
        ClientAttestationError("ClientAttestation: missing 'exp' claim")
    }
    public static func MissingCnfClaim(): ClientAttestationError {
        ClientAttestationError("ClientAttestation: missing 'cnf' claim")
    }
    public static func NotSigned(): ClientAttestationError {
        ClientAttestationError("ClientAttestation: JWT is not signed")
    }
}

// ---------------------------------------------------------------------------
// ClientAttestationPoPJWTSpec
// Ported from iOS struct ClientAttestationPoPJWTSpec.
// Carries the signing parameters for building a PoP JWT.
// ---------------------------------------------------------------------------

public class ClientAttestationPoPJWTSpec {
    public let signingAlgorithm: String    // e.g. "ES256"
    public let durationSeconds: Float64    // validity window in seconds (default 300)
    public let typ: String                 // JWT type header value
    public let signingKey: ECDSAPrivateKey

    public init(
        signingAlgorithm: String,
        durationSeconds: Float64,
        typ: String,
        signingKey: ECDSAPrivateKey
    ) {
        // Reject HMAC algorithms (MAC, not asymmetric)
        if (signingAlgorithm == "HS256" || signingAlgorithm == "HS384" || signingAlgorithm == "HS512") {
            throw ValidationError.Error("Signing algorithm cannot be a MAC algorithm: " + signingAlgorithm)
        }
        if (durationSeconds <= 0.0) {
            throw ValidationError.Error("JWT duration must be positive")
        }
        this.signingAlgorithm = signingAlgorithm
        this.durationSeconds = durationSeconds
        this.typ = typ
        this.signingKey = signingKey
    }

    // Default spec: ES256, 5 minutes, wallet attestation PoP type
    public static func withDefaults(signingKey: ECDSAPrivateKey): ClientAttestationPoPJWTSpec {
        return ClientAttestationPoPJWTSpec(
            "ES256",
            300.0,
            "wallet-attestation-pop+jwt",
            signingKey
        )
    }
}

// ---------------------------------------------------------------------------
// ClientAttestationPoPJWT
// Ported from iOS struct ClientAttestationPoPJWT.
// The signed PoP JWT compact string + parsed fields.
// ---------------------------------------------------------------------------

public class ClientAttestationPoPJWT {
    public let compact: String    // compact JWS string (base64url.base64url.base64url)

    public init(compact: String) {
        this.compact = compact
    }
}

// ---------------------------------------------------------------------------
// DefaultClientAttestationPoPBuilder
// Ported from iOS DefaultClientAttestationPoPBuilder.
//
// Builds a ClientAttestationPoPJWT for an Attested client.
//
// Payload fields (per OAuth 2.0 Attestation-Based Client Auth draft):
//   iss  — clientId (from attestation JWT sub claim)
//   jti  — random base64url (prevents replay)
//   exp  — iat + durationSeconds
//   iat  — now (Unix seconds)
//   aud  — authorization server URL
//   cnf  — confirmation key (from attestation JWT cnf.jwk)
//   nonce — challenge from auth server (if present)
// ---------------------------------------------------------------------------

public class DefaultClientAttestationPoPBuilder {

    public init() {
    }

    /*
     * Build the PoP JWT.
     *
     * clientId        — the wallet client identifier (attestation JWT sub claim)
     * cnfJwkJson      — JSON string of the confirmation key (attestation JWT cnf.jwk)
     * authServerId    — the authorization server issuer URL (becomes "aud")
     * popJwtSpec      — signing parameters (key, algorithm, duration, typ)
     * challenge       — optional nonce from the auth server
     */
    public func buildAttestationPoPJWT(
        clientId: String,
        cnfJwkJson: Option<String>,
        authServerId: String,
        popJwtSpec: ClientAttestationPoPJWTSpec,
        challenge: Option<String>
    ): ClientAttestationPoPJWT {
        let nowSeconds = Float64(DateTime.nowUTC().toUnixTimeStamp().toSeconds())
        let expSeconds = nowSeconds + popJwtSpec.durationSeconds

        // --- Header ---
        let header = JsonObject()
        header.put(JWTClaimNames.algorithm, JsonString(popJwtSpec.signingAlgorithm))
        header.put(JWTClaimNames.typ, JsonString(popJwtSpec.typ))
        let headerJson = header.toJsonString()

        // --- Payload ---
        let payload = JsonObject()
        payload.put(JWTClaimNames.issuer, JsonString(clientId))
        // jti: random 15-byte → base64url
        let jtiBytes = Rng.bytes(15)
        payload.put(JWTClaimNames.jwtId, JsonString(Base64Url.encode(jtiBytes)))
        payload.put(JWTClaimNames.expiration, JsonFloat(expSeconds))
        payload.put(JWTClaimNames.issuedAt, JsonFloat(nowSeconds))
        payload.put(JWTClaimNames.audience, JsonString(authServerId))

        // cnf field (confirmation key)
        match (cnfJwkJson) {
            case Some(jwkStr) =>
                let cnfObj = JsonObject()
                let jwkValue: JsonValue = JsonValue.fromStr(jwkStr)
                cnfObj.put("jwk", jwkValue)
                payload.put(JWTClaimNames.cnf, cnfObj)
            case None => ()
        }

        // nonce (challenge)
        match (challenge) {
            case Some(c) => payload.put(JWTClaimNames.nonce, JsonString(c))
            case None => ()
        }

        let payloadBytes = payload.toJsonString().toArray()

        // --- Sign (ES256) ---
        let compact = JoseJws.signEs256(headerJson, payloadBytes, popJwtSpec.signingKey)
        return ClientAttestationPoPJWT(compact)
    }
}

// ---------------------------------------------------------------------------
// ClientAuthenticationMethod
// Ported from iOS enum ClientAuthenticationMethod.
// Determines how the client authenticates in token/PAR requests.
// ---------------------------------------------------------------------------

public enum ClientAuthenticationMethod {
    | None
    | ClientSecretBasic(String, String)    // (clientId, clientSecret)
    | AttestationBased(String)             // popJwtCompact

    /*
     * Build from client kind.
     * For Attested clients: caller must supply the PoP JWT compact string.
     */
    public static func forClient(
        clientId: String,
        clientSecret: Option<String>,
        attestationPopJwt: Option<String>
    ): ClientAuthenticationMethod {
        match (attestationPopJwt) {
            case Some(jwt) =>
                return ClientAuthenticationMethod.AttestationBased(jwt)
            case None => ()
        }
        match (clientSecret) {
            case Some(secret) =>
                return ClientAuthenticationMethod.ClientSecretBasic(clientId, secret)
            case None =>
                return ClientAuthenticationMethod.None
        }
    }

    /*
     * Inject authentication into request body (form params).
     * Attestation-based: adds client_assertion_type + client_assertion params.
     */
    public func addToRequestParams(params: HashMap<String, String>): Unit {
        match (this) {
            case None => ()
            case ClientSecretBasic(clientId, _) =>
                // Basic auth is typically in HTTP header, but for simplicity add client_id
                params.add("client_id", clientId)
            case AttestationBased(jwt) =>
                params.add(
                    "client_assertion_type",
                    "urn:ietf:params:oauth:client-assertion-type:jwt-client-attestation"
                )
                params.add("client_assertion", jwt)
        }
    }
}
