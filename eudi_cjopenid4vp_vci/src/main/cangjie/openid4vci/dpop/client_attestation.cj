/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * client_attestation.cj — OAuth 2.0 Attestation-Based Client Authentication
 * (`attest_jwt_client_auth`, draft-ietf-oauth-attestation-based-client-auth).
 *
 * Ported from iOS OpenID4VCI ClientAttestationPoPBuilder / the
 * `OAuth-Client-Attestation` + `OAuth-Client-Attestation-PoP` header pair the
 * Swift AuthorizationServerClient attaches to PAR / token requests.
 *
 * The wallet-provider issues the attestation JWT (`oauth-client-attestation+jwt`)
 * over the public JWK of a wallet-held key; every PAR / token request then proves
 * possession of that key with a freshly signed PoP JWT. Without the pair the
 * authorization server falls back to `public` client auth and the access token it
 * mints carries no `client_status` claim — which the credential endpoint requires.
 */
package ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.dpop

import eudi_lib_core_crypto.Base64Url
import stdx.encoding.json.*
import stdx.crypto.keys.ECDSAPrivateKey
import ohos_app_cangjie_eudi_cjjose.jose.JoseJws
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.util.JWTClaimNames

/*
 * ClientAttestationType — interface so the wallet layer can supply its own
 * attestation source. Mirrors the iOS `ClientAttestationPoPBuilder` protocol.
 */
public interface ClientAttestationType {
    /** The wallet-instance attestation JWT (`oauth-client-attestation+jwt`). */
    func attestationJwt(): String

    /**
     * A freshly signed PoP JWT for `audience` (the authorization server issuer).
     * `challenge` carries a server-supplied `OAuth-Client-Attestation-Challenge`
     * when one was returned on a previous attempt.
     */
    func popJwt(audience: String, challenge: Option<String>): String
}

/*
 * ClientAttestation — concrete implementation signing the PoP with the same
 * private key whose public JWK the wallet-provider attested.
 */
public class ClientAttestation <: ClientAttestationType {

    public static let POP_TYPE = "oauth-client-attestation-pop+jwt"

    /** PoP lifetime; the spec requires a short-lived proof. */
    public static let POP_LIFETIME_SECONDS: Int64 = 300

    private let attestation: String
    private let clientId: String
    private let algorithm: String
    private let privateKey: ECDSAPrivateKey
    /** Public JWK of `privateKey` — the key the attestation binds via `cnf`. */
    private let publicJwk: JsonObject

    public init(
        attestation: String,
        clientId: String,
        algorithm: String,
        privateKey: ECDSAPrivateKey,
        publicJwk: JsonObject
    ) {
        this.attestation = attestation
        this.clientId = clientId
        this.algorithm = algorithm
        this.privateKey = privateKey
        this.publicJwk = publicJwk
    }

    public func attestationJwt(): String {
        return this.attestation
    }

    /*
     * JWT header:  { kid: "0", alg, typ: "oauth-client-attestation-pop+jwt", jwk }
     * JWT payload: { iss: clientId, aud: audience, jti, iat, exp, cnf, [challenge] }
     *
     * `iss` is the client_id (the attestation's subject), NOT the issuer URL —
     * the PoP is issued *by* the client *to* the authorization server.
     *
     * The header `jwk` / `kid` and the payload `cnf` repeat the attested key.
     * They are redundant for a server that resolves the signing key from the
     * attestation's own `cnf`, but Keycloak (`attest_jwt_client_auth`) rejects
     * the PoP without them — matches iOS DefaultClientAttestationPoPBuilder
     * claim for claim.
     */
    public func popJwt(audience: String, challenge: Option<String>): String {
        let headerJson = clientAttestationBuildHeader(this.algorithm, this.publicJwk).toJsonString()
        let payloadBytes = clientAttestationBuildPayload(
            this.clientId, audience, challenge, this.publicJwk).toJsonString().toArray()
        return JoseJws.signEs256(headerJson, payloadBytes, this.privateKey)
    }
}

/**
 * Client-attestation PoP that signs via a callback (HUKS / SecureArea).
 * Same header and claims as ClientAttestation; the private key never leaves HUKS.
 * The software ClientAttestation path is kept for protocol-library tests.
 */
public class ClientAttestationCallback <: ClientAttestationType {
    private let attestation: String
    private let clientId: String
    private let algorithm: String
    private let publicJwk: JsonObject
    private let signFn: (Array<UInt8>) -> Array<UInt8>

    public init(
        attestation: String,
        clientId: String,
        algorithm: String,
        publicJwk: JsonObject,
        signFn: (Array<UInt8>) -> Array<UInt8>
    ) {
        this.attestation = attestation
        this.clientId = clientId
        this.algorithm = algorithm
        this.publicJwk = publicJwk
        this.signFn = signFn
    }

    public func attestationJwt(): String {
        return this.attestation
    }

    public func popJwt(audience: String, challenge: Option<String>): String {
        let headerJson = clientAttestationBuildHeader(this.algorithm, this.publicJwk).toJsonString()
        let payloadBytes = clientAttestationBuildPayload(
            this.clientId, audience, challenge, this.publicJwk).toJsonString().toArray()
        let signingInput = Base64Url.encode(headerJson.toArray()) + "." + Base64Url.encode(payloadBytes)
        let rawSig = this.signFn(signingInput.toArray())
        return signingInput + "." + Base64Url.encode(rawSig)
    }
}

func clientAttestationBuildHeader(algorithm: String, publicJwk: JsonObject): JsonObject {
    let header = JsonObject()
    header.put(JWTClaimNames.kid, JsonString("0"))
    header.put(JWTClaimNames.algorithm, JsonString(algorithm))
    header.put(JWTClaimNames.typ, JsonString(ClientAttestation.POP_TYPE))
    header.put(JWTClaimNames.JWK, publicJwk)
    return header
}

func clientAttestationBuildPayload(
    clientId: String,
    audience: String,
    challenge: Option<String>,
    publicJwk: JsonObject
): JsonObject {
    let payload = JsonObject()
    let iat = currentUnixTimestampSeconds()
    payload.put(JWTClaimNames.issuer, JsonString(clientId))
    payload.put(JWTClaimNames.audience, JsonString(audience))
    payload.put(JWTClaimNames.issuedAt, JsonInt(iat))
    payload.put(JWTClaimNames.expiration, JsonInt(iat + ClientAttestation.POP_LIFETIME_SECONDS))
    payload.put(JWTClaimNames.jwtId, JsonString(randomBase64UrlString(20)))
    payload.put(JWTClaimNames.cnf, publicJwk)
    match (challenge) {
        case Some(c) => payload.put("challenge", JsonString(c))
        case None => ()
    }
    return payload
}
