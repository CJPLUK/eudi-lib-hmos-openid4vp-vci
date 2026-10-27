/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * dpop.cj — DPoP (Demonstrating Proof-of-Possession) JWT constructor.
 * Ported from iOS Sources/DPoP/DPoPConstructor.swift.
 *
 * iOS JOSESwift JWS → jose library JoseJws + core-crypto Jws.signEs256
 * iOS SHA256 hash of access token → core-crypto Digest.sha256 + Base64Url
 * iOS SecRandomCopyBytes (for jti) → core-crypto Rng.bytes
 * iOS async → sync
 *
 * Degradation notes:
 * - iOS JWK.toDictionary() for header embedded JWK uses Jose EcPublicKey serialization.
 * - iOS actor → Cangjie class (no actor keyword).
 * - iOS SigningKeyProxy (SecKey wrapper) → stdx.crypto ECDSAPrivateKey.
 */
package ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.dpop

import eudi_lib_core_crypto.{Base64Url, Digest, Rng}
import ohos_app_cangjie_eudi_cjjose.jose.{EcPublicKey, JoseJws}
import stdx.crypto.keys.ECDSAPrivateKey
import stdx.encoding.json.*
import std.time.DateTime
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.util.JWTClaimNames

/*
 * DPoPConstructorType — interface for DPoP JWT generation.
 * Mirrors iOS protocol DPoPConstructorType.
 */
public interface DPoPConstructorType {
    func jwt(endpoint: String, accessToken: Option<String>, nonce: Option<String>): String
}

/*
 * DPoPConstructor — concrete implementation.
 * Mirrors iOS class DPoPConstructor.
 */
public class DPoPConstructor <: DPoPConstructorType {

    public static let TYPE = "dpop+jwt"

    public let algorithm: String        // e.g. "ES256"
    public let publicKey: EcPublicKey   // JWK for header
    public let privateKey: ECDSAPrivateKey

    public init(algorithm: String, publicKey: EcPublicKey, privateKey: ECDSAPrivateKey) {
        this.algorithm = algorithm
        this.publicKey = publicKey
        this.privateKey = privateKey
    }

    /*
     * Build and sign a DPoP JWT for the given endpoint.
     * accessToken: if provided, compute ath = BASE64URL(SHA256(ASCII(accessToken))).
     * nonce: if provided, include as "nonce" claim.
     *
     * JWT header: { typ: "dpop+jwt", alg: algorithm, jwk: {...} }
     * JWT payload: { iat, htm: "POST", htu: endpoint, jti, [ath], [nonce] }
     */
    public func jwt(endpoint: String, accessToken: Option<String>, nonce: Option<String>): String {
        // Build header JSON
        let headerObj = dpopBuildHeader(algorithm, publicKey)
        let headerJson = headerObj.toJsonString()

        // Build payload JSON
        let payloadObj = dpopBuildPayload(endpoint, accessToken, nonce)
        let payloadBytes = payloadObj.toJsonString().toArray()

        // Sign with ES256
        return JoseJws.signEs256(headerJson, payloadBytes, privateKey)
    }
}

/**
 * DPoP JWT constructor that signs via a callback (HUKS / SecureArea).
 * Same header and claims as DPoPConstructor; the private key never leaves HUKS.
 */
public class DPoPConstructorCallback <: DPoPConstructorType {
    public let algorithm: String
    public let publicKey: EcPublicKey
    public let signFn: (Array<UInt8>) -> Array<UInt8>

    public init(algorithm: String, publicKey: EcPublicKey, signFn: (Array<UInt8>) -> Array<UInt8>) {
        this.algorithm = algorithm
        this.publicKey = publicKey
        this.signFn = signFn
    }

    public func jwt(endpoint: String, accessToken: Option<String>, nonce: Option<String>): String {
        let headerJson = dpopBuildHeader(algorithm, publicKey).toJsonString()
        let payloadBytes = dpopBuildPayload(endpoint, accessToken, nonce).toJsonString().toArray()
        let signingInput = Base64Url.encode(headerJson.toArray()) + "." + Base64Url.encode(payloadBytes)
        let rawSig = signFn(signingInput.toArray())
        return signingInput + "." + Base64Url.encode(rawSig)
    }
}

// ---------------------------------------------------------------------------
// Helpers (package-private)
// ---------------------------------------------------------------------------

func dpopBuildHeader(algorithm: String, publicKey: EcPublicKey): JsonObject {
    let header = JsonObject()
    header.put(JWTClaimNames.typ, JsonString(DPoPConstructor.TYPE))
    header.put(JWTClaimNames.algorithm, JsonString(algorithm))
    let jwk = JsonObject()
    jwk.put("kty", JsonString("EC"))
    jwk.put("crv", JsonString(publicKey.crv.rawValue()))
    jwk.put("x", JsonString(publicKey.x))
    jwk.put("y", JsonString(publicKey.y))
    header.put(JWTClaimNames.JWK, jwk)
    return header
}

func dpopBuildPayload(
    endpoint: String,
    accessToken: Option<String>,
    nonce: Option<String>
): JsonObject {
    let payload = JsonObject()
    let iat = currentUnixTimestampSeconds()
    payload.put(JWTClaimNames.issuedAt, JsonInt(iat))
    payload.put(JWTClaimNames.htm, JsonString("POST"))
    payload.put(JWTClaimNames.htu, JsonString(endpoint))
    payload.put(JWTClaimNames.jwtId, JsonString(randomBase64UrlString(20)))

    match (nonce) {
        case Some(n) => payload.put(JWTClaimNames.nonce, JsonString(n))
        case None => ()
    }

    if (!accessToken.isNone()) {
        let token = accessToken.getOrThrow()
        let tokenBytes = token.toArray()
        let hashed = Digest.sha256(tokenBytes)
        payload.put(JWTClaimNames.ath, JsonString(Base64Url.encode(hashed)))
    }

    return payload
}

/*
 * Generate length random bytes and base64url-encode them.
 * Used for jti (JWT ID).
 */
func randomBase64UrlString(length: Int64): String {
    let bytes = Rng.bytes(length)
    return Base64Url.encode(bytes)
}

/*
 * Return current Unix timestamp in seconds as Int64.
 * Uses std.time.DateTime.nowUTC().toUnixTimeStamp().toSeconds().
 */
func currentUnixTimestampSeconds(): Int64 {
    return DateTime.nowUTC().toUnixTimeStamp().toSeconds()
}
