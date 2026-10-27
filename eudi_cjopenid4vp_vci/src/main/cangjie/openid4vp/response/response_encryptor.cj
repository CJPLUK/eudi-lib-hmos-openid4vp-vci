/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * response_encryptor.cj — JWE response encryption for JARM (direct_post.jwt).
 * Block 5 scope: encrypt AuthorizationResponsePayload using ECDH-ES + A256GCM.
 *
 * Ported from iOS: Main/Encryption/ResponseEncryptor.swift.
 * iOS JOSESwift Encrypter → Cangjie jose EcdhEsEncrypter.
 *
 * Known limitation:
 *   - Only ECDH-ES (alg=ECDH-ES, enc=A256GCM) is supported in block 5.
 *   - RSA family and other ECDH-ES variants (A128KW, A256KW) are not implemented.
 *   - The jwkSetJson in ResponseEncryptionSpecification must contain a valid
 *     EC P-256 public key in JWK format. Other key types are rejected.
 */
package ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.response

import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.error.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.entity.metadata.*
import ohos_app_cangjie_eudi_cjjose.jose.*
import eudi_lib_core_crypto.Base64Url
import std.collection.*
import stdx.encoding.json.*

// ---------------------------------------------------------------------------
// ResponseEncryptor — mirrors iOS ResponseEncryptor
// Encrypts an AuthorizationResponsePayload as a JWE compact string.
// ---------------------------------------------------------------------------

public class ResponseEncryptor {

    public init() {}

    // Encrypt an AuthorizationResponsePayload as a JWE compact string.
    // Mirrors iOS ResponseEncryptor.encryptResponse(responseEncryptionSpecification:data:)
    public func encryptResponse(
        responseEncryptionSpecification!: ResponseEncryptionSpecification,
        data!: AuthorizationResponsePayload
    ): String {
        // Serialize payload to JSON bytes (plaintext)
        let jsonStr = data.toJsonString()
        let plaintext = jsonStr.toArray()

        // D-5 fix: apv = raw UTF-8 bytes of nonce (not pre-base64url-encoded).
        // EcdhEsEncrypter.encrypt() internally does Base64Url.encode(apv) when writing
        // the JWE protected header, so passing already-encoded bytes would double-encode.
        // iOS: apv = nonce.data(using: .utf8) — raw bytes, library encodes once.
        let nonce = data.nonce()
        let apv: Array<UInt8> = if (nonce.isEmpty()) {
            Array<UInt8>()
        } else {
            nonce.toArray()
        }

        // apu = raw bytes of apu string from payload (library encodes once internally)
        let apu: Array<UInt8> = match (data.apu()) {
            case Some(apuStr) => apuStr.toArray()
            case None => Array<UInt8>()
        }

        // D-4 fix: find the recipient public key AND its kid from the JWK set
        let (recipientKey, recipientKid) = findEcPublicKeyWithKid(responseEncryptionSpecification)

        // Encrypt using ECDH-ES + A256GCM; pass kid so it lands in the JWE protected header.
        try {
            return EcdhEsEncrypter.encrypt(
                recipientKey,
                plaintext,
                apu,
                apv,
                kid: recipientKid
            )
        } catch (e: Exception) {
            // Stage-tag the underlying crypto error (HUKS reports bare
            // "Invalid parameters." with no context otherwise).
            throw VpValidationError.ValidationError(
                "ResponseEncryptor: JWE encrypt failed (" + e.message + ")")
        }
    }

    // Parse the JWK set JSON and extract the first EC public key together with its kid.
    private func findEcPublicKeyWithKid(spec: ResponseEncryptionSpecification): (EcPublicKey, Option<String>) {
        let jwksJsonOpt = spec.jwkSetJson
        match (jwksJsonOpt) {
            case None =>
                throw VpValidationError.ValidationError(
                    "ResponseEncryptor: ResponseEncryptionSpecification has no jwkSetJson"
                )
            case Some(jwksJson) =>
                return extractFirstEcPublicKeyWithKid(jwksJson)
        }
    }

    // Extract first EC public key (plus its optional kid) from JWKS JSON.
    // Mirrors iOS ResponseEncryptor.findEncrypters(jweAlgorithm:encryptionMethod:keySet:)
    // Expected format: {"keys": [{"kty":"EC","crv":"P-256","x":"...","y":"...","kid":"..."},...]}
    // or a single JWK object: {"kty":"EC","crv":"P-256","x":"...","y":"..."}
    private func extractFirstEcPublicKeyWithKid(jwksJson: String): (EcPublicKey, Option<String>) {
        try {
            let parsed = JsonValue.fromStr(jwksJson)
            match (parsed) {
                case obj: JsonObject =>
                    // Check if it has a "keys" array (JWKS format)
                    match (obj.get("keys")) {
                        case Some(arr: JsonArray) =>
                            let items = arr.getItems()
                            for (item in items) {
                                match (item) {
                                    case keyObj: JsonObject =>
                                        let jwkStr = keyObj.toJsonString()
                                        let key = tryParseEcPublicKey(jwkStr)
                                        match (key) {
                                            case Some(k) =>
                                                let kid = extractKidFromJwkObject(keyObj)
                                                return (k, kid)
                                            case None => ()
                                        }
                                    case _ => ()
                                }
                            }
                            throw VpValidationError.ValidationError(
                                "ResponseEncryptor: no valid EC P-256 public key found in JWKS"
                            )
                        case _ =>
                            // Try parse as single JWK
                            match (tryParseEcPublicKey(jwksJson)) {
                                case Some(k) =>
                                    let kid = extractKidFromJwkString(parsed)
                                    return (k, kid)
                                case None =>
                                    throw VpValidationError.ValidationError(
                                        "ResponseEncryptor: cannot parse EC public key from JWK"
                                    )
                            }
                    }
                case _ =>
                    throw VpValidationError.ValidationError(
                        "ResponseEncryptor: jwkSetJson is not a JSON object"
                    )
            }
        } catch (e: VpValidationError) {
            throw e
        } catch (_: Exception) {
            throw VpValidationError.ValidationError(
                "ResponseEncryptor: failed to parse jwkSetJson"
            )
        }
    }

    // Extract the "kid" string field from an already-parsed JsonObject (one JWK entry).
    private func extractKidFromJwkObject(obj: JsonObject): Option<String> {
        match (obj.get("kid")) {
            case Some(v: JsonString) => return Option<String>.Some(v.getValue())
            case _ => return Option<String>.None
        }
    }

    // Extract the "kid" string field from a JsonValue (single-JWK path).
    private func extractKidFromJwkString(v: JsonValue): Option<String> {
        match (v) {
            case obj: JsonObject => return extractKidFromJwkObject(obj)
            case _ => return Option<String>.None
        }
    }

    // Try to parse an EC public key from a JWK JSON string.
    // Returns None if the JWK is not an EC P-256 key.
    private func tryParseEcPublicKey(jwkJson: String): Option<EcPublicKey> {
        try {
            let key = EcPublicKey.fromJson(jwkJson)
            return Some(key)
        } catch (_: Exception) {
            return None
        }
    }
}
