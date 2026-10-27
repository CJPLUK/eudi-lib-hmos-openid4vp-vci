/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * metadata_fetcher.cj — HTTP fetch + policy-driven JSON/JWT dispatch for issuer metadata.
 * Ported from iOS:
 *   - Sources/Main/Metadata/MetadataFetcher.swift
 *   - Sources/Main/Metadata/MetadataProcessor.swift (JSON branch only)
 *
 * iOS async/actor → sync class; Result<T,E> → throw.
 * Signed-metadata (JWT) branch: IgnoreSigned → JSON-only.
 *   PreferSigned(trust): try JWT first (Accept: application/jwt, application/json),
 *     fall back to JSON if content-type is JSON.
 *   RequireSigned(trust): Accept application/jwt; non-JWT content-type → throw.
 *
 * SECURITY: signed metadata IS cryptographically verified (ES256) against the
 *   IssuerTrust carried by the policy:
 *     ByPublicKey(jwk)          → verify against the supplied EC public key.
 *     ByCertificateChain(roots) → verify the x5c chain against the roots, then
 *                                 verify the JWS with the x5c leaf public key.
 *   Plus typ header (openidvci-issuer-metadata+jwt) and sub/iat claim checks.
 *   Fail-closed: an empty/invalid trust ⇒ verification fails ⇒ reject.
 */
package ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.resolver

import std.collection.*
import stdx.encoding.json.*
import stdx.crypto.keys.ECDSAPublicKey
import stdx.crypto.common.DerBlob
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.network.{HttpFetcher, RawFetchResponse}
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.issuer.{CredentialIssuerId, CredentialIssuerMetadata}
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.config.{IssuerMetadataPolicy, IssuerTrust}
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.util.{Constants, JWTClaimNames}
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.error.{
    CredentialIssuerMetadataError, ValidationError
}
import ohos_app_cangjie_eudi_cjjose.jose.{JoseJws, EcPublicKey}
import ohos_app_cangjie_eudi_cjx509.x509.core.{Cert, verifyChain}

// ---------------------------------------------------------------------------
// MetadataFetcher — fetch issuer metadata honoring the IssuerMetadataPolicy
// Ported from iOS MetadataFetcher + MetadataProcessor (JSON branch).
// ---------------------------------------------------------------------------

public class MetadataFetcher {
    private let fetcher: HttpFetcher

    public init() {
        fetcher = HttpFetcher()
    }

    public init(fetcher: HttpFetcher) {
        this.fetcher = fetcher
    }

    /*
     * Fetch and parse CredentialIssuerMetadata from wellKnownUrl.
     * Policy controls Accept header and how the response is interpreted.
     * Throws CredentialIssuerMetadataError on any failure.
     */
    public func fetchMetadata(
        url: String,
        policy: IssuerMetadataPolicy,
        issuerId: CredentialIssuerId
    ): CredentialIssuerMetadata {
        let acceptHeader = determineAcceptHeader(policy)
        let headers = HashMap<String, String>()
        headers.add("Accept", acceptHeader)

        let rawResponse: RawFetchResponse
        try {
            rawResponse = fetcher.fetchRawWithHeaders(url, headers)
        } catch (e: Exception) {
            throw CredentialIssuerMetadataError.UnableToFetchCredentialIssuerMetadata(e.message)
        }

        return processResponse(rawResponse, policy, issuerId)
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    func determineAcceptHeader(policy: IssuerMetadataPolicy): String {
        match (policy) {
            case IssuerMetadataPolicy.RequireSigned(_) =>
                Constants.CONTENT_TYPE_APPLICATION_JWT
            case IssuerMetadataPolicy.PreferSigned(_) =>
                Constants.CONTENT_TYPE_APPLICATION_JWT + ", " + Constants.CONTENT_TYPE_APPLICATION_JSON
            case IssuerMetadataPolicy.IgnoreSigned =>
                Constants.CONTENT_TYPE_APPLICATION_JSON
        }
    }

    func processResponse(
        raw: RawFetchResponse,
        policy: IssuerMetadataPolicy,
        issuerId: CredentialIssuerId
    ): CredentialIssuerMetadata {
        let contentType = getContentTypeHeader(raw.headers)

        let isJwt = contentType.contains(Constants.CONTENT_TYPE_APPLICATION_JWT)
        let isJson = contentType.contains(Constants.CONTENT_TYPE_APPLICATION_JSON)

        match (policy) {
            case IssuerMetadataPolicy.RequireSigned(trust) =>
                if (!isJwt) {
                    throw CredentialIssuerMetadataError.MissingRightContentTypeHeader()
                }
                return handleJwtMetadata(raw.data, issuerId, trust)
            case IssuerMetadataPolicy.PreferSigned(trust) =>
                if (!isJwt && !isJson) {
                    throw CredentialIssuerMetadataError.MissingRightContentTypeHeader()
                }
                if (isJwt) {
                    return handleJwtMetadata(raw.data, issuerId, trust)
                }
                return handleJsonMetadata(raw.data)
            case IssuerMetadataPolicy.IgnoreSigned =>
                if (!isJson) {
                    throw CredentialIssuerMetadataError.MissingRightContentTypeHeader()
                }
                return handleJsonMetadata(raw.data)
        }
    }

    func getContentTypeHeader(headers: HashMap<String, String>): String {
        let lowerKey = "content-type"
        for ((k, v) in headers) {
            if (k.toAsciiLower() == lowerKey) {
                return v.toAsciiLower()
            }
        }
        // No content-type header — default to json to allow leniency on ignoreSigned
        return Constants.CONTENT_TYPE_APPLICATION_JSON
    }

    func handleJsonMetadata(data: Array<UInt8>): CredentialIssuerMetadata {
        let jsonStr: String
        try {
            jsonStr = String.fromUtf8(data)
        } catch (e: Exception) {
            throw CredentialIssuerMetadataError.NonParseableCredentialIssuerMetadata("UTF-8 decode error: " + e.message)
        }
        try {
            return CredentialIssuerMetadata.fromJsonString(jsonStr)
        } catch (e: Exception) {
            throw CredentialIssuerMetadataError.NonParseableCredentialIssuerMetadata(e.message)
        }
    }

    /*
     * JWT (signed metadata) branch. Mirrors iOS MetadataProcessor signed path:
     *   1. typ header == openidvci-issuer-metadata+jwt
     *   2. cryptographically verify the ES256 JWS against the IssuerTrust
     *      (ByPublicKey: supplied JWK; ByCertificateChain: x5c chain verified
     *      against roots, then JWS verified with the leaf public key)
     *   3. validate sub == issuer + iat present
     *   4. parse the verified payload into CredentialIssuerMetadata
     * Fail-closed: a failed signature/chain verification throws (rejection).
     */
    func handleJwtMetadata(
        data: Array<UInt8>,
        issuerId: CredentialIssuerId,
        trust: IssuerTrust
    ): CredentialIssuerMetadata {
        let jwsStr: String
        try {
            jwsStr = String.fromUtf8(data).trimAscii()
        } catch (e: Exception) {
            throw CredentialIssuerMetadataError.NonParseableSignedMetadata()
        }

        // Compact JWS: header.payload.signature
        let parts = jwsStr.split(".")
        if (parts.size < 3) {
            throw CredentialIssuerMetadataError.NonParseableSignedMetadata()
        }

        // Validate typ header (mirrors iOS validateJOSEHeader).
        validateSignedMetadataTyp(parts[0])

        // ---- Cryptographic signature verification (security-critical) ----
        if (!verifySignedMetadataSignature(jwsStr, trust)) {
            throw CredentialIssuerMetadataError.InvalidSignedMetadata(
                "signed metadata JWS signature verification failed")
        }

        // Base64url decode the (now verified) payload.
        let payloadJson = base64UrlDecode(parts[1])
        if (payloadJson.isNone()) {
            throw CredentialIssuerMetadataError.NonParseableSignedMetadata()
        }
        let jsonStr = payloadJson.getOrThrow()

        // Validate sub and iat claims
        try {
            let jv = JsonValue.fromStr(jsonStr)
            match (jv) {
                case jobj: JsonObject =>
                    validateSignedMetadataClaims(jobj, issuerId.url)
                case _ =>
                    throw CredentialIssuerMetadataError.NonParseableSignedMetadata()
            }
        } catch (e: CredentialIssuerMetadataError) {
            throw e
        } catch (e: Exception) {
            throw CredentialIssuerMetadataError.NonParseableSignedMetadata()
        }

        // Parse actual metadata from payload
        let parsedMetadata: CredentialIssuerMetadata
        try {
            parsedMetadata = CredentialIssuerMetadata.fromJsonString(jsonStr)
        } catch (e: Exception) {
            throw CredentialIssuerMetadataError.NonParseableCredentialIssuerMetadata(e.message)
        }

        // Capture the verified WRPAC (base64 DER — the LEAF of the JWS `x5c`
        // header) and attach it to the metadata so it can be used later by
        // WRPRC policy enforcement. The chain has already been trust-validated
        // at this point; only the leaf carries the WRP's identity.
        // Mirrors iOS MetadataProcessor `metadata.withWrpac(leaf)` (v0.53.1).
        match (extractX5cLeafB64(jwsStr)) {
            case Some(leafB64) => parsedMetadata.wrpac = Some(leafB64)
            case None => ()
        }
        return parsedMetadata
    }

    // The raw base64 (standard alphabet) x5c[0] entry of a compact JWS header.
    static func extractX5cLeafB64(jwsStr: String): Option<String> {
        let parts = jwsStr.split(".")
        if (parts.size < 1) { return None }
        let headerJsonOpt = base64UrlDecode(parts[0])
        let headerJson = match (headerJsonOpt) {
            case Some(s) => s
            case None => return None
        }
        try {
            match (JsonValue.fromStr(headerJson)) {
                case obj: JsonObject =>
                    match (obj.get("x5c")) {
                        case Some(arr: JsonArray) =>
                            let items = arr.getItems()
                            if (items.size < 1) { return None }
                            match (items[0]) {
                                case s: JsonString => return Some(s.getValue())
                                case _ => return None
                            }
                        case _ => return None
                    }
                case _ => return None
            }
        } catch (_: Exception) {
            return None
        }
    }

    // Validate the JWS protected header declares the signed-metadata typ.
    func validateSignedMetadataTyp(headerB64: String): Unit {
        let headerJsonOpt = base64UrlDecode(headerB64)
        let headerJson = match (headerJsonOpt) {
            case Some(s) => s
            case None => throw CredentialIssuerMetadataError.NonParseableSignedMetadata()
        }
        let typ: Option<String> = try {
            match (JsonValue.fromStr(headerJson)) {
                case obj: JsonObject =>
                    match (obj.get("typ")) {
                        case Some(s: JsonString) => Some(s.getValue())
                        case _ => None
                    }
                case _ => None
            }
        } catch (_: Exception) {
            None
        }
        match (typ) {
            case Some(t) =>
                if (t != Constants.SIGNED_METADATA_JWT_TYPE) {
                    throw CredentialIssuerMetadataError.InvalidSignedMetadata(
                        "Invalid 'typ' header. Expected: " + Constants.SIGNED_METADATA_JWT_TYPE)
                }
            case None =>
                throw CredentialIssuerMetadataError.InvalidSignedMetadata(
                    "Missing 'typ' header in signed metadata")
        }
    }

    // Cryptographically verify the signed-metadata JWS against the IssuerTrust.
    // Public+static so it is the single source of truth for the verification used
    // both by the production fetch path and by proof tests.
    public static func verifySignedMetadataSignature(jwsStr: String, trust: IssuerTrust): Bool {
        match (trust) {
            case IssuerTrust.ByPublicKey(jwkJson) =>
                let pub = try {
                    // jose EcPublicKey.fromJson → uncompressed point → SPKI →
                    // stdx ECDSAPublicKey.decodeDer.
                    let ecPub = EcPublicKey.fromJson(jwkJson)
                    let point = ecPub.toHuksUncompressed()  // 0x04||X||Y, on-curve checked
                    ECDSAPublicKey.decodeDer(DerBlob(buildP256SpkiVci(point)))
                } catch (_: Exception) {
                    return false
                }
                try {
                    return JoseJws.verifyEs256(jwsStr, pub)
                } catch (_: Exception) {
                    return false
                }
            case IssuerTrust.ByCertificateChain(rootsPem) =>
                // Parse x5c leaf from the header.
                let leafOpt = extractX5cLeaf(jwsStr)
                let leaf = match (leafOpt) {
                    case Some(c) => c
                    case None => return false
                }
                // Verify the chain against the supplied trust anchors (fail-closed).
                if (!verifyMetadataChain(jwsStr, rootsPem)) {
                    return false
                }
                // Verify the JWS signature with the leaf public key.
                let pub = try {
                    ECDSAPublicKey.decodeDer(DerBlob(leaf.publicKeyDer))
                } catch (_: Exception) {
                    return false
                }
                try {
                    return JoseJws.verifyEs256(jwsStr, pub)
                } catch (_: Exception) {
                    return false
                }
            case IssuerTrust.ByValidator(validator) =>
                // Chain trust is delegated to an injected lazy validator (anchors
                // resolved only here, never at startup). Mirrors iOS's injected
                // CertificateChainTrust: chain trust and JWS signature are checked
                // separately, and both are fail-closed.
                let chain = match (extractX5cChain(jwsStr)) {
                    case Some(c) => c
                    case None => return false
                }
                if (!validator.isValid(chain)) {
                    return false
                }
                let vLeaf = match (extractX5cLeaf(jwsStr)) {
                    case Some(c) => c
                    case None => return false
                }
                let vPub = try {
                    ECDSAPublicKey.decodeDer(DerBlob(vLeaf.publicKeyDer))
                } catch (_: Exception) {
                    return false
                }
                try {
                    return JoseJws.verifyEs256(jwsStr, vPub)
                } catch (_: Exception) {
                    return false
                }
        }
    }

    // Extract the full x5c chain (standard base64-DER strings; chain[0] = leaf)
    // from a compact JWS header, for delegation to a CertChainTrust validator.
    static func extractX5cChain(jwsStr: String): Option<Array<String>> {
        let parts = jwsStr.split(".")
        if (parts.size < 1) { return None }
        let headerJson = match (base64UrlDecode(parts[0])) {
            case Some(s) => s
            case None => return None
        }
        try {
            match (JsonValue.fromStr(headerJson)) {
                case obj: JsonObject =>
                    match (obj.get("x5c")) {
                        case Some(arr: JsonArray) =>
                            let acc = ArrayList<String>()
                            for (it in arr.getItems()) {
                                match (it) {
                                    case s: JsonString => acc.add(s.getValue())
                                    case _ => ()
                                }
                            }
                            if (acc.size < 1) { return None }
                            return Some(acc.toArray())
                        case _ => return None
                    }
                case _ => return None
            }
        } catch (_: Exception) {
            return None
        }
    }

    // Extract the leaf certificate (x5c[0]) from a compact JWS header.
    static func extractX5cLeaf(jwsStr: String): Option<Cert> {
        let parts = jwsStr.split(".")
        if (parts.size < 1) { return None }
        let headerJsonOpt = base64UrlDecode(parts[0])
        let headerJson = match (headerJsonOpt) {
            case Some(s) => s
            case None => return None
        }
        let entries = try {
            match (JsonValue.fromStr(headerJson)) {
                case obj: JsonObject =>
                    match (obj.get("x5c")) {
                        case Some(arr: JsonArray) =>
                            let items = arr.getItems()
                            let acc = ArrayList<String>()
                            for (it in items) {
                                match (it) {
                                    case s: JsonString => acc.add(s.getValue())
                                    case _ => ()
                                }
                            }
                            acc.toArray()
                        case _ => return None
                    }
                case _ => return None
            }
        } catch (_: Exception) {
            return None
        }
        if (entries.size < 1) { return None }
        try {
            let der = metaBase64StdDecode(entries[0])
            return Some(Cert.fromDer(der))
        } catch (_: Exception) {
            return None
        }
    }

    // Verify the x5c chain of a signed metadata JWS against the roots PEM.
    // Fail-closed: empty roots ⇒ false.
    static func verifyMetadataChain(jwsStr: String, rootsPem: String): Bool {
        if (rootsPem.isEmpty()) { return false }
        let parts = jwsStr.split(".")
        if (parts.size < 1) { return false }
        let headerJsonOpt = base64UrlDecode(parts[0])
        let headerJson = match (headerJsonOpt) {
            case Some(s) => s
            case None => return false
        }
        let entries = try {
            match (JsonValue.fromStr(headerJson)) {
                case obj: JsonObject =>
                    match (obj.get("x5c")) {
                        case Some(arr: JsonArray) =>
                            let items = arr.getItems()
                            let acc = ArrayList<String>()
                            for (it in items) {
                                match (it) {
                                    case s: JsonString => acc.add(s.getValue())
                                    case _ => ()
                                }
                            }
                            acc.toArray()
                        case _ => return false
                    }
                case _ => return false
            }
        } catch (_: Exception) {
            return false
        }
        let certs = ArrayList<Cert>()
        for (b64 in entries) {
            try {
                certs.add(Cert.fromDer(metaBase64StdDecode(b64)))
            } catch (_: Exception) {
                ()
            }
        }
        if (certs.size < 1) { return false }
        let roots = try {
            Cert.fromPem(rootsPem)
        } catch (_: Exception) {
            return false
        }
        if (roots.size < 1) { return false }
        let leaf = certs[0]
        let intermediates: Array<Cert> = if (certs.size > 1) {
            certs.toArray()[1..certs.size]
        } else {
            Array<Cert>()
        }
        try {
            return verifyChain(leaf, intermediates, roots)
        } catch (_: Exception) {
            return false
        }
    }

    func validateSignedMetadataClaims(payload: JsonObject, expectedIssuer: String): Unit {
        // sub must match issuer id
        let sub: String = match (payload.get(JWTClaimNames.subject)) {
            case Some(js: JsonString) => js.getValue()
            case _ => throw CredentialIssuerMetadataError.InvalidJWTClaims("Missing 'sub' claim")
        }
        if (sub != expectedIssuer) {
            throw CredentialIssuerMetadataError.InvalidJWTClaims(
                "Invalid 'sub' claim. Expected: " + expectedIssuer
            )
        }

        // iat must be present
        let _iat: Int64 = match (payload.get(JWTClaimNames.issuedAt)) {
            case Some(ji: JsonInt) => ji.getValue()
            case _ => throw CredentialIssuerMetadataError.InvalidJWTClaims("Missing 'iat' claim")
        }
    }
}

// ---------------------------------------------------------------------------
// Base64Url decode helper (no padding required, URL-safe alphabet)
// ---------------------------------------------------------------------------

func base64UrlDecode(encoded: String): Option<String> {
    // Convert base64url to base64: replace - with + and _ with /
    var b64 = encoded.replace("-", "+").replace("_", "/")

    // Add padding
    let rem = b64.size % 4
    if (rem == 2) {
        b64 = b64 + "=="
    } else if (rem == 3) {
        b64 = b64 + "="
    }

    // Decode base64 manually
    let decoded = decodeBase64(b64)
    if (decoded.isNone()) {
        return Option<String>.None
    }
    try {
        let s = String.fromUtf8(decoded.getOrThrow())
        return Option<String>.Some(s)
    } catch (_: Exception) {
        return Option<String>.None
    }
}

// Wrap a 65-byte uncompressed P-256 EC point (0x04||X||Y) into a complete
// SubjectPublicKeyInfo DER (id-ecPublicKey + prime256v1) for ECDSAPublicKey.decodeDer.
func buildP256SpkiVci(point: Array<UInt8>): Array<UInt8> {
    let prefix: Array<UInt8> = [
        0x30u8, 0x59u8, 0x30u8, 0x13u8, 0x06u8, 0x07u8, 0x2au8, 0x86u8,
        0x48u8, 0xceu8, 0x3du8, 0x02u8, 0x01u8, 0x06u8, 0x08u8, 0x2au8,
        0x86u8, 0x48u8, 0xceu8, 0x3du8, 0x03u8, 0x01u8, 0x07u8, 0x03u8,
        0x42u8, 0x00u8
    ]
    let out = Array<UInt8>(prefix.size + point.size, repeat: 0)
    for (i in 0..prefix.size) {
        out[i] = prefix[i]
    }
    for (i in 0..point.size) {
        out[prefix.size + i] = point[i]
    }
    return out
}

// Standard base64 decode (alphabet +/) used for x5c DER certificate entries.
func metaBase64StdDecode(b64In: String): Array<UInt8> {
    var b64 = b64In
    let rem = b64.size % 4
    if (rem == 2) {
        b64 = b64 + "=="
    } else if (rem == 3) {
        b64 = b64 + "="
    }
    let decoded = decodeBase64(b64)
    match (decoded) {
        case Some(bytes) => return bytes
        case None => throw Exception("metaBase64StdDecode: invalid base64")
    }
}

func decodeBase64(s: String): Option<Array<UInt8>> {
    let table: Array<Int64> = [
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1
    ]
    let bytes = s.toArray()
    let result = ArrayList<UInt8>()
    var i = 0
    while (i + 3 < bytes.size) {
        let b0 = Int64(bytes[i])
        let b1 = Int64(bytes[i + 1])
        let b2 = Int64(bytes[i + 2])
        let b3 = Int64(bytes[i + 3])
        if (b0 >= 128 || b1 >= 128 || b2 >= 128 || b3 >= 128) {
            return Option<Array<UInt8>>.None
        }
        let v0 = table[b0]
        let v1 = table[b1]
        let v2 = table[b2]
        let v3 = table[b3]
        if (v0 < 0 || v1 < 0) {
            return Option<Array<UInt8>>.None
        }
        result.add(UInt8((v0 << 2) | (v1 >> 4)))
        if (bytes[i + 2] != 61u8) {
            if (v2 < 0) { return Option<Array<UInt8>>.None }
            result.add(UInt8(((v1 & 0xF) << 4) | (v2 >> 2)))
        }
        if (bytes[i + 3] != 61u8) {
            if (v3 < 0) { return Option<Array<UInt8>>.None }
            result.add(UInt8(((v2 & 0x3) << 6) | v3))
        }
        i += 4
    }
    return Option<Array<UInt8>>.Some(result.toArray())
}
