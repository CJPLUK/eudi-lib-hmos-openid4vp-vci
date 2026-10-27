/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * issuance_requester.cj — Credential endpoint HTTP client.
 * Ported from iOS Sources/Issuers/IssuanceRequester.swift.
 *
 * iOS actor → class; async → sync.
 * Cangjie: no named arguments in function calls; all calls use positional args.
 */
package ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.issuance

import std.collection.*
import std.time.DateTime
import stdx.encoding.json.*
import stdx.crypto.keys.ECDSAPrivateKey
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.types.{Nonce, TransactionId, CredentialConfigurationIdentifier}
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.access.{IssuanceAccessToken, TokenType}
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.issuance.{
    IssuanceRequestPayload, BindingKey,
    CredentialIssuanceResponse, IssuedCredential, Credential,
    DeferredCredentialIssuanceResponse, SubmittedRequest,
    NotificationObject, Proof
}
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.issuer.CredentialIssuerMetadata
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.dpop.DPoPConstructorType
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.network.{HttpPoster, PostError}
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.util.{Constants, JWTClaimNames}
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.error.{
    ValidationError, CredentialIssuanceError, CredentialError, CredentialIssuerMetadataValidationError
}
import ohos_app_cangjie_eudi_cjjose.jose.JoseJws
import ohos_app_cangjie_eudi_cjjose.jose.EcPublicKey
import eudi_lib_core_crypto.Base64Url
import eudi_lib_core_crypto.EcdsaP256
import kit.PerformanceAnalysisKit.Hilog

/*
 * Diagnostics for the credential request: the proof JWT (with the embedded key
 * attestation replaced by its own decoded summary) and the DPoP proof outline.
 * hilog truncates lines at ~4 KB, so the raw JWTs are never logged whole.
 */
func logProofDiagnostics(kind: String, header: JsonObject, payload: JsonObject, keyAttestation: Option<String>): Unit {
    let hdr = JsonObject()
    for ((k, v) in header.getFields()) {
        if (k == "key_attestation") {
            hdr.put(k, JsonString("<jwt len=" + v.toJsonString().size.toString() + ">"))
        } else {
            hdr.put(k, v)
        }
    }
    Hilog.info(0, "VCI-PROOF", kind + " header=" + hdr.toJsonString() + " payload=" + payload.toJsonString())
    match (keyAttestation) {
        case Some(att) => logKeyAttestationSummary(att)
        case None => ()
    }
}

func logKeyAttestationSummary(att: String): Unit {
    let parts = att.split(".")
    if (parts.size < 2) {
        Hilog.warn(0, "VCI-PROOF", "key_attestation is not a compact JWS (parts=" + parts.size.toString() + ")")
        return
    }
    try {
        let payloadJson = String.fromUtf8(Base64Url.decode(parts[1]))
        let summary = match (JsonValue.fromStr(payloadJson)) {
            case obj: JsonObject =>
                var s = ""
                for ((k, v) in obj.getFields()) {
                    let rendered = v.toJsonString()
                    let clipped = if (rendered.size > 160) { String.fromUtf8(rendered.toArray()[0..160]) + "…" } else { rendered }
                    s = s + " " + k + "=" + clipped
                }
                s
            case _ => payloadJson
        }
        Hilog.info(0, "VCI-PROOF", "key_attestation payload:" + summary)
    } catch (e: Exception) {
        Hilog.warn(0, "VCI-PROOF", "key_attestation payload decode failed: " + e.message)
    }
}

// ---------------------------------------------------------------------------
// IssuanceRequester
// Ported from iOS actor IssuanceRequester.
// ---------------------------------------------------------------------------

public class IssuanceRequester {
    public let issuerMetadata: CredentialIssuerMetadata
    public let dpopConstructor: Option<DPoPConstructorType>
    private let poster: HttpPoster

    public init(
        issuerMetadata: CredentialIssuerMetadata,
        dpopConstructor: Option<DPoPConstructorType>
    ) {
        this.issuerMetadata = issuerMetadata
        this.dpopConstructor = dpopConstructor
        this.poster = HttpPoster()
    }

    // -----------------------------------------------------------------------
    // placeIssuanceRequest
    // -----------------------------------------------------------------------

    public func placeIssuanceRequest(
        accessToken: IssuanceAccessToken,
        credentialConfigurationId: CredentialConfigurationIdentifier,
        proofs: Array<Proof>,
        payload: IssuanceRequestPayload,
        dpopNonce: Option<Nonce>,
        maxRetries: Int64
    ): CredentialIssuanceResponse {
        let endpoint = issuerMetadata.credentialEndpoint.url
        let authHeader = buildAuthorizationHeader(accessToken, endpoint, dpopNonce)
        let requestBody = buildCredentialRequestBody(credentialConfigurationId, payload, proofs)
        let additionalHeaders = HashMap<String, String>()
        for ((k, v) in authHeader) {
            additionalHeaders.add(k, v)
        }

        try {
            let rr = poster.post(
                endpoint,
                requestBody,
                Constants.CONTENT_TYPE_APPLICATION_JSON,
                additionalHeaders
            )
            return parseCredentialResponse(rr.body)
        } catch (e: PostError) {
            let msg = e.message
            if (msg.startsWith("Use dPop Nonce error: ")) {
                let nonce = msg.removePrefix("Use dPop Nonce error: ")
                if (maxRetries <= 0) {
                    throw ValidationError.RetryFailedAfterDpopNonce()
                }
                return placeIssuanceRequest(
                    accessToken,
                    credentialConfigurationId,
                    proofs,
                    payload,
                    Option<Nonce>.Some(Nonce(nonce)),
                    maxRetries - 1
                )
            }
            throw CredentialIssuanceError.InvalidIssuanceRequest(e.message)
        }
    }

    // -----------------------------------------------------------------------
    // placeDeferredCredentialRequest
    // -----------------------------------------------------------------------

    public func placeDeferredCredentialRequest(
        accessToken: IssuanceAccessToken,
        transactionId: TransactionId,
        dpopNonce: Option<Nonce>,
        maxRetries: Int64
    ): DeferredCredentialIssuanceResponse {
        let deferredEndpointOpt = issuerMetadata.deferredCredentialEndpoint
        if (deferredEndpointOpt.isNone()) {
            throw CredentialError.IssuerDoesNotSupportDeferredIssuance()
        }
        let endpoint = deferredEndpointOpt.getOrThrow().url

        let authHeader = buildAuthorizationHeader(accessToken, endpoint, dpopNonce)
        let requestObj = JsonObject()
        requestObj.put("transaction_id", JsonString(transactionId.value))
        let requestBody = requestObj.toJsonString()

        let additionalHeaders = HashMap<String, String>()
        for ((k, v) in authHeader) {
            additionalHeaders.add(k, v)
        }

        try {
            let rr = poster.post(
                endpoint,
                requestBody,
                Constants.CONTENT_TYPE_APPLICATION_JSON,
                additionalHeaders
            )
            let jv = JsonValue.fromStr(rr.body)
            match (jv) {
                case jobj: JsonObject =>
                    return DeferredCredentialIssuanceResponse.fromJson(jobj)
                case _ => throw CredentialIssuanceError.ResponseUnparsable("Deferred credential response not JSON object")
            }
        } catch (e: PostError) {
            let msg = e.message
            if (msg.startsWith("Use dPop Nonce error: ")) {
                let nonce = msg.removePrefix("Use dPop Nonce error: ")
                if (maxRetries <= 0) {
                    throw ValidationError.RetryFailedAfterDpopNonce()
                }
                return placeDeferredCredentialRequest(
                    accessToken,
                    transactionId,
                    Option<Nonce>.Some(Nonce(nonce)),
                    maxRetries - 1
                )
            }
            // OID4VCI v1 signals "credential not ready yet" as HTTP 400 with
            // error=issuance_pending — that is a normal still-pending outcome,
            // not a failure (iOS maps it the same way).
            if (msg.contains("issuance_pending")) {
                return DeferredCredentialIssuanceResponse.IssuanceStillPending(5.0)
            }
            throw CredentialIssuanceError.InvalidIssuanceRequest(e.message)
        }
    }

    // -----------------------------------------------------------------------
    // notifyIssuer
    // -----------------------------------------------------------------------

    public func notifyIssuer(
        accessToken: IssuanceAccessToken,
        notification: NotificationObject,
        dpopNonce: Option<Nonce>,
        maxRetries: Int64
    ): Unit {
        let notifEndpointOpt = issuerMetadata.notificationEndpoint
        if (notifEndpointOpt.isNone()) {
            throw CredentialIssuerMetadataValidationError.InvalidNotificationEndpoint()
        }
        let endpoint = notifEndpointOpt.getOrThrow().url

        let authHeader = buildAuthorizationHeader(accessToken, endpoint, dpopNonce)
        let requestBody = notification.toJsonObject().toJsonString()

        let additionalHeaders = HashMap<String, String>()
        for ((k, v) in authHeader) {
            additionalHeaders.add(k, v)
        }

        try {
            let _ = poster.post(
                endpoint,
                requestBody,
                Constants.CONTENT_TYPE_APPLICATION_JSON,
                additionalHeaders
            )
        } catch (e: PostError) {
            let msg = e.message
            if (msg.startsWith("Use dPop Nonce error: ")) {
                let nonce = msg.removePrefix("Use dPop Nonce error: ")
                if (maxRetries <= 0) {
                    throw ValidationError.RetryFailedAfterDpopNonce()
                }
                return notifyIssuer(
                    accessToken,
                    notification,
                    Option<Nonce>.Some(Nonce(nonce)),
                    maxRetries - 1
                )
            }
            throw CredentialIssuanceError.NotificationFailed(e.message)
        }
    }

    // -----------------------------------------------------------------------
    // buildJwtProof — create a JWT proof for credential request
    // -----------------------------------------------------------------------

    public func buildJwtProof(
        privateKey: ECDSAPrivateKey,
        algorithm: String,
        clientId: String,
        issuerUrl: String,
        cNonce: Option<String>,
        keyAttestation!: Option<String> = Option<String>.None
    ): String {
        // Proof-of-possession header: typ "openid4vci-proof+jwt", alg, and either the
        // public JWK (default) or a key_attestation JWT (for key_attestations_required
        // configs). Mirrors iOS BindingKey.jwt (jwk header) vs .jwtKeyAttestation
        // (key_attestation header). When key_attestation is present the JWK is omitted
        // — the attested key set lives inside the attestation JWT.
        let header = JsonObject()
        header.put(JWTClaimNames.algorithm, JsonString(algorithm))
        header.put(JWTClaimNames.typ, JsonString("openid4vci-proof+jwt"))
        match (keyAttestation) {
            case Some(att) =>
                header.put("key_attestation", JsonString(att))
                // pid-issuer v0.10+ resolves the proof signing key as
                // attested_keys[kid] and requires the proof to be signed by
                // attested_keys[0] with kid "0"; omitting kid makes the
                // server's key resolution throw (500). Mirrors iOS
                // BindingKey.jwtKeyAttestation (kid: "0" header).
                header.put(JWTClaimNames.kid, JsonString("0"))
            case None => header.put(JWTClaimNames.JWK, buildPublicJwk(privateKey))
        }
        let headerJson = header.toJsonString()

        let payload = JsonObject()
        payload.put(JWTClaimNames.issuer, JsonString(clientId))
        payload.put(JWTClaimNames.audience, JsonString(issuerUrl))
        let iat = DateTime.nowUTC().toUnixTimeStamp().toSeconds()
        payload.put(JWTClaimNames.issuedAt, JsonInt(iat))
        match (cNonce) {
            case Some(n) => payload.put(JWTClaimNames.nonce, JsonString(n))
            case None => ()
        }
        let payloadBytes = payload.toJsonString().toArray()
        logProofDiagnostics("jwt-proof", header, payload, keyAttestation)

        return JoseJws.signEs256(headerJson, payloadBytes, privateKey)
    }

    // -----------------------------------------------------------------------
    // buildJwtProofFromPublic — same proof JWT, signed by a callback.
    // Used when the holder key lives in HUKS / SecureArea and this process
    // only has the public point plus a sign(signingInput) -> raw r||s function.
    // -----------------------------------------------------------------------

    public func buildJwtProofFromPublic(
        publicKeyX963: Array<UInt8>,
        algorithm: String,
        clientId: String,
        issuerUrl: String,
        cNonce: Option<String>,
        signFn: (Array<UInt8>) -> Array<UInt8>,
        keyAttestation!: Option<String> = Option<String>.None
    ): String {
        let header = JsonObject()
        header.put(JWTClaimNames.algorithm, JsonString(algorithm))
        header.put(JWTClaimNames.typ, JsonString("openid4vci-proof+jwt"))
        match (keyAttestation) {
            case Some(att) =>
                header.put("key_attestation", JsonString(att))
                header.put(JWTClaimNames.kid, JsonString("0"))
            case None => header.put(JWTClaimNames.JWK, buildPublicJwkFromX963(publicKeyX963))
        }
        let headerJson = header.toJsonString()

        let payload = JsonObject()
        payload.put(JWTClaimNames.issuer, JsonString(clientId))
        payload.put(JWTClaimNames.audience, JsonString(issuerUrl))
        let iat = DateTime.nowUTC().toUnixTimeStamp().toSeconds()
        payload.put(JWTClaimNames.issuedAt, JsonInt(iat))
        match (cNonce) {
            case Some(n) => payload.put(JWTClaimNames.nonce, JsonString(n))
            case None => ()
        }
        let payloadBytes = payload.toJsonString().toArray()
        logProofDiagnostics("jwt-proof(secure-area)", header, payload, keyAttestation)
        let signingInput = Base64Url.encode(headerJson.toArray()) + "." + Base64Url.encode(payloadBytes)
        let rawSig = signFn(signingInput.toArray())
        return signingInput + "." + Base64Url.encode(rawSig)
    }

    // -----------------------------------------------------------------------
    // buildPublicJwk — derive the EC public JWK for the proof header.
    // Exports the uncompressed P-256 point (0x04||X||Y) from the device private
    // key, splits into x/y, base64url-encodes via EcPublicKey, and emits a
    // {kty:"EC",crv:"P-256",x,y} JSON object.
    // -----------------------------------------------------------------------

    public func buildPublicJwkFromX963(uncompressed: Array<UInt8>): JsonObject {
        let ecPub = EcPublicKey.fromHuksUncompressed(uncompressed)
        let jwk = JsonObject()
        jwk.put("kty", JsonString("EC"))
        jwk.put("crv", JsonString(ecPub.crv.rawValue()))
        jwk.put("x", JsonString(ecPub.x))
        jwk.put("y", JsonString(ecPub.y))
        return jwk
    }

    public func buildPublicJwk(privateKey: ECDSAPrivateKey): JsonObject {
        return buildPublicJwkFromX963(EcdsaP256.publicKeyUncompressedOf(privateKey))
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    private func buildAuthorizationHeader(
        accessToken: IssuanceAccessToken,
        endpoint: String,
        dpopNonce: Option<Nonce>
    ): HashMap<String, String> {
        let headers = HashMap<String, String>()

        let tokenType = accessToken.tokenType
        let isDpop: Bool = match (tokenType) {
            case Some(TokenType.DPoP) => true
            case _ => false
        }

        if (isDpop) {
            headers.add("Authorization", "DPoP " + accessToken.accessToken)
            match (dpopConstructor) {
                case Some(dc) =>
                    let nonceStr: Option<String> = match (dpopNonce) {
                        case Some(n) => Option<String>.Some(n.value)
                        case None => Option<String>.None
                    }
                    let dpopToken = dc.jwt(
                        endpoint,
                        Option<String>.Some(accessToken.accessToken),
                        nonceStr
                    )
                    headers.add(Constants.DPOP, dpopToken)
                    Hilog.info(0, "VCI-PROOF",
                        "dpop proof htu=" + endpoint + " ath=true nonce=" + (!nonceStr.isNone()).toString())
                case None => ()
            }
        } else {
            headers.add("Authorization", "Bearer " + accessToken.accessToken)
        }

        return headers
    }

    private func buildCredentialRequestBody(
        configId: CredentialConfigurationIdentifier,
        payload: IssuanceRequestPayload,
        proofs: Array<Proof>
    ): String {
        let obj = JsonObject()
        obj.put("credential_configuration_id", JsonString(configId.value))

        match (payload) {
            case IssuanceRequestPayload.IdentifierBased(_, credId) =>
                obj.put("credential_identifier", JsonString(credId.value))
            case _ => ()
        }

        if (!proofs.isEmpty()) {
            // Always emit "proofs" (plural array), matching iOS CredentialIssuanceRequest
            // (proofs: ProofsTO — always plural, even for a single proof). OpenID4VCI 1.0
            // (openid4vci_version=v1) issuers read "proofs"; a singular "proof" is ignored
            // → invalid_proof "The Credential Request must include Proof of Possession".
            let jwtArr = JsonArray()
            let attestArr = JsonArray()
            var jwtCount: Int64 = 0
            var attestCount: Int64 = 0
            for (p in proofs) {
                match (p) {
                    case Proof.JwtProof(jwt) =>
                        jwtArr.add(JsonString(jwt))
                        jwtCount += 1
                    case Proof.AttestationProof(att) =>
                        attestArr.add(JsonString(att))
                        attestCount += 1
                }
            }
            let proofsObj = JsonObject()
            if (jwtCount > 0) {
                proofsObj.put("jwt", jwtArr)
            }
            if (attestCount > 0) {
                proofsObj.put("attestation", attestArr)
            }
            obj.put("proofs", proofsObj)
        }

        return obj.toJsonString()
    }

    private func proofToJson(proof: Proof): JsonObject {
        let obj = JsonObject()
        match (proof) {
            case Proof.JwtProof(jwt) =>
                obj.put("proof_type", JsonString("jwt"))
                obj.put("jwt", JsonString(jwt))
            case Proof.AttestationProof(att) =>
                obj.put("proof_type", JsonString("attestation"))
                obj.put("attestation", JsonString(att))
        }
        return obj
    }

    private func parseCredentialResponse(body: String): CredentialIssuanceResponse {
        let jv = JsonValue.fromStr(body)
        let jobj: JsonObject = match (jv) {
            case jo: JsonObject => jo
            case _ => throw CredentialIssuanceError.ResponseUnparsable("Credential response not JSON object")
        }

        match (jobj.get("error")) {
            case Some(js: JsonString) =>
                let errStr = js.getValue()
                if (errStr == "invalid_proof") {
                    let desc: Option<String> = match (jobj.get("error_description")) {
                        case Some(jd: JsonString) => Option<String>.Some(jd.getValue())
                        case _ => Option<String>.None
                    }
                    throw CredentialIssuanceError.InvalidProof(desc)
                }
                let errDesc: Option<String> = match (jobj.get("error_description")) {
                    case Some(jd: JsonString) => Option<String>.Some(jd.getValue())
                    case _ => Option<String>.None
                }
                throw CredentialIssuanceError.RequestFailed(
                    400,
                    errStr,
                    errDesc
                )
            case _ => ()
        }

        match (jobj.get("credential")) {
            case Some(js: JsonString) =>
                let notifId: Option<String> = match (jobj.get("notification_id")) {
                    case Some(jn: JsonString) => Option<String>.Some(jn.getValue())
                    case _ => Option<String>.None
                }
                let issued = IssuedCredential.Issued(
                    Option<String>.None,
                    Credential.StringCredential(js.getValue()),
                    notifId
                )
                return CredentialIssuanceResponse([issued])
            case _ => ()
        }

        match (jobj.get("transaction_id")) {
            case Some(js: JsonString) =>
                let txId = TransactionId(js.getValue())
                let interval: Float64 = match (jobj.get("interval")) {
                    case Some(ji: JsonInt) => Float64(ji.getValue())
                    case Some(jf: JsonFloat) => jf.getValue()
                    case _ => 5.0
                }
                let deferred = IssuedCredential.Deferred(txId, interval)
                return CredentialIssuanceResponse([deferred])
            case _ => ()
        }

        match (jobj.get("credentials")) {
            case Some(jarr: JsonArray) =>
                let result = ArrayList<IssuedCredential>()
                for (item in jarr.getItems()) {
                    match (item) {
                        case js: JsonString =>
                            result.add(IssuedCredential.Issued(
                                Option<String>.None,
                                Credential.StringCredential(js.getValue()),
                                Option<String>.None
                            ))
                        // OpenID4VCI draft-15+ / eudiw: credentials is an array of
                        // objects, each {"credential": "<mdoc>"}.
                        case jo: JsonObject =>
                            match (jo.get("credential")) {
                                case Some(cs: JsonString) =>
                                    result.add(IssuedCredential.Issued(
                                        Option<String>.None,
                                        Credential.StringCredential(cs.getValue()),
                                        Option<String>.None
                                    ))
                                case _ => ()
                            }
                        case _ => ()
                    }
                }
                if (!result.isEmpty()) {
                    return CredentialIssuanceResponse(result.toArray())
                }
            case _ => ()
        }

        throw CredentialIssuanceError.ResponseUnparsable(
            "Credential response missing 'credential', 'credentials', or 'transaction_id'"
        )
    }
}
