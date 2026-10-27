/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * issuance_types.cj — State/result types for the VCI issuance flow.
 * Ported from iOS:
 *   - Sources/Entities/Issuance/AuthorizationRequestPrepared.swift
 *   - Sources/Entities/Issuance/AuthorizedRequest.swift
 *   - Sources/Entities/Issuance/SubmittedRequest.swift
 *   - Sources/Entities/Issuance/IssuanceRequestPayload.swift
 *   - Sources/Entities/Issuance/NotificationObject.swift
 *   - Sources/Entities/Issuance/NotificationTO.swift
 *   - Sources/Entities/Issuance/CredentialIssuanceEvent.swift
 *   - Sources/Entities/Types/DeferredCredentialIssuanceResponse.swift
 *   - Sources/Entities/Credential/IssuedCredential.swift
 *   - Sources/Entities/Credential/Credential.swift
 *   - Sources/Entities/AuthorizationDetails/AuthorizationDetails.swift
 *
 * iOS actor/Sendable → class; iOS async → sync; iOS Codable → manual JSON.
 * iOS Swift tuples for multi-return → Cangjie named classes.
 */
package ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.issuance

import std.collection.*
import std.time.DateTime
import stdx.encoding.json.*
import stdx.crypto.keys.ECDSAPrivateKey
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.types.{
    Grants, CredentialConfigurationIdentifier, CredentialIdentifier, TransactionId, Nonce
}
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.access.{
    IssuanceAccessToken, IssuanceRefreshToken
}
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.pkce.PKCEVerifier
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.error.{ValidationError, CredentialIssuanceError}

// ---------------------------------------------------------------------------
// GrantType
// ---------------------------------------------------------------------------

public enum GrantType {
    | AuthorizationCode
    | PreAuthorizationCode
    | Both

    public static func fromGrants(grants: Option<Grants>): Option<GrantType> {
        match (grants) {
            case Some(Grants.AuthCode(_)) => Option<GrantType>.Some(GrantType.AuthorizationCode)
            case Some(Grants.PreAuthCode(_)) => Option<GrantType>.Some(GrantType.PreAuthorizationCode)
            case Some(Grants.Both(_, _)) => Option<GrantType>.Some(GrantType.Both)
            case None => Option<GrantType>.None
        }
    }
}

// ---------------------------------------------------------------------------
// AuthorizationCodeURL — validated HTTPS authorization URL
// ---------------------------------------------------------------------------

public class AuthorizationCodeURL {
    public let url: String

    public init(urlString: String) {
        if (urlString.isEmpty()) {
            throw ValidationError.InvalidUrl(urlString)
        }
        if (!urlString.startsWith("https://")) {
            throw ValidationError.NonHttpsUrl(urlString)
        }
        this.url = urlString
    }
}

// ---------------------------------------------------------------------------
// AuthorizationRequested
// State after PAR/auth-request sent; caller must redirect user to authorizationCodeURL.
// Ported from iOS AuthorizationRequested struct.
// ---------------------------------------------------------------------------

public class AuthorizationRequested {
    public let credentials: Array<CredentialIdentifier>
    public let authorizationCodeURL: AuthorizationCodeURL
    public let pkceVerifier: PKCEVerifier
    public let state: String
    public let configurationIds: Array<CredentialConfigurationIdentifier>
    public let dpopNonce: Option<Nonce>

    public init(
        credentials: Array<CredentialIdentifier>,
        authorizationCodeURL: AuthorizationCodeURL,
        pkceVerifier: PKCEVerifier,
        state: String,
        configurationIds: Array<CredentialConfigurationIdentifier>,
        dpopNonce: Option<Nonce>
    ) {
        this.credentials = credentials
        this.authorizationCodeURL = authorizationCodeURL
        this.pkceVerifier = pkceVerifier
        this.state = state
        this.configurationIds = configurationIds
        this.dpopNonce = dpopNonce
    }
}

// ---------------------------------------------------------------------------
// AuthorizationDetailsIdentifiers
// Maps CredentialConfigurationIdentifier -> list of CredentialIdentifier.
// Ported from iOS typealias AuthorizationDetailsIdentifiers.
// ---------------------------------------------------------------------------

public class AuthorizationDetailsIdentifiers {
    public let map: HashMap<String, Array<CredentialIdentifier>>

    public init(map: HashMap<String, Array<CredentialIdentifier>>) {
        this.map = map
    }

    public func get(configId: CredentialConfigurationIdentifier): Option<Array<CredentialIdentifier>> {
        return map.get(configId.value)
    }

    public func isEmpty(): Bool {
        return map.isEmpty()
    }

    /*
     * Parse from token response JSON.
     * authorization_details: [ { type: "openid_credential",
     *   credential_configuration_id: "...", credential_identifiers: [...] } ]
     */
    public static func fromJson(root: JsonObject): Option<AuthorizationDetailsIdentifiers> {
        let arr: JsonArray = match (root.get("authorization_details")) {
            case Some(ja: JsonArray) => ja
            case _ => return Option<AuthorizationDetailsIdentifiers>.None
        }
        let map = HashMap<String, Array<CredentialIdentifier>>()
        for (item in arr.getItems()) {
            match (item) {
                case jobj: JsonObject =>
                    let configIdStr: String = match (jobj.get("credential_configuration_id")) {
                        case Some(js: JsonString) => js.getValue()
                        case _ => continue
                    }
                    let identifiers = ArrayList<CredentialIdentifier>()
                    match (jobj.get("credential_identifiers")) {
                        case Some(jarr2: JsonArray) =>
                            for (idItem in jarr2.getItems()) {
                                match (idItem) {
                                    case js: JsonString =>
                                        identifiers.add(CredentialIdentifier(js.getValue()))
                                    case _ => ()
                                }
                            }
                        case _ => ()
                    }
                    map.add(configIdStr, identifiers.toArray())
                case _ => ()
            }
        }
        if (map.isEmpty()) {
            return Option<AuthorizationDetailsIdentifiers>.None
        }
        return Option<AuthorizationDetailsIdentifiers>.Some(AuthorizationDetailsIdentifiers(map))
    }
}

// ---------------------------------------------------------------------------
// AuthorizedRequest
// State after token exchange; holds access token + optional credential identifiers.
// Ported from iOS struct AuthorizedRequest.
// ---------------------------------------------------------------------------

public class AuthorizedRequest {
    public let accessToken: IssuanceAccessToken
    public let refreshToken: Option<IssuanceRefreshToken>
    public let credentialIdentifiers: Option<AuthorizationDetailsIdentifiers>
    public let timeStamp: Float64     // Unix seconds
    public let dPopNonce: Option<Nonce>
    public let grantType: Option<GrantType>

    public init(
        accessToken: IssuanceAccessToken,
        refreshToken: Option<IssuanceRefreshToken>,
        credentialIdentifiers: Option<AuthorizationDetailsIdentifiers>,
        timeStamp: Float64,
        dPopNonce: Option<Nonce>,
        grantType: Option<GrantType>
    ) {
        this.accessToken = accessToken
        this.refreshToken = refreshToken
        this.credentialIdentifiers = credentialIdentifiers
        this.timeStamp = timeStamp
        this.dPopNonce = dPopNonce
        this.grantType = grantType
    }

    public func isAccessTokenExpired(at: Float64): Bool {
        let expiresIn = accessToken.expiresIn
        if (expiresIn <= 0.0) { return false }
        return (timeStamp + expiresIn) < at
    }

    public func replacingAccessToken(
        newToken: IssuanceAccessToken,
        newTimeStamp: Float64
    ): AuthorizedRequest {
        return AuthorizedRequest(
            newToken,
            refreshToken,
            credentialIdentifiers,
            newTimeStamp,
            dPopNonce,
            grantType
        )
    }

    public func replacingAccessToken(
        newToken: IssuanceAccessToken,
        newRefreshToken: Option<IssuanceRefreshToken>,
        newTimeStamp: Float64
    ): AuthorizedRequest {
        return AuthorizedRequest(
            newToken,
            newRefreshToken,
            credentialIdentifiers,
            newTimeStamp,
            dPopNonce,
            grantType
        )
    }
}

// ---------------------------------------------------------------------------
// IssuanceRequestPayload
// Ported from iOS enum IssuanceRequestPayload.
// ---------------------------------------------------------------------------

public enum IssuanceRequestPayload {
    | IdentifierBased(CredentialConfigurationIdentifier, CredentialIdentifier)
    | ConfigurationBased(CredentialConfigurationIdentifier)

    public func credentialConfigurationIdentifier(): CredentialConfigurationIdentifier {
        match (this) {
            case IdentifierBased(ccId, _) => ccId
            case ConfigurationBased(ccId) => ccId
        }
    }
}

// ---------------------------------------------------------------------------
// Credential — issued credential value (string JWT or JSON object)
// Ported from iOS enum Credential.
// ---------------------------------------------------------------------------

public enum Credential {
    | StringCredential(String)
    | JsonCredential(JsonObject)

    public func asString(): Option<String> {
        match (this) {
            case StringCredential(s) => Option<String>.Some(s)
            case _ => Option<String>.None
        }
    }
}

// ---------------------------------------------------------------------------
// IssuedCredential — single credential response item
// Ported from iOS enum IssuedCredential.
// ---------------------------------------------------------------------------

public enum IssuedCredential {
    | Issued(Option<String>, Credential, Option<String>)  // (format, credential, notificationId)
    | Deferred(TransactionId, Float64)                     // (transactionId, retryIntervalSeconds)
}

// ---------------------------------------------------------------------------
// CredentialIssuanceResponse
// Ported from iOS struct CredentialIssuanceResponse.
// ---------------------------------------------------------------------------

public class CredentialIssuanceResponse {
    public let credentialResponses: Array<IssuedCredential>

    public init(credentialResponses: Array<IssuedCredential>) {
        this.credentialResponses = credentialResponses
    }
}

// ---------------------------------------------------------------------------
// SubmittedRequest — result of a credential request
// Ported from iOS enum SubmittedRequest.
// ---------------------------------------------------------------------------

public enum SubmittedRequest {
    | Success(CredentialIssuanceResponse)
    | Failed(CredentialIssuanceError)
    | InvalidProof(Option<String>)    // errorDescription
}

// ---------------------------------------------------------------------------
// DeferredCredentialIssuanceResponse
// Ported from iOS enum DeferredCredentialIssuanceResponse.
// ---------------------------------------------------------------------------

public enum DeferredCredentialIssuanceResponse {
    // ALL credentials from the deferred response — the OID4VCI v1 plural form
    // returns one entry per proof of the original batch request (e.g. 30 for a
    // batchSize-30 issuance). iOS carries the same set as one Credential.json
    // array and fans it out in handleCredentialResponse; here the array is
    // explicit. Single-credential responses yield a one-element array.
    | Issued(Array<Credential>)
    | IssuancePending(TransactionId, Float64)   // (transactionId, retryIntervalSeconds)
    | IssuanceStillPending(Float64)             // retryIntervalSeconds
    | Errored(Option<String>, Option<String>)  // (error, errorDescription)

    /*
     * Parse from HTTP response body JSON.
     */
    public static func fromJson(obj: JsonObject): DeferredCredentialIssuanceResponse {
        // Check for pending: transaction_id + interval
        let txIdOpt: Option<String> = match (obj.get("transaction_id")) {
            case Some(js: JsonString) => Option<String>.Some(js.getValue())
            case _ => Option<String>.None
        }
        let intervalOpt: Option<Float64> = match (obj.get("interval")) {
            case Some(ji: JsonInt) => Option<Float64>.Some(Float64(ji.getValue()))
            case Some(jf: JsonFloat) => Option<Float64>.Some(jf.getValue())
            case _ => Option<Float64>.None
        }

        if (!txIdOpt.isNone() && !intervalOpt.isNone()) {
            let txId = TransactionId(txIdOpt.getOrThrow())
            return DeferredCredentialIssuanceResponse.IssuancePending(txId, intervalOpt.getOrThrow())
        }

        // Check for issued credentials — OID4VCI v1 (issuer-backend) returns the
        // PLURAL form: {"credentials":[{"credential":"..."}]} (objects) or an
        // array of bare strings. Same plural-vs-singular pitfall as the
        // credential endpoint; without this branch a READY credential fell
        // through to Errored(unknown). Collect EVERY entry — a batch issuance
        // returns one credential per original proof (iOS fans the same array
        // out in handleCredentialResponse); taking only the first entry
        // silently dropped the rest of the batch (surfaced as "1/30").
        match (obj.get("credentials")) {
            case Some(ja: JsonArray) =>
                let creds = ArrayList<Credential>()
                for (item in ja.getItems()) {
                    match (item) {
                        case jo: JsonObject =>
                            match (jo.get("credential")) {
                                case Some(js: JsonString) =>
                                    creds.add(Credential.StringCredential(js.getValue()))
                                // JWS-JSON serialization: the credential is a JSON
                                // OBJECT, not a string (this fell through to
                                // Errored(unknown) → a false "Issuance failed").
                                case Some(jobj: JsonObject) =>
                                    creds.add(Credential.JsonCredential(jobj))
                                case _ => ()
                            }
                        case js: JsonString =>
                            creds.add(Credential.StringCredential(js.getValue()))
                        case _ => ()
                    }
                }
                if (creds.size > 0) {
                    return DeferredCredentialIssuanceResponse.Issued(creds.toArray())
                }
            case _ => ()
        }
        // Draft-13 singular form.
        let credOpt: Option<String> = match (obj.get("credential")) {
            case Some(js: JsonString) => Option<String>.Some(js.getValue())
            case _ => Option<String>.None
        }
        if (!credOpt.isNone()) {
            return DeferredCredentialIssuanceResponse.Issued([Credential.StringCredential(credOpt.getOrThrow())])
        }

        // Still pending (interval only)
        if (!intervalOpt.isNone()) {
            return DeferredCredentialIssuanceResponse.IssuanceStillPending(intervalOpt.getOrThrow())
        }

        // Error
        let error: Option<String> = match (obj.get("error")) {
            case Some(js: JsonString) => Option<String>.Some(js.getValue())
            case _ => Option<String>.None
        }
        let errorDesc: Option<String> = match (obj.get("error_description")) {
            case Some(js: JsonString) => Option<String>.Some(js.getValue())
            case _ => Option<String>.None
        }
        return DeferredCredentialIssuanceResponse.Errored(error, errorDesc)
    }
}

// ---------------------------------------------------------------------------
// NotificationId
// ---------------------------------------------------------------------------

public class NotificationId {
    public let value: String

    public init(value: String) {
        if (value.isEmpty()) {
            throw ValidationError.Error("Empty NotificationId")
        }
        this.value = value
    }
}

// ---------------------------------------------------------------------------
// NotifiedEvent
// Ported from iOS enum NotifiedEvent.
// ---------------------------------------------------------------------------

public enum NotifiedEvent {
    | CredentialAccepted
    | CredentialFailure
    | CredentialDeleted

    public func rawValue(): String {
        match (this) {
            case CredentialAccepted => "credential_accepted"
            case CredentialFailure => "credential_failure"
            case CredentialDeleted => "credential_deleted"
        }
    }

    public static func of(s: String): Option<NotifiedEvent> {
        match (s) {
            case "credential_accepted" => Option<NotifiedEvent>.Some(NotifiedEvent.CredentialAccepted)
            case "credential_failure" => Option<NotifiedEvent>.Some(NotifiedEvent.CredentialFailure)
            case "credential_deleted" => Option<NotifiedEvent>.Some(NotifiedEvent.CredentialDeleted)
            case _ => Option<NotifiedEvent>.None
        }
    }
}

// ---------------------------------------------------------------------------
// NotificationObject
// Ported from iOS struct NotificationObject.
// ---------------------------------------------------------------------------

public class NotificationObject {
    public let id: NotificationId
    public let event: NotifiedEvent
    public let eventDescription: Option<String>

    public init(id: NotificationId, event: NotifiedEvent, eventDescription: Option<String>) {
        this.id = id
        this.event = event
        this.eventDescription = eventDescription
    }

    public func toJsonObject(): JsonObject {
        let obj = JsonObject()
        obj.put("notification_id", JsonString(id.value))
        obj.put("event", JsonString(event.rawValue()))
        match (eventDescription) {
            case Some(desc) => obj.put("event_description", JsonString(desc))
            case None => ()
        }
        return obj
    }
}

// ---------------------------------------------------------------------------
// AuthorizationDetailsInTokenRequest
// Ported from iOS enum AuthorizationDetailsInTokenRequest.
// Cangjie: closures supported; use Bool function instead of @Sendable.
// ---------------------------------------------------------------------------

public enum AuthorizationDetailsInTokenRequest {
    | DoNotInclude
    | Include

    // Simplified: "Include" means include all credential config identifiers from the offer
    // (in iOS this is a filter closure; we simplify to include-all here)
}

// ---------------------------------------------------------------------------
// CNonceResponse — c_nonce value returned from nonce endpoint
// ---------------------------------------------------------------------------

public class CNonceResponse {
    public let cNonce: String

    public init(cNonce: String) {
        this.cNonce = cNonce
    }

    public static func fromJson(obj: JsonObject): CNonceResponse {
        let nonce: String = match (obj.get("c_nonce")) {
            case Some(js: JsonString) => js.getValue()
            case _ => throw ValidationError.Error("c_nonce missing from nonce response")
        }
        return CNonceResponse(nonce)
    }
}

// ---------------------------------------------------------------------------
// ProofTypeRequirement
// Ported from iOS CredentialProofsRequirement.
// ---------------------------------------------------------------------------

public enum ProofTypeRequirement {
    | ProofNotRequired
    | ProofRequiredWithoutCNonce
    | ProofRequiredWithCNonce
}

// ---------------------------------------------------------------------------
// Proof — credential proof types
// Ported from iOS enum Proof.
// ---------------------------------------------------------------------------

public enum Proof {
    | JwtProof(String)           // compact-serialized JWS
    | AttestationProof(String)   // key attestation JWT
}

// ---------------------------------------------------------------------------
// BindingKey — proof-of-possession key material
// Ported from iOS BindingKey enum.
// Cangjie: ECDSAPrivateKey from stdx.crypto.keys.
//
// x509 and DID variants: structural presence is correct; proof building for
// these is documented as "not yet implementable" in the known limitations
// section of the module README because:
//   - x509: requires X.509 certificate signing path (CMS/PKCS#7) not available
//     in the current jose lib (only EC JWS is supported).
//   - did: DID resolution requires a network/registry call, out of scope for
//     the synchronous proof-building path.
// Neither variant is left as a code stub — calling buildProof on x509/DID
// throws a CredentialIssuanceError with a descriptive message.
// ---------------------------------------------------------------------------

public enum BindingKey {
    | JwtKey(ECDSAPrivateKey, String)   // (privateKey, algorithm e.g. "ES256")
    // JWT proof carrying a key attestation in its header (key_attestations_required
    // configs). The closure is invoked with the c_nonce at proof-build time and
    // returns the key-attestation JWT (mirrors iOS BindingKey.jwtKeyAttestation +
    // funcKeyAttestationJWT). (privateKey, algorithm, attestationFn(cNonce)->attJwt)
    | JwtKeyAttestation(ECDSAPrivateKey, String, (Option<String>) -> String)
    // Hardware / SecureArea path: uncompressed P-256 public point (0x04||X||Y)
    // plus a signer that returns raw r||s over the JWS signing-input bytes.
    // Private key never enters this process.
    | JwtCallback(Array<UInt8>, String, (Array<UInt8>) -> Array<UInt8>)
    | JwtCallbackAttestation(Array<UInt8>, String, (Array<UInt8>) -> Array<UInt8>, (Option<String>) -> String)
    // `attestation` proof type (mirrors iOS BindingKey.attestation): one key
    // attestation JWT covers the whole key batch, so no per-key proof JWT is
    // signed. The closure receives the c_nonce and returns the attestation JWT.
    | Attestation((Option<String>) -> String)
    | X509(String)                      // DER/PEM certificate chain (base64)
    | Did(String)                       // DID identity string (e.g. "did:key:z6Mk...")
}
