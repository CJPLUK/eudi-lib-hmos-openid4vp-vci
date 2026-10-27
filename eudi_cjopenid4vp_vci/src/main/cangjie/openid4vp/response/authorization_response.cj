/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * authorization_response.cj — VP response side types.
 * Block 5 scope: Consensus → AuthorizationResponse → dispatch.
 *
 * Ported from iOS:
 *   - Entities/Types/VpToken.swift          (VerifiablePresentation, VpToken)
 *   - Entities/Types/VPContent.swift        (VpContent)
 *   - Entities/Types/ClientConsent.swift    (ClientConsent)
 *   - Entities/AuthorisationRequest/AuthorizationResponsePayload.swift
 *   - Entities/AuthorisationRequest/AuthorizationResponse.swift
 *   - Entities/Types/EncryptionParameters.swift
 *   - Entities/Types/AuthorizationRequestErrorCode.swift
 *
 * iOS enum with associated values → Cangjie sealed class hierarchy.
 * iOS Codable → manual JSON serialization via stdx.encoding.json.
 * iOS SwiftyJSON → Cangjie JsonValue from stdx.encoding.json.
 */
package ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.response

import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.error.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.entity.types.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.entity.dcql.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.entity.client.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.entity.request.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.entity.metadata.*
import std.collection.*
import stdx.encoding.json.*

// VerifiablePresentation, GenericPresentation, JsonPresentation are defined
// in openid4vp.entity.dcql (dcql.cj) and imported via dcql.* above.

// ---------------------------------------------------------------------------
// VpContent — mirrors iOS VpContent
// DCQL variant: QueryId -> [VerifiablePresentation]
// ---------------------------------------------------------------------------

public abstract sealed class VpContent {}

public class DcqlVpContent <: VpContent {
    // Maps credential query ID (String) to list of verifiable presentations
    public let verifiablePresentations: HashMap<String, Array<VerifiablePresentation>>
    public init(verifiablePresentations: HashMap<String, Array<VerifiablePresentation>>) {
        this.verifiablePresentations = verifiablePresentations
    }
}

// Encode DCQL content as JSON object: {"queryId": ["vp1", ...], ...}
// Mirrors iOS VpContent.encodeDCQLQuery(_:)
public func encodeDCQLQuery(query: HashMap<String, Array<VerifiablePresentation>>): JsonObject {
    let obj = JsonObject()
    for ((queryId, presentations) in query) {
        let arr = JsonArray()
        for (vp in presentations) {
            match (vp) {
                case g: GenericPresentation =>
                    arr.add(JsonString(g.value))
                case j: JsonPresentation =>
                    // Try to parse as JSON, fall back to string
                    try {
                        let parsed = JsonValue.fromStr(j.jsonStr)
                        arr.add(parsed)
                    } catch (_: Exception) {
                        arr.add(JsonString(j.jsonStr))
                    }
                case _ => ()
            }
        }
        obj.put(queryId, arr)
    }
    return obj
}

// ---------------------------------------------------------------------------
// EncryptionParameters — mirrors iOS EncryptionParameters
// ---------------------------------------------------------------------------

public abstract sealed class EncryptionParameters {}

public class ApuParam <: EncryptionParameters {
    // base64url-encoded string (PartyUInfo for ECDH-ES JARM)
    public let apu: String
    public init(apu: String) { this.apu = apu }
}

// ---------------------------------------------------------------------------
// AuthorizationRequestErrorCode — mirrors iOS AuthorizationRequestErrorCode
// ---------------------------------------------------------------------------

public enum AuthorizationRequestErrorCode <: ToString {
    | InvalidScope
    | InvalidRequest
    | AccessDenied
    | InvalidClient
    | VpFormatsNotSupported
    | InvalidRequestURIMethod
    | InvalidTransactionData
    | UserCancelled
    | RegistrationValueNotSupported
    | SubjectSyntaxTypesNotSupported
    | InvalidRegistrationURI
    | InvalidRegistrationObject
    | InvalidRequestURI
    | InvalidRequestObject
    | RequestURINotSupported
    | ProcessingFailure

    public func toString(): String {
        match (this) {
            case InvalidScope => "invalid_scope"
            case InvalidRequest => "invalid_request"
            case AccessDenied => "access_denied"
            case InvalidClient => "invalid_client"
            case VpFormatsNotSupported => "vp_formats_not_supported"
            case InvalidRequestURIMethod => "invalid_request_uri_method"
            case InvalidTransactionData => "invalid_transaction_data"
            case UserCancelled => "user_cancelled"
            case RegistrationValueNotSupported => "registration_value_not_supported"
            case SubjectSyntaxTypesNotSupported => "subject_syntax_types_not_supported"
            case InvalidRegistrationURI => "invalid_registration_uri"
            case InvalidRegistrationObject => "invalid_registration_object"
            case InvalidRequestURI => "invalid_request_uri"
            case InvalidRequestObject => "invalid_request_object"
            case RequestURINotSupported => "request_uri_not_supported"
            case ProcessingFailure => "processing_error"
        }
    }
}

// ---------------------------------------------------------------------------
// AuthorizationResponsePayload — mirrors iOS AuthorizationResponsePayload
// ---------------------------------------------------------------------------

public abstract sealed class AuthorizationResponsePayload {

    // openId4VPAuthorizationResponse(vpContent, state, nonce, clientId, encryptionParameters?)
    public static func openId4VPAuthorizationResponse(
        vpContent!: VpContent,
        state!: String,
        nonce!: String,
        clientId!: VerifierId,
        encryptionParameters!: Option<EncryptionParameters> = None
    ): VpAuthorizationPayload {
        VpAuthorizationPayload(vpContent, state, nonce, clientId, encryptionParameters)
    }

    // failure
    public static func failure(): FailurePayload {
        FailurePayload()
    }

    // invalidRequest(error, nonce?, state?, clientId?)
    public static func invalidRequest(
        error!: String,
        nonce!: Option<String>,
        state!: Option<String>,
        clientId!: Option<VerifierId>
    ): InvalidRequestPayload {
        InvalidRequestPayload(error, nonce, state, clientId)
    }

    // noConsensusResponseData(state, error)
    public static func noConsensusResponseData(
        state!: String,
        error!: String
    ): NoConsensusPayload {
        NoConsensusPayload(state, error)
    }

    // Get the nonce value (for JARM apv)
    public func nonce(): String {
        match (this) {
            case p: VpAuthorizationPayload => p.nonceVal
            case _ => ""
        }
    }

    // Get the apu value (for JARM ECDH-ES header)
    public func apu(): Option<String> {
        match (this) {
            case p: VpAuthorizationPayload =>
                match (p.encryptionParameters) {
                    case Some(ap: ApuParam) => Some(ap.apu)
                    case _ => None
                }
            case _ => None
        }
    }

    // Serialize payload to form-encoded dict (HashMap<String, String>)
    // Mirrors iOS AuthorizationResponsePayload.toDictionary()
    public func toFormParams(): HashMap<String, String> {
        let result = HashMap<String, String>()
        match (this) {
            case p: VpAuthorizationPayload =>
                result.add("state", p.state)
                // Encode vp_token
                match (p.vpContent) {
                    case dc: DcqlVpContent =>
                        let vpObj = encodeDCQLQuery(dc.verifiablePresentations)
                        result.add("vp_token", vpObj.toJsonString())
                    case _ => ()
                }
            case p: NoConsensusPayload =>
                result.add("state", p.state)
                result.add("error", p.errorMsg)
            case p: InvalidRequestPayload =>
                result.add("error", p.errorCode)
                match (p.errorDescription) {
                    case Some(desc) => result.add("error_description", desc)
                    case None => ()
                }
                match (p.state) {
                    case Some(st) => result.add("state", st)
                    case None => ()
                }
            case _: FailurePayload => ()
            case _ => ()
        }
        return result
    }

    // Serialize payload to JSON string (for JWE plaintext in JARM)
    public func toJsonString(): String {
        let params = toFormParams()
        let obj = JsonObject()
        for ((k, v) in params) {
            if (k == "vp_token") {
                // vp_token must be embedded as a JSON object (DCQL: queryId →
                // presentations map). Nimbus on the verifier side rejects a
                // string-typed vp_token claim ("not a JSON object or Map").
                try {
                    obj.put(k, JsonValue.fromStr(v))
                } catch (_: Exception) {
                    obj.put(k, JsonString(v))
                }
            } else {
                obj.put(k, JsonString(v))
            }
        }
        return obj.toJsonString()
    }
}

public class VpAuthorizationPayload <: AuthorizationResponsePayload {
    public let vpContent: VpContent
    public let state: String
    public let nonceVal: String
    public let clientId: VerifierId
    public let encryptionParameters: Option<EncryptionParameters>

    public init(
        vpContent: VpContent,
        state: String,
        nonce: String,
        clientId: VerifierId,
        encryptionParameters: Option<EncryptionParameters>
    ) {
        this.vpContent = vpContent
        this.state = state
        this.nonceVal = nonce
        this.clientId = clientId
        this.encryptionParameters = encryptionParameters
    }
}

public class FailurePayload <: AuthorizationResponsePayload {
    public init() {}
}

public class InvalidRequestPayload <: AuthorizationResponsePayload {
    public let errorCode: String
    public let errorDescription: Option<String>
    public let nonce_: Option<String>
    public let state: Option<String>
    public let clientId: Option<VerifierId>

    public init(
        errorCode: String,
        nonce: Option<String>,
        state: Option<String>,
        clientId: Option<VerifierId>
    ) {
        this.errorCode = errorCode
        this.errorDescription = None
        this.nonce_ = nonce
        this.state = state
        this.clientId = clientId
    }
}

public class NoConsensusPayload <: AuthorizationResponsePayload {
    public let state: String
    public let errorMsg: String
    public init(state: String, errorMsg: String) {
        this.state = state
        this.errorMsg = errorMsg
    }
}

// ---------------------------------------------------------------------------
// ClientConsent — mirrors iOS ClientConsent
// ---------------------------------------------------------------------------

public abstract sealed class ClientConsent {}

public class VpTokenConsent <: ClientConsent {
    public let vpContent: VpContent
    public init(vpContent: VpContent) { this.vpContent = vpContent }
}

public class NegativeConsent <: ClientConsent {
    public let message: String
    public init(message: String) { this.message = message }
}

// ---------------------------------------------------------------------------
// AuthorizationResponse — mirrors iOS AuthorizationResponse
// ---------------------------------------------------------------------------

public abstract sealed class AuthorizationResponse {

    // directPost(url, data)
    public static func directPost(url!: String, data!: AuthorizationResponsePayload): DirectPostResponse {
        DirectPostResponse(url, data)
    }
    // directPostJwt(url, data, encSpec)
    public static func directPostJwt(
        url!: String,
        data!: AuthorizationResponsePayload,
        responseEncryptionSpecification!: ResponseEncryptionSpecification
    ): DirectPostJwtResponse {
        DirectPostJwtResponse(url, data, responseEncryptionSpecification)
    }
    // query(url, data)
    public static func query(url!: String, data!: AuthorizationResponsePayload): QueryResponse {
        QueryResponse(url, data)
    }
    // fragment(url, data)
    public static func fragment(url!: String, data!: AuthorizationResponsePayload): FragmentResponse {
        FragmentResponse(url, data)
    }
    // invalidRequest(error, nonce?, state?, clientId?)
    public static func invalidRequest(
        error!: String,
        nonce!: Option<String>,
        state!: Option<String>,
        clientId!: Option<VerifierId>
    ): InvalidRequestResponse {
        InvalidRequestResponse(error, nonce, state, clientId)
    }

    // Factory: build from ResolvedRequestData + ClientConsent
    // Mirrors iOS AuthorizationResponse.init(resolvedRequest:consent:walletOpenId4VPConfig:encryptionParameters:)
    public static func fromConsent(
        resolvedRequest!: ResolvedRequestData,
        consent!: ClientConsent,
        encryptionParameters!: Option<EncryptionParameters> = None
    ): AuthorizationResponse {
        let request = resolvedRequest.request
        match (consent) {
            case c: VpTokenConsent =>
                let clientId: VerifierId = request.client.id()
                let state = match (request.state) { case Some(s) => s; case None => "" }
                let payload = VpAuthorizationPayload(
                    c.vpContent,
                    state,
                    request.nonce,
                    clientId,
                    encryptionParameters
                )
                return buildAuthorizationResponse(
                    request.responseMode,
                    payload,
                    request.responseEncryptionSpecification
                )
            case c: NegativeConsent =>
                let state = match (request.state) {
                    case Some(s) => s
                    case None => throw VpAuthorizationError.InvalidState()
                }
                let payload = NoConsensusPayload(state, c.message)
                return buildAuthorizationResponse(
                    request.responseMode,
                    payload,
                    request.responseEncryptionSpecification
                )
            case _ =>
                throw VpAuthorizationError.InvalidResponseMode()
        }
    }
}

// Build the response based on response mode
func buildAuthorizationResponse(
    responseMode: Option<ResponseMode>,
    payload: AuthorizationResponsePayload,
    responseEncryptionSpec: Option<ResponseEncryptionSpecification>
): AuthorizationResponse {
    match (responseMode) {
        case None => throw VpAuthorizationError.InvalidResponseMode()
        case Some(mode) =>
            match (mode) {
                case dp: DirectPost =>
                    return DirectPostResponse(dp.responseUri, payload)
                case dpj: DirectPostJWT =>
                    let encSpec = match (responseEncryptionSpec) {
                        case Some(spec) => spec
                        case None => throw VpValidationError.MissingRequiredField("responseEncryptionSpecification")
                    }
                    return DirectPostJwtResponse(dpj.responseUri, payload, encSpec)
                case q: QueryMode =>
                    return QueryResponse(q.responseUri, payload)
                case f: FragmentMode =>
                    return FragmentResponse(f.responseUri, payload)
                case _: NoneMode =>
                    throw VpAuthorizationError.InvalidResponseMode()
                case _ =>
                    throw VpAuthorizationError.InvalidResponseMode()
            }
    }
}

public class DirectPostResponse <: AuthorizationResponse {
    public let url: String
    public let data: AuthorizationResponsePayload
    public init(url: String, data: AuthorizationResponsePayload) {
        this.url = url
        this.data = data
    }
}

public class DirectPostJwtResponse <: AuthorizationResponse {
    public let url: String
    public let data: AuthorizationResponsePayload
    public let responseEncryptionSpecification: ResponseEncryptionSpecification
    public init(url: String, data: AuthorizationResponsePayload, spec: ResponseEncryptionSpecification) {
        this.url = url
        this.data = data
        this.responseEncryptionSpecification = spec
    }
}

public class QueryResponse <: AuthorizationResponse {
    public let url: String
    public let data: AuthorizationResponsePayload
    public init(url: String, data: AuthorizationResponsePayload) {
        this.url = url
        this.data = data
    }
}

public class FragmentResponse <: AuthorizationResponse {
    public let url: String
    public let data: AuthorizationResponsePayload
    public init(url: String, data: AuthorizationResponsePayload) {
        this.url = url
        this.data = data
    }
}

public class InvalidRequestResponse <: AuthorizationResponse {
    public let error: String
    public let nonce: Option<String>
    public let state: Option<String>
    public let clientId: Option<VerifierId>
    public init(error: String, nonce: Option<String>, state: Option<String>, clientId: Option<VerifierId>) {
        this.error = error
        this.nonce = nonce
        this.state = state
        this.clientId = clientId
    }
}

// ---------------------------------------------------------------------------
// VpAuthorizationError — mirrors iOS AuthorizationError (VP side)
// ---------------------------------------------------------------------------

public class VpAuthorizationError <: Exception {
    public init(msg: String) { super(msg) }

    public static func UnsupportedResponseType(type_: String): VpAuthorizationError {
        VpAuthorizationError("unsupportedResponseType: " + type_)
    }
    public static func MissingResponseType(): VpAuthorizationError {
        VpAuthorizationError("missingResponseType")
    }
    public static func UnsupportedURLScheme(): VpAuthorizationError {
        VpAuthorizationError("unsupportedURLScheme")
    }
    public static func InvalidState(): VpAuthorizationError {
        VpAuthorizationError("invalidState")
    }
    public static func InvalidNonce(): VpAuthorizationError {
        VpAuthorizationError("invalidNonce")
    }
    public static func InvalidResponseMode(): VpAuthorizationError {
        VpAuthorizationError("invalidResponseMode")
    }
    public static func NonDispatchableError(): VpAuthorizationError {
        VpAuthorizationError("nonDispatchableError")
    }
    public static func JwtDecryptionFailed(): VpAuthorizationError {
        VpAuthorizationError("jwtDecryptionFailed")
    }
    public static func InvalidAlgorithms(): VpAuthorizationError {
        VpAuthorizationError("invalidAlgorithms")
    }
}
