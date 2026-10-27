/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * resolved_request.cj — Resolved authorization request models.
 * Ported from iOS: ResolvedRequestData.swift, VpTokenData (nested struct),
 * AuthorizationRequest.swift, ErrorDispatchDetails.swift, AuthorizationError.
 *
 * iOS async init → sync factory method.
 */
package ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.entity.request

import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.error.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.entity.types.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.entity.dcql.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.entity.client.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.entity.metadata.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.entity.config.*
import std.collection.*
import stdx.encoding.json.*

// ---------------------------------------------------------------------------
// ErrorDispatchDetails — mirrors iOS ErrorDispatchDetails
// ---------------------------------------------------------------------------

public class ErrorDispatchDetails {
    public let responseMode: Option<ResponseMode>
    public let nonce: Option<String>
    public let state: Option<String>
    public let clientId: Option<VerifierId>
    public let responseEncryptionSpecification: Option<ResponseEncryptionSpecification>

    public init(
        responseMode!: Option<ResponseMode>,
        nonce!: Option<String> = None,
        state!: Option<String> = None,
        clientId!: Option<VerifierId>,
        responseEncryptionSpecification!: Option<ResponseEncryptionSpecification> = None
    ) {
        this.responseMode = responseMode
        this.nonce = nonce
        this.state = state
        this.clientId = clientId
        this.responseEncryptionSpecification = responseEncryptionSpecification
    }
}

// ---------------------------------------------------------------------------
// VpTokenData — mirrors iOS ResolvedRequestData.VpTokenData (nested struct)
// ---------------------------------------------------------------------------

public class VpTokenData {
    public let presentationQuery: PresentationQuery
    public let clientMetaData: Option<ValidatedClientMetaData>
    public let client: Client
    public let nonce: String
    public let responseMode: Option<ResponseMode>
    public let state: Option<String>
    public let vpFormatsSupported: VpFormatsSupported
    public let transactionData: Option<Array<TransactionData>>
    public let responseEncryptionSpecification: Option<ResponseEncryptionSpecification>
    public let verifierInfo: Option<Array<VerifierInfo>>
    /**
     * WRP Registration Certificate (WRPRC) raw value extracted from the
     * `verifier_info` entry with format "registration_cert", if any.
     * Mirrors iOS ResolvedRequestData.registrationCertificate (v0.41.0).
     */
    public let registrationCertificate: Option<String>

    public init(
        presentationQuery!: PresentationQuery,
        clientMetaData!: Option<ValidatedClientMetaData> = None,
        client!: Client,
        nonce!: String,
        responseMode!: Option<ResponseMode> = None,
        state!: Option<String> = None,
        vpFormatsSupported!: VpFormatsSupported,
        responseEncryptionSpecification!: Option<ResponseEncryptionSpecification> = None,
        transactionData!: Option<Array<TransactionData>> = None,
        verifierInfo!: Option<Array<VerifierInfo>> = None,
        registrationCertificate!: Option<String> = None
    ) {
        this.presentationQuery = presentationQuery
        this.clientMetaData = clientMetaData
        this.client = client
        this.nonce = nonce
        this.responseMode = responseMode
        this.state = state
        this.vpFormatsSupported = vpFormatsSupported
        this.transactionData = transactionData
        this.responseEncryptionSpecification = responseEncryptionSpecification
        this.verifierInfo = verifierInfo
        this.registrationCertificate = registrationCertificate
    }
}

// ---------------------------------------------------------------------------
// ResolvedRequestData — mirrors iOS ResolvedRequestData
// ---------------------------------------------------------------------------

public class ResolvedRequestData {
    public let request: VpTokenData

    public init(request: VpTokenData) {
        this.request = request
    }

    public func dcql(): Option<DCQL> {
        match (request.presentationQuery) {
            case q: DCQLQuery => Some(q.dcql)
            case _ => None
        }
    }

    public func client(): Client { request.client }
    public func legalName(): Option<String> { request.client.legalName() }

    /**
     * The raw WRP Registration Certificate (WRPRC) delivered in `verifier_info`
     * (format "registration_cert"), if the request carried one.
     */
    public func registrationCertificate(): Option<String> { request.registrationCertificate }

    // Factory: build ResolvedRequestData from ValidatedRequestData + metadata
    // Mirrors iOS ResolvedRequestData.init(walletConfiguration:vpConfiguration:validatedClientMetaData:validatedAuthorizationRequest:)
    public static func fromValidated(
        vpConfiguration: VPConfiguration,
        validatedClientMetaData: ValidatedClientMetaData,
        validatedAuthorizationRequest: ValidatedRequestData
    ): ResolvedRequestData {
        let req = validatedAuthorizationRequest.request

        // Resolve presentation query from query source
        let presentationQuery = resolvePresentationQuery(req.querySource)

        // Common VP formats
        let commonFormats = match (VpFormatsSupported.common(req.vpFormatsSupported, vpConfiguration.vpFormatsSupported)) {
            case Some(f) => f
            case None => req.vpFormatsSupported
        }

        // Parse transaction data (base64url encoded JSON blobs)
        let parsedTransactionData: Option<Array<TransactionData>> = match (req.transactionData) {
            case None => None
            case Some(tds) =>
                var result = ArrayList<TransactionData>()
                for (tdStr in tds) {
                    match (TransactionData.parse(
                        tdStr,
                        vpConfiguration.supportedTransactionDataTypes,
                        presentationQuery
                    )) {
                        case Some(td) => result.add(td)
                        case None => ()  // skip unsupported items (mirrors compactMap)
                    }
                }
                Some(result.toArray())
        }

        // Parse verifier info
        let verifierInfo: Option<Array<VerifierInfo>> = match (req.verifierInfoJsons) {
            case None => None
            case Some(jsonStrs) =>
                var vis = ArrayList<VerifierInfo>()
                for (jsonStr in jsonStrs) {
                    let parsed = JsonValue.fromStr(jsonStr)
                    match (parsed) {
                        case obj: JsonObject =>
                            vis.add(VerifierInfo.fromJson(obj))
                        case _ => ()
                    }
                }
                // Validate verifier info credential IDs
                match (presentationQuery) {
                    case q: DCQLQuery =>
                        let validated = VerifierInfo.validatedVerifierInfo(Some(vis.toArray()), q.dcql)
                        validated
                    case _ => Some(vis.toArray())
                }
        }

        // Extract the WRP Registration Certificate (WRPRC) from verifier_info.
        // Mirrors iOS RequestAuthenticator (v0.41.0): the WRPRC travels as the
        // single verifier_info entry with format "registration_cert" whose
        // `data` member is the compact-serialized JWT string.
        let registrationCertificate = extractRegistrationCertificate(verifierInfo)

        let vpTokenData = VpTokenData(
            presentationQuery: presentationQuery,
            clientMetaData: Some(validatedClientMetaData),
            client: req.client,
            nonce: req.nonce,
            responseMode: req.responseMode,
            state: req.state,
            vpFormatsSupported: commonFormats,
            responseEncryptionSpecification: validatedClientMetaData.responseEncryptionSpecification,
            transactionData: parsedTransactionData,
            verifierInfo: verifierInfo,
            registrationCertificate: registrationCertificate
        )

        return ResolvedRequestData(vpTokenData)
    }
}

/**
 * Pick the WRPRC out of the parsed verifier_info entries.
 *
 * - No verifier_info / no "registration_cert" entry → None (the wallet decides
 *   how to treat an absent WRPRC based on its own policy).
 * - More than one "registration_cert" entry → error: per CIR 2024/2082 only one
 *   WRPRC is allowed (mirrors iOS RequestAuthenticator).
 * - The entry's `data` must be a JSON string (the raw compact JWT/CWT value).
 */
func extractRegistrationCertificate(verifierInfo: Option<Array<VerifierInfo>>): Option<String> {
    let entries = match (verifierInfo) {
        case None => return None
        case Some(vis) => vis
    }
    var found: Option<String> = None
    for (vi in entries) {
        if (vi.format != "registration_cert") { continue }
        if (found.isSome()) {
            throw VpValidationError.ValidationError(
                "Multiple WRPRCs found in verifier_info. Per CIR 2024/2082, only one WRPRC is allowed.")
        }
        // dataJson holds the serialized JSON of the "data" member; unwrap the
        // string literal to recover the raw certificate value.
        let raw: String = try {
            match (JsonValue.fromStr(vi.dataJson)) {
                case s: JsonString => s.getValue()
                case _ =>
                    throw VpValidationError.ValidationError(
                        "WRPRC verifier_info data must be a string value")
            }
        } catch (e: VpValidationError) {
            throw e
        } catch (_: Exception) {
            throw VpValidationError.ValidationError(
                "WRPRC verifier_info data must be a string value")
        }
        found = Some(raw)
    }
    return found
}

// Resolve PresentationQuery from QuerySource
func resolvePresentationQuery(querySource: QuerySource): PresentationQuery {
    match (querySource) {
        case src: DcqlQuerySource => DCQLQuery(src.dcql)
        case _: ByScopeSource =>
            throw VpValidationError.ValidationError("Query source by scope is not supported")
        case _ =>
            throw VpValidationError.ValidationError("Unknown query source type")
    }
}

// ---------------------------------------------------------------------------
// AuthorizationRequest — mirrors iOS AuthorizationRequest
// ---------------------------------------------------------------------------

public abstract sealed class AuthorizationRequest {
    public static func notSecured(data: ResolvedRequestData): NotSecuredRequest {
        NotSecuredRequest(data)
    }
    public static func jwt(request: ResolvedRequestData): JwtRequest {
        JwtRequest(request)
    }
    public static func invalidResolution(
        error: Exception,
        dispatchDetails: Option<ErrorDispatchDetails>
    ): InvalidResolution {
        InvalidResolution(error, dispatchDetails)
    }

    public func resolved(): Option<ResolvedRequestData> {
        match (this) {
            case r: NotSecuredRequest => Some(r.data)
            case r: JwtRequest => Some(r.request)
            case _: InvalidResolution => None
            case _ => None
        }
    }
}

public class NotSecuredRequest <: AuthorizationRequest {
    public let data: ResolvedRequestData
    public init(d: ResolvedRequestData) { this.data = d }
}

public class JwtRequest <: AuthorizationRequest {
    public let request: ResolvedRequestData
    public init(r: ResolvedRequestData) { this.request = r }
}

public class InvalidResolution <: AuthorizationRequest {
    public let error: Exception
    public let dispatchDetails: Option<ErrorDispatchDetails>
    public init(e: Exception, d: Option<ErrorDispatchDetails>) {
        this.error = e
        this.dispatchDetails = d
    }
}
