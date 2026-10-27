/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * dispatcher.cj — Dispatcher and ErrorDispatcher for VP response submission.
 * Block 5 scope: submits AuthorizationResponse to verifier, returns DispatchOutcome.
 *
 * Ported from iOS:
 *   - Main/Services/Dispatcher.swift
 *   - Main/Services/ErrorDispatcher.swift
 *
 * iOS actor → Cangjie class (synchronous, no actor model).
 * iOS async throws → Cangjie synchronous throw.
 */
package ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.service

import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.error.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.response.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.entity.request.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.entity.types.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.network.*
import std.collection.*

// ---------------------------------------------------------------------------
// Dispatcher — mirrors iOS Dispatcher actor
// Submits a pre-built AuthorizationResponse to the verifier.
// ---------------------------------------------------------------------------

public class Dispatcher {

    private let service: AuthorisationService
    public let authorizationResponse: AuthorizationResponse

    public init(
        service!: AuthorisationService = AuthorisationService(),
        authorizationResponse!: AuthorizationResponse
    ) {
        this.service = service
        this.authorizationResponse = authorizationResponse
    }

    // Dispatch the authorization response.
    // Mirrors iOS Dispatcher.dispatch(poster:)
    public func dispatch(httpPoster!: HttpPoster = HttpPoster()): DispatchOutcome {
        let result = service.formCheck(
            this.authorizationResponse,
            httpPoster
        )
        let (redirectUriStr, accepted) = result
        if (accepted) {
            let redirectUri: Option<String> = if (redirectUriStr.isEmpty()) { None } else { Some(redirectUriStr) }
            return AcceptedOutcome(redirectUri)
        } else {
            return RejectedOutcome(redirectUriStr)
        }
    }
}

// ---------------------------------------------------------------------------
// ErrorDispatcher — mirrors iOS ErrorDispatcher actor
// Dispatches an error response to the verifier.
// ---------------------------------------------------------------------------

public class ErrorDispatcher {

    private let service: AuthorisationService
    public let error: Exception
    public let details: Option<ErrorDispatchDetails>

    public init(
        service!: AuthorisationService = AuthorisationService(),
        error!: Exception,
        details!: Option<ErrorDispatchDetails>
    ) {
        this.service = service
        this.error = error
        this.details = details
    }

    // Dispatch the error response.
    // Mirrors iOS ErrorDispatcher.dispatch(poster:)
    public func dispatch(httpPoster!: HttpPoster = HttpPoster()): DispatchOutcome {
        let responseOpt = buildErrorResponse(this.error, this.details)
        match (responseOpt) {
            case None =>
                return RejectedOutcome("Unsupported response mode")
            case Some(response) =>
                let result = service.formCheck(
                    response,
                    httpPoster
                )
                let (str, accepted) = result
                if (accepted) {
                    let redirectUri: Option<String> = if (str.isEmpty()) { None } else { Some(str) }
                    return AcceptedOutcome(redirectUri)
                } else {
                    return RejectedOutcome("")
                }
        }
    }
}

// Build error AuthorizationResponse from error and dispatch details.
// Mirrors iOS AuthorizationRequestError.responseWith(details:)
func buildErrorResponse(
    error: Exception,
    details: Option<ErrorDispatchDetails>
): Option<AuthorizationResponse> {
    match (details) {
        case None => return None
        case Some(dd) =>
            let errorCode = exceptionToErrorCode(error)
            let payload = InvalidRequestPayload(
                errorCode,
                dd.nonce,
                dd.state,
                dd.clientId
            )
            match (dd.responseMode) {
                case Some(dp: DirectPost) =>
                    return Some(DirectPostResponse(dp.responseUri, payload))
                case Some(dpj: DirectPostJWT) =>
                    match (dd.responseEncryptionSpecification) {
                        case Some(encSpec) =>
                            return Some(DirectPostJwtResponse(dpj.responseUri, payload, encSpec))
                        case None =>
                            return None
                    }
                case _ =>
                    return None
            }
    }
}

// Map an exception to an OAuth2 error code string.
// Mirrors iOS AuthorizationRequestErrorCode.fromError(_:)
func exceptionToErrorCode(e: Exception): String {
    let msg = e.message
    // Simple heuristic mapping based on error message prefixes
    if (msg.contains("clientId") || msg.contains("invalidClient") ||
        msg.contains("unsupportedClientIdScheme") || msg.contains("invalidClientMetadata")) {
        return AuthorizationRequestErrorCode.InvalidClient.toString()
    }
    if (msg.contains("invalidRequestUri") || msg.contains("invalidUri")) {
        return AuthorizationRequestErrorCode.InvalidRequestURI.toString()
    }
    if (msg.contains("invalidRequestUriMethod")) {
        return AuthorizationRequestErrorCode.InvalidRequestURIMethod.toString()
    }
    if (msg.contains("invalidJWTWebKeySet") || msg.contains("invalidJwtPayload")) {
        return AuthorizationRequestErrorCode.InvalidRequestObject.toString()
    }
    if (msg.contains("invalidFormat") || msg.contains("vpFormats")) {
        return AuthorizationRequestErrorCode.VpFormatsNotSupported.toString()
    }
    if (msg.contains("accessDenied") || msg.contains("negativeConsent")) {
        return AuthorizationRequestErrorCode.AccessDenied.toString()
    }
    return AuthorizationRequestErrorCode.InvalidRequest.toString()
}
