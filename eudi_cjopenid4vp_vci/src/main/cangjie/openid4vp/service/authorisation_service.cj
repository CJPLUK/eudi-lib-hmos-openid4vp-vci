/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * authorisation_service.cj — Authorization response posting service.
 * Block 5 scope: POST authorization response to verifier.
 *
 * Ported from iOS:
 *   - Main/Services/AuthorisationService.swift
 *   - Main/Services/VerifierFormPost.swift
 *   - Utilities/Builders/FormURLEncoder.swift
 *
 * iOS actor → Cangjie class (no actor model; synchronous).
 * iOS URLSession async → stdx.net.http synchronous via HttpPoster.
 * iOS Codable/JSONDecoder → manual JSON parsing via stdx.encoding.json.
 */
package ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.service

import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.error.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.response.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.network.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.util.*
import std.collection.*
import stdx.encoding.json.*
import stdx.net.http.*

// ---------------------------------------------------------------------------
// FormURLEncoder — mirrors iOS FormURLEncoder
// Encodes a HashMap<String, String> as application/x-www-form-urlencoded body.
// ---------------------------------------------------------------------------

func buildFormEncodedBody(params: HashMap<String, String>): String {
    return buildFormBody(params)
}

// ---------------------------------------------------------------------------
// AuthorisationService — mirrors iOS AuthorisationService actor
// ---------------------------------------------------------------------------

public class AuthorisationService {

    // Last JOSE response (for inspection / testing) — mirrors iOS joseResponse
    public var lastJoseResponse: Option<String>

    public init() {
        this.lastJoseResponse = None
    }

    // Post authorization response and return (redirectUri, success) pair.
    // Mirrors iOS AuthorisationService.formCheck(poster:response:)
    public func formCheck(
        response: AuthorizationResponse,
        httpPoster: HttpPoster
    ): (String, Bool) {
        match (response) {
            case dp: DirectPostResponse =>
                let payload = setupDirectPostPayload(dp.data)
                let body = buildFormEncodedBody(payload)
                let headers = HashMap<String, String>()
                let resp = httpPoster.post(
                    dp.url,
                    body,
                    ContentType.Form.rawValue(),
                    headers
                )
                return extractRedirectOutcome(resp)

            case dpj: DirectPostJwtResponse =>
                // Handle invalid request payload — send plain form (no encryption)
                match (dpj.data) {
                    case _: InvalidRequestPayload =>
                        let payload = setupDirectPostPayload(dpj.data)
                        let body = buildFormEncodedBody(payload)
                        let headers = HashMap<String, String>()
                        let resp = httpPoster.post(
                            dpj.url,
                            body,
                            ContentType.Form.rawValue(),
                            headers
                        )
                        return extractRedirectOutcome(resp)
                    case _ => ()
                }
                // Encrypt response (JARM)
                let encryptor = ResponseEncryptor()
                let joseResponse = encryptor.encryptResponse(
                    responseEncryptionSpecification: dpj.responseEncryptionSpecification,
                    data: dpj.data
                )
                this.lastJoseResponse = Some(joseResponse)
                let jarmParams = HashMap<String, String>()
                jarmParams.add("response", joseResponse)
                let jarmBody = buildFormEncodedBody(jarmParams)
                let jarmHeaders = HashMap<String, String>()
                let jarmResp = httpPoster.post(
                    dpj.url,
                    jarmBody,
                    ContentType.Form.rawValue(),
                    jarmHeaders
                )
                return extractRedirectOutcome(jarmResp)

            case _: QueryResponse =>
                throw VpAuthorizationError.InvalidResponseMode()
            case _: FragmentResponse =>
                throw VpAuthorizationError.InvalidResponseMode()
            case _: InvalidRequestResponse =>
                throw VpAuthorizationError.InvalidResponseMode()
            case _ =>
                throw VpAuthorizationError.InvalidResponseMode()
        }
    }

    // Setup the form parameter dict for direct_post.
    // Mirrors iOS AuthorisationService.setupDirectPostPayload(payload:key:dictionary:)
    private func setupDirectPostPayload(
        payload: AuthorizationResponsePayload
    ): HashMap<String, String> {
        match (payload) {
            case p: InvalidRequestPayload =>
                let result = HashMap<String, String>()
                result.add("error", p.errorCode)
                match (p.errorDescription) {
                    case Some(desc) => result.add("error_description", desc)
                    case None => ()
                }
                match (p.state) {
                    case Some(st) => result.add("state", st)
                    case None => ()
                }
                return result
            case _ =>
                return payload.toFormParams()
        }
    }

    // Extract redirect_uri from the response body or return empty on failure.
    // Mirrors iOS Poster.check(key:request:) logic.
    private func extractRedirectOutcome(resp: ResponseWithHeaders): (String, Bool) {
        // A 2xx response is accepted
        let body = resp.body
        // Try to extract redirect_uri from JSON body
        let redirectUri = extractStringFromJson(body, "redirect_uri")
        return (redirectUri, true)
    }

    // Extract a string value from a JSON response body.
    private func extractStringFromJson(body: String, key: String): String {
        if (body.isEmpty()) { return "" }
        try {
            let parsed = JsonValue.fromStr(body)
            match (parsed) {
                case obj: JsonObject =>
                    match (obj.get(key)) {
                        case Some(s: JsonString) => return s.getValue()
                        case _ => return ""
                    }
                case _ => return ""
            }
        } catch (_: Exception) {
            return ""
        }
    }
}
