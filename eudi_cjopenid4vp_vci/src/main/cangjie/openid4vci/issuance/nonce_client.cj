/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * nonce_client.cj — Nonce endpoint client.
 * Ported from iOS Sources/Main/Nonce/NonceEndpointClient.swift.
 *
 * iOS actor → class; async → sync.
 * NonceEndpointClientType interface preserved for extensibility.
 */
package ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.issuance

import std.collection.*
import stdx.encoding.json.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.types.Nonce
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.issuance.CNonceResponse
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.issuer.CredentialIssuerEndpoint
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.network.{HttpPoster, PostError}
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.util.Constants
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.error.ValidationError

// ---------------------------------------------------------------------------
// NonceAndDPoPNonce — bundled result
// ---------------------------------------------------------------------------

public class NonceResult {
    public let cNonce: CNonceResponse
    public let dPopNonce: Option<Nonce>

    public init(cNonce: CNonceResponse, dPopNonce: Option<Nonce>) {
        this.cNonce = cNonce
        this.dPopNonce = dPopNonce
    }
}

// ---------------------------------------------------------------------------
// NonceEndpointClient
// Ported from iOS actor NonceEndpointClient.
// ---------------------------------------------------------------------------

public class NonceEndpointClient {
    public let nonceEndpoint: CredentialIssuerEndpoint
    private let poster: HttpPoster

    public init(nonceEndpoint: CredentialIssuerEndpoint) {
        this.nonceEndpoint = nonceEndpoint
        this.poster = HttpPoster()
    }

    /*
     * POST to nonce endpoint (body is empty; endpoint just returns c_nonce).
     * Returns NonceResult with c_nonce and optional DPoP nonce from response headers.
     */
    public func getNonce(): NonceResult {
        let endpoint = nonceEndpoint.url
        let emptyHeaders = HashMap<String, String>()
        let rr = poster.post(endpoint, "", "application/json", emptyHeaders)

        // Parse c_nonce from response body
        let jv = JsonValue.fromStr(rr.body)
        let jobj: JsonObject = match (jv) {
            case jo: JsonObject => jo
            case _ => throw ValidationError.Error("Nonce endpoint response not JSON object")
        }
        let cnr = CNonceResponse.fromJson(jobj)

        // Extract DPoP nonce from headers
        let dPopNonce = extractDpopNonce(rr.headers)

        return NonceResult(cnr, dPopNonce)
    }
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

func extractDpopNonce(headers: HashMap<String, String>): Option<Nonce> {
    let lowerKey = Constants.DPOP_NONCE_HEADER.toAsciiLower()
    for ((k, v) in headers) {
        if (k.toAsciiLower() == lowerKey) {
            return Option<Nonce>.Some(Nonce(v))
        }
    }
    return Option<Nonce>.None
}
