/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * index.cj — public surface of ohos_app_cangjie_eudi_cjopenid4vp_vci (block 1+2).
 *
 * This is the top-level entry for the cjpm package.  It imports sub-packages
 * so their symbols are accessible to external consumers, and provides a
 * smoke-test function used by the entry module.
 *
 * Block 1 scope: VCI basic layer — utilities, network, PKCE, DPoP,
 * error types, and core entity models.
 * Block 2 scope: Complete issuance flow — authorization, token, credential request,
 * deferred, notify, refresh.
 */
package ohos_app_cangjie_eudi_cjopenid4vp_vci

import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.util.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.error.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.network.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.pkce.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.dpop.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.types.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.issuer.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.offer.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.access.*
// Block 2 additions
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.issuance.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.access_mgmt.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.config.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.issuance.*
// Block 3 additions: credential configurations, reuse policies, response encryption
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.credential.*
// Block 4 additions: VP (SiopOpenID4VP) side — basic layer + request parsing
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.error.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.entity.types.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.entity.dcql.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.entity.client.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.entity.request.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.entity.metadata.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.entity.config.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.resolver.*
// Block 5 additions: VP response side — consensus, authorization response, dispatch
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.response.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.service.*
// GAP-01: VCI resolver entry — CredentialIssuerMetadataResolver, AuthorizationServerMetadataResolver,
//         CredentialOfferRequestResolver (wallet VCI entry point)
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.resolver.*

/**
 * Smoke-test function consumed by entry module.
 * Exercises PKCE generation and Constants (no network I/O).
 */
public func runOpenId4VciDemo(): String {
    var result = "OpenID4VCI block-1 demo:\n"

    // 1. PKCE verifier generation
    try {
        let verifier = PKCEVerifier.generate()
        if (!verifier.codeVerifier.isEmpty() && !verifier.codeChallenge.isEmpty()) {
            result = result + "PKCE generate: OK (verifier len=" +
                verifier.codeVerifier.size.toString() + ")\n"
        } else {
            result = result + "PKCE generate: FAIL (empty output)\n"
        }
    } catch (e: Exception) {
        result = result + "PKCE generate: FAIL (" + e.message + ")\n"
    }

    // 2. Constants sanity check
    let grantType = Constants.GRANT_TYPE_PARAM_VALUE
    if (grantType.startsWith("urn:ietf:params:oauth")) {
        result = result + "Constants.GRANT_TYPE_PARAM_VALUE: OK\n"
    } else {
        result = result + "Constants.GRANT_TYPE_PARAM_VALUE: FAIL\n"
    }

    // 3. StateValue random generation
    let sv = StateValue()
    if (!sv.value.isEmpty()) {
        result = result + "StateValue.generate: OK (len=" + sv.value.size.toString() + ")\n"
    } else {
        result = result + "StateValue.generate: FAIL\n"
    }

    // 4. Error types instantiation
    let err = ValidationError.Error("test")
    result = result + "ValidationError: OK (" + err.message + ")\n"

    return result
}
