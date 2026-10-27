/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * constants.cj — OAuth2/OpenID4VCI protocol constants.
 * Direct port of iOS Sources/Utilities/Constants.swift.
 */
package ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.util

public class Constants {
    public static let GRANT_TYPE_PARAM = "grant_type"
    public static let GRANT_TYPE_PARAM_VALUE =
        "urn:ietf:params:oauth:grant-type:pre-authorized_code"

    public static let REDIRECT_URI_PARAM = "redirect_uri"
    public static let CLIENT_ID_PARAM = "client_id"
    public static let CODE_VERIFIER_PARAM = "code_verifier"
    public static let AUTHORIZATION_CODE_PARAM = "code"
    public static let AUTHORIZATION_DETAILS = "authorization_details"
    public static let USER_PIN_PARAM = "user_pin"
    public static let PRE_AUTHORIZED_CODE_PARAM = "pre-authorized_code"

    public static let OPENID_SCOPE = "openid"
    public static let TX_CODE_PARAM = "tx_code"

    public static let PLACEHOLDER_URL = "https://a.bc"

    public static let DPOP_NONCE_HEADER = "dpop-nonce"
    public static let USE_DPOP_NONCE = "use_dpop_nonce"
    public static let USE_ATTESTATION_CHALLENGE = "use_attestation_challenge"

    public static let REFRESH_TOKEN = "refresh_token"
    public static let REFRESH_TOKEN_PARAM = "refresh_token"

    public static let DPOP = "DPoP"
    public static let HTTPS = "https"

    public static let OAUTH_CLIENT_ATTESTATION = "OAuth-Client-Attestation"
    public static let OAUTH_CLIENT_ATTESTATION_POP = "OAuth-Client-Attestation-PoP"
    public static let OAUTH_CLIENT_ATTESTATION_CHALLENGE = "OAuth-Client-Attestation-Challenge"
    public static let CONTENT_TYPE_APPLICATION_JWT = "application/jwt"
    public static let CONTENT_TYPE_APPLICATION_JSON = "application/json"
    public static let SIGNED_METADATA_JWT_TYPE = "openidvci-issuer-metadata+jwt"

    public static let MAX_RETRIES: Int64 = 3
}

// JWT standard claim names (mirrors iOS JWTClaimNames.swift)
public class JWTClaimNames {
    public static let issuer = "iss"
    public static let subject = "sub"
    public static let audience = "aud"
    public static let issuedAt = "iat"
    public static let expiration = "exp"
    public static let notBefore = "nbf"
    public static let jwtId = "jti"
    public static let nonce = "nonce"
    public static let typ = "typ"
    public static let algorithm = "alg"
    public static let JWK = "jwk"
    public static let kid = "kid"
    public static let htm = "htm"
    public static let htu = "htu"
    public static let ath = "ath"
    public static let cnf = "cnf"
    public static let keyAttestation = "key-attestation+jwt"
}
