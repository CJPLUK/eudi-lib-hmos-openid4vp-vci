/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * authorization_server_client.cj — OAuth2/OIDC authorization server HTTP client.
 * Ported from iOS Sources/Main/Authorisers/AuthorizationServerClient.swift.
 *
 * iOS actor → class (no actor keyword in Cangjie).
 * iOS async throws → throws (sync).
 * iOS PostingType Poster → HttpPoster from block-1 network package.
 * iOS SwiftyJSON → stdx.encoding.json JsonObject.
 *
 * Degradation:
 * - iOS client attestation PoP JWTs → not implemented in block 2 (skipped).
 * - Cangjie does not support named-argument call syntax; all calls use positional args.
 */
package ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.issuance

import std.collection.*
import stdx.encoding.json.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.types.{
    Nonce, Scope, CredentialConfigurationIdentifier, TxCode
}
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.access.{
    IssuanceAccessToken, IssuanceRefreshToken, TokenType
}
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.issuance.{
    AuthorizationCodeURL, AuthorizationDetailsIdentifiers, AuthorizedRequest, GrantType
}
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.config.{
    OpenId4VCIConfig, ParUsage, Client, ClientKind
}
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.access_mgmt.IdentityAndAccessManagementMetadata
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.issuer.CredentialIssuerId
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.dpop.{DPoPConstructorType, ClientAttestationType}
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.pkce.{PKCEVerifier, PKCEGenerator}
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.network.{HttpPoster, PostError}
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.util.{Constants, buildFormBody, urlEncodeComponent}
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.error.{
    ValidationError, CredentialIssuanceError
}

// ---------------------------------------------------------------------------
// AccessTokenResult — bundles multi-field token response
// ---------------------------------------------------------------------------

public class AccessTokenResult {
    public let accessToken: IssuanceAccessToken
    public let refreshToken: Option<IssuanceRefreshToken>
    public let identifiers: Option<AuthorizationDetailsIdentifiers>
    public let dPopNonce: Option<Nonce>

    public init(
        accessToken: IssuanceAccessToken,
        refreshToken: Option<IssuanceRefreshToken>,
        identifiers: Option<AuthorizationDetailsIdentifiers>,
        dPopNonce: Option<Nonce>
    ) {
        this.accessToken = accessToken
        this.refreshToken = refreshToken
        this.identifiers = identifiers
        this.dPopNonce = dPopNonce
    }
}

// ---------------------------------------------------------------------------
// PARResult — bundles PAR response
// ---------------------------------------------------------------------------

public class PARResult {
    public let pkceVerifier: PKCEVerifier
    public let authorizationCodeURL: AuthorizationCodeURL
    public let dPopNonce: Option<Nonce>

    public init(
        pkceVerifier: PKCEVerifier,
        authorizationCodeURL: AuthorizationCodeURL,
        dPopNonce: Option<Nonce>
    ) {
        this.pkceVerifier = pkceVerifier
        this.authorizationCodeURL = authorizationCodeURL
        this.dPopNonce = dPopNonce
    }
}

// ---------------------------------------------------------------------------
// AuthorizationServerClient
// ---------------------------------------------------------------------------

public class AuthorizationServerClient {

    static let RESPONSE_TYPE = "code"
    static let GRANT_AUTHORIZATION_CODE = "authorization_code"
    static let GRANT_PRE_AUTHORIZATION_CODE =
        "urn:ietf:params:oauth:grant-type:pre-authorized_code"

    public let config: OpenId4VCIConfig
    public let authorizationServerMetadata: IdentityAndAccessManagementMetadata
    public let credentialIssuerIdentifier: CredentialIssuerId
    public let dpopConstructor: Option<DPoPConstructorType>
    public let clientAttestation: Option<ClientAttestationType>

    private let poster: HttpPoster

    public init(
        config: OpenId4VCIConfig,
        authorizationServerMetadata: IdentityAndAccessManagementMetadata,
        credentialIssuerIdentifier: CredentialIssuerId,
        dpopConstructor: Option<DPoPConstructorType>,
        clientAttestation!: Option<ClientAttestationType> = Option<ClientAttestationType>.None
    ) {
        this.config = config
        this.authorizationServerMetadata = authorizationServerMetadata
        this.credentialIssuerIdentifier = credentialIssuerIdentifier
        this.dpopConstructor = dpopConstructor
        this.clientAttestation = clientAttestation
        this.poster = HttpPoster()

        if (config.requireDpop) {
            let dpopAlgs = authorizationServerMetadata.dpopSigningAlgValuesSupported()
            if (dpopAlgs.isEmpty()) {
                throw ValidationError.DpopRequired()
            }
        }
    }

    // -----------------------------------------------------------------------
    // authorizationRequestUrl — build non-PAR authorization URL
    // -----------------------------------------------------------------------

    public func authorizationRequestUrl(
        scopes: Array<Scope>,
        credentialConfigurationIdentifiers: Array<CredentialConfigurationIdentifier>,
        state: String,
        issuerState: Option<String>
    ): (PKCEVerifier, AuthorizationCodeURL) {
        if (scopes.isEmpty() && credentialConfigurationIdentifiers.isEmpty()) {
            throw ValidationError.Error("Both scopes and credential configuration identifiers are missing")
        }

        let authorizationEndpoint = requireEndpoint(
            authorizationServerMetadata.authorizationEndpoint(), "authorization_endpoint"
        )

        let pkce = PKCEVerifier.generate()
        let params = buildAuthRequestParams(scopes, credentialConfigurationIdentifiers, state, issuerState, pkce.codeChallenge, pkce.codeChallengeMethod, Option<String>.None)
        let urlWithParams = appendQueryParams(authorizationEndpoint, params)
        let authCodeUrl = AuthorizationCodeURL(urlWithParams)

        return (pkce, authCodeUrl)
    }

    // -----------------------------------------------------------------------
    // submitPushedAuthorizationRequest (PAR)
    // -----------------------------------------------------------------------

    public func submitPushedAuthorizationRequest(
        scopes: Array<Scope>,
        credentialConfigurationIdentifiers: Array<CredentialConfigurationIdentifier>,
        state: String,
        issuerState: Option<String>,
        resource: Option<String>,
        dpopNonce: Option<Nonce>,
        maxRetries: Int64
    ): PARResult {
        return submitPushedAuthorizationRequestWithPkce(
            scopes, credentialConfigurationIdentifiers, state, issuerState, resource,
            PKCEVerifier.generate(), dpopNonce, maxRetries
        )
    }

    // PAR variant that accepts a caller-supplied PKCE pair. Lets a deterministic
    // (fixed code_verifier) two-run live test reuse the same verifier in step 2.
    public func submitPushedAuthorizationRequestWithPkce(
        scopes: Array<Scope>,
        credentialConfigurationIdentifiers: Array<CredentialConfigurationIdentifier>,
        state: String,
        issuerState: Option<String>,
        resource: Option<String>,
        pkce: PKCEVerifier,
        dpopNonce: Option<Nonce>,
        maxRetries: Int64
    ): PARResult {
        if (scopes.isEmpty() && credentialConfigurationIdentifiers.isEmpty()) {
            throw ValidationError.Error("Both scopes and credential configuration identifiers are missing")
        }

        let parEndpoint = requireEndpoint(
            authorizationServerMetadata.pushedAuthorizationRequestEndpoint(), "pushed_authorization_request_endpoint"
        )
        let authorizationEndpoint = requireEndpoint(
            authorizationServerMetadata.authorizationEndpoint(), "authorization_endpoint"
        )

        let params = HashMap<String, String>()
        params.add("response_type", AuthorizationServerClient.RESPONSE_TYPE)
        params.add("client_id", config.client.id())
        params.add("redirect_uri", config.authFlowRedirectionURI)
        params.add("state", state)
        params.add("code_challenge", pkce.codeChallenge)
        params.add("code_challenge_method", pkce.codeChallengeMethod)

        if (!scopes.isEmpty()) {
            // iOS PAR sends the bare credential scopes WITHOUT "openid".
            params.add("scope", buildScopeString(scopes, withOpenId: false))
        }

        if (!credentialConfigurationIdentifiers.isEmpty()) {
            params.add("authorization_details", buildAuthorizationDetails(credentialConfigurationIdentifiers))
        }

        match (issuerState) {
            case Some(s) => params.add("issuer_state", s)
            case None => ()
        }

        // iOS sends an RFC 8707 resource indicator for an issuer that declares
        // an authorization server. Without it the PAR session is not bound to
        // the credential issuer when the browser follows the request_uri.
        match (resource) {
            case Some(r) => params.add("resource", r)
            case None => ()
        }

        let headers = buildTokenRequestHeaders(parEndpoint, dpopNonce)
        let body = buildFormBody(params)

        try {
            let rr = poster.post(parEndpoint, body, "application/x-www-form-urlencoded", headers)
            let respHeaders = rr.headers

            let jv = JsonValue.fromStr(rr.body)
            let jobj: JsonObject = match (jv) {
                case jo: JsonObject => jo
                case _ => throw ValidationError.Error("PAR response not JSON object")
            }

            match (jobj.get("error")) {
                case Some(js: JsonString) =>
                    let errDesc: Option<String> = match (jobj.get("error_description")) {
                        case Some(jd: JsonString) => Option<String>.Some(jd.getValue())
                        case _ => Option<String>.None
                    }
                    throw CredentialIssuanceError.PushedAuthorizationRequestFailed(js.getValue(), errDesc)
                case _ => ()
            }

            let requestUri: String = match (jobj.get("request_uri")) {
                case Some(js: JsonString) => js.getValue()
                case _ => throw ValidationError.Error("PAR response missing request_uri")
            }

            let redirectParams = HashMap<String, String>()
            redirectParams.add("client_id", config.client.id())
            redirectParams.add("request_uri", requestUri)
            redirectParams.add("state", state)
            let finalUrl = appendQueryParams(authorizationEndpoint, redirectParams)
            let authCodeUrl = AuthorizationCodeURL(finalUrl)
            let dPopNonceFromHeaders = extractDpopNonce(respHeaders)

            return PARResult(pkce, authCodeUrl, dPopNonceFromHeaders)
        } catch (e: PostError) {
            let msg = e.message
            if (msg.startsWith("Use dPop Nonce error: ")) {
                let nonce = msg.removePrefix("Use dPop Nonce error: ")
                if (maxRetries <= 0) {
                    throw ValidationError.RetryFailedAfterDpopNonce()
                }
                return submitPushedAuthorizationRequestWithPkce(scopes, credentialConfigurationIdentifiers, state, issuerState, resource, pkce, Option<Nonce>.Some(Nonce(nonce)), maxRetries - 1)
            }
            throw CredentialIssuanceError.PushedAuthorizationRequestFailed(e.message, Option<String>.None)
        }
    }

    // -----------------------------------------------------------------------
    // requestAccessTokenAuthFlow — exchange auth code for token
    // -----------------------------------------------------------------------

    public func requestAccessTokenAuthFlow(
        authorizationCode: String,
        codeVerifier: String,
        identifiers: Array<CredentialConfigurationIdentifier>,
        dpopNonce: Option<Nonce>,
        maxRetries: Int64
    ): AccessTokenResult {
        let tokenEndpoint = requireEndpoint(authorizationServerMetadata.tokenEndpoint(), "token_endpoint")

        let params = HashMap<String, String>()
        params.add("grant_type", AuthorizationServerClient.GRANT_AUTHORIZATION_CODE)
        params.add("code", authorizationCode)
        params.add("redirect_uri", config.authFlowRedirectionURI)
        params.add("client_id", config.client.id())
        params.add("code_verifier", codeVerifier)

        if (!identifiers.isEmpty()) {
            params.add("authorization_details", buildAuthorizationDetails(identifiers))
        }

        let headers = buildTokenRequestHeaders(tokenEndpoint, dpopNonce)
        let body = buildFormBody(params)

        try {
            let rr = poster.post(tokenEndpoint, body, "application/x-www-form-urlencoded", headers)
            return parseTokenResponse(rr.body, rr.headers)
        } catch (e: PostError) {
            let msg = e.message
            if (msg.startsWith("Use dPop Nonce error: ")) {
                let nonce = msg.removePrefix("Use dPop Nonce error: ")
                if (maxRetries <= 0) {
                    throw ValidationError.RetryFailedAfterDpopNonce()
                }
                return requestAccessTokenAuthFlow(authorizationCode, codeVerifier, identifiers, Option<Nonce>.Some(Nonce(nonce)), maxRetries - 1)
            }
            throw CredentialIssuanceError.AccessTokenRequestFailed(e.message, Option<String>.None)
        }
    }

    // -----------------------------------------------------------------------
    // requestAccessTokenPreAuthFlow — exchange pre-auth code for token
    // -----------------------------------------------------------------------

    public func requestAccessTokenPreAuthFlow(
        preAuthorizedCode: String,
        txCode: Option<TxCode>,
        client: Client,
        transactionCode: Option<String>,
        identifiers: Array<CredentialConfigurationIdentifier>,
        dpopNonce: Option<Nonce>,
        maxRetries: Int64
    ): AccessTokenResult {
        let tokenEndpoint = requireEndpoint(authorizationServerMetadata.tokenEndpoint(), "token_endpoint")

        let params = HashMap<String, String>()
        params.add("grant_type", AuthorizationServerClient.GRANT_PRE_AUTHORIZATION_CODE)
        params.add("pre-authorized_code", preAuthorizedCode)
        params.add("client_id", client.id())

        match (transactionCode) {
            case Some(tc) => params.add("tx_code", tc)
            case None => ()
        }

        if (!identifiers.isEmpty()) {
            params.add("authorization_details", buildAuthorizationDetails(identifiers))
        }

        let headers = buildTokenRequestHeaders(tokenEndpoint, dpopNonce)
        let body = buildFormBody(params)

        try {
            let rr = poster.post(tokenEndpoint, body, "application/x-www-form-urlencoded", headers)
            return parseTokenResponse(rr.body, rr.headers)
        } catch (e: PostError) {
            let msg = e.message
            if (msg.startsWith("Use dPop Nonce error: ")) {
                let nonce = msg.removePrefix("Use dPop Nonce error: ")
                if (maxRetries <= 0) {
                    throw ValidationError.RetryFailedAfterDpopNonce()
                }
                return requestAccessTokenPreAuthFlow(preAuthorizedCode, txCode, client, transactionCode, identifiers, Option<Nonce>.Some(Nonce(nonce)), maxRetries - 1)
            }
            throw CredentialIssuanceError.AccessTokenRequestFailed(e.message, Option<String>.None)
        }
    }

    // -----------------------------------------------------------------------
    // refreshAccessToken
    // -----------------------------------------------------------------------

    public func refreshAccessToken(
        clientId: String,
        refreshToken: IssuanceRefreshToken,
        dpopNonce: Option<Nonce>,
        maxRetries: Int64
    ): AccessTokenResult {
        let tokenEndpoint = requireEndpoint(authorizationServerMetadata.tokenEndpoint(), "token_endpoint")

        let rtOpt = refreshToken.refreshToken
        if (rtOpt.isNone()) {
            throw ValidationError.Error("Missing refresh token value")
        }
        let rt = rtOpt.getOrThrow()

        let params = HashMap<String, String>()
        params.add("client_id", clientId)
        params.add("grant_type", Constants.REFRESH_TOKEN)
        params.add("refresh_token", rt)

        let headers = buildTokenRequestHeaders(tokenEndpoint, dpopNonce)
        let body = buildFormBody(params)

        try {
            let rr = poster.post(tokenEndpoint, body, "application/x-www-form-urlencoded", headers)
            return parseTokenResponse(rr.body, rr.headers)
        } catch (e: PostError) {
            let msg = e.message
            if (msg.startsWith("Use dPop Nonce error: ")) {
                let nonce = msg.removePrefix("Use dPop Nonce error: ")
                if (maxRetries <= 0) {
                    throw ValidationError.RetryFailedAfterDpopNonce()
                }
                return refreshAccessToken(clientId, refreshToken, Option<Nonce>.Some(Nonce(nonce)), maxRetries - 1)
            }
            throw CredentialIssuanceError.AccessTokenRequestFailed(e.message, Option<String>.None)
        }
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    private func requireEndpoint(endpoint: Option<String>, name: String): String {
        match (endpoint) {
            case Some(url) => url
            case None => throw ValidationError.Error("Missing required endpoint: " + name)
        }
    }

    private func buildTokenRequestHeaders(endpoint: String, dpopNonce: Option<Nonce>): HashMap<String, String> {
        let headers = HashMap<String, String>()
        match (dpopConstructor) {
            case Some(dc) =>
                let nonceStr: Option<String> = match (dpopNonce) {
                    case Some(n) => Option<String>.Some(n.value)
                    case None => Option<String>.None
                }
                let dpopToken = dc.jwt(endpoint, Option<String>.None, nonceStr)
                headers.add(Constants.DPOP, dpopToken)
            case None => ()
        }
        // Attestation-based client authentication (`attest_jwt_client_auth`).
        // Without this pair the AS authenticates the client as `public` and the
        // access token it mints omits `client_status`, which the credential
        // endpoint then requires (iOS sends these on PAR + token + refresh).
        match (clientAttestation) {
            case Some(ca) =>
                // PoP `aud` is the AS issuer identifier; fall back to the
                // credential issuer id when the AS metadata omits `issuer`.
                let aud = match (authorizationServerMetadata.issuer()) {
                    case Some(i) => i
                    case None => credentialIssuerIdentifier.absoluteString()
                }
                headers.add(Constants.OAUTH_CLIENT_ATTESTATION, ca.attestationJwt())
                headers.add(Constants.OAUTH_CLIENT_ATTESTATION_POP, ca.popJwt(aud, fetchAttestationChallenge()))
            case None => ()
        }
        return headers
    }

    /*
     * Attestation challenge (draft-ietf-oauth-attestation-based-client-auth).
     * An AS that publishes `challenge_endpoint` requires the PoP to carry a
     * challenge it minted; Keycloak rejects the PAR with a bare 401
     * "Authentication failed." otherwise. Challenges are single-use, so one is
     * fetched per request rather than cached. Returns None when the AS does not
     * advertise the endpoint or the fetch fails — the PoP is then sent without a
     * challenge, which is what a non-Keycloak AS expects.
     */
    private func fetchAttestationChallenge(): Option<String> {
        let endpoint = match (authorizationServerMetadata.challengeEndpoint()) {
            case Some(e) => e
            case None => return Option<String>.None
        }
        try {
            let rr = poster.post(endpoint, "", Constants.CONTENT_TYPE_APPLICATION_JSON, HashMap<String, String>())
            match (JsonValue.fromStr(rr.body)) {
                case obj: JsonObject =>
                    match (obj.get("attestation_challenge")) {
                        case Some(v: JsonString) => return Option<String>.Some(v.getValue())
                        case _ => return Option<String>.None
                    }
                case _ => return Option<String>.None
            }
        } catch (e: Exception) {
            return Option<String>.None
        }
    }

    private func buildAuthRequestParams(
        scopes: Array<Scope>,
        configIds: Array<CredentialConfigurationIdentifier>,
        state: String,
        issuerState: Option<String>,
        codeChallenge: String,
        codeChallengeMethod: String,
        requestUri: Option<String>
    ): HashMap<String, String> {
        let params = HashMap<String, String>()
        params.add("response_type", AuthorizationServerClient.RESPONSE_TYPE)
        params.add("client_id", config.client.id())
        params.add("redirect_uri", config.authFlowRedirectionURI)
        params.add("state", state)
        params.add("code_challenge", codeChallenge)
        params.add("code_challenge_method", codeChallengeMethod)
        if (!scopes.isEmpty()) {
            // Plain authorization URL keeps iOS's "+ openid" scope behaviour.
            params.add("scope", buildScopeString(scopes, withOpenId: true))
        }
        if (!configIds.isEmpty()) {
            params.add("authorization_details", buildAuthorizationDetails(configIds))
        }
        match (issuerState) {
            case Some(s) => params.add("issuer_state", s)
            case None => ()
        }
        match (requestUri) {
            case Some(uri) => params.add("request_uri", uri)
            case None => ()
        }
        return params
    }

    // iOS AuthorizationServerClient builds the scope differently per path:
    // PAR (submitPushedAuthorizationRequest) sends the bare credential scopes,
    // while the plain authorization URL path appends the "openid" scope. The
    // eudiw prod issuer's dynamic-auth bridge mis-routes a PAR carrying the
    // "openid" scope (verify_user dies with KeyError 'code'), so the split
    // must be preserved.
    private func buildScopeString(scopes: Array<Scope>, withOpenId!: Bool): String {
        var result = ""
        var first = true
        for (s in scopes) {
            if (!first) { result = result + " " }
            result = result + s.value
            first = false
        }
        if (!withOpenId) {
            return result
        }
        if (!result.isEmpty()) {
            result = result + " " + Constants.OPENID_SCOPE
        } else {
            result = Constants.OPENID_SCOPE
        }
        return result
    }

    private func buildAuthorizationDetails(configIds: Array<CredentialConfigurationIdentifier>): String {
        let arr = JsonArray()
        for (id in configIds) {
            let obj = JsonObject()
            obj.put("type", JsonString("openid_credential"))
            obj.put("credential_configuration_id", JsonString(id.value))
            arr.add(obj)
        }
        return arr.toJsonString()
    }

    private func appendQueryParams(baseUrl: String, params: HashMap<String, String>): String {
        // Percent-encode every value. curl tolerates raw colons in query
        // values (e.g. request_uri=urn:uuid:...), but the in-app ArkWeb
        // WebviewController drops such params, making the issuer return
        // "Missing required parameters". RFC 3986 query values must be
        // percent-encoded; the issuer decodes them back transparently.
        var result = baseUrl
        var first = !baseUrl.contains("?")
        for ((k, v) in params) {
            if (first) {
                result = result + "?" + k + "=" + urlEncodeComponent(v)
                first = false
            } else {
                result = result + "&" + k + "=" + urlEncodeComponent(v)
            }
        }
        return result
    }

    private func extractDpopNonce(headers: HashMap<String, String>): Option<Nonce> {
        let lowerKey = Constants.DPOP_NONCE_HEADER.toAsciiLower()
        for ((k, v) in headers) {
            if (k.toAsciiLower() == lowerKey) {
                return Option<Nonce>.Some(Nonce(v))
            }
        }
        return Option<Nonce>.None
    }

    private func parseTokenResponse(body: String, headers: HashMap<String, String>): AccessTokenResult {
        let jv = JsonValue.fromStr(body)
        let jobj: JsonObject = match (jv) {
            case jo: JsonObject => jo
            case _ => throw CredentialIssuanceError.ResponseUnparsable("Token response not JSON object")
        }

        match (jobj.get("error")) {
            case Some(js: JsonString) =>
                let errDesc: Option<String> = match (jobj.get("error_description")) {
                    case Some(jd: JsonString) => Option<String>.Some(jd.getValue())
                    case _ => Option<String>.None
                }
                throw CredentialIssuanceError.AccessTokenRequestFailed(js.getValue(), errDesc)
            case _ => ()
        }

        let accessToken = IssuanceAccessToken.fromJsonObject(jobj)
        let refreshToken = IssuanceRefreshToken.fromJsonObject(jobj)

        let identifiers = AuthorizationDetailsIdentifiers.fromJson(jobj)
        let dPopNonce = extractDpopNonce(headers)

        let refreshOpt: Option<IssuanceRefreshToken> = match (refreshToken.refreshToken) {
            case Some(_) => Option<IssuanceRefreshToken>.Some(refreshToken)
            case None => Option<IssuanceRefreshToken>.None
        }

        return AccessTokenResult(accessToken, refreshOpt, identifiers, dPopNonce)
    }
}
