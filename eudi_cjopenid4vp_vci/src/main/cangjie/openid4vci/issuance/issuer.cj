/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * issuer.cj — Main issuance orchestrator.
 * Ported from iOS Sources/Issuers/Issuer.swift + Sources/Authorization/AuthorizeIssuance.swift.
 *
 * iOS actor → class; async → sync.
 * Cangjie: no named arguments in function calls; all calls use positional args.
 */
package ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.issuance

import std.collection.*
import std.time.DateTime
import stdx.encoding.json.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.types.{
    Nonce, Scope, CredentialConfigurationIdentifier, CredentialIdentifier, TransactionId, StateValue, Grants, TxCode
}
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.access.{IssuanceAccessToken, IssuanceRefreshToken}
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.issuance.{
    AuthorizationRequested, AuthorizedRequest, IssuanceRequestPayload, BindingKey,
    SubmittedRequest, DeferredCredentialIssuanceResponse, CredentialIssuanceResponse,
    NotificationObject, AuthorizationDetailsInTokenRequest, GrantType, Proof
}
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.config.{OpenId4VCIConfig, AuthorizeIssuanceConfig}
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.access_mgmt.IdentityAndAccessManagementMetadata
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.issuer.{CredentialIssuerId, CredentialIssuerMetadata}
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.offer.CredentialOffer
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.dpop.{DPoPConstructorType, ClientAttestationType}
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.pkce.{PKCEVerifier, PKCEGenerator}
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.util.{Constants, JWTClaimNames}
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.error.{
    ValidationError, CredentialIssuanceError, CredentialError
}

// ---------------------------------------------------------------------------
// IssuerType — interface (ported from iOS protocol IssuerType)
// ---------------------------------------------------------------------------

public interface IssuerType {
    func prepareAuthorizationRequest(credentialOffer: CredentialOffer): AuthorizationRequested

    func authorizeWithPreAuthorizationCode(
        credentialOffer: CredentialOffer,
        authorizationCode: String,
        transactionCode: Option<String>,
        authorizationDetailsInTokenRequest: AuthorizationDetailsInTokenRequest
    ): AuthorizedRequest

    func authorizeWithAuthorizationCode(
        serverState: String,
        request: AuthorizationRequested,
        authorizationCode: String,
        authorizationDetailsInTokenRequest: AuthorizationDetailsInTokenRequest,
        grant: Option<Grants>
    ): AuthorizedRequest

    func requestCredential(
        request: AuthorizedRequest,
        bindingKeys: Array<BindingKey>,
        requestPayload: IssuanceRequestPayload
    ): SubmittedRequest

    func requestDeferredCredential(
        request: AuthorizedRequest,
        transactionId: TransactionId,
        dPopNonce: Option<Nonce>
    ): DeferredCredentialIssuanceResponse

    func notify(
        authorizedRequest: AuthorizedRequest,
        notification: NotificationObject,
        dPopNonce: Option<Nonce>
    ): Unit

    func refresh(
        clientId: String,
        authorizedRequest: AuthorizedRequest,
        dPopNonce: Option<Nonce>
    ): AuthorizedRequest
}

// ---------------------------------------------------------------------------
// Issuer — concrete orchestrator
// Ported from iOS actor Issuer.
// ---------------------------------------------------------------------------

public class Issuer <: IssuerType {

    public let authorizationServerMetadata: IdentityAndAccessManagementMetadata
    public let issuerMetadata: CredentialIssuerMetadata
    public let config: OpenId4VCIConfig

    private let authorizer: AuthorizationServerClient
    private let issuanceRequester: IssuanceRequester
    private let deferredIssuanceRequester: IssuanceRequester
    private let nonceEndpointClient: Option<NonceEndpointClient>

    public init(
        authorizationServerMetadata: IdentityAndAccessManagementMetadata,
        issuerMetadata: CredentialIssuerMetadata,
        config: OpenId4VCIConfig,
        dpopConstructor: Option<DPoPConstructorType>,
        clientAttestation!: Option<ClientAttestationType> = Option<ClientAttestationType>.None
    ) {
        this.authorizationServerMetadata = authorizationServerMetadata
        this.issuerMetadata = issuerMetadata
        this.config = config

        this.authorizer = AuthorizationServerClient(
            config,
            authorizationServerMetadata,
            issuerMetadata.credentialIssuerIdentifier,
            dpopConstructor,
            clientAttestation: clientAttestation
        )

        this.issuanceRequester = IssuanceRequester(
            issuerMetadata,
            dpopConstructor
        )

        // The deferred requester MUST share the session's DPoP constructor:
        // a DPoP-bound access token presented at the deferred endpoint without
        // a matching proof header is rejected with a bare 401 (iOS wires the
        // same dpopConstructor into its deferred poster).
        this.deferredIssuanceRequester = IssuanceRequester(
            issuerMetadata,
            dpopConstructor
        )

        match (issuerMetadata.nonceEndpoint) {
            case Some(ep) =>
                this.nonceEndpointClient = Option<NonceEndpointClient>.Some(NonceEndpointClient(ep))
            case None =>
                this.nonceEndpointClient = Option<NonceEndpointClient>.None
        }
    }

    // -----------------------------------------------------------------------
    // prepareAuthorizationRequest
    // -----------------------------------------------------------------------

    public func prepareAuthorizationRequest(credentialOffer: CredentialOffer): AuthorizationRequested {
        let issuerState = getIssuerState(credentialOffer.grants)
        let (scopes, configIds) = scopesAndConfigIds(credentialOffer)
        let resource = if (!credentialOffer.credentialIssuerMetadata.authorizationServers.isEmpty()) {
            Option<String>.Some(credentialOffer.credentialIssuerIdentifier.url)
        } else {
            Option<String>.None
        }

        let state = StateValue().value

        let supportsPar = authorizationServerMetadata.supportsPar() && config.requirePAR.isRequired()

        if (config.requirePAR.isRequired()) {
            match (authorizationServerMetadata.pushedAuthorizationRequestEndpoint()) {
                case None => throw ValidationError.ParRequired()
                case Some(_) => ()
            }
        }

        if (supportsPar) {
            let parResult = authorizer.submitPushedAuthorizationRequest(
                scopes,
                configIds,
                state,
                issuerState,
                resource,
                Option<Nonce>.None,
                Constants.MAX_RETRIES
            )

            let credentials = ArrayList<CredentialIdentifier>()
            for (id in configIds) {
                credentials.add(CredentialIdentifier(id.value))
            }

            return AuthorizationRequested(
                credentials.toArray(),
                parResult.authorizationCodeURL,
                parResult.pkceVerifier,
                state,
                configIds,
                parResult.dPopNonce
            )
        } else {
            let (pkce, authCodeUrl) = authorizer.authorizationRequestUrl(
                scopes,
                configIds,
                state,
                issuerState
            )

            let credentials = ArrayList<CredentialIdentifier>()
            for (id in configIds) {
                credentials.add(CredentialIdentifier(id.value))
            }

            return AuthorizationRequested(
                credentials.toArray(),
                authCodeUrl,
                pkce,
                state,
                configIds,
                Option<Nonce>.None
            )
        }
    }

    // -----------------------------------------------------------------------
    // authorizeWithPreAuthorizationCode
    // -----------------------------------------------------------------------

    public func authorizeWithPreAuthorizationCode(
        credentialOffer: CredentialOffer,
        authorizationCode: String,
        transactionCode: Option<String>,
        authorizationDetailsInTokenRequest: AuthorizationDetailsInTokenRequest
    ): AuthorizedRequest {
        let grants = credentialOffer.grants
        let txCodeOpt: Option<TxCode>

        match (grants) {
            case Some(Grants.PreAuthCode(pac)) =>
                txCodeOpt = pac.txCode
            case Some(Grants.Both(_, pac)) =>
                txCodeOpt = pac.txCode
            case _ =>
                throw ValidationError.Error("Invalid issuance authorisation, pre authorisation supported only")
        }

        match (txCodeOpt) {
            case Some(txCode) =>
                match (transactionCode) {
                    case Some(tc) =>
                        match (txCode.length) {
                            case Some(expectedLen) =>
                                if (expectedLen != Int64(tc.size)) {
                                    throw ValidationError.Error(
                                        "Expected transaction code length is " + expectedLen.toString() +
                                        " but code of length " + tc.size.toString() + " passed"
                                    )
                                }
                            case None => ()
                        }
                    case None => ()
                }
            case None => ()
        }

        let identifiers: Array<CredentialConfigurationIdentifier> = match (authorizationDetailsInTokenRequest) {
            case AuthorizationDetailsInTokenRequest.DoNotInclude => []
            case AuthorizationDetailsInTokenRequest.Include =>
                credentialOffer.credentialConfigurationIdentifiers
        }

        let tokenResult = authorizer.requestAccessTokenPreAuthFlow(
            authorizationCode,
            txCodeOpt,
            config.client,
            transactionCode,
            identifiers,
            Option<Nonce>.None,
            Constants.MAX_RETRIES
        )

        let grantType = GrantType.fromGrants(credentialOffer.grants)
        let now = Float64(DateTime.nowUTC().toUnixTimeStamp().toSeconds())

        return AuthorizedRequest(
            tokenResult.accessToken,
            tokenResult.refreshToken,
            tokenResult.identifiers,
            now,
            tokenResult.dPopNonce,
            grantType
        )
    }

    // -----------------------------------------------------------------------
    // authorizeWithAuthorizationCode
    // -----------------------------------------------------------------------

    public func authorizeWithAuthorizationCode(
        serverState: String,
        request: AuthorizationRequested,
        authorizationCode: String,
        authorizationDetailsInTokenRequest: AuthorizationDetailsInTokenRequest,
        grant: Option<Grants>
    ): AuthorizedRequest {
        if (serverState != request.state) {
            throw ValidationError.StateMismatch(serverState, request.state)
        }

        let identifiers: Array<CredentialConfigurationIdentifier> = match (authorizationDetailsInTokenRequest) {
            case AuthorizationDetailsInTokenRequest.DoNotInclude => []
            case AuthorizationDetailsInTokenRequest.Include => request.configurationIds
        }

        let tokenResult = authorizer.requestAccessTokenAuthFlow(
            authorizationCode,
            request.pkceVerifier.codeVerifier,
            identifiers,
            request.dpopNonce,
            Constants.MAX_RETRIES
        )

        let grantType: Option<GrantType> = match (grant) {
            case Some(g) => GrantType.fromGrants(Option<Grants>.Some(g))
            case None => Option<GrantType>.None
        }
        let now = Float64(DateTime.nowUTC().toUnixTimeStamp().toSeconds())

        return AuthorizedRequest(
            tokenResult.accessToken,
            tokenResult.refreshToken,
            tokenResult.identifiers,
            now,
            tokenResult.dPopNonce,
            grantType
        )
    }

    // -----------------------------------------------------------------------
    // requestCredential
    // -----------------------------------------------------------------------

    public func requestCredential(
        request: AuthorizedRequest,
        bindingKeys: Array<BindingKey>,
        requestPayload: IssuanceRequestPayload
    ): SubmittedRequest {
        let configId = requestPayload.credentialConfigurationIdentifier()

        let cNonceOpt: Option<String> = match (nonceEndpointClient) {
            case Some(nc) =>
                let nr = nc.getNonce()
                Option<String>.Some(nr.cNonce.cNonce)
            case None => Option<String>.None
        }

        let proofs = buildProofs(
            bindingKeys,
            config.client.id(),
            issuerMetadata.credentialIssuerIdentifier.url,
            cNonceOpt
        )

        let dPopNonce = request.dPopNonce
        try {
            let credResponse = issuanceRequester.placeIssuanceRequest(
                request.accessToken,
                configId,
                proofs,
                requestPayload,
                dPopNonce,
                Constants.MAX_RETRIES
            )
            return SubmittedRequest.Success(credResponse)
        } catch (e: CredentialIssuanceError) {
            if (e.message.startsWith("Invalid proof")) {
                return SubmittedRequest.InvalidProof(Option<String>.Some(e.message))
            }
            return SubmittedRequest.Failed(e)
        }
    }

    // -----------------------------------------------------------------------
    // requestDeferredCredential
    // -----------------------------------------------------------------------

    public func requestDeferredCredential(
        request: AuthorizedRequest,
        transactionId: TransactionId,
        dPopNonce: Option<Nonce>
    ): DeferredCredentialIssuanceResponse {
        return deferredIssuanceRequester.placeDeferredCredentialRequest(
            request.accessToken,
            transactionId,
            dPopNonce,
            Constants.MAX_RETRIES
        )
    }

    // -----------------------------------------------------------------------
    // notify
    // -----------------------------------------------------------------------

    public func notify(
        authorizedRequest: AuthorizedRequest,
        notification: NotificationObject,
        dPopNonce: Option<Nonce>
    ): Unit {
        issuanceRequester.notifyIssuer(
            authorizedRequest.accessToken,
            notification,
            dPopNonce,
            Constants.MAX_RETRIES
        )
    }

    // -----------------------------------------------------------------------
    // refresh
    // -----------------------------------------------------------------------

    public func refresh(
        clientId: String,
        authorizedRequest: AuthorizedRequest,
        dPopNonce: Option<Nonce>
    ): AuthorizedRequest {
        let rtOpt = authorizedRequest.refreshToken
        match (rtOpt) {
            case Some(rt) =>
                let tokenResult = authorizer.refreshAccessToken(
                    clientId,
                    rt,
                    dPopNonce,
                    Constants.MAX_RETRIES
                )
                let now = Float64(DateTime.nowUTC().toUnixTimeStamp().toSeconds())
                return authorizedRequest.replacingAccessToken(tokenResult.accessToken, now)
            case None => return authorizedRequest
        }
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    private func getIssuerState(grants: Option<Grants>): Option<String> {
        match (grants) {
            case Some(Grants.AuthCode(ac)) => ac.issuerState
            case Some(Grants.Both(ac, _)) => ac.issuerState
            case _ => Option<String>.None
        }
    }

    private func scopesAndConfigIds(
        credentialOffer: CredentialOffer
    ): (Array<Scope>, Array<CredentialConfigurationIdentifier>) {
        let scopes = ArrayList<Scope>()
        let configIds = ArrayList<CredentialConfigurationIdentifier>()
        let raw = issuerMetadata.credentialConfigurationsRaw

        for (id in credentialOffer.credentialConfigurationIdentifiers) {
            match (config.authorizeIssuanceConfig) {
                case AuthorizeIssuanceConfig.FavorScopes =>
                    match (raw.get(id.value)) {
                        case Some(jobj) =>
                            match (jobj.get("scope")) {
                                case Some(js: JsonString) =>
                                    let scopeVal = js.getValue()
                                    if (!scopeVal.isEmpty()) {
                                        scopes.add(Scope(scopeVal))
                                    } else {
                                        configIds.add(id)
                                    }
                                case _ => configIds.add(id)
                            }
                        case None => configIds.add(id)
                    }
                case AuthorizeIssuanceConfig.AuthorizationDetails =>
                    configIds.add(id)
            }
        }

        return (scopes.toArray(), configIds.toArray())
    }

    private func buildProofs(
        bindingKeys: Array<BindingKey>,
        clientId: String,
        issuerUrl: String,
        cNonce: Option<String>
    ): Array<Proof> {
        if (bindingKeys.isEmpty()) {
            return []
        }
        let proofs = ArrayList<Proof>()
        for (key in bindingKeys) {
            match (key) {
                case BindingKey.JwtKey(privateKey, algorithm) =>
                    let jwt = issuanceRequester.buildJwtProof(
                        privateKey,
                        algorithm,
                        clientId,
                        issuerUrl,
                        cNonce
                    )
                    proofs.add(Proof.JwtProof(jwt))
                case BindingKey.JwtKeyAttestation(privateKey, algorithm, attestationFn) =>
                    // Fetch the key attestation now that the c_nonce is known
                    // (mirrors iOS funcKeyAttestationJWT(nonce)), then emit a JWT
                    // proof whose header carries `key_attestation` instead of `jwk`.
                    let attestationJwt = attestationFn(cNonce)
                    let jwt = issuanceRequester.buildJwtProof(
                        privateKey,
                        algorithm,
                        clientId,
                        issuerUrl,
                        cNonce,
                        keyAttestation: Option<String>.Some(attestationJwt)
                    )
                    proofs.add(Proof.JwtProof(jwt))
                case BindingKey.JwtCallback(pubX963, algorithm, signFn) =>
                    let jwt = issuanceRequester.buildJwtProofFromPublic(
                        pubX963,
                        algorithm,
                        clientId,
                        issuerUrl,
                        cNonce,
                        signFn
                    )
                    proofs.add(Proof.JwtProof(jwt))
                case BindingKey.JwtCallbackAttestation(pubX963, algorithm, signFn, attestationFn) =>
                    let attestationJwt = attestationFn(cNonce)
                    let jwt = issuanceRequester.buildJwtProofFromPublic(
                        pubX963,
                        algorithm,
                        clientId,
                        issuerUrl,
                        cNonce,
                        signFn,
                        keyAttestation: Option<String>.Some(attestationJwt)
                    )
                    proofs.add(Proof.JwtProof(jwt))
                case BindingKey.Attestation(attestationFn) =>
                    // Mirrors iOS BindingKey.attestation → Proof.attestation: the
                    // key attestation JWT (bound to the c_nonce) IS the proof.
                    let attestationJwt = attestationFn(cNonce)
                    logKeyAttestationSummary(attestationJwt)
                    proofs.add(Proof.AttestationProof(attestationJwt))
                case BindingKey.X509(_) =>
                    throw CredentialIssuanceError.CryptographicBindingMethodNotSupported()
                case BindingKey.Did(_) =>
                    throw CredentialIssuanceError.CryptographicBindingMethodNotSupported()
            }
        }
        return proofs.toArray()
    }
}
