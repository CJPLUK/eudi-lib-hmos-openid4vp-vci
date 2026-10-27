/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * authorization_server_metadata.cj — Authorization server metadata models.
 * Ported from iOS:
 *   - Sources/Entities/AccessManagement/AuthorizationServerMetadata.swift
 *   - Sources/Entities/AccessManagement/OIDCProviderMetadata.swift
 *   - Sources/Entities/AccessManagement/IdentityAndAccessManagementMetadata.swift
 *
 * iOS Codable → manual JSON parse; key naming follows RFC8414/OIDC-Discovery.
 */
package ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.access_mgmt

import std.collection.*
import stdx.encoding.json.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.error.ValidationError

// ---------------------------------------------------------------------------
// AuthorizationServerMetadata (OAuth2 AS)
// ---------------------------------------------------------------------------

public class AuthorizationServerMetadata {
    public let issuer: Option<String>
    public let authorizationEndpoint: Option<String>
    public let tokenEndpoint: Option<String>
    public let pushedAuthorizationRequestEndpoint: Option<String>
    public let tokenEndpointAuthMethodsSupported: Array<String>
    public let dpopSigningAlgValuesSupported: Array<String>
    public let challengeEndpoint: Option<String>
    public let clientAttestationPopSigningAlgValuesSupported: Array<String>

    public init(
        issuer: Option<String>,
        authorizationEndpoint: Option<String>,
        tokenEndpoint: Option<String>,
        pushedAuthorizationRequestEndpoint: Option<String>,
        tokenEndpointAuthMethodsSupported: Array<String>,
        dpopSigningAlgValuesSupported: Array<String>,
        challengeEndpoint: Option<String>,
        clientAttestationPopSigningAlgValuesSupported: Array<String>
    ) {
        this.issuer = issuer
        this.authorizationEndpoint = authorizationEndpoint
        this.tokenEndpoint = tokenEndpoint
        this.pushedAuthorizationRequestEndpoint = pushedAuthorizationRequestEndpoint
        this.tokenEndpointAuthMethodsSupported = tokenEndpointAuthMethodsSupported
        this.dpopSigningAlgValuesSupported = dpopSigningAlgValuesSupported
        this.challengeEndpoint = challengeEndpoint
        this.clientAttestationPopSigningAlgValuesSupported = clientAttestationPopSigningAlgValuesSupported
    }

    public static func fromJsonString(jsonStr: String): AuthorizationServerMetadata {
        let jv = JsonValue.fromStr(jsonStr)
        match (jv) {
            case jobj: JsonObject => return fromJson(jobj)
            case _ => throw ValidationError.Error("AuthorizationServerMetadata: root not JSON object")
        }
    }

    public static func fromJson(root: JsonObject): AuthorizationServerMetadata {
        let issuer = optStr(root, "issuer")
        let authEndpoint = optStr(root, "authorization_endpoint")
        let tokenEndpoint = optStr(root, "token_endpoint")
        let parEndpoint = optStr(root, "pushed_authorization_request_endpoint")
        let tokenAuthMethods = strArr(root, "token_endpoint_auth_methods_supported")
        let dpopAlgs = strArr(root, "dpop_signing_alg_values_supported")
        let challengeEndpoint = optStr(root, "challenge_endpoint")
        let clientAttestAlgs = strArr(root, "client_attestation_pop_signing_alg_values_supported")
        return AuthorizationServerMetadata(
            issuer,
            authEndpoint,
            tokenEndpoint,
            parEndpoint,
            tokenAuthMethods,
            dpopAlgs,
            challengeEndpoint,
            clientAttestAlgs
        )
    }

    // Convenience: minimal constructor used by the deferred-issuer factory (createDeferredIssuer)
    public static func placeholder(
        authorizationEndpoint: String,
        tokenEndpoint: String,
        pushedAuthorizationRequestEndpoint: String
    ): AuthorizationServerMetadata {
        return AuthorizationServerMetadata(
            Option<String>.None,
            Option<String>.Some(authorizationEndpoint),
            Option<String>.Some(tokenEndpoint),
            Option<String>.Some(pushedAuthorizationRequestEndpoint),
            [],
            [],
            Option<String>.None,
            []
        )
    }
}

// ---------------------------------------------------------------------------
// OIDCProviderMetadata — OIDC variant, same fields as OAuth2 AS metadata
// ---------------------------------------------------------------------------

public class OIDCProviderMetadata {
    public let inner: AuthorizationServerMetadata

    public init(inner: AuthorizationServerMetadata) {
        this.inner = inner
    }

    public static func fromJsonString(jsonStr: String): OIDCProviderMetadata {
        let meta = AuthorizationServerMetadata.fromJsonString(jsonStr)
        return OIDCProviderMetadata(meta)
    }

    public static func fromJson(root: JsonObject): OIDCProviderMetadata {
        return OIDCProviderMetadata(AuthorizationServerMetadata.fromJson(root))
    }
}

// ---------------------------------------------------------------------------
// IdentityAndAccessManagementMetadata
// Ported from iOS enum IdentityAndAccessManagementMetadata.
// ---------------------------------------------------------------------------

public enum IdentityAndAccessManagementMetadata {
    | OIDC(OIDCProviderMetadata)
    | OAuth(AuthorizationServerMetadata)

    public func issuer(): Option<String> {
        match (this) {
            case OIDC(meta) => meta.inner.issuer
            case OAuth(meta) => meta.issuer
        }
    }

    public func authorizationEndpoint(): Option<String> {
        match (this) {
            case OIDC(meta) => meta.inner.authorizationEndpoint
            case OAuth(meta) => meta.authorizationEndpoint
        }
    }

    public func tokenEndpoint(): Option<String> {
        match (this) {
            case OIDC(meta) => meta.inner.tokenEndpoint
            case OAuth(meta) => meta.tokenEndpoint
        }
    }

    public func pushedAuthorizationRequestEndpoint(): Option<String> {
        match (this) {
            case OIDC(meta) => meta.inner.pushedAuthorizationRequestEndpoint
            case OAuth(meta) => meta.pushedAuthorizationRequestEndpoint
        }
    }

    public func supportsPar(): Bool {
        match (pushedAuthorizationRequestEndpoint()) {
            case Some(_) => true
            case None => false
        }
    }

    public func tokenEndpointAuthMethods(): Array<String> {
        match (this) {
            case OIDC(meta) => meta.inner.tokenEndpointAuthMethodsSupported
            case OAuth(meta) => meta.tokenEndpointAuthMethodsSupported
        }
    }

    public func dpopSigningAlgValuesSupported(): Array<String> {
        match (this) {
            case OIDC(meta) => meta.inner.dpopSigningAlgValuesSupported
            case OAuth(meta) => meta.dpopSigningAlgValuesSupported
        }
    }

    public func challengeEndpoint(): Option<String> {
        match (this) {
            case OIDC(meta) => meta.inner.challengeEndpoint
            case OAuth(meta) => meta.challengeEndpoint
        }
    }

    public func clientAttestationPopSigningAlgValuesSupported(): Array<String> {
        match (this) {
            case OIDC(meta) => meta.inner.clientAttestationPopSigningAlgValuesSupported
            case OAuth(meta) => meta.clientAttestationPopSigningAlgValuesSupported
        }
    }
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

func optStr(obj: JsonObject, key: String): Option<String> {
    match (obj.get(key)) {
        case Some(js: JsonString) => Option<String>.Some(js.getValue())
        case _ => Option<String>.None
    }
}

func strArr(obj: JsonObject, key: String): Array<String> {
    match (obj.get(key)) {
        case Some(jarr: JsonArray) =>
            let result = ArrayList<String>()
            for (item in jarr.getItems()) {
                match (item) {
                    case js: JsonString => result.add(js.getValue())
                    case _ => ()
                }
            }
            return result.toArray()
        case _ => return []
    }
}
