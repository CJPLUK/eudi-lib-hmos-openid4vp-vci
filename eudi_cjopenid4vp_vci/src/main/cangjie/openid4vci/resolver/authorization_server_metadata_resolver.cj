/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * authorization_server_metadata_resolver.cj — AS metadata resolver.
 * Ported from iOS Sources/Main/Resolvers/CredentialOffer/AuthorizationServerMetadataResolver.swift.
 *
 * iOS actor/async → sync class; Result<T,E> → throw.
 * Strategy: try /.well-known/oauth-authorization-server first (RFC 8414),
 * fall back to /.well-known/openid-configuration (OIDC Discovery).
 * Uses HttpFetcher from existing network package.
 */
package ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.resolver

import stdx.encoding.json.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.network.HttpFetcher
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.access_mgmt.{
    AuthorizationServerMetadata, OIDCProviderMetadata, IdentityAndAccessManagementMetadata
}
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.error.ValidationError

// ---------------------------------------------------------------------------
// AuthorizationServerMetadataResolver
// Mirrors iOS AuthorizationServerMetadataResolver.
// ---------------------------------------------------------------------------

public class AuthorizationServerMetadataResolver {
    private let fetcher: HttpFetcher

    public init() {
        fetcher = HttpFetcher()
    }

    public init(fetcher: HttpFetcher) {
        this.fetcher = fetcher
    }

    /*
     * Resolve authorization server metadata for a given server URL.
     * Tries RFC 8414 /.well-known/oauth-authorization-server first,
     * then falls back to OIDC Discovery /.well-known/openid-configuration.
     * Returns IdentityAndAccessManagementMetadata (OAuth or OIDC variant).
     * Throws ValidationError if neither endpoint succeeds.
     */
    public func resolve(url: String): IdentityAndAccessManagementMetadata {
        // Try OAuth 2.0 Authorization Server Metadata (RFC 8414) first
        let oauthMeta = tryFetchOAuth(url)
        if (!oauthMeta.isNone()) {
            return IdentityAndAccessManagementMetadata.OAuth(oauthMeta.getOrThrow())
        }

        // Fall back to OIDC Discovery
        let oidcMeta = tryFetchOIDC(url)
        if (!oidcMeta.isNone()) {
            return IdentityAndAccessManagementMetadata.OIDC(oidcMeta.getOrThrow())
        }

        throw ValidationError.Error("Unable to fetch authorization server metadata from " + url)
    }

    // -----------------------------------------------------------------------
    // Private fetch helpers
    // -----------------------------------------------------------------------

    func tryFetchOAuth(serverUrl: String): Option<AuthorizationServerMetadata> {
        let wellKnownUrl = insertWellKnown(serverUrl, "oauth-authorization-server")
        try {
            let data = fetcher.fetch(wellKnownUrl)
            let jsonStr = String.fromUtf8(data)
            let meta = AuthorizationServerMetadata.fromJsonString(jsonStr)
            return Option<AuthorizationServerMetadata>.Some(meta)
        } catch (_: Exception) {
            return Option<AuthorizationServerMetadata>.None
        }
    }

    func tryFetchOIDC(serverUrl: String): Option<OIDCProviderMetadata> {
        let wellKnownUrl = insertWellKnown(serverUrl, "openid-configuration")
        try {
            let data = fetcher.fetch(wellKnownUrl)
            let jsonStr = String.fromUtf8(data)
            let meta = OIDCProviderMetadata.fromJsonString(jsonStr)
            return Option<OIDCProviderMetadata>.Some(meta)
        } catch (_: Exception) {
            return Option<OIDCProviderMetadata>.None
        }
    }

    /*
     * Build a well-known discovery URL by inserting ".well-known/<discoveryPath>"
     * after the authority (host[:port]).
     *
     * iOS modifyURL logic:
     *   - If URL has a non-empty path, insert .well-known/<path> before existing path
     *   - If URL has no path, append .well-known/<path>
     *
     * Example:
     *   "https://as.example.com" → "https://as.example.com/.well-known/oauth-authorization-server"
     *   "https://as.example.com/tenant" → "https://as.example.com/.well-known/oauth-authorization-server/tenant"
     */
    func insertWellKnown(url: String, discoveryPath: String): String {
        let wellKnown = ".well-known"

        // Strip trailing slash
        let urlBytes = url.toArray()
        let base = if (url.endsWith("/")) {
            String.fromUtf8(urlBytes[0..(urlBytes.size - 1)])
        } else {
            url
        }

        // Find end of authority (scheme://host[:port])
        let pathStart = findAuthorityEnd(base)
        let bBase = base.toArray()

        if (pathStart >= bBase.size) {
            // No path — append well-known directly
            return base + "/" + wellKnown + "/" + discoveryPath
        }

        let pathPart = String.fromUtf8(bBase[pathStart..bBase.size])

        if (pathPart == "" || pathPart == "/") {
            return base + "/" + wellKnown + "/" + discoveryPath
        }

        // Insert well-known before existing path
        let authority = String.fromUtf8(bBase[0..pathStart])
        return authority + "/" + wellKnown + "/" + discoveryPath + pathPart
    }

    // Returns index where path starts (first '/' after scheme://host)
    func findAuthorityEnd(url: String): Int64 {
        let bytes = url.toArray()
        var i = 0
        // Skip "scheme://"
        while (i + 2 < bytes.size) {
            if (bytes[i] == 58u8 && bytes[i + 1] == 47u8 && bytes[i + 2] == 47u8) {
                i += 3
                break
            }
            i += 1
        }
        // Find next '/' which is the start of the path
        while (i < bytes.size) {
            if (bytes[i] == 47u8) {
                return i
            }
            i += 1
        }
        return bytes.size
    }
}
