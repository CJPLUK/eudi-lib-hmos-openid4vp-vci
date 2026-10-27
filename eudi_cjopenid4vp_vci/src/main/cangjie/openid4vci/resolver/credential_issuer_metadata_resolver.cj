/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * credential_issuer_metadata_resolver.cj — Resolves credential issuer metadata.
 * Ported from iOS Sources/Main/Resolvers/CredentialOffer/CredentialIssuerMetadataResolver.swift.
 *
 * iOS actor/async → sync class; Result<T,E> → throw.
 * Builds /.well-known/openid-credential-issuer URL, fetches via MetadataFetcher,
 * validates that the returned issuer identifier domain matches the request domain.
 */
package ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.resolver

import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.issuer.{CredentialIssuerId, CredentialIssuerMetadata}
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.config.IssuerMetadataPolicy
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.error.{CredentialIssuerMetadataError, ValidationError}

// ---------------------------------------------------------------------------
// CredentialIssuerMetadataResolver
// Mirrors iOS CredentialIssuerMetadataResolver.
// ---------------------------------------------------------------------------

public class CredentialIssuerMetadataResolver {
    private let fetcher: MetadataFetcher

    public init() {
        fetcher = MetadataFetcher()
    }

    public init(fetcher: MetadataFetcher) {
        this.fetcher = fetcher
    }

    /*
     * Resolve credential issuer metadata.
     * issuerId: the issuer's URL (e.g. "https://issuer.example.com")
     * policy: IssuerMetadataPolicy — controls Accept header and signed-metadata handling.
     * Returns CredentialIssuerMetadata on success; throws CredentialIssuerMetadataError on failure.
     */
    public func resolve(
        issuerId: CredentialIssuerId,
        policy: IssuerMetadataPolicy
    ): CredentialIssuerMetadata {
        let wellKnownUrl = buildWellKnownUrl(issuerId.url)
        let metadata = fetcher.fetchMetadata(wellKnownUrl, policy, issuerId)

        // Validate: domain in response must match request domain
        let requestHost = extractHost(issuerId.url)
        let issuerHost = extractHost(metadata.credentialIssuerIdentifier.url)
        if (!requestHost.isNone() && !issuerHost.isNone()) {
            let rh = requestHost.getOrThrow().toAsciiLower()
            let ih = issuerHost.getOrThrow().toAsciiLower()
            if (rh != ih) {
                throw ValidationError.Error("Issuer domain does not match metadata issuer")
            }
        }

        return metadata
    }

    // -----------------------------------------------------------------------
    // Build /.well-known/openid-credential-issuer URL
    // Mirrors iOS buildWellKnownCredentialIssuerURL.
    // iOS logic:
    //   - If path != "/" → prepend /.well-known/openid-credential-issuer to existing path
    //   - If path == "/" or empty → use /.well-known/openid-credential-issuer alone
    // -----------------------------------------------------------------------

    func buildWellKnownUrl(issuerUrl: String): String {
        let wellKnownPath = "/.well-known/openid-credential-issuer"

        // Strip trailing slash for uniform handling
        let baseBytes = issuerUrl.toArray()
        let base = if (issuerUrl.endsWith("/")) {
            String.fromUtf8(baseBytes[0..(baseBytes.size - 1)])
        } else {
            issuerUrl
        }

        // Find path start: after scheme://host[:port]
        let schemeEnd = findSchemeEnd(base)
        let pathStart = findPathStart(base, schemeEnd)
        let bBase = base.toArray()

        if (pathStart >= bBase.size) {
            // No path component — just append well-known
            return base + wellKnownPath
        }

        let pathPart = String.fromUtf8(bBase[pathStart..bBase.size])

        if (pathPart == "" || pathPart == "/") {
            return base + wellKnownPath
        }

        // Non-root path: prepend well-known before existing path
        let authority = String.fromUtf8(bBase[0..pathStart])
        return authority + wellKnownPath + pathPart
    }

    // Returns index of the first '/' after scheme://host, or issuerUrl.size if absent
    func findSchemeEnd(url: String): Int64 {
        let bytes = url.toArray()
        var i = 0
        while (i < bytes.size) {
            if (bytes[i] == 58u8) {  // ':'
                if (i + 2 < bytes.size && bytes[i + 1] == 47u8 && bytes[i + 2] == 47u8) {
                    return i + 3  // skip "://"
                }
            }
            i += 1
        }
        return 0
    }

    func findPathStart(url: String, afterScheme: Int64): Int64 {
        let bytes = url.toArray()
        var i = afterScheme
        while (i < bytes.size) {
            if (bytes[i] == 47u8) {  // '/'
                return i
            }
            i += 1
        }
        return bytes.size
    }
}

// ---------------------------------------------------------------------------
// extractHost — extract hostname from a URL string
// Returns None if the URL doesn't contain a recognizable host.
// ---------------------------------------------------------------------------

func extractHost(url: String): Option<String> {
    // Find "://" then take up to the next '/', ':', or end
    let bytes = url.toArray()
    var i = 0
    while (i + 2 < bytes.size) {
        if (bytes[i] == 58u8 && bytes[i + 1] == 47u8 && bytes[i + 2] == 47u8) {
            // Found "://"
            let hostStart = i + 3
            var j = hostStart
            while (j < bytes.size) {
                let b = bytes[j]
                if (b == 47u8 || b == 58u8 || b == 63u8 || b == 35u8) {
                    break
                }
                j += 1
            }
            if (j == hostStart) {
                return Option<String>.None
            }
            let host = String.fromUtf8(bytes[hostStart..j])
            return Option<String>.Some(host)
        }
        i += 1
    }
    return Option<String>.None
}
