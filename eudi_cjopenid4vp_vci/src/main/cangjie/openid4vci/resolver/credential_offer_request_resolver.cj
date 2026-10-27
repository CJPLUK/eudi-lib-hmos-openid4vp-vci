/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * credential_offer_request_resolver.cj — Full credential offer resolution pipeline.
 * Ported from iOS Sources/Main/Resolvers/CredentialOffer/CredentialOfferRequestResolver.swift.
 *
 * iOS actor/async → sync class; Result<T,E> → throw.
 *
 * Flow:
 *   1. Parse openid-credential-offer:// URI:
 *      - passByValue: credential_offer query param = inline JSON
 *      - fetchByReference: credential_offer_uri query param = URL to fetch
 *   2. Parse raw JSON → CredentialOfferRequestObject
 *   3. Resolve CredentialIssuerMetadata via CredentialIssuerMetadataResolver
 *   4. Select authorization server from grants hint or first available
 *   5. Resolve IdentityAndAccessManagementMetadata via AuthorizationServerMetadataResolver
 *   6. Build domain CredentialOffer
 */
package ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.resolver

import std.collection.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.network.HttpFetcher
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.types.{
    CredentialConfigurationIdentifier, Grants
}
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.issuer.{CredentialIssuerId, CredentialIssuerMetadata}
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.access_mgmt.IdentityAndAccessManagementMetadata
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.offer.{
    CredentialOffer, CredentialOfferRequestObject, GrantsDTO
}
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.config.IssuerMetadataPolicy
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.error.{
    CredentialOfferRequestError, CredentialOfferRequestValidationError, ValidationError
}

// ---------------------------------------------------------------------------
// CredentialOfferRequest — discriminated union for the two offer delivery modes
// Mirrors iOS enum CredentialOfferRequest (passByValue / fetchByReference).
// ---------------------------------------------------------------------------

public enum CredentialOfferRequest {
    | PassByValue(String)          // inline JSON string
    | FetchByReference(String)     // URL to fetch
}

// ---------------------------------------------------------------------------
// CredentialOfferRequestResolver
// Mirrors iOS actor CredentialOfferRequestResolver.
// ---------------------------------------------------------------------------

public class CredentialOfferRequestResolver {
    private let fetcher: HttpFetcher
    private let issuerMetadataResolver: CredentialIssuerMetadataResolver
    private let asMetadataResolver: AuthorizationServerMetadataResolver

    public init() {
        fetcher = HttpFetcher()
        issuerMetadataResolver = CredentialIssuerMetadataResolver()
        asMetadataResolver = AuthorizationServerMetadataResolver()
    }

    public init(
        fetcher: HttpFetcher,
        issuerMetadataResolver: CredentialIssuerMetadataResolver,
        asMetadataResolver: AuthorizationServerMetadataResolver
    ) {
        this.fetcher = fetcher
        this.issuerMetadataResolver = issuerMetadataResolver
        this.asMetadataResolver = asMetadataResolver
    }

    /*
     * Parse a credential offer URI string into a CredentialOfferRequest.
     * Accepts:
     *   openid-credential-offer://?credential_offer=<JSON>
     *   openid-credential-offer://?credential_offer_uri=<URL>
     *   haip-vci://…  — the HAIP alias scheme; iOS registers it in
     *   Wallet.plist and DeepLinkController maps .haip_vci to the same
     *   .credential_offer action (issuer.eudiw.dev QR codes use it).
     * Throws CredentialOfferRequestError / CredentialOfferRequestValidationError on failure.
     */
    public func parseOfferUri(uri: String): CredentialOfferRequest {
        // The scheme portion
        if (!uri.startsWith("openid-credential-offer:") && !uri.startsWith("haip-vci:")) {
            // Also accept https:// URIs as fetchByReference
            if (uri.startsWith("https://") || uri.startsWith("http://")) {
                return CredentialOfferRequest.FetchByReference(uri)
            }
            throw CredentialError2.InvalidScheme()
        }

        // Extract query string
        let queryStart = findQueryStart(uri)
        if (queryStart >= uri.size) {
            throw CredentialOfferRequestValidationError.OneOfCredentialOfferOrCredentialOfferUri()
        }
        let uriBytes = uri.toArray()
        let query = String.fromUtf8(uriBytes[(queryStart + 1)..uriBytes.size])
        let params = parseQueryParams(query)

        let offerParam = params.get("credential_offer")
        if (!offerParam.isNone()) {
            let raw = percentDecode(offerParam.getOrThrow())
            return CredentialOfferRequest.PassByValue(raw)
        }

        let uriParam = params.get("credential_offer_uri")
        if (!uriParam.isNone()) {
            let raw = percentDecode(uriParam.getOrThrow())
            return CredentialOfferRequest.FetchByReference(raw)
        }

        throw CredentialOfferRequestValidationError.OneOfCredentialOfferOrCredentialOfferUri()
    }

    /*
     * Resolve a CredentialOfferRequest into a full CredentialOffer.
     * Throws on any resolution failure.
     */
    public func resolve(
        source: CredentialOfferRequest,
        policy: IssuerMetadataPolicy
    ): CredentialOffer {
        let offerObject = fetchOfferObject(source)
        return resolveFromObject(offerObject, policy)
    }

    /*
     * Convenience: parse URI then resolve.
     */
    public func resolveUri(
        uri: String,
        policy: IssuerMetadataPolicy
    ): CredentialOffer {
        let source = parseOfferUri(uri)
        return resolve(source, policy)
    }

    // -----------------------------------------------------------------------
    // Private implementation
    // -----------------------------------------------------------------------

    func fetchOfferObject(source: CredentialOfferRequest): CredentialOfferRequestObject {
        match (source) {
            case CredentialOfferRequest.PassByValue(jsonStr) =>
                try {
                    return CredentialOfferRequestObject.fromJsonString(jsonStr)
                } catch (e: Exception) {
                    throw CredentialOfferRequestError.NonParseableCredentialOffer(e.message)
                }
            case CredentialOfferRequest.FetchByReference(refUrl) =>
                let data: Array<UInt8>
                try {
                    data = fetcher.fetch(refUrl)
                } catch (e: Exception) {
                    throw CredentialOfferRequestError.UnableToFetchCredentialOffer(e.message)
                }
                let jsonStr: String
                try {
                    jsonStr = String.fromUtf8(data)
                } catch (e: Exception) {
                    throw CredentialOfferRequestError.NonParseableCredentialOffer("UTF-8 decode: " + e.message)
                }
                try {
                    return CredentialOfferRequestObject.fromJsonString(jsonStr)
                } catch (e: Exception) {
                    throw CredentialOfferRequestError.NonParseableCredentialOffer(e.message)
                }
        }
    }

    func resolveFromObject(
        offerObject: CredentialOfferRequestObject,
        policy: IssuerMetadataPolicy
    ): CredentialOffer {
        // Step 1: resolve issuer metadata
        let issuerId: CredentialIssuerId
        try {
            issuerId = CredentialIssuerId(offerObject.credentialIssuer)
        } catch (e: Exception) {
            throw CredentialOfferRequestValidationError.InvalidCredentialIssuerId()
        }

        let issuerMetadata: CredentialIssuerMetadata
        try {
            issuerMetadata = issuerMetadataResolver.resolve(issuerId, policy)
        } catch (e: Exception) {
            throw CredentialOfferRequestError.UnableToResolveCredentialIssuerMetadata(e.message)
        }

        // Step 2: select authorization server
        let authServerHint = getAuthorizationServerFromGrants(offerObject.grants)
        let authServerUrl = selectAuthorizationServer(authServerHint, issuerMetadata.authorizationServers)

        // Step 3: resolve AS metadata
        let asMeta: IdentityAndAccessManagementMetadata
        try {
            asMeta = asMetadataResolver.resolve(authServerUrl)
        } catch (e: Exception) {
            throw CredentialOfferRequestError.UnableToResolveAuthorizationServerMetadata(e.message)
        }

        // Step 4: build domain CredentialOffer
        return toDomain(offerObject, issuerMetadata, asMeta)
    }

    /*
     * Extract the authorization server URL hint from grants, if specified.
     * Mirrors iOS getAuthorizationServerFromGrants.
     */
    func getAuthorizationServerFromGrants(grants: Option<GrantsDTO>): Option<String> {
        if (grants.isNone()) {
            return Option<String>.None
        }
        let g = grants.getOrThrow()

        if (!g.authorizationCode.isNone()) {
            let ac = g.authorizationCode.getOrThrow()
            if (!ac.authorizationServer.isNone()) {
                let s = ac.authorizationServer.getOrThrow()
                if (!s.isEmpty()) {
                    return Option<String>.Some(s)
                }
            }
        }

        if (!g.preAuthorizationCode.isNone()) {
            let pac = g.preAuthorizationCode.getOrThrow()
            if (!pac.authorizationServer.isNone()) {
                let s = pac.authorizationServer.getOrThrow()
                if (!s.isEmpty()) {
                    return Option<String>.Some(s)
                }
            }
        }

        return Option<String>.None
    }

    /*
     * Select authorization server: if hint provided, validate it's in available list;
     * otherwise use the first available server.
     * Mirrors iOS selectAuthorizationServer.
     */
    func selectAuthorizationServer(
        hint: Option<String>,
        availableServers: Array<String>
    ): String {
        if (availableServers.isEmpty()) {
            throw ValidationError.Error("No authorization servers available")
        }

        if (!hint.isNone()) {
            let hintUrl = hint.getOrThrow()
            for (server in availableServers) {
                if (server == hintUrl) {
                    return server
                }
            }
            throw ValidationError.Error(
                "Authorization server '" + hintUrl + "' from credential offer is not in the list of available authorization servers"
            )
        }

        return availableServers[0]
    }

    /*
     * Build CredentialOffer domain object from resolved parts.
     * Mirrors iOS toDomain.
     */
    func toDomain(
        offerObject: CredentialOfferRequestObject,
        issuerMetadata: CredentialIssuerMetadata,
        asMeta: IdentityAndAccessManagementMetadata
    ): CredentialOffer {
        let configIds = ArrayList<CredentialConfigurationIdentifier>()
        for (idStr in offerObject.credentialConfigurationIds) {
            configIds.add(CredentialConfigurationIdentifier(idStr))
        }

        let grants: Option<Grants> = if (offerObject.grants.isNone()) {
            Option<Grants>.None
        } else {
            try {
                let g = offerObject.grants.getOrThrow().toDomain()
                Option<Grants>.Some(g)
            } catch (e: Exception) {
                throw CredentialOfferRequestValidationError.InvalidGrants()
            }
        }

        return CredentialOffer(
            issuerMetadata.credentialIssuerIdentifier,
            issuerMetadata,
            configIds.toArray(),
            grants
        )
    }
}

// ---------------------------------------------------------------------------
// CredentialError2 — local error for scheme validation (avoids import conflict)
// Note: CredentialError in errors.cj doesn't export an InvalidScheme factory
// that matches our needs directly; we reuse the existing class from errors.cj.
// ---------------------------------------------------------------------------

class CredentialError2 {
    static func InvalidScheme(): Exception {
        return Exception("CredentialOfferRequestResolver: invalid URI scheme")
    }
}

// ---------------------------------------------------------------------------
// URI parsing helpers
// ---------------------------------------------------------------------------

func findQueryStart(uri: String): Int64 {
    let bytes = uri.toArray()
    var i = 0
    while (i < bytes.size) {
        if (bytes[i] == 63u8) {  // '?'
            return i
        }
        i += 1
    }
    return bytes.size
}

func parseQueryParams(query: String): HashMap<String, String> {
    let result = HashMap<String, String>()
    let pairs = query.split("&")
    for (pair in pairs) {
        let eqIdx = findEq(pair)
        if (eqIdx >= pair.size) {
            result.add(pair, "")
        } else {
            let pairBytes = pair.toArray()
            let k = String.fromUtf8(pairBytes[0..eqIdx])
            let v = String.fromUtf8(pairBytes[(eqIdx + 1)..pairBytes.size])
            result.add(k, v)
        }
    }
    return result
}

func findEq(s: String): Int64 {
    let bytes = s.toArray()
    var i = 0
    while (i < bytes.size) {
        if (bytes[i] == 61u8) {  // '='
            return i
        }
        i += 1
    }
    return bytes.size
}

/*
 * Percent-decode a URL-encoded string.
 * Replaces %XX sequences with their byte values, and '+' with space.
 */
func percentDecode(encoded: String): String {
    let bytes = encoded.toArray()
    let result = ArrayList<UInt8>()
    var i = 0
    while (i < bytes.size) {
        if (bytes[i] == 43u8) {
            // '+' → space
            result.add(32u8)
            i += 1
        } else if (bytes[i] == 37u8 && i + 2 < bytes.size) {
            // '%XX'
            let hi = hexVal(bytes[i + 1])
            let lo = hexVal(bytes[i + 2])
            if (hi >= 0 && lo >= 0) {
                result.add(UInt8(hi * 16 + lo))
                i += 3
            } else {
                result.add(bytes[i])
                i += 1
            }
        } else {
            result.add(bytes[i])
            i += 1
        }
    }
    return String.fromUtf8(result.toArray())
}

func hexVal(b: UInt8): Int64 {
    if (b >= 48u8 && b <= 57u8) { return Int64(b) - 48 }  // '0'-'9'
    if (b >= 65u8 && b <= 70u8) { return Int64(b) - 55 }  // 'A'-'F'
    if (b >= 97u8 && b <= 102u8) { return Int64(b) - 87 } // 'a'-'f'
    return -1
}
