/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * authorization_resolver.cj — Authorization request resolution pipeline.
 * Ported from iOS: AuthorizationRequestResolver.swift, RequestFetcher.swift,
 * ClientMetaDataValidator.swift (inline), AccessValidator.swift (inline),
 * ClientAuthenticator.swift (x509 chain validation + JWS verification).
 *
 * iOS actor → Cangjie class (no actor model).
 * iOS async → sync.
 *
 * SECURITY: JAR (request object) JWS signatures ARE cryptographically verified.
 *   - x509_san_dns / x509_hash: the JWS is verified with the leaf certificate's
 *     EC public key (ES256), and the x5c chain is verified against the
 *     wallet-configured trust anchors (config.trustedRootCertsPem). Mirrors iOS
 *     AccessValidator.validateX509 (SAN/hash binding + chain trust + signature).
 *   - verifier_attestation: the verifier-attestation+jwt is verified (typ +
 *     ES256 signature against its x5c leaf + iss/sub/exp/iat time checks).
 *   - decentralized_identifier: rejected unless a DID resolver is supplied
 *     (no silent trust — mirrors iOS didPublicKeyLookup which fails closed).
 * Trust anchors are fail-closed: with no roots, x509 chains are NOT trusted and
 * the request is rejected.
 */
package ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.resolver

import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.error.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.entity.types.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.entity.dcql.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.entity.client.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.entity.request.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.entity.metadata.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.entity.config.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.network.*
import ohos_app_cangjie_eudi_cjx509.x509.core.{Cert, verifyChain}
import std.collection.*
import std.time.DateTime
import stdx.encoding.json.*

// DidPublicKeyResolver — wallet-supplied DID document resolver.
// Mirrors iOS DIDPublicKeyLookupAgentType.resolveKey(from:). Given a DID
// string and the kid from the JWS header, returns the EC public key (as a
// 65-byte uncompressed P-256 point, 0x04||X||Y) to verify the JWS, or None if
// the DID/key cannot be resolved (which causes the request to be rejected).
public interface DidPublicKeyResolver {
    func resolveKey(did: String, kid: Option<String>): Option<Array<UInt8>>
}

// ---------------------------------------------------------------------------
// AuthorizationRequestResolver — mirrors iOS AuthorizationRequestResolver actor
//
// Security model:
//   1. JAR (request object) JWS signatures are cryptographically verified for
//      x509_san_dns / x509_hash (leaf-cert ES256) and verifier_attestation.
//   2. X.509 chain trust is verified against config.trustedRootCertsPem
//      (fail-closed: no roots ⇒ chain not trusted ⇒ reject).
//   3. request_uri (pass-by-reference) fetches JWT via HTTP. Only GET supported.
//   4. DID: rejected unless a DidPublicKeyResolver is supplied (no silent trust).
// ---------------------------------------------------------------------------

public class AuthorizationRequestResolver {

    private let didResolver: Option<DidPublicKeyResolver>

    public init() {
        this.didResolver = None
    }

    public init(didResolver!: Option<DidPublicKeyResolver>) {
        this.didResolver = didResolver
    }

    // Main entry point — mirrors iOS AuthorizationRequestResolver.resolve(...)
    // Synchronous (iOS async → sync).
    public func resolve(
        walletConfiguration: OpenId4VPWalletConfiguration,
        unvalidatedRequest: UnvalidatedRequest,
        httpFetcher!: Option<HttpFetcher> = None
    ): AuthorizationRequest {

        // Step 1: Fetch the request (plain / jwt-by-value / jwt-by-reference)
        var fetchedRequestOpt: Option<FetchedRequest> = None
        try {
            fetchedRequestOpt = Some(fetchRequest(
                walletConfiguration,
                unvalidatedRequest,
                httpFetcher
            ))
        } catch (e: Exception) {
            return InvalidResolution(e, None)
        }
        let fetchedRequest: FetchedRequest = fetchedRequestOpt.getOrThrow()

        // Step 2: Authenticate the request (extract UnvalidatedRequestObject + client)
        var requestObjectOpt: Option<UnvalidatedRequestObject> = None
        var clientOpt: Option<Client> = None
        var isJwtSecured: Bool = false
        try {
            let (ro, cl, jwt) = authenticateRequest(
                walletConfiguration,
                fetchedRequest
            )
            requestObjectOpt = Some(ro)
            clientOpt = Some(cl)
            isJwtSecured = jwt
        } catch (e: Exception) {
            let dispatchDetails = makeDispatchDetailsFromFetched(fetchedRequest)
            match (walletConfiguration.errorDispatchPolicy) {
                case ErrorDispatchPolicy.AllClients =>
                    return InvalidResolution(e, dispatchDetails)
                case ErrorDispatchPolicy.OnlyAuthenticatedClients =>
                    return InvalidResolution(e, None)
            }
        }
        let requestObject: UnvalidatedRequestObject = requestObjectOpt.getOrThrow()
        let client: Client = clientOpt.getOrThrow()

        // Step 3: Validate client metadata
        let responseMode = requestObject.validatedResponseMode()
        var validatedClientMetaData: ValidatedClientMetaData = ValidatedClientMetaData.makeDefault()
        match (requestObject.clientMetaData) {
            case Some(metaStr) =>
                try {
                    let metaData = ClientMetaData.fromJsonString(metaStr)
                    validatedClientMetaData = ValidatedClientMetaData.validate(metaData, responseMode)
                } catch (e: Exception) {
                    let dd = makeDispatchDetails(requestObject, client)
                    return InvalidResolution(
                        VpValidationError.InvalidClientMetadata(), Some(dd)
                    )
                }
            case None =>
                validatedClientMetaData = ValidatedClientMetaData.makeDefault()
        }

        // Step 4: Validate response_type
        let responseTypeStr = match (requestObject.responseType) {
            case Some(rt) => rt
            case None =>
                return InvalidResolution(VpValidationError.MissingResponseType(), Some(makeDispatchDetails(requestObject, client)))
        }
        match (ResponseType.fromRawValue(responseTypeStr)) {
            case None =>
                return InvalidResolution(
                    VpValidationError.UnsupportedResponseType(responseTypeStr),
                    Some(makeDispatchDetails(requestObject, client))
                )
            case Some(ResponseType.VpToken) => ()
            case Some(ResponseType.Code) =>
                return InvalidResolution(
                    VpValidationError.UnsupportedResponseType(responseTypeStr),
                    Some(makeDispatchDetails(requestObject, client))
                )
        }

        // Step 5: Validate nonce
        match (requestObject.nonce) {
            case None =>
                return InvalidResolution(VpValidationError.MissingNonce(), Some(makeDispatchDetails(requestObject, client)))
            case Some(_) => ()
        }

        // Step 6: Build ValidatedRequestData
        var validatedOpt: Option<ValidatedRequestData> = None
        try {
            validatedOpt = Some(ValidatedRequestData.fromPlainRequest(requestObject, client))
        } catch (e: Exception) {
            return InvalidResolution(e, Some(makeDispatchDetails(requestObject, client)))
        }
        let validated: ValidatedRequestData = validatedOpt.getOrThrow()

        // Step 7: Resolve ResolvedRequestData
        var resolvedOpt: Option<ResolvedRequestData> = None
        try {
            resolvedOpt = Some(ResolvedRequestData.fromValidated(
                walletConfiguration.vpConfiguration,
                validatedClientMetaData,
                validated
            ))
        } catch (e: Exception) {
            return InvalidResolution(e, Some(makeDispatchDetails(requestObject, client)))
        }
        let resolved: ResolvedRequestData = resolvedOpt.getOrThrow()

        // Step 8: Return final AuthorizationRequest
        if (isJwtSecured) {
            return JwtRequest(resolved)
        } else {
            return NotSecuredRequest(resolved)
        }
    }

    // -----------------------------------------------------------------------
    // Step 1: Fetch request
    // -----------------------------------------------------------------------

    private func fetchRequest(
        config: OpenId4VPWalletConfiguration,
        unvalidatedRequest: UnvalidatedRequest,
        httpFetcher: Option<HttpFetcher>
    ): FetchedRequest {
        match (unvalidatedRequest) {
            case r: Plain =>
                return PlainFetched(r.requestObject)
            case r: JwtSecuredPassByValue =>
                return JwtSecuredFetched(r.clientId, r.jwt)
            case r: JwtSecuredPassByReference =>
                // Fetch JWT from URI via GET
                let jwt = fetchJwtFromUri(r.jwtUri, httpFetcher)
                return JwtSecuredFetched(r.clientId, jwt)
            case _ =>
                throw VpValidationError.ValidationError("Unknown UnvalidatedRequest type")
        }
    }

    private func fetchJwtFromUri(uri: String, httpFetcher: Option<HttpFetcher>): String {
        if (httpFetcher.isNone()) {
            throw VpValidationError.ValidationError("HttpFetcher required for request_uri but not provided")
        }
        let fetcher = httpFetcher.getOrThrow()
        try {
            let data = fetcher.fetch(uri)
            let body = String.fromUtf8(data)
            return extractJwtFromResponseBody(body)
        } catch (e: Exception) {
            throw VpValidationError.ValidationError("Failed to fetch request_uri: " + e.message)
        }
    }

    // Extract JWT from response body (may be JSON {jwt: "..."} or raw JWT string)
    private func extractJwtFromResponseBody(body: String): String {
        let trimmed = body.trimAscii()
        // If starts with '{', try JSON parse for {"jwt": "..."}
        if (trimmed.startsWith("{")) {
            try {
                let parsed = JsonValue.fromStr(trimmed)
                match (parsed) {
                    case obj: JsonObject =>
                        match (obj.get("jwt")) {
                            case Some(s: JsonString) => return s.getValue()
                            case _ => ()
                        }
                    case _ => ()
                }
            } catch (_: Exception) { () }
        }
        // Return raw string (assume it is a JWT)
        return trimmed
    }

    // -----------------------------------------------------------------------
    // Step 2: Authenticate request
    // Returns (requestObject, client, isJwtSecured)
    // -----------------------------------------------------------------------

    private func authenticateRequest(
        config: OpenId4VPWalletConfiguration,
        fetchedRequest: FetchedRequest
    ): (UnvalidatedRequestObject, Client, Bool) {
        match (fetchedRequest) {
            case r: PlainFetched =>
                // Determine client from clientId + clientIdScheme
                let client = buildClientFromRequest(r.requestObject, config, jwtCompact: None)
                return (r.requestObject, client, false)
            case r: JwtSecuredFetched =>
                // Parse JWT payload to get request object
                let requestObject = parseJwtPayload(r.jwt)
                // Validate client_id matches JWT claim
                let jwtClientId = match (requestObject.clientId) {
                    case Some(id) => id
                    case None => throw VpValidationError.MissingClientId()
                }
                // Validate client_id matches the one from the URI/query
                if (jwtClientId != r.clientId) {
                    // Try VerifierId comparison
                    let parsedJwt = VerifierId.parse(jwtClientId)
                    let parsedUri = VerifierId.parse(r.clientId)
                    if (parsedJwt.originalClientId != parsedUri.originalClientId) {
                        throw VpValidationError.ClientIdMismatch(r.clientId, jwtClientId)
                    }
                }
                let client = buildClientFromRequest(requestObject, config, jwtCompact: Some(r.jwt))
                return (requestObject, client, true)
            case _ =>
                throw VpValidationError.ValidationError("Unknown FetchedRequest type")
        }
    }

    // Parse JWT compact serialization payload into the request object. The
    // cryptographic JWS signature is verified separately, per client_id scheme,
    // inside buildClientFromRequest (x509/attestation/DID), which mirrors iOS
    // ordering (parse claims to learn the scheme, then authenticate the signer).
    private func parseJwtPayload(jwt: String): UnvalidatedRequestObject {
        let parts = jwt.split(".")
        if (parts.size < 2) {
            throw VpValidationError.InvalidJwtPayload()
        }
        // parts[1] is the payload (base64url encoded)
        let payloadBytes = base64UrlDecode(parts[1])
        let payloadStr = String.fromUtf8(payloadBytes)
        var parsedOpt: Option<JsonValue> = None
        try {
            parsedOpt = Some(JsonValue.fromStr(payloadStr))
        } catch (_: Exception) {
            throw VpValidationError.InvalidJwtPayload()
        }
        let parsed = parsedOpt.getOrThrow()
        match (parsed) {
            case obj: JsonObject => UnvalidatedRequestObject.fromJsonObject(obj)
            case _ => throw VpValidationError.InvalidJwtPayload()
        }
    }

    // Build Client from request object + wallet configuration.
    // jwtCompact: the raw JWT compact string (present for JwtSecured requests),
    // used to extract the x5c header for X.509 chain validation.
    private func buildClientFromRequest(
        requestObject: UnvalidatedRequestObject,
        config: OpenId4VPWalletConfiguration,
        jwtCompact!: Option<String> = None
    ): Client {
        let clientIdRaw = match (requestObject.clientId) {
            case Some(id) => id
            case None => throw VpValidationError.MissingClientId()
        }
        // OpenID4VP draft 22+ dropped the separate client_id_scheme parameter;
        // the scheme travels as a prefix inside client_id ("x509_hash:...").
        // Prefer the legacy explicit field when present, else parse the prefix
        // (VerifierId.parse falls back to pre-registered when there is none).
        let scheme = match (requestObject.clientIdScheme) {
            case Some(s) => ClientIdPrefix.fromSchemeOrThrow(Some(s))
            case None => VerifierId.parse(clientIdRaw).scheme
        }

        // Validate scheme is supported by wallet
        var schemeSupported = false
        for (supported in config.supportedClientIdSchemes) {
            if (supported == scheme) {
                schemeSupported = true
                break
            }
        }
        if (!schemeSupported) {
            throw VpValidationError.UnsupportedClientIdScheme(scheme.toString())
        }

        match (scheme) {
            case ClientIdPrefix.PreRegistered =>
                PreRegisteredClient(clientId: clientIdRaw)
            case ClientIdPrefix.RedirectUri =>
                RedirectUriClient(clientId: clientIdRaw)
            case ClientIdPrefix.X509SanDns =>
                buildX509SanDnsClient(clientIdRaw, jwtCompact, config)
            case ClientIdPrefix.X509Hash =>
                buildX509HashClient(clientIdRaw, jwtCompact, config)
            case ClientIdPrefix.DecentralizedIdentifier =>
                buildDidClient(clientIdRaw, jwtCompact)
            case ClientIdPrefix.VerifierAttestation =>
                buildAttestedClient(clientIdRaw, jwtCompact)
            case ClientIdPrefix.OpenidFederation =>
                // OpenID Federation → treat as pre-registered (DID resolution: block 5)
                PreRegisteredClient(clientId: clientIdRaw)
        }
    }

    // Build X509SanDnsClient — mirrors iOS ClientAuthenticator.getClient
    // case .x509SanDns + AccessValidator.validateX509:
    // 1. Extract x5c from JWT header → parse cert chain with cjx509.
    // 2. Validate that the leaf certificate's SAN dnsName contains the clientId.
    // 3. Verify the x5c chain against wallet trust anchors (fail-closed).
    // 4. Cryptographically verify the JWS signature with the leaf public key.
    private func buildX509SanDnsClient(
        clientId: String,
        jwtCompact: Option<String>,
        config: OpenId4VPWalletConfiguration
    ): Client {
        match (jwtCompact) {
            case None =>
                // x509_san_dns requires a signed (JAR) request: an unsigned plain
                // request carries no x5c and cannot be authenticated. Reject.
                throw VpValidationError.ValidationError(
                    "x509_san_dns: a signed request object (x5c) is required")
            case Some(jwt) =>
                let leaf = extractAndValidateX5cLeaf(jwt, "x509_san_dns", config)
                // SAN dnsName must contain the clientId (host binding).
                let verifierId = VerifierId.parse(clientId)
                let sanNames = extractSanDnsNames(leaf)
                let targetDns = verifierId.originalClientId
                var sanMatches = false
                for (name in sanNames) {
                    if (name == targetDns) {
                        sanMatches = true
                        break
                    }
                }
                if (!sanMatches) {
                    throw VpValidationError.ValidationError(
                        "x509_san_dns: clientId '${targetDns}' not found in SAN dnsName list")
                }
                X509SanDnsClient(clientId: clientId, cert: Some(leaf))
        }
    }

    // Build X509HashClient — mirrors iOS .x509Hash:
    // 1. Extract x5c from JWT header → parse leaf cert.
    // 2. SHA-256(leafDer) base64url == originalClientId.
    // 3. Verify the chain against trust anchors (fail-closed) + JWS signature.
    private func buildX509HashClient(
        clientId: String,
        jwtCompact: Option<String>,
        config: OpenId4VPWalletConfiguration
    ): Client {
        match (jwtCompact) {
            case None =>
                throw VpValidationError.ValidationError(
                    "x509_hash: a signed request object (x5c) is required")
            case Some(jwt) =>
                let leaf = extractAndValidateX5cLeaf(jwt, "x509_hash", config)
                let verifierId = VerifierId.parse(clientId)
                let expectedHash = certSha256Base64Url(leaf)
                if (expectedHash != verifierId.originalClientId) {
                    throw VpValidationError.ValidationError(
                        "x509_hash: clientId hash mismatch")
                }
                X509HashClient(clientId: clientId, cert: Some(leaf))
        }
    }

    // Shared x509 authentication core for x509_san_dns / x509_hash:
    //   - parse x5c, require ≥1 cert
    //   - verify chain against config trust anchors (fail-closed: no roots ⇒ reject)
    //   - cryptographically verify the JWS signature with the leaf public key
    // Returns the validated leaf certificate.
    private func extractAndValidateX5cLeaf(
        jwt: String,
        schemeName: String,
        config: OpenId4VPWalletConfiguration
    ): Cert {
        let x5cOpt = extractX5cFromJwtHeader(jwt)
        let x5cEntries: Array<String> = match (x5cOpt) {
            case None =>
                throw VpValidationError.ValidationError(
                    "${schemeName}: JWT header missing x5c field")
            case Some(entries) => entries
        }
        let certs = parseCertsFromX5c(x5cEntries)
        if (certs.size < 1) {
            throw VpValidationError.ValidationError(
                "${schemeName}: x5c contains no valid certificates")
        }
        let leaf = certs[0]

        // iOS chainVerifier: live CertificateTrust when supplied; otherwise PEM PKIX.
        let chainTrusted = match (config.x509ChainTrust) {
            case Some(trust) =>
                if (certs.size != x5cEntries.size) {
                    false
                } else {
                    trust.isTrusted(certsToDerU8(certs))
                }
            case None =>
                let roots = parseRootsFromPem(config.trustedRootCertsPem)
                verifyX5cChain(certs, roots)
        }
        if (!chainTrusted) {
            throw VpValidationError.ValidationError(
                "${schemeName}: certificate chain is not trusted (no/invalid trust anchors)")
        }

        // Cryptographic JWS signature verification with the leaf public key.
        if (!verifyJwsWithCert(jwt, leaf)) {
            throw VpValidationError.ValidationError(
                "${schemeName}: request object JWS signature verification failed")
        }
        return leaf
    }

    // Build DidClient — mirrors iOS didPublicKeyLookup. Requires a DID resolver
    // and a verified JWS signature against the resolved key. With no resolver,
    // the DID cannot be trusted ⇒ reject (no silent trust).
    private func buildDidClient(clientId: String, jwtCompact: Option<String>): Client {
        let jwt = match (jwtCompact) {
            case Some(j) => j
            case None =>
                throw VpValidationError.ValidationError(
                    "decentralized_identifier: a signed request object is required")
        }
        let resolver = match (didResolver) {
            case Some(r) => r
            case None =>
                throw VpValidationError.ValidationError(
                    "decentralized_identifier: no DID resolver configured; cannot trust DID client")
        }
        let kid = extractStringFromJwtHeader(jwt, "kid")
        // iOS requires the kid URL to be prefixed by the DID (binding check).
        match (kid) {
            case Some(k) =>
                if (!k.startsWith(clientId)) {
                    throw VpValidationError.ValidationError(
                        "decentralized_identifier: kid '${k}' is not bound to DID '${clientId}'")
                }
            case None => ()
        }
        let keyPointOpt = resolver.resolveKey(clientId, kid)
        let keyPoint = match (keyPointOpt) {
            case Some(p) => p
            case None =>
                throw VpValidationError.ValidationError(
                    "decentralized_identifier: unable to resolve public key for DID '${clientId}'")
        }
        if (!verifyJwsWithDidKey(jwt, keyPoint)) {
            throw VpValidationError.ValidationError(
                "decentralized_identifier: request object JWS signature verification failed")
        }
        DidClient(did: clientId)
    }

    // Build AttestedClient — mirrors iOS verifierAttestation:
    //   - typ header == "verifier-attestation+jwt"
    //   - JWS ES256 signature verified against the attestation's x5c leaf
    //   - iss / sub present, exp / iat time-checked
    private func buildAttestedClient(clientId: String, jwtCompact: Option<String>): Client {
        let jwt = match (jwtCompact) {
            case Some(j) => j
            case None =>
                throw VpValidationError.ValidationError(
                    "verifier_attestation: a signed request object is required")
        }
        let typ = extractStringFromJwtHeader(jwt, "typ")
        match (typ) {
            case Some(t) =>
                if (t != "verifier-attestation+jwt") {
                    throw VpValidationError.ValidationError(
                        "verifier_attestation: unexpected typ header '${t}'")
                }
            case None =>
                throw VpValidationError.ValidationError(
                    "verifier_attestation: missing 'typ' header (expected verifier-attestation+jwt)")
        }
        // Verify the attestation JWS signature against its own x5c leaf.
        let x5cOpt = extractX5cFromJwtHeader(jwt)
        match (x5cOpt) {
            case Some(entries) =>
                let certs = parseCertsFromX5c(entries)
                if (certs.size < 1) {
                    throw VpValidationError.ValidationError(
                        "verifier_attestation: x5c contains no valid certificates")
                }
                if (!verifyJwsWithCert(jwt, certs[0])) {
                    throw VpValidationError.ValidationError(
                        "verifier_attestation: attestation JWS signature verification failed")
                }
            case None =>
                throw VpValidationError.ValidationError(
                    "verifier_attestation: attestation JWT header missing x5c (cannot verify signature)")
        }
        // Validate iss / sub / exp / iat claims of the attestation payload.
        validateAttestationClaims(jwt)
        AttestedClient(clientId: clientId)
    }

    // Verify a compact ES256 JWS against a DID-resolved EC public key, supplied
    // as a 65-byte uncompressed P-256 point (0x04||X||Y).
    private func verifyJwsWithDidKey(jwt: String, keyPoint: Array<UInt8>): Bool {
        if (keyPoint.size != 65 || keyPoint[0] != 0x04u8) {
            return false
        }
        // Wrap the raw EC point into a SubjectPublicKeyInfo DER so we can reuse
        // ECDSAPublicKey.decodeDer via the shared verifier.
        let spki = buildP256Spki(keyPoint)
        return verifyJwsWithSpki(jwt, spki)
    }

    // Validate verifier-attestation payload claims: iss + sub present;
    // exp not in the past, iat not in the future (with a small clock skew).
    private func validateAttestationClaims(jwt: String): Unit {
        let parts = jwt.split(".")
        if (parts.size < 2) {
            throw VpValidationError.ValidationError("verifier_attestation: malformed JWT")
        }
        let payloadBytes = base64UrlDecode(parts[1])
        let payloadStr = String.fromUtf8(payloadBytes)
        let parsed = try {
            JsonValue.fromStr(payloadStr)
        } catch (_: Exception) {
            throw VpValidationError.ValidationError("verifier_attestation: unparseable payload")
        }
        let obj = match (parsed) {
            case o: JsonObject => o
            case _ => throw VpValidationError.ValidationError("verifier_attestation: payload not an object")
        }
        // iss + sub required.
        match (obj.get("iss")) {
            case Some(_: JsonString) => ()
            case _ => throw VpValidationError.ValidationError("verifier_attestation: missing 'iss' claim")
        }
        match (obj.get("sub")) {
            case Some(_: JsonString) => ()
            case _ => throw VpValidationError.ValidationError("verifier_attestation: missing 'sub' claim")
        }
        let nowSecs = DateTime.nowUTC().toUnixTimeStamp().toSeconds()
        let skew: Int64 = 300
        // exp must not be in the past beyond skew.
        match (obj.get("exp")) {
            case Some(ji: JsonInt) =>
                if (ji.getValue() + skew < nowSecs) {
                    throw VpValidationError.ValidationError("verifier_attestation: attestation expired")
                }
            case _ => ()
        }
        // iat must not be in the future beyond skew.
        match (obj.get("iat")) {
            case Some(ji: JsonInt) =>
                if (ji.getValue() - skew > nowSecs) {
                    throw VpValidationError.ValidationError("verifier_attestation: 'iat' in the future")
                }
            case _ => ()
        }
    }

    // Extract a string header value (e.g. "kid", "typ") from the JWS header.
    private func extractStringFromJwtHeader(jwt: String, key: String): Option<String> {
        let parts = jwt.split(".")
        if (parts.size < 1) { return None }
        let headerBytes = base64UrlDecode(parts[0])
        let headerStr = String.fromUtf8(headerBytes)
        let parsed = try {
            JsonValue.fromStr(headerStr)
        } catch (_: Exception) {
            return None
        }
        match (parsed) {
            case obj: JsonObject =>
                match (obj.get(key)) {
                    case Some(s: JsonString) => Some(s.getValue())
                    case _ => None
                }
            case _ => None
        }
    }

    // Extract the x5c array from the JWT header (parts[0] base64url-decoded JSON).
    // Returns None if no x5c field; returns Some([]) if x5c is present but empty.
    private func extractX5cFromJwtHeader(jwt: String): Option<Array<String>> {
        let parts = jwt.split(".")
        if (parts.size < 1) { return None }
        let headerBytes = base64UrlDecode(parts[0])
        let headerStr = String.fromUtf8(headerBytes)
        var parsedOpt: Option<JsonValue> = None
        try {
            parsedOpt = Some(JsonValue.fromStr(headerStr))
        } catch (_: Exception) {
            return None
        }
        let parsed = match (parsedOpt) {
            case Some(p) => p
            case None => return None
        }
        match (parsed) {
            case obj: JsonObject =>
                match (obj.get("x5c")) {
                    case Some(arr: JsonArray) =>
                        let items = arr.getItems()
                        let result = ArrayList<String>()
                        for (item in items) {
                            match (item) {
                                case s: JsonString => result.add(s.getValue())
                                case _ => ()
                            }
                        }
                        Some(result.toArray())
                    case _ => None
                }
            case _ => None
        }
    }

    // -----------------------------------------------------------------------
    // Dispatch detail helpers
    // -----------------------------------------------------------------------

    private func makeDispatchDetails(
        requestObject: UnvalidatedRequestObject,
        client: Client
    ): ErrorDispatchDetails {
        let responseMode = requestObject.validatedResponseMode()
        // Only non-JARM response modes can be dispatched
        let dispatchableMode: Option<ResponseMode> = match (responseMode) {
            case Some(dm: DirectPostJWT) => None  // JARM — skip
            case other => other
        }
        return ErrorDispatchDetails(
            responseMode: dispatchableMode,
            nonce: requestObject.nonce,
            state: requestObject.state,
            clientId: Some(client.id())
        )
    }

    private func makeDispatchDetailsFromFetched(fetchedRequest: FetchedRequest): Option<ErrorDispatchDetails> {
        match (fetchedRequest) {
            case r: PlainFetched =>
                let responseMode = r.requestObject.validatedResponseMode()
                let dispatchableMode: Option<ResponseMode> = match (responseMode) {
                    case Some(dm: DirectPostJWT) => None
                    case other => other
                }
                let clientId: Option<VerifierId> = match (r.requestObject.clientId) {
                    case Some(id) => Some(VerifierId.parse(id))
                    case None => None
                }
                Some(ErrorDispatchDetails(
                    responseMode: dispatchableMode,
                    nonce: r.requestObject.nonce,
                    state: r.requestObject.state,
                    clientId: clientId
                ))
            case _: JwtSecuredFetched =>
                // For JWT-secured: try to parse response_mode from payload
                // If parsing fails, return None (mirrors iOS behavior)
                None
            case _ =>
                None
        }
    }
}

func certsToDerU8(certs: Array<Cert>): Array<Array<UInt8>> {
    let out = Array<Array<UInt8>>(certs.size, repeat: Array<UInt8>())
    var i: Int64 = 0
    while (i < certs.size) {
        let der = certs[i].toDer()
        let u8 = Array<UInt8>(der.size, repeat: 0u8)
        var j: Int64 = 0
        while (j < der.size) {
            u8[j] = UInt8(der[j])
            j = j + 1
        }
        out[i] = u8
        i = i + 1
    }
    out
}
