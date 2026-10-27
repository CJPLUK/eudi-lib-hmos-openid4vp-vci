/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * openid4vci_config.cj — Wallet configuration types.
 * Ported from iOS Sources/Entities/Wallet/Config.swift.
 *
 * iOS Client enum → Cangjie class Client with kind enum.
 * iOS ParUsage, AuthorizeIssuanceConfig, OpenId4VCIConfig → Cangjie classes/enums.
 * IssuerMetadataPolicy → simplified enum; CompressionAlgorithm not required in block 2.
 */
package ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.config

// ---------------------------------------------------------------------------
// AuthorizeIssuanceConfig
// ---------------------------------------------------------------------------

public enum AuthorizeIssuanceConfig {
    | FavorScopes
    | AuthorizationDetails
}

// ---------------------------------------------------------------------------
// ParUsage — Pushed Authorization Request usage policy
// ---------------------------------------------------------------------------

public enum ParUsage {
    | Never
    | Required(Bool)   // authorizationCodeDPoPBinding

    public func isRequired(): Bool {
        match (this) {
            case Never => false
            case Required(_) => true
        }
    }

    public func authorizationCodeDPoPBinding(): Bool {
        match (this) {
            case Never => false
            case Required(binding) => binding
        }
    }
}

// ---------------------------------------------------------------------------
// IssuerTrust — how the signed issuer metadata's signature is trusted.
// Ported from iOS IssuerTrust:
//   byPublicKey(jwk)          → trust a known EC public key directly (JWK JSON)
//   byCertificateChain(roots) → trust an x5c chain anchored at the given roots
// Fail-closed: byCertificateChain with no roots verifies nothing and rejects.
// ---------------------------------------------------------------------------

// Lazy certificate-chain trust evaluator. Mirrors iOS CertificateChainTrust:
// the verifier holds no eager anchors — anchors are resolved only when a chain
// is presented for validation, so configuration never touches the network.
// `chain` is the x5c array (each entry a standard base64-encoded DER cert;
// chain[0] = leaf, chain[1..] = intermediates).
public interface CertChainTrust {
    func isValid(chain: Array<String>): Bool
}

public enum IssuerTrust {
    // Trust the signature against this EC public key, supplied as a JWK JSON
    // string (must contain crv/x/y for P-256). Mirrors iOS .byPublicKey(jwk:).
    | ByPublicKey(String)
    // Trust the signature against the x5c leaf, provided the x5c chain verifies
    // against these trust anchors (PEM, one or more root CAs). Mirrors iOS
    // .byCertificateChain(certificateChainTrust:).
    | ByCertificateChain(String)
    // Trust the signature provided the x5c chain passes this lazy validator.
    // Mirrors iOS .byCertificateChain(certificateChainTrust:) where the trust is
    // an injected evaluator rather than an eager roots blob — anchors resolved
    // lazily at validation time, never at config/startup.
    | ByValidator(CertChainTrust)
}

// ---------------------------------------------------------------------------
// IssuerMetadataPolicy
// Ported from iOS IssuerMetadataPolicy. RequireSigned/PreferSigned now carry an
// IssuerTrust (as iOS does) so signed metadata can be cryptographically
// verified rather than structurally trusted.
// ---------------------------------------------------------------------------

public enum IssuerMetadataPolicy {
    | IgnoreSigned
    | PreferSigned(IssuerTrust)
    | RequireSigned(IssuerTrust)
}

// ---------------------------------------------------------------------------
// Client — the wallet's OAuth2 client configuration
// Ported from iOS Client enum (only public/attested variants used in block 2).
// ---------------------------------------------------------------------------

public enum ClientKind {
    | Public(String)             // clientId only
    | Attested(String, String)   // (clientId, clientSecret) — simplified from iOS attestation
}

public class Client {
    public let kind: ClientKind

    public init(kind: ClientKind) {
        this.kind = kind
    }

    public static func public_(clientId: String): Client {
        return Client(ClientKind.Public(clientId))
    }

    public static func attested(clientId: String, secret: String): Client {
        return Client(ClientKind.Attested(clientId, secret))
    }

    public func id(): String {
        match (kind) {
            case ClientKind.Public(id) => id
            case ClientKind.Attested(id, _) => id
        }
    }

    public func isAttested(): Bool {
        match (kind) {
            case ClientKind.Attested(_, _) => true
            case _ => false
        }
    }
}

// ---------------------------------------------------------------------------
// OpenId4VCIConfig
// Ported from iOS struct OpenId4VCIConfig.
// ---------------------------------------------------------------------------

public class OpenId4VCIConfig {
    public let client: Client
    public let authFlowRedirectionURI: String    // iOS URL → String
    public let authorizeIssuanceConfig: AuthorizeIssuanceConfig
    public let requirePAR: ParUsage
    public let issuerMetadataPolicy: IssuerMetadataPolicy
    public let requireDpop: Bool

    public init(
        client: Client,
        authFlowRedirectionURI: String,
        authorizeIssuanceConfig: AuthorizeIssuanceConfig,
        requirePAR: ParUsage,
        issuerMetadataPolicy: IssuerMetadataPolicy,
        requireDpop: Bool
    ) {
        this.client = client
        this.authFlowRedirectionURI = authFlowRedirectionURI
        this.authorizeIssuanceConfig = authorizeIssuanceConfig
        this.requirePAR = requirePAR
        this.issuerMetadataPolicy = issuerMetadataPolicy
        this.requireDpop = requireDpop
    }

    // Convenience init with defaults (mirrors iOS defaults)
    public static func withDefaults(
        client: Client,
        authFlowRedirectionURI: String
    ): OpenId4VCIConfig {
        return OpenId4VCIConfig(
            client,
            authFlowRedirectionURI,
            AuthorizeIssuanceConfig.FavorScopes,
            ParUsage.Required(true),
            IssuerMetadataPolicy.IgnoreSigned,
            true
        )
    }
}
