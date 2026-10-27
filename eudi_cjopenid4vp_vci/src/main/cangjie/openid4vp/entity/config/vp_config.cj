/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * vp_config.cj — VP wallet and VP configuration.
 * Ported from iOS: VPConfiguration.swift, OpenId4VPConfiguration.swift (VP-relevant parts),
 * JARConfiguration.swift, SupportedRequestUriMethod.swift (partial port).
 *
 * iOS SecKey, URLSession → not applicable; omitted (platform APIs).
 * iOS async → sync.
 */
package ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.entity.config

import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.error.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.entity.types.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.entity.dcql.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.entity.metadata.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.entity.client.*
import std.collection.*

/**
 * iOS `CertificateTrust` used by `.x509SanDns` / `.x509Hash`.
 * `chainDer` is the request object's x5c (leaf first) as DER.
 */
public interface X509CertificateTrust {
    func isTrusted(chainDer: Array<Array<UInt8>>): Bool
}

// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// VPConfiguration — mirrors iOS VPConfiguration
// ---------------------------------------------------------------------------

public class VPConfiguration {
    // Known DCQL queries per scope key (simplified: scope string → DCQL JSON string)
    public let knownDcqlQueriesPerScope: HashMap<String, DCQL>
    public let vpFormatsSupported: VpFormatsSupported
    public let supportedTransactionDataTypes: Array<SupportedTransactionDataType>

    public init(
        knownDcqlQueriesPerScope!: HashMap<String, DCQL> = HashMap<String, DCQL>(),
        vpFormatsSupported!: VpFormatsSupported,
        supportedTransactionDataTypes!: Array<SupportedTransactionDataType>
    ) {
        this.knownDcqlQueriesPerScope = knownDcqlQueriesPerScope
        this.vpFormatsSupported = vpFormatsSupported
        this.supportedTransactionDataTypes = supportedTransactionDataTypes
    }

    public static func makeDefault(): VPConfiguration {
        VPConfiguration(
            vpFormatsSupported: VpFormatsSupported(values: [
                SdJwtVcFormat(sdJwtAlgorithms: ["ES256"], kbJwtAlgorithms: ["ES256"]),
                MsoMdocFormat(issuerAuthAlgorithms: Some([-7i64]), deviceAuthAlgorithms: Some([-7i64]))
            ]),
            supportedTransactionDataTypes: [
                SupportedTransactionDataType(TransactionDataType("authorization"))
            ]
        )
    }
}

// ---------------------------------------------------------------------------
// JARSigningAlgorithm — wraps algorithm name string
// ---------------------------------------------------------------------------

public class JARSigningAlgorithm {
    public let name: String
    public init(name!: String) { this.name = name }
    public static let ES256: JARSigningAlgorithm = JARSigningAlgorithm(name: "ES256")
    public static let RS256: JARSigningAlgorithm = JARSigningAlgorithm(name: "RS256")
}

// ---------------------------------------------------------------------------
// NonceOption — mirrors iOS NonceOption
// ---------------------------------------------------------------------------

public enum NonceOption {
    | DoNotUse
    | Use(Int64)   // byteLength

    public static func makeDefault(): NonceOption {
        Use(32i64)
    }
}

// ---------------------------------------------------------------------------
// SupportedRequestUriMethod — simplified mirrors iOS SupportedRequestUriMethod
// ---------------------------------------------------------------------------

public enum SupportedRequestUriMethod {
    | GetOnly
    | PostOnly
    | Both
}

// ---------------------------------------------------------------------------
// OpenId4VPWalletConfiguration — mirrors iOS OpenId4VPConfiguration (VP-relevant subset)
// iOS SecKey, URLSession, JARConfiguration details → omitted / simplified.
// The full configuration is used for validation of incoming requests.
// ---------------------------------------------------------------------------

public class OpenId4VPWalletConfiguration {
    // Supported client_id schemes (as ClientIdPrefix values)
    public let supportedClientIdSchemes: Array<ClientIdPrefix>
    // VP formats the wallet supports
    public let vpFormatsSupported: VpFormatsSupported
    // VP flow configuration
    public let vpConfiguration: VPConfiguration
    // Error dispatch policy
    public let errorDispatchPolicy: ErrorDispatchPolicy
    // JAR signing algorithms
    public let jarSigningAlgorithms: Array<JARSigningAlgorithm>
    // Issuer (self-issued)
    public let issuer: Option<String>
    // Public JWK set as raw JSON (wallet's own keys for response encryption)
    public let publicWebKeySetJson: Option<String>
    // Request URI method support
    public let supportedRequestUriMethod: SupportedRequestUriMethod
    // Nonce usage for request_uri POST
    public let nonceOption: NonceOption
    // X.509 trust anchors (PEM, one or more concatenated root CA certificates).
    // Used when `x509ChainTrust` is None. Fail-closed if both are absent.
    public let trustedRootCertsPem: Option<String>
    /**
     * iOS `CertificateTrust` / `chainVerifier`: live x5c chain check.
     * When set, x509_san_dns / x509_hash use this instead of PEM PKIX.
     */
    public let x509ChainTrust: ?X509CertificateTrust

    public static let SELF_ISSUED_V2: String = "https://self-issued.me/v2"

    public init(
        supportedClientIdSchemes!: Array<ClientIdPrefix>,
        vpFormatsSupported!: VpFormatsSupported = VpFormatsSupported.makeDefault(),
        vpConfiguration!: VPConfiguration = VPConfiguration.makeDefault(),
        errorDispatchPolicy!: ErrorDispatchPolicy = ErrorDispatchPolicy.OnlyAuthenticatedClients,
        jarSigningAlgorithms!: Array<JARSigningAlgorithm> = [JARSigningAlgorithm.ES256],
        issuer!: Option<String> = Some(OpenId4VPWalletConfiguration.SELF_ISSUED_V2),
        publicWebKeySetJson!: Option<String> = None,
        supportedRequestUriMethod!: SupportedRequestUriMethod = SupportedRequestUriMethod.GetOnly,
        nonceOption!: NonceOption = NonceOption.DoNotUse,
        trustedRootCertsPem!: Option<String> = None,
        x509ChainTrust!: ?X509CertificateTrust = None
    ) {
        this.supportedClientIdSchemes = supportedClientIdSchemes
        this.vpFormatsSupported = vpFormatsSupported
        this.vpConfiguration = vpConfiguration
        this.errorDispatchPolicy = errorDispatchPolicy
        this.jarSigningAlgorithms = jarSigningAlgorithms
        this.issuer = issuer
        this.publicWebKeySetJson = publicWebKeySetJson
        this.supportedRequestUriMethod = supportedRequestUriMethod
        this.nonceOption = nonceOption
        this.trustedRootCertsPem = trustedRootCertsPem
        this.x509ChainTrust = x509ChainTrust
    }

    public static func makeDefault(): OpenId4VPWalletConfiguration {
        OpenId4VPWalletConfiguration(
            supportedClientIdSchemes: [ClientIdPrefix.PreRegistered]
        )
    }
}
