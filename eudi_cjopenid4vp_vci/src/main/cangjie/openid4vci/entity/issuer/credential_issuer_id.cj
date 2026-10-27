/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * credential_issuer_id.cj — Credential issuer identifier and endpoint wrappers.
 * Ported from iOS:
 *   - Sources/Entities/CredentialIssuer/CredentialIssuerId.swift
 *   - Sources/Entities/CredentialIssuer/CredentialIssuerEndpoint.swift
 *
 * iOS URLComponents → manual string parsing; iOS URL struct → String.
 * Validation: must be https, no fragment, no query components.
 */
package ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.issuer

import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.util.Constants
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.error.{CredentialError, ValidationError}

// ---------------------------------------------------------------------------
// CredentialIssuerId
// ---------------------------------------------------------------------------

public class CredentialIssuerId {
    public let url: String

    public init(string: String) {
        // Must have no query components
        if (string.contains("?")) {
            throw CredentialError.ExtraneousQueryComponents()
        }
        // Must have no fragment
        if (string.contains("#")) {
            throw CredentialError.InvalidScheme()
        }
        // Must be https
        if (!string.startsWith(Constants.HTTPS + "://")) {
            throw CredentialError.InvalidScheme()
        }
        this.url = string
    }

    public func absoluteString(): String {
        return url
    }
}

// ---------------------------------------------------------------------------
// CredentialIssuerEndpoint
// ---------------------------------------------------------------------------

public class CredentialIssuerEndpoint {
    public let url: String

    public init(string: String) {
        // Must have no query components
        if (string.contains("?")) {
            throw CredentialError.GenericError()
        }
        // Must have no fragment
        if (string.contains("#")) {
            throw CredentialError.GenericError()
        }
        if (string.isEmpty()) {
            throw CredentialError.GenericError()
        }
        this.url = string
    }

    public func absoluteString(): String {
        return url
    }
}
