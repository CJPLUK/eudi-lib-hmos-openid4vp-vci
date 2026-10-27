/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * vp_types.cj — VP basic type aliases and enums.
 * Ported from iOS: Types.swift, VPAliases.swift, ResponseMode.swift,
 * ResponseType.swift, NonceOption.swift, ErrorDispatchPolicy.swift,
 * HashAlgorithm.swift, TransactionDataType.swift.
 *
 * iOS async/actor → Cangjie sync/class.
 * Swift enum with associated values → Cangjie sealed class hierarchy.
 */
package ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.entity.types

import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.error.*
import std.collection.*
import stdx.encoding.json.*

// ---------------------------------------------------------------------------
// Type aliases — mirrors iOS VPAliases.swift
// ---------------------------------------------------------------------------

// JWTString = String (JWT compact serialization)
// JWTUri = String
// Nonce = String
// Scope = String

public func scopeItems(scope: String): Array<String> {
    if (scope.isEmpty()) {
        return Array<String>()
    }
    let parts = scope.split(VPConstants.SCOPE_SEPARATOR)
    var result = ArrayList<String>()
    for (p in parts) {
        let trimmed = p.trimAscii()
        if (!trimmed.isEmpty()) {
            result.add(trimmed)
        }
    }
    return result.toArray()
}

// ---------------------------------------------------------------------------
// RequestUriMethod — mirrors iOS RequestUriMethod
// ---------------------------------------------------------------------------

public enum RequestUriMethod <: ToString {
    | GET
    | POST

    public func toString(): String {
        match (this) {
            case GET => "GET"
            case POST => "POST"
        }
    }

    public static func fromString(method: Option<String>): RequestUriMethod {
        match (method) {
            case None => GET
            case Some(m) =>
                match (m.toAsciiUpper()) {
                    case "GET" => GET
                    case "POST" => POST
                    case _ => GET
                }
        }
    }
}

// ---------------------------------------------------------------------------
// ResponseMode — mirrors iOS ResponseMode (enum with URL payload)
// Cangjie sealed class hierarchy (enum with data → sealed class).
// ---------------------------------------------------------------------------

public abstract sealed class ResponseMode {
    // directPost(responseURI: URL)
    public static func directPost(responseUri: String): DirectPost {
        DirectPost(responseUri)
    }
    // directPostJWT(responseURI: URL)
    public static func directPostJwt(responseUri: String): DirectPostJWT {
        DirectPostJWT(responseUri)
    }
    // query(responseURI: URL) — redirect_uri based
    public static func query(responseUri: String): QueryMode {
        QueryMode(responseUri)
    }
    // fragment(responseURI: URL) — redirect_uri based
    public static func fragment(responseUri: String): FragmentMode {
        FragmentMode(responseUri)
    }
    // none
    public static func none(): NoneMode {
        NoneMode()
    }
}

public class DirectPost <: ResponseMode {
    public let responseUri: String
    public init(uri: String) {
        this.responseUri = uri
    }
    public func requiresEncryption(): Bool { false }
    public func isJarm(): Bool { false }
}

public class DirectPostJWT <: ResponseMode {
    public let responseUri: String
    public init(uri: String) {
        this.responseUri = uri
    }
    public func requiresEncryption(): Bool { true }
    public func isJarm(): Bool { true }
}

public class QueryMode <: ResponseMode {
    public let responseUri: String
    public init(uri: String) {
        this.responseUri = uri
    }
    public func requiresEncryption(): Bool { false }
    public func isJarm(): Bool { false }
}

public class FragmentMode <: ResponseMode {
    public let responseUri: String
    public init(uri: String) {
        this.responseUri = uri
    }
    public func requiresEncryption(): Bool { false }
    public func isJarm(): Bool { false }
}

public class NoneMode <: ResponseMode {
    public init() {}
    public func requiresEncryption(): Bool { false }
    public func isJarm(): Bool { false }
}

// Parse ResponseMode from raw string fields
// Returns None if parsing fails (mirrors Swift's optional try?)
public func parseResponseMode(
    responseMode: Option<String>,
    responseUri: Option<String>,
    redirectUri: Option<String>
): Option<ResponseMode> {
    match (responseMode) {
        case None => None
        case Some(rm) =>
            match (rm) {
                case "direct_post" =>
                    match (responseUri) {
                        case Some(uri) => Some(DirectPost(uri))
                        case None => None
                    }
                case "direct_post.jwt" =>
                    match (responseUri) {
                        case Some(uri) => Some(DirectPostJWT(uri))
                        case None => None
                    }
                case "query" =>
                    match (redirectUri) {
                        case Some(uri) => Some(QueryMode(uri))
                        case None => None
                    }
                case "fragment" =>
                    match (redirectUri) {
                        case Some(uri) => Some(FragmentMode(uri))
                        case None => None
                    }
                case _ => None
            }
    }
}

// Throwing version for validated parsing
public func parseResponseModeOrThrow(
    responseMode: Option<String>,
    responseUri: Option<String>,
    redirectUri: Option<String>
): ResponseMode {
    match (responseMode) {
        case None => throw VpValidationError.MissingRequiredField(".responseMode")
        case Some(rm) =>
            match (rm) {
                case "direct_post" =>
                    match (responseUri) {
                        case Some(uri) => DirectPost(uri)
                        case None => throw VpValidationError.MissingRequiredField(".responseUri")
                    }
                case "direct_post.jwt" =>
                    match (responseUri) {
                        case Some(uri) => DirectPostJWT(uri)
                        case None => throw VpValidationError.MissingRequiredField(".responseUri")
                    }
                case "query" =>
                    match (redirectUri) {
                        case Some(uri) => QueryMode(uri)
                        case None => throw VpValidationError.MissingRequiredField(".redirectUri")
                    }
                case "fragment" =>
                    match (redirectUri) {
                        case Some(uri) => FragmentMode(uri)
                        case None => throw VpValidationError.MissingRequiredField(".redirectUri")
                    }
                case other => throw VpValidationError.UnsupportedResponseMode(other)
            }
    }
}

// ---------------------------------------------------------------------------
// ResponseType — mirrors iOS ResponseType
// ---------------------------------------------------------------------------

public enum ResponseType <: ToString {
    | VpToken
    | Code

    public func toString(): String {
        match (this) {
            case VpToken => "vp_token"
            case Code => "code"
        }
    }

    public static func fromRawValue(raw: String): Option<ResponseType> {
        match (raw) {
            case "vp_token" => Some(VpToken)
            case "code" => Some(Code)
            case _ => None
        }
    }
}

// ---------------------------------------------------------------------------
// ErrorDispatchPolicy — mirrors iOS ErrorDispatchPolicy
// ---------------------------------------------------------------------------

public enum ErrorDispatchPolicy {
    | AllClients
    | OnlyAuthenticatedClients
}

// ---------------------------------------------------------------------------
// HashAlgorithm — mirrors iOS HashAlgorithm
// ---------------------------------------------------------------------------

public class HashAlgorithm <: Equatable<HashAlgorithm> & Hashable {
    public let name: String

    public init(name: String) {
        this.name = name
    }

    public static let sha256: HashAlgorithm = HashAlgorithm("sha-256")

    public operator func ==(other: HashAlgorithm): Bool {
        this.name == other.name
    }

    public func hashCode(): Int64 {
        this.name.hashCode()
    }
}

// ---------------------------------------------------------------------------
// TransactionDataType — mirrors iOS TransactionDataType
// ---------------------------------------------------------------------------

public class TransactionDataType <: Equatable<TransactionDataType> & ToString {
    public let value: String

    public init(value: String) {
        if (value.isEmpty()) {
            throw VpValidationError.ValidationError("TransactionDataType value cannot be empty")
        }
        this.value = value
    }

    public func toString(): String { value }

    public operator func ==(other: TransactionDataType): Bool {
        this.value == other.value
    }
}

// ---------------------------------------------------------------------------
// SupportedTransactionDataType — mirrors iOS SupportedTransactionDataType
// ---------------------------------------------------------------------------

public class SupportedTransactionDataType {
    public let dataType: TransactionDataType
    public let hashAlgorithms: Array<HashAlgorithm>

    public init(dataType: TransactionDataType, hashAlgorithms!: Array<HashAlgorithm> = [HashAlgorithm.sha256]) {
        if (hashAlgorithms.isEmpty()) {
            throw VpValidationError.ValidationError("SupportedTransactionDataType hashAlgorithms cannot be empty")
        }
        var hasSha256 = false
        for (alg in hashAlgorithms) {
            if (alg == HashAlgorithm.sha256) {
                hasSha256 = true
                break
            }
        }
        if (!hasSha256) {
            throw VpValidationError.ValidationError("sha-256 must be a supported hash algorithm")
        }
        this.dataType = dataType
        this.hashAlgorithms = hashAlgorithms
    }

    public static func makeDefault(): SupportedTransactionDataType {
        SupportedTransactionDataType(TransactionDataType("authorization"))
    }
}
