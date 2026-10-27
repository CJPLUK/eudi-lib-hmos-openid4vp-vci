/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * http_types.cj — HTTP method enum, status codes, request protocol.
 * Ported from iOS:
 *   - Sources/Utilities/RemoteDataAccess/Request.swift (HTTPMethod, Request protocol)
 *   - Sources/Utilities/Networking/HTTPStatusCode.swift
 *
 * iOS URLSession → stdx.net.http (synchronous in this port).
 * Cangjie constraint: enum cannot extend class (only implement interface).
 *   FetchError and PostError are class <: Exception (not enum).
 */
package ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.network

import std.collection.*

// ---------------------------------------------------------------------------
// HTTPMethod
// ---------------------------------------------------------------------------

public enum HTTPMethod {
    | GET
    | POST
    | PUT
    | DELETE
    | PATCH

    public func rawValue(): String {
        match (this) {
            case GET => "GET"
            case POST => "POST"
            case PUT => "PUT"
            case DELETE => "DELETE"
            case PATCH => "PATCH"
        }
    }
}

// ---------------------------------------------------------------------------
// HTTPStatusCode
// ---------------------------------------------------------------------------

public class HTTPStatusCode {
    // Success (2xx)
    public static let ok = 200
    public static let created = 201
    public static let accepted = 202
    public static let noContent = 204

    // Client Error (4xx)
    public static let badRequest = 400
    public static let unauthorized = 401
    public static let forbidden = 403
    public static let notFound = 404
    public static let unprocessableEntity = 422
    public static let tooManyRequests = 429

    // Server Error (5xx)
    public static let internalServerError = 500
    public static let badGateway = 502
    public static let serviceUnavailable = 503
    public static let gatewayTimeout = 504

    public static func isSuccess(code: Int64): Bool {
        return code >= 200 && code <= 299
    }

    public static func isClientError(code: Int64): Bool {
        return code >= 400 && code < 500
    }

    public static func isServerError(code: Int64): Bool {
        return code >= 500
    }
}

// ---------------------------------------------------------------------------
// ContentType — MIME type values for HTTP headers
// Note: Cangjie enums cannot have static let fields.
//       ContentTypeHeader.key holds the "Content-Type" string.
// ---------------------------------------------------------------------------

public enum ContentType {
    | Form
    | Json
    | Jwt

    public func rawValue(): String {
        match (this) {
            case Form => "application/x-www-form-urlencoded"
            case Json => "application/json"
            case Jwt => "application/jwt"
        }
    }
}

// Content-Type header key constant (cannot be inside enum in Cangjie)
public class ContentTypeHeader {
    public static let key = "Content-Type"
}

// ---------------------------------------------------------------------------
// RawFetchResponse — carries body bytes + response headers
// ---------------------------------------------------------------------------

public class RawFetchResponse {
    public let data: Array<UInt8>
    public let headers: HashMap<String, String>

    public init(data: Array<UInt8>, headers: HashMap<String, String>) {
        this.data = data
        this.headers = headers
    }
}

// ---------------------------------------------------------------------------
// FetchError — thrown by HttpFetcher
// Cangjie: class <: Exception (enum cannot extend class)
// ---------------------------------------------------------------------------

public class FetchError <: Exception {
    public init(msg: String) {
        super(msg)
    }

    public static let InvalidUrl = FetchError(".invalidUrl")
    public static let InvalidResponse = FetchError(".invalidResponse")

    public static func NetworkError(error: String): FetchError {
        FetchError(".networkError " + error)
    }

    public static func DecodingError(error: String): FetchError {
        FetchError(".decodingError " + error)
    }

    public static func InvalidStatusCode(url: String, code: Int64): FetchError {
        FetchError(".invalidStatusCode " + code.toString() + " " + url)
    }
}

// ---------------------------------------------------------------------------
// PostError — thrown by HttpPoster
// Cangjie: class <: Exception (enum cannot extend class)
// ---------------------------------------------------------------------------

public class PostError <: Exception {
    public init(msg: String) {
        super(msg)
    }

    public static let InvalidUrl = PostError("Invalid URL")
    public static let ServerError = PostError("Server error")

    public static func NetworkError(error: String): PostError {
        PostError("Network Error: " + error)
    }

    public static func CannotParse(s: String): PostError {
        PostError("Could not parse: " + s)
    }

    public static func UseDpopNonce(nonce: String): PostError {
        PostError("Use dPop Nonce error: " + nonce)
    }

    public static func UseAttestationNonce(nonce: String): PostError {
        PostError("Use attestation Nonce error: " + nonce)
    }

    public static func RequestError(statusCode: Int64, error: String): PostError {
        PostError("Request error: " + statusCode.toString() + " " + error)
    }
}
