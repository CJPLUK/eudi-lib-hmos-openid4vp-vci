/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * http_client.cj — HTTP Fetcher and Poster.
 * Ported from iOS:
 *   - Sources/Utilities/RemoteDataAccess/Fetcher.swift
 *   - Sources/Utilities/RemoteDataAccess/Poster.swift
 *   - Sources/Utilities/RemoteDataAccess/RawDataFetcher.swift
 *
 * iOS URLSession async → stdx.net.http Client (synchronous).
 * Degradation: iOS throws typed errors (FetchError, PostError enums).
 *   Cangjie does not have Result<T, E>; throwing is done via FetchError/PostError
 *   subclassing Exception. Callers catch specific error types.
 * Headers: HttpHeaders.iterator() yields (String, Collection<String>).
 */
package ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.network

import std.collection.*
import std.io.InputStream
import std.time.*
import stdx.net.http.*
import stdx.net.tls.TlsClientConfig
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.util.Constants

// ---------------------------------------------------------------------------
// Internal helper: read all bytes from an InputStream
// Mirrors statium/network/networking_service.cj pattern.
// ---------------------------------------------------------------------------

func readAllBytes(stream: InputStream): Array<UInt8> {
    let buf = Array<UInt8>(4096, repeat: 0u8)
    var result = Array<UInt8>(0, repeat: 0u8)
    var n = stream.read(buf)
    while (n > 0) {
        let newResult = Array<UInt8>(result.size + n, repeat: 0u8)
        result.copyTo(newResult, 0, 0, result.size)
        buf.copyTo(newResult, 0, result.size, n)
        result = newResult
        n = stream.read(buf)
    }
    return result
}

// ---------------------------------------------------------------------------
// HttpFetcher — GET requests, returns raw bytes + headers
// Throws FetchError on any failure.
// ---------------------------------------------------------------------------

public class HttpFetcher {
    private let _client: Client

    public init() {
        // HTTPS requires an explicit TLS config (stdx throws "TLS must be
        // configured" otherwise). TlsClientConfig() defaults to verifying the
        // system certificate store.
        // Bounded timeouts, same rationale as HttpPoster: an emulator-network
        // black hole on one GET (metadata / offer re-resolve) must fail fast so
        // the transport-retry loop below re-sends instead of hanging forever.
        _client = ClientBuilder()
            .tlsConfig(TlsClientConfig())
            .readTimeout(Duration.second * 45)
            .writeTimeout(Duration.second * 30)
            .build()
    }

    /*
     * Fetch raw bytes from url with optional additional headers.
     * Throws FetchError on failure.
     */
    public func fetchRawWithHeaders(
        url: String,
        additionalHeaders: HashMap<String, String>
    ): RawFetchResponse {
        // Retry transient transport failures (e.g. the emulator's intermittent
        // libc DNS "Failed to resolve address"). HTTP status errors are NOT
        // transient and are rethrown immediately without retry.
        var attempt = 0
        while (true) {
            try {
                var builder = HttpRequestBuilder()
                    .url(url)
                    .method("GET")
                for ((k, v) in additionalHeaders) {
                    builder = builder.header(k, v)
                }
                let req = builder.build()
                let resp = _client.send(req)
                let statusCode = Int64(resp.status)
                if (!HTTPStatusCode.isSuccess(statusCode)) {
                    throw FetchError.InvalidStatusCode(url, statusCode)
                }
                let data = readAllBytes(resp.body)
                let headers = extractHeaders(resp)
                return RawFetchResponse(data, headers)
            } catch (e: FetchError) {
                throw e
            } catch (e: Exception) {
                attempt++
                if (attempt >= 5) {
                    throw e
                }
                sleep(Duration.millisecond * 500)
            }
        }
        throw FetchError.InvalidStatusCode(url, 0)
    }

    /*
     * Fetch raw bytes from url (no additional headers).
     * Throws FetchError on failure.
     */
    public func fetch(url: String): Array<UInt8> {
        let empty = HashMap<String, String>()
        let r = fetchRawWithHeaders(url, empty)
        return r.data
    }
}

// ---------------------------------------------------------------------------
// HttpPoster — POST requests
// ---------------------------------------------------------------------------

/*
 * ResponseWithHeaders: carries decoded body string + response headers.
 */
public class ResponseWithHeaders {
    public let headers: HashMap<String, String>
    public let body: String

    public init(headers: HashMap<String, String>, body: String) {
        this.headers = headers
        this.body = body
    }

    public func headerValue(forKey: String): Option<String> {
        return headers.get(forKey)
    }

    // Case-insensitive header lookup
    public func headerValueCaseInsensitive(forKey: String): Option<String> {
        let lowerKey = forKey.toAsciiLower()
        for ((k, v) in headers) {
            if (k.toAsciiLower() == lowerKey) {
                return Option<String>.Some(v)
            }
        }
        return Option<String>.None
    }
}

public class HttpPoster {
    private let _client: Client

    public init() {
        // Bounded timeouts: the emulator's slirp network intermittently
        // black-holes a single connection (response never arrives). Without a
        // timeout the issuance flow spins forever on one dead request; with a
        // bound it fails fast and the transport-retry loop in post() re-sends.
        _client = ClientBuilder()
            .tlsConfig(TlsClientConfig())
            .readTimeout(Duration.second * 45)
            .writeTimeout(Duration.second * 30)
            .build()
    }

    /*
     * POST with a pre-built body string and content-type.
     * Returns ResponseWithHeaders on success, throws PostError on failure.
     */
    public func post(
        url: String,
        body: String,
        contentType: String,
        additionalHeaders: HashMap<String, String>
    ): ResponseWithHeaders {
        // Retry transient transport failures (intermittent emulator DNS). HTTP
        // status outcomes (PostError: ServerError / RequestError / UseDpopNonce /
        // UseAttestationNonce) are NOT transport failures and are rethrown
        // immediately without retry so the caller's flow (DPoP nonce, etc.) is
        // preserved.
        var attempt = 0
        while (true) {
            try {
                var builder = HttpRequestBuilder()
                    .url(url)
                    .method("POST")
                    .header(ContentTypeHeader.key, contentType)
                builder = builder.body(body.toArray())
                for ((k, v) in additionalHeaders) {
                    builder = builder.header(k, v)
                }
                let req = builder.build()
                let resp = _client.send(req)
                let statusCode = Int64(resp.status)
                let headers = extractHeaders(resp)
                let data = readAllBytes(resp.body)
                let bodyStr = String.fromUtf8(data)
                if (HTTPStatusCode.isServerError(statusCode)) {
                    throw PostError.ServerError
                }

                if (HTTPStatusCode.isClientError(statusCode)) {
                    let dpopNonce = headerValueCaseInsensitive(headers, Constants.DPOP_NONCE_HEADER)
                    // RFC 9449: only retry with a fresh DPoP nonce when the server
                    // actually signals `use_dpop_nonce`. The issuer rotates the
                    // DPoP-Nonce header on EVERY response (incl. genuine 400s like
                    // invalid_proof), so retrying on any 4xx-with-nonce loops until
                    // exhaustion and masks the real error as retryFailedAfterDpopNonce.
                    let wwwAuth = match (headerValueCaseInsensitive(headers, "www-authenticate")) {
                        case Some(w) => w
                        case None => ""
                    }
                    let signalsUseNonce = bodyStr.contains(Constants.USE_DPOP_NONCE) ||
                        wwwAuth.contains(Constants.USE_DPOP_NONCE) ||
                        (statusCode == 401 && bodyStr.isEmpty())
                    if (!dpopNonce.isNone() && signalsUseNonce) {
                        throw PostError.UseDpopNonce(dpopNonce.getOrThrow())
                    }
                    let attestChallenge = headerValueCaseInsensitive(headers, Constants.OAUTH_CLIENT_ATTESTATION_CHALLENGE)
                    if (!attestChallenge.isNone()) {
                        throw PostError.UseAttestationNonce(attestChallenge.getOrThrow())
                    }
                    throw PostError.RequestError(statusCode, bodyStr)
                }

                return ResponseWithHeaders(headers, bodyStr)
            } catch (e: PostError) {
                throw e
            } catch (e: Exception) {
                attempt++
                if (attempt >= 5) {
                    throw e
                }
                sleep(Duration.millisecond * 500)
            }
        }
        throw PostError.ServerError
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/*
 * Extract response headers into a HashMap.
 * HttpHeaders.iterator() yields (name: String, values: Collection<String>).
 * We take the first value of each header.
 */
func extractHeaders(resp: HttpResponse): HashMap<String, String> {
    let result = HashMap<String, String>()
    for ((name, values) in resp.headers) {
        let vIter = values.iterator()
        let first = vIter.next()
        if (!first.isNone()) {
            result.add(name, first.getOrThrow())
        }
    }
    return result
}

func headerValueCaseInsensitive(headers: HashMap<String, String>, key: String): Option<String> {
    let lowerKey = key.toAsciiLower()
    for ((k, v) in headers) {
        if (k.toAsciiLower() == lowerKey) {
            return Option<String>.Some(v)
        }
    }
    return Option<String>.None
}
