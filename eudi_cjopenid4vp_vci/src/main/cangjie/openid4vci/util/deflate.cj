/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * deflate.cj — DEFLATE decompression for credential response / request payloads.
 * Ported from iOS:
 *   Sources/Utilities/Compression/DeflateDecompressor.swift
 *   Sources/Entities/Types/CompressionAlgorithm.swift
 *
 * iOS zlib.inflate (raw DEFLATE + auto-detect) →
 *   stdx.compress.zlib.DecompressInputStream(wrap: DeflateFormat).
 * Verified pattern from statium/util/decompress.cj (same SDK version).
 *
 * GAP-02: This replaces the ResponseCompressionMethodNotSupportedByIssuer /
 * RequestCompressionMethodNotSupportedByIssuer stub error paths for the "DEF"
 * (DEFLATE, RFC 1951) compression algorithm.
 *
 * Only DEF (raw DEFLATE) is implemented. Other algorithms remain unsupported.
 */
package ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.util

import stdx.compress.zlib.*
import std.io.ByteBuffer
import std.collection.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.error.CredentialIssuanceError

// ---------------------------------------------------------------------------
// CompressionAlgorithm — mirrors iOS CompressionAlgorithm struct
// ---------------------------------------------------------------------------

public class CompressionAlgorithm {
    public let rawValue: String

    public init(name: String) {
        if (name.isEmpty()) {
            throw Exception("Compression algorithm name must not be empty")
        }
        this.rawValue = name
    }

    // Standard DEFLATE per RFC 7516 ("zip":"DEF")
    public static let def: CompressionAlgorithm = CompressionAlgorithm("DEF")

    public func isDef(): Bool {
        return rawValue == "DEF"
    }
}

// ---------------------------------------------------------------------------
// DeflateDecompressor — mirrors iOS DeflateDecompressor actor
// Implements DEFLATE ("DEF") decompression via stdx.compress.zlib.
// ---------------------------------------------------------------------------

public class DeflateDecompressor {
    public init() {}

    /*
     * Decompress raw DEFLATE-compressed bytes.
     * Throws CredentialIssuanceError.ResponseUnparsable on failure.
     * Mirrors iOS DataDecompressing.decompress(_ data: Data) throws -> Data.
     */
    public func decompress(data: Array<UInt8>): Array<UInt8> {
        if (data.size == 0) {
            throw CredentialIssuanceError.ResponseUnparsable("DEFLATE: empty input")
        }
        try {
            return decompressImpl(data)
        } catch (e: CredentialIssuanceError) {
            throw e
        } catch (e: Exception) {
            throw CredentialIssuanceError.ResponseUnparsable("DEFLATE decompress failed: " + e.message)
        }
    }

    /*
     * Decompress a base64-encoded DEFLATE-compressed string, returning UTF-8 string.
     * Mirrors iOS DataDecompressing.decompress(_ string: String) throws -> String.
     */
    public func decompressBase64(base64Str: String): String {
        let decoded = base64StdDecode(base64Str)
        if (decoded.isNone()) {
            throw CredentialIssuanceError.ResponseUnparsable("DEFLATE: base64 decode failed")
        }
        let decompressed = decompress(decoded.getOrThrow())
        try {
            return String.fromUtf8(decompressed)
        } catch (e: Exception) {
            throw CredentialIssuanceError.ResponseUnparsable("DEFLATE: UTF-8 decode failed: " + e.message)
        }
    }
}

// ---------------------------------------------------------------------------
// decompressDeflate — module-level function for callers without a class
// ---------------------------------------------------------------------------

/*
 * Decompress DEFLATE bytes, throws CredentialIssuanceError on failure.
 * Used by the credential response decryption path when the issuer negotiated
 * CompressionAlgorithm "DEF".
 */
public func decompressDeflate(data: Array<UInt8>): Array<UInt8> {
    return DeflateDecompressor().decompress(data)
}

/*
 * Apply decompression to a credential response body if zip==DEF was negotiated.
 * If zipAlgorithm is None or not "DEF", returns the data unchanged.
 * Throws CredentialIssuanceError if DEF decompression fails, or if an
 * unsupported zip algorithm is encountered.
 */
public func applyCompressionIfNeeded(
    data: Array<UInt8>,
    zipAlgorithm: Option<String>
): Array<UInt8> {
    if (zipAlgorithm.isNone()) {
        return data
    }
    let alg = zipAlgorithm.getOrThrow()
    if (alg == "DEF") {
        return decompressDeflate(data)
    }
    throw CredentialIssuanceError.ResponseUnparsable(
        "Unsupported zip compression algorithm: " + alg + " (only DEF is supported)"
    )
}

// ---------------------------------------------------------------------------
// Private implementation
// ---------------------------------------------------------------------------

func decompressImpl(compressed: Array<UInt8>): Array<UInt8> {
    let buf = ByteBuffer(compressed)
    let stream = DecompressInputStream(buf, wrap: DeflateFormat, bufLen: 4096)
    let chunkSize: Int64 = 4096
    let chunk = Array<UInt8>(chunkSize, repeat: 0u8)
    var result = Array<UInt8>(0, repeat: 0u8)
    var n = stream.read(chunk)
    while (n > 0) {
        let newResult = Array<UInt8>(result.size + n, repeat: 0u8)
        result.copyTo(newResult, 0, 0, result.size)
        chunk.copyTo(newResult, 0, result.size, n)
        result = newResult
        n = stream.read(chunk)
    }
    stream.close()
    return result
}

// ---------------------------------------------------------------------------
// base64StdDecode — standard base64 decoder (with padding)
// ---------------------------------------------------------------------------

func base64StdDecode(s: String): Option<Array<UInt8>> {
    let table: Array<Int64> = [
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1
    ]
    // Add padding if necessary
    var input = s
    let rem = input.size % 4
    if (rem == 2) {
        input = input + "=="
    } else if (rem == 3) {
        input = input + "="
    }
    let bytes = input.toArray()
    let resultList = ArrayList<UInt8>()
    var i = 0
    while (i + 3 < bytes.size) {
        let b0 = Int64(bytes[i])
        let b1 = Int64(bytes[i + 1])
        let b2 = Int64(bytes[i + 2])
        let b3 = Int64(bytes[i + 3])
        if (b0 >= 128 || b1 >= 128 || b2 >= 128 || b3 >= 128) {
            return Option<Array<UInt8>>.None
        }
        let v0 = table[b0]
        let v1 = table[b1]
        let v2 = table[b2]
        let v3 = table[b3]
        if (v0 < 0 || v1 < 0) {
            return Option<Array<UInt8>>.None
        }
        resultList.add(UInt8((v0 << 2) | (v1 >> 4)))
        if (bytes[i + 2] != 61u8) {
            if (v2 < 0) { return Option<Array<UInt8>>.None }
            resultList.add(UInt8(((v1 & 0xF) << 4) | (v2 >> 2)))
        }
        if (bytes[i + 3] != 61u8) {
            if (v3 < 0) { return Option<Array<UInt8>>.None }
            resultList.add(UInt8(((v2 & 0x3) << 6) | v3))
        }
        i += 4
    }
    return Option<Array<UInt8>>.Some(resultList.toArray())
}
