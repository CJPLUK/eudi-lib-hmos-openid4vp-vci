/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * functions.cj — Utility functions.
 * Ported from iOS Sources/Utilities/Functions/Functions.swift.
 *
 * iOS async → sync (HarmonyOS HTTP is synchronous in this port).
 * convertToJsonString: stdx.encoding.json → JsonObject.toJsonString().
 */
package ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.util

import std.collection.*
import stdx.encoding.json.*

/*
 * Serialize a String→String map as a JSON object string.
 * Returns None if serialization fails.
 * iOS: convertToJsonString(dictionary: [String: Any]) — here we restrict to String values
 * for the common case; the full Any variant is not needed in block 1.
 */
public func convertToJsonStringFromMap(dictionary: HashMap<String, String>): Option<String> {
    try {
        var obj = JsonObject()
        for ((k, v) in dictionary) {
            obj.put(k, JsonString(v))
        }
        return Option<String>.Some(obj.toJsonString())
    } catch (_: Exception) {
        return Option<String>.None
    }
}

/*
 * Unwrap an Option<T> or throw the provided exception.
 * Mirrors iOS: unwrapOrThrow<T>(_ optional: T?, error: Error) throws -> T
 */
public func unwrapOrThrow<T>(optional: Option<T>, error: Exception): T {
    match (optional) {
        case Some(v) => return v
        case None => throw error
    }
}

/*
 * Percent-encode a string for use in URL query parameters (application/x-www-form-urlencoded).
 * Replaces non-unreserved characters with %XX sequences.
 * Used by Poster to build form bodies.
 */
public func urlEncodeComponent(value: String): String {
    let unreserved: Array<UInt8> = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~".toArray()
    let bytes = value.toArray()
    var result = ""
    for (b in bytes) {
        var isUnreserved = false
        for (u in unreserved) {
            if (b == u) {
                isUnreserved = true
                break
            }
        }
        if (isUnreserved) {
            result = result + String.fromUtf8([b])
        } else {
            result = result + "%" + byteToHexUpper(b)
        }
    }
    return result
}

/*
 * Build a form-encoded body string from a map.
 * key1=value1&key2=value2 (both keys and values are percent-encoded).
 */
public func buildFormBody(params: HashMap<String, String>): String {
    var result = ""
    var first = true
    for ((k, v) in params) {
        if (!first) { result = result + "&" }
        result = result + urlEncodeComponent(k) + "=" + urlEncodeComponent(v)
        first = false
    }
    return result
}

// internal helpers

func byteToHexUpper(b: UInt8): String {
    let hi = Int64(b >> 4)
    let lo = Int64(b & 0x0Fu8)
    return hexDigitUpper(hi) + hexDigitUpper(lo)
}

func hexDigitUpper(n: Int64): String {
    if (n < 10) { return n.toString() }
    if (n == 10) { return "A" }
    if (n == 11) { return "B" }
    if (n == 12) { return "C" }
    if (n == 13) { return "D" }
    if (n == 14) { return "E" }
    return "F"
}
