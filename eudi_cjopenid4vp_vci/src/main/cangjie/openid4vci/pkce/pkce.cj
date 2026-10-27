/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * pkce.cj — RFC 7636 PKCE (Proof Key for Code Exchange).
 * Ported from iOS Sources/PKCE/PKCEGenerator.swift.
 *
 * iOS CryptoKit SHA256 → core-crypto Digest.sha256
 * iOS SecRandomCopyBytes → core-crypto Rng.bytes
 * iOS Data.base64EncodedString() → stdx.encoding.base64
 * URL-safe base64 without padding → core-crypto Base64Url
 *
 * All methods are synchronous (no iOS async).
 */
package ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.pkce

import eudi_lib_core_crypto.{Base64Url, Digest, Rng}
import stdx.encoding.base64.*

public class PKCEGenerator {

    // RFC 7636: code_verifier length MUST be between 43 and 128 characters
    private static let minCodeVerifierLength: Int64 = 43
    private static let maxCodeVerifierLength: Int64 = 128

    /*
     * Generates a default RFC7636 code verifier (43 chars).
     * Returns None if generation fails.
     */
    public static func codeVerifier(): Option<String> {
        return codeVerifierWithLength(minCodeVerifierLength)
    }

    /*
     * RFC7636-conformant code verifier generator.
     * length must be in 43..128.
     */
    public static func codeVerifierWithLength(length: Int64): Option<String> {
        if (length < minCodeVerifierLength || length > maxCodeVerifierLength) {
            return Option<String>.None
        }
        return generateRandomString(length)
    }

    /*
     * Generate length cryptographically random bytes.
     * Returns None on error.
     */
    public static func generateRandomData(length: Int64): Option<Array<UInt8>> {
        try {
            let data = Rng.bytes(length)
            return Option<Array<UInt8>>.Some(data)
        } catch (_: Exception) {
            return Option<Array<UInt8>>.None
        }
    }

    /*
     * Generate a random string of given length using URL-safe chars: a-z A-Z 0-9 - . _ ~
     */
    public static func generateRandomString(length: Int64): Option<String> {
        let charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
        let charsetBytes = charset.toArray()
        let charsetLen = charsetBytes.size

        let randomBytesOpt = generateRandomData(length)
        if (randomBytesOpt.isNone()) {
            return Option<String>.None
        }
        let randomBytes = randomBytesOpt.getOrThrow()
        let outChars = Array<UInt8>(length, repeat: 0u8)
        for (i in 0..length) {
            let idx = Int64(randomBytes[i]) % charsetLen
            outChars[i] = charsetBytes[idx]
        }
        return Option<String>.Some(String.fromUtf8(outChars))
    }

    /*
     * Generate a code challenge from the given code verifier.
     * challenge = BASE64URL(SHA256(ASCII(code_verifier))) with no padding.
     * Mirrors iOS generateCodeChallenge(codeVerifier:) -> String.
     */
    public static func generateCodeChallenge(codeVerifier: String): String {
        let data = codeVerifier.toArray()
        let hashed = Digest.sha256(data)
        // base64url without padding
        return Base64Url.encode(hashed)
    }

    /*
     * Generate a random code challenge (generates verifier internally).
     * Returns None if generation fails.
     */
    public static func generateCodeChallenge(): Option<String> {
        let vOpt = codeVerifier()
        if (vOpt.isNone()) {
            return Option<String>.None
        }
        return Option<String>.Some(generateCodeChallenge(vOpt.getOrThrow()))
    }
}

/*
 * PKCEVerifier — bundles verifier + challenge together.
 * Mirrors iOS PKCEVerifier struct used in AuthorizationRequested.
 */
public class PKCEVerifier {
    public let codeVerifier: String
    public let codeChallenge: String
    public let codeChallengeMethod: String

    public init(codeVerifier: String, codeChallenge: String, codeChallengeMethod: String) {
        this.codeVerifier = codeVerifier
        this.codeChallenge = codeChallenge
        this.codeChallengeMethod = codeChallengeMethod
    }

    /*
     * Generate a fresh PKCE pair using S256 method.
     * Throws ValidationError if random generation fails.
     */
    public static func generate(): PKCEVerifier {
        let verifierOpt = PKCEGenerator.codeVerifier()
        if (verifierOpt.isNone()) {
            throw Exception("PKCE: failed to generate code verifier")
        }
        let verifier = verifierOpt.getOrThrow()
        let challenge = PKCEGenerator.generateCodeChallenge(verifier)
        return PKCEVerifier(verifier, challenge, "S256")
    }
}
