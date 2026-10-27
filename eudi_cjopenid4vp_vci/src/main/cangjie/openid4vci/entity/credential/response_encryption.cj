/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * response_encryption.cj — RequestedCredentialResponseEncryption + JWE decrypt for
 * encrypted credential responses.
 *
 * Ported from iOS:
 *   - Sources/Entities/CredentialIssuer/RequestedCredentialResponseEncryption.swift
 *   - Sources/Entities/Encryption/CredentialResponseEncryptionSpec.swift
 *   - Sources/Main/Encryption/EncryptionSpec.swift
 *
 * iOS SecKey/JWK-based JWE → Cangjie: jose EcdhEsDecrypter (ECDH-ES family).
 * iOS async → sync.
 *
 * Degradation:
 *   - Only ECDH-ES family algorithms supported (EUDI wallet spec default).
 *   - RSA-OAEP family not available; documented in Known Limitations.
 *
 * Known Limitations:
 *   - RSA-OAEP / RSA-OAEP-256 JWE decryption not implemented;
 *     ECDH-ES / ECDH-ES+A128KW / ECDH-ES+A192KW / ECDH-ES+A256KW are the
 *     algorithms used by the EUDI wallet spec.
 */
package ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.credential

import stdx.encoding.json.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.error.{ValidationError, CredentialIssuanceError}
import ohos_app_cangjie_eudi_cjjose.jose.{EcPrivateKey, EcPublicKey, EcCurve, EcdhEsDecrypter, EcdhEsEncrypter}

// ---------------------------------------------------------------------------
// RequestedCredentialResponseEncryption
// Ported from iOS enum RequestedCredentialResponseEncryption.
//
// Represents the encryption parameters to include in a credential issuance request
// when the caller wants the credential response to be JWE-encrypted.
// ---------------------------------------------------------------------------

public enum RequestedCredentialResponseEncryption {
    | NotRequested
    | Requested(
        String,       // encryptionPublicKeyJson — EC public key JWK JSON (e.g. {"crv":"P-256","x":"...","y":"..."})
        EcPrivateKey, // decryptionKey — caller's EC private key for decryption
        String,       // responseEncryptionAlg — e.g. "ECDH-ES"
        String        // responseEncryptionMethod — e.g. "A128GCM"
    )

    /*
     * Build from components; validates asymmetric alg requirement.
     * Matches iOS RequestedCredentialResponseEncryption.init(encryptionJwk:encryptionKey:
     * responseEncryptionAlg:responseEncryptionMethod:).
     */
    public static func of(
        encryptionPublicKeyJson: Option<String>,
        decryptionKey: Option<EcPrivateKey>,
        responseEncryptionAlg: Option<String>,
        responseEncryptionMethod: Option<String>
    ): RequestedCredentialResponseEncryption {
        // If any component is absent → not requested
        if (encryptionPublicKeyJson.isNone() || decryptionKey.isNone() ||
            responseEncryptionAlg.isNone() || responseEncryptionMethod.isNone()) {
            return RequestedCredentialResponseEncryption.NotRequested
        }

        let alg = responseEncryptionAlg.getOrThrow()
        // Validate algorithm is asymmetric (ECDH-ES family or RSA-OAEP family)
        let isAsymmetric = alg.startsWith("ECDH-ES") || alg.startsWith("RSA-OAEP")
        if (!isAsymmetric) {
            throw ValidationError.Error(
                "Provided encryption algorithm is not an asymmetric encryption algorithm: " + alg
            )
        }

        return RequestedCredentialResponseEncryption.Requested(
            encryptionPublicKeyJson.getOrThrow(),
            decryptionKey.getOrThrow(),
            alg,
            responseEncryptionMethod.getOrThrow()
        )
    }

    public func isRequested(): Bool {
        match (this) {
            case Requested(_, _, _, _) => true
            case NotRequested => false
        }
    }

    /*
     * Build the JSON fields to add to a credential request body:
     *   "credential_response_encryption": {
     *     "jwk": <public JWK>,
     *     "alg": "<alg>",
     *     "enc": "<method>"
     *   }
     * Ported from iOS CredentialRequestEncryptionSpec.toJson().
     */
    public func toRequestJsonFields(requestObj: JsonObject): Unit {
        match (this) {
            case NotRequested => ()
            case Requested(pubKeyJson, _, alg, enc) =>
                let encryptionObj = JsonObject()
                // Embed the public JWK object
                let jwkValue: JsonValue = JsonValue.fromStr(pubKeyJson)
                encryptionObj.put("jwk", jwkValue)
                encryptionObj.put("alg", JsonString(alg))
                encryptionObj.put("enc", JsonString(enc))
                requestObj.put("credential_response_encryption", encryptionObj)
        }
    }

    /*
     * Decrypt a JWE compact-serialized credential response body.
     * Uses jose EcdhEsDecrypter (ECDH-ES family).
     *
     * If the response body is not a valid JWE (no "." separator in 5-part form),
     * it is assumed to be plaintext and returned as-is.
     *
     * Known limitation: RSA-OAEP is not supported; ECDH-ES only.
     */
    public func decryptResponseIfNeeded(responseBody: String): String {
        match (this) {
            case NotRequested =>
                return responseBody
            case Requested(_, decryptionKey, alg, _) =>
                // Heuristic: a JWE compact has exactly 4 dots (5 segments)
                let dotCount = countDots(responseBody)
                if (dotCount != 4) {
                    // Not a JWE compact — treat as plaintext JSON
                    return responseBody
                }
                if (alg.startsWith("ECDH-ES")) {
                    try {
                        let plaintextBytes = EcdhEsDecrypter.decrypt(responseBody, decryptionKey)
                        return String.fromUtf8(plaintextBytes)
                    } catch (e: Exception) {
                        throw CredentialIssuanceError.ResponseUnparsable(
                            "JWE decrypt (ECDH-ES) failed: " + e.message
                        )
                    }
                } else {
                    // RSA-OAEP not implemented
                    throw CredentialIssuanceError.ResponseUnparsable(
                        "Unsupported JWE algorithm for decryption: " + alg +
                        " (only ECDH-ES family supported)"
                    )
                }
        }
    }
}

// Count '.' characters in a string
func countDots(s: String): Int64 {
    let bytes = s.toArray()
    var count: Int64 = 0
    for (b in bytes) {
        if (b == b'.') {
            count += 1
        }
    }
    return count
}

// ---------------------------------------------------------------------------
// CredentialResponseEncryptionSpec
// Simple value class carrying encryption parameters for constructing a
// RequestedCredentialResponseEncryption to include in a request.
// Ported from iOS IssuanceResponseEncryptionSpec.
// ---------------------------------------------------------------------------

public class CredentialResponseEncryptionSpec {
    public let publicKey: EcPublicKey      // EC public key (for inclusion in request)
    public let privateKey: EcPrivateKey    // EC private key (for decryption)
    public let algorithm: String           // e.g. "ECDH-ES"
    public let encryptionMethod: String    // e.g. "A128GCM"

    public init(
        publicKey: EcPublicKey,
        privateKey: EcPrivateKey,
        algorithm: String,
        encryptionMethod: String
    ) {
        this.publicKey = publicKey
        this.privateKey = privateKey
        this.algorithm = algorithm
        this.encryptionMethod = encryptionMethod
    }

    public func toRequestedEncryption(): RequestedCredentialResponseEncryption {
        return RequestedCredentialResponseEncryption.of(
            Option<String>.Some(publicKey.toJson()),
            Option<EcPrivateKey>.Some(privateKey),
            Option<String>.Some(algorithm),
            Option<String>.Some(encryptionMethod)
        )
    }
}
