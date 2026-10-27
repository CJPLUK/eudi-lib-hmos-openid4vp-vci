/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * client_metadata.cj — VP ClientMetaData models.
 * Ported from iOS: ClientMetaData.swift, VpFormatsSupported.swift,
 * ResponseEncryptionSpecification.swift (block 4 minimal port).
 *
 * iOS Codable + SwiftyJSON → Cangjie stdx.encoding.json.
 * iOS JWEAlgorithm, JWSAlgorithm → stored as String names.
 */
package ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.entity.metadata

import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.error.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.entity.types.*
import std.collection.*
import stdx.encoding.json.*

// ---------------------------------------------------------------------------
// VpFormatSupported — mirrors iOS VpFormatSupported enum
// ---------------------------------------------------------------------------

public abstract sealed class VpFormatSupported {
    public func formatName(): String {
        match (this) {
            case _: SdJwtVcFormat => OpenId4VPSpec.FORMAT_SD_JWT_VC
            case _: MsoMdocFormat => OpenId4VPSpec.FORMAT_MSO_MDOC
            case _: JwtVpFormat => "jwt_vp"
            case _: LdpVpFormat => "ldp_vp"
            case _ => "unknown"
        }
    }
}

public class SdJwtVcFormat <: VpFormatSupported {
    public let sdJwtAlgorithms: Array<String>   // JWSAlgorithm name
    public let kbJwtAlgorithms: Array<String>
    public init(sdJwtAlgorithms!: Array<String>, kbJwtAlgorithms!: Array<String>) {
        if (sdJwtAlgorithms.isEmpty()) {
            throw VpValidationError.ValidationError("SD-JWT algorithms cannot be empty")
        }
        this.sdJwtAlgorithms = sdJwtAlgorithms
        this.kbJwtAlgorithms = kbJwtAlgorithms
    }
}

public class MsoMdocFormat <: VpFormatSupported {
    public let issuerAuthAlgorithms: Option<Array<Int64>>  // COSE algorithm IDs
    public let deviceAuthAlgorithms: Option<Array<Int64>>
    public init(
        issuerAuthAlgorithms!: Option<Array<Int64>>,
        deviceAuthAlgorithms!: Option<Array<Int64>>
    ) {
        this.issuerAuthAlgorithms = issuerAuthAlgorithms
        this.deviceAuthAlgorithms = deviceAuthAlgorithms
    }
}

public class JwtVpFormat <: VpFormatSupported {
    public let algorithms: Array<String>
    public init(algorithms!: Array<String>) { this.algorithms = algorithms }
}

public class LdpVpFormat <: VpFormatSupported {
    public let proofTypes: Array<String>
    public init(proofTypes!: Array<String>) { this.proofTypes = proofTypes }
}

// ---------------------------------------------------------------------------
// VpFormatsSupported — mirrors iOS VpFormatsSupported
// ---------------------------------------------------------------------------

public class VpFormatsSupported {
    public let values: Array<VpFormatSupported>

    public init(values!: Array<VpFormatSupported>) {
        // Ensure unique per format name
        var seen = HashSet<String>()
        for (f in values) {
            let name = f.formatName()
            if (seen.contains(name)) {
                throw VpValidationError.ValidationError(
                    "Multiple instances found for " + name
                )
            }
            seen.add(name)
        }
        this.values = values
    }

    public static func makeDefault(): VpFormatsSupported {
        VpFormatsSupported(values: [
            SdJwtVcFormat(sdJwtAlgorithms: ["ES256"], kbJwtAlgorithms: ["ES256"]),
            MsoMdocFormat(issuerAuthAlgorithms: Some([-7i64]), deviceAuthAlgorithms: Some([-7i64]))
        ])
    }

    public static func empty(): VpFormatsSupported {
        VpFormatsSupported(values: [])
    }

    // Compute intersection — mirrors iOS VpFormatsSupported.common
    public static func common(this_: VpFormatsSupported, that: VpFormatsSupported): Option<VpFormatsSupported> {
        var common = ArrayList<VpFormatSupported>()
        for (fmt in this_.values) {
            let name = fmt.formatName()
            for (other in that.values) {
                if (other.formatName() == name) {
                    common.add(fmt)
                    break
                }
            }
        }
        if (common.isEmpty()) { return None }
        return Some(VpFormatsSupported(values: common.toArray()))
    }

    // Parse from JsonObject (vp_formats_supported field)
    public static func fromJson(obj: JsonObject): VpFormatsSupported {
        var values = ArrayList<VpFormatSupported>()

        // dc+sd-jwt
        match (obj.get("dc+sd-jwt")) {
            case Some(sdJwtObj: JsonObject) =>
                let sdAlgs = parseStringArray(sdJwtObj, "sd-jwt_alg_values")
                let kbAlgs = parseStringArray(sdJwtObj, "kb-jwt_alg_values")
                if (!sdAlgs.isEmpty()) {
                    values.add(SdJwtVcFormat(sdJwtAlgorithms: sdAlgs, kbJwtAlgorithms: kbAlgs))
                }
            case _ => ()
        }

        // mso_mdoc
        match (obj.get("mso_mdoc")) {
            case Some(msoObj: JsonObject) =>
                let issuer = parseIntArray(msoObj, "issuerauth_alg_values")
                let device = parseIntArray(msoObj, "deviceauth_alg_values")
                values.add(MsoMdocFormat(
                    issuerAuthAlgorithms: if (issuer.isEmpty()) { None } else { Some(issuer) },
                    deviceAuthAlgorithms: if (device.isEmpty()) { None } else { Some(device) }
                ))
            case _ => ()
        }

        // jwt_vp
        match (obj.get("jwt_vp")) {
            case Some(jwtVpObj: JsonObject) =>
                let algs = parseStringArray(jwtVpObj, "alg")
                values.add(JwtVpFormat(algorithms: algs))
            case _ => ()
        }

        // ldp_vp
        match (obj.get("ldp_vp")) {
            case Some(ldpVpObj: JsonObject) =>
                let proofTypes = parseStringArray(ldpVpObj, "proof_type")
                values.add(LdpVpFormat(proofTypes: proofTypes))
            case _ => ()
        }

        return VpFormatsSupported(values: values.toArray())
    }
}

func parseStringArray(obj: JsonObject, key: String): Array<String> {
    var result = ArrayList<String>()
    match (obj.get(key)) {
        case Some(arr: JsonArray) =>
            for (item in arr.getItems()) {
                match (item) {
                    case s: JsonString => result.add(s.getValue())
                    case _ => ()
                }
            }
        case _ => ()
    }
    return result.toArray()
}

func parseIntArray(obj: JsonObject, key: String): Array<Int64> {
    var result = ArrayList<Int64>()
    match (obj.get(key)) {
        case Some(arr: JsonArray) =>
            for (item in arr.getItems()) {
                match (item) {
                    case n: JsonInt => result.add(n.getValue())
                    case _ => ()
                }
            }
        case _ => ()
    }
    return result.toArray()
}

// ---------------------------------------------------------------------------
// ResponseEncryptionSpecification — mirrors iOS ResponseEncryptionSpecification
// Block 4: minimal implementation storing algorithm/method as Strings.
// Full JWE key negotiation is block 5 scope.
// ---------------------------------------------------------------------------

public class ResponseEncryptionSpecification {
    public let encryptionAlgorithm: String  // e.g. "ECDH-ES"
    public let encryptionMethod: String     // e.g. "A128GCM"
    // The JWK set for response encryption key exchange
    public let jwkSetJson: Option<String>

    public init(
        encryptionAlgorithm!: String,
        encryptionMethod!: String,
        jwkSetJson!: Option<String> = None
    ) {
        this.encryptionAlgorithm = encryptionAlgorithm
        this.encryptionMethod = encryptionMethod
        this.jwkSetJson = jwkSetJson
    }
}

// ---------------------------------------------------------------------------
// ClientMetaData — mirrors iOS ClientMetaData
// ---------------------------------------------------------------------------

public class ClientMetaData {
    // jwks as raw JSON string (mirrors iOS .jwks: String?)
    public let jwksJson: Option<String>
    public let vpFormatsSupported: Option<VpFormatsSupported>
    // encrypted_response_enc_values_supported
    public let responseEncryptionMethodsSupported: Option<Array<String>>

    public init(
        jwksJson!: Option<String> = None,
        vpFormatsSupported!: Option<VpFormatsSupported> = None,
        responseEncryptionMethodsSupported!: Option<Array<String>> = None
    ) {
        this.jwksJson = jwksJson
        this.vpFormatsSupported = vpFormatsSupported
        this.responseEncryptionMethodsSupported = responseEncryptionMethodsSupported
    }

    // Parse from JSON object (mirrors iOS ClientMetaData.init(metaData: JSON))
    public static func fromJsonObject(obj: JsonObject): ClientMetaData {
        let jwksJson: Option<String> = match (obj.get("jwks")) {
            case Some(v) => Some(v.toJsonString())
            case None => None
        }

        let vpFormatsSupported: Option<VpFormatsSupported> = match (obj.get("vp_formats_supported")) {
            case Some(fmtObj: JsonObject) =>
                try {
                    Some(VpFormatsSupported.fromJson(fmtObj))
                } catch (_: Exception) {
                    None
                }
            case _ => None
        }

        let encMethods: Option<Array<String>> = match (obj.get("encrypted_response_enc_values_supported")) {
            case Some(arr: JsonArray) =>
                var methods = ArrayList<String>()
                for (item in arr.getItems()) {
                    match (item) {
                        case s: JsonString => methods.add(s.getValue())
                        case _ => ()
                    }
                }
                Some(methods.toArray())
            case _ => None
        }

        return ClientMetaData(
            jwksJson: jwksJson,
            vpFormatsSupported: vpFormatsSupported,
            responseEncryptionMethodsSupported: encMethods
        )
    }

    // Parse from JSON string (mirrors iOS ClientMetaData.init(metaDataString:))
    public static func fromJsonString(jsonStr: String): ClientMetaData {
        let parsed = JsonValue.fromStr(jsonStr)
        match (parsed) {
            case obj: JsonObject => ClientMetaData.fromJsonObject(obj)
            case _ => throw VpValidationError.InvalidClientMetadata()
        }
    }
}

// ---------------------------------------------------------------------------
// ClientMetaData.Validated — mirrors iOS ClientMetaData.Validated
// Stores validated/resolved fields post-validation.
// ---------------------------------------------------------------------------

public class ValidatedClientMetaData {
    // jwkSet as raw JSON string (full WebKeySet not parsed in block 4)
    public let jwkSetJson: Option<String>
    // Signing/encryption algorithm names (stored as String, not JWSAlgorithm)
    public let authorizationSignedResponseAlg: Option<String>
    public let authorizationEncryptedResponseAlg: Option<String>
    public let authorizationEncryptedResponseEnc: Option<String>
    public let vpFormatsSupported: VpFormatsSupported
    public let responseEncryptionSpecification: Option<ResponseEncryptionSpecification>

    public init(
        jwkSetJson!: Option<String> = None,
        authorizationSignedResponseAlg!: Option<String> = None,
        authorizationEncryptedResponseAlg!: Option<String> = None,
        authorizationEncryptedResponseEnc!: Option<String> = None,
        vpFormatsSupported!: VpFormatsSupported,
        responseEncryptionSpecification!: Option<ResponseEncryptionSpecification> = None
    ) {
        this.jwkSetJson = jwkSetJson
        this.authorizationSignedResponseAlg = authorizationSignedResponseAlg
        this.authorizationEncryptedResponseAlg = authorizationEncryptedResponseAlg
        this.authorizationEncryptedResponseEnc = authorizationEncryptedResponseEnc
        this.vpFormatsSupported = vpFormatsSupported
        this.responseEncryptionSpecification = responseEncryptionSpecification
    }

    // Build a default with all-formats-supported (used when metadata is absent)
    public static func makeDefault(): ValidatedClientMetaData {
        ValidatedClientMetaData(vpFormatsSupported: VpFormatsSupported.makeDefault())
    }

    // Validate from ClientMetaData (simplified — full JWK resolution is block 5)
    public static func validate(
        metaData: ClientMetaData,
        responseMode: Option<ResponseMode>
    ): ValidatedClientMetaData {
        let vpFmts = match (metaData.vpFormatsSupported) {
            case Some(f) => f
            case None => VpFormatsSupported.makeDefault()
        }

        // Determine encryption spec from response mode + metadata
        let encSpec: Option<ResponseEncryptionSpecification> =
            match (responseMode) {
                case Some(dm: DirectPostJWT) =>
                    // directPost.jwt requires encryption; build spec from metadata if available
                    match (metaData.responseEncryptionMethodsSupported) {
                        case Some(methods) =>
                            if (methods.isEmpty()) {
                                None
                            } else {
                                Some(ResponseEncryptionSpecification(
                                    encryptionAlgorithm: "ECDH-ES",
                                    encryptionMethod: methods[0],
                                    // The verifier's ephemeral encryption key
                                    // travels in client_metadata.jwks — without
                                    // it the ResponseEncryptor cannot build the
                                    // JWE (direct_post.jwt).
                                    jwkSetJson: metaData.jwksJson
                                ))
                            }
                        case None => None
                    }
                case _ => None
            }

        return ValidatedClientMetaData(
            jwkSetJson: metaData.jwksJson,
            vpFormatsSupported: vpFmts,
            responseEncryptionSpecification: encSpec
        )
    }
}
