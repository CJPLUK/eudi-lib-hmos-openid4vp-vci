/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * credential_configurations.cj — Format-specific credential configuration types.
 *
 * Ported from iOS:
 *   - Sources/Entities/Profiles/MsoMdocFormat.swift (CredentialConfiguration)
 *   - Sources/Entities/Profiles/SdJwtVcFormat.swift (CredentialConfiguration)
 *   - Sources/Entities/Profiles/W3CJsonLdSignedJwtFormat.swift (CredentialConfiguration)
 *   - Sources/Entities/Profiles/W3CJsonLdDataIntegrityFormat.swift (CredentialConfiguration)
 *   - Sources/Entities/CredentialIssuer/CryptographicBindingMethod.swift
 *   - Sources/Entities/Encryption/ProofTypeSupportedMeta.swift
 *
 * iOS Codable → manual JSON parse.
 * iOS Swift struct → Cangjie class.
 * CoseAlgorithm CBOR int codes → name mapping included.
 */
package ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.credential

import std.collection.*
import stdx.encoding.json.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.types.{Display, Policy}
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.error.ValidationError

// ---------------------------------------------------------------------------
// CryptographicBindingMethod
// Ported from iOS enum CryptographicBindingMethod.
// ---------------------------------------------------------------------------

public enum CryptographicBindingMethod {
    | Jwk
    | X5c
    | CoseKey
    | Mso
    | Did(String)    // did:method string

    public static func of(method: String): CryptographicBindingMethod {
        match (method) {
            case "jwk" => CryptographicBindingMethod.Jwk
            case "x5c" => CryptographicBindingMethod.X5c
            case "cose_key" => CryptographicBindingMethod.CoseKey
            case "mso" => CryptographicBindingMethod.Mso
            case _ =>
                if (method.startsWith("did")) {
                    CryptographicBindingMethod.Did(method)
                } else {
                    throw ValidationError.Error("Unknown cryptographic binding method: " + method)
                }
        }
    }

    public func rawValue(): String {
        match (this) {
            case Jwk => "jwk"
            case X5c => "x5c"
            case CoseKey => "cose_key"
            case Mso => "mso"
            case Did(m) => m
        }
    }
}

// ---------------------------------------------------------------------------
// ProofTypeSupportedMeta
// Ported from iOS struct ProofTypeSupportedMeta.
// Represents proof_types_supported entry (e.g. "jwt": { "proof_signing_alg_values_supported": ["ES256"] }).
// ---------------------------------------------------------------------------

public class ProofTypeSupportedMeta {
    public let algorithms: Array<String>     // proof_signing_alg_values_supported
    // Presence of a "key_attestations_required" member means the issuer requires
    // this proof type to carry a key attestation (e.g. EHIC). {} => required.
    public let keyAttestationsRequired: Bool

    public init(algorithms: Array<String>, keyAttestationsRequired!: Bool = false) {
        this.algorithms = algorithms
        this.keyAttestationsRequired = keyAttestationsRequired
    }

    public static func fromJson(obj: JsonObject): ProofTypeSupportedMeta {
        let algs = ArrayList<String>()
        match (obj.get("proof_signing_alg_values_supported")) {
            case Some(jarr: JsonArray) =>
                for (item in jarr.getItems()) {
                    match (item) {
                        case js: JsonString => algs.add(js.getValue())
                        case _ => ()
                    }
                }
            case _ => ()
        }
        let keyAttReq = match (obj.get("key_attestations_required")) {
            case Some(_) => true
            case None => false
        }
        return ProofTypeSupportedMeta(algs.toArray(), keyAttestationsRequired: keyAttReq)
    }
}

// ---------------------------------------------------------------------------
// ClaimPath / Claim
// Simplified port from iOS Claim and ClaimPath.
// ---------------------------------------------------------------------------

public class Claim {
    public let mandatory: Option<Bool>
    public let display: Array<Display>
    public let valueType: Option<String>

    public init(
        mandatory: Option<Bool>,
        display: Array<Display>,
        valueType: Option<String>
    ) {
        this.mandatory = mandatory
        this.display = display
        this.valueType = valueType
    }

    public static func fromJson(obj: JsonObject): Claim {
        let mandatory: Option<Bool> = match (obj.get("mandatory")) {
            case Some(jb: JsonBool) => Option<Bool>.Some(jb.getValue())
            case _ => Option<Bool>.None
        }
        let valueType: Option<String> = match (obj.get("value_type")) {
            case Some(js: JsonString) => Option<String>.Some(js.getValue())
            case _ => Option<String>.None
        }
        let displayList = ArrayList<Display>()
        match (obj.get("display")) {
            case Some(jarr: JsonArray) =>
                for (item in jarr.getItems()) {
                    match (item) {
                        case jobj: JsonObject => displayList.add(Display.fromJson(jobj))
                        case _ => ()
                    }
                }
            case _ => ()
        }
        return Claim(mandatory, displayList.toArray(), valueType)
    }
}

// Helper — parse proof_types_supported map from JSON object
func parseProofTypes(obj: JsonObject): HashMap<String, ProofTypeSupportedMeta> {
    let result = HashMap<String, ProofTypeSupportedMeta>()
    match (obj.get("proof_types_supported")) {
        case Some(jmap: JsonObject) =>
            for ((key, value) in jmap.getFields()) {
                match (value) {
                    case jobj: JsonObject =>
                        result.add(key, ProofTypeSupportedMeta.fromJson(jobj))
                    case _ => ()
                }
            }
        case _ => ()
    }
    return result
}

// Helper — parse cryptographic_binding_methods_supported
func parseCryptographicBindingMethods(obj: JsonObject): Array<CryptographicBindingMethod> {
    let result = ArrayList<CryptographicBindingMethod>()
    match (obj.get("cryptographic_binding_methods_supported")) {
        case Some(jarr: JsonArray) =>
            for (item in jarr.getItems()) {
                match (item) {
                    case js: JsonString =>
                        try {
                            result.add(CryptographicBindingMethod.of(js.getValue()))
                        } catch (_: ValidationError) {
                            // skip unknown methods
                        }
                    case _ => ()
                }
            }
        case _ => ()
    }
    return result.toArray()
}

// Helper — parse credential_signing_alg_values_supported (with COSE int mapping)
func parseSigningAlgs(obj: JsonObject): Array<String> {
    // COSE algorithm integer → string name (per RFC 8152)
    let coseMap = HashMap<Int64, String>()
    coseMap.add(-7, "ES256")
    coseMap.add(-35, "ES384")
    coseMap.add(-36, "ES512")

    let result = ArrayList<String>()
    match (obj.get("credential_signing_alg_values_supported")) {
        case Some(jarr: JsonArray) =>
            for (item in jarr.getItems()) {
                match (item) {
                    case js: JsonString => result.add(js.getValue())
                    case ji: JsonInt =>
                        match (coseMap.get(ji.getValue())) {
                            case Some(name) => result.add(name)
                            case None => ()
                        }
                    case _ => ()
                }
            }
        case _ => ()
    }
    return result.toArray()
}

func optJsonStr(obj: JsonObject, key: String): Option<String> {
    match (obj.get(key)) {
        case Some(js: JsonString) => Option<String>.Some(js.getValue())
        case _ => Option<String>.None
    }
}

func parseStringList(obj: JsonObject, key: String): Array<String> {
    let result = ArrayList<String>()
    match (obj.get(key)) {
        case Some(jarr: JsonArray) =>
            for (item in jarr.getItems()) {
                match (item) {
                    case js: JsonString => result.add(js.getValue())
                    case _ => ()
                }
            }
        case _ => ()
    }
    return result.toArray()
}

// OID4VCI v1 (issuer.eudiw.dev) nests `display` / `claims` under a
// `credential_metadata` object; older drafts (dev.issuer) keep them at the
// top level of the credential configuration. Check the top level first,
// then fall through to credential_metadata — otherwise v1 issuers lose the
// credential display name ("PID (MSO Mdoc)" → raw config id) and claims.
func v1MetadataObj(obj: JsonObject): ?JsonObject {
    match (obj.get("credential_metadata")) {
        case Some(cm: JsonObject) => Some(cm)
        case _ => None
    }
}

func parseDisplays(obj: JsonObject): Array<Display> {
    let result = ArrayList<Display>()
    var src: ?JsonValue = obj.get("display")
    match (src) {
        case Some(_: JsonArray) => ()
        case _ =>
            match (v1MetadataObj(obj)) {
                case Some(cm) => src = cm.get("display")
                case None => ()
            }
    }
    match (src) {
        case Some(jarr: JsonArray) =>
            for (item in jarr.getItems()) {
                match (item) {
                    case jobj: JsonObject => result.add(Display.fromJson(jobj))
                    case _ => ()
                }
            }
        case _ => ()
    }
    return result.toArray()
}

func parseClaims(obj: JsonObject): Array<Claim> {
    let result = ArrayList<Claim>()
    var src: ?JsonValue = obj.get("claims")
    match (src) {
        case Some(_: JsonArray) => ()
        case _ =>
            match (v1MetadataObj(obj)) {
                case Some(cm) => src = cm.get("claims")
                case None => ()
            }
    }
    match (src) {
        case Some(jarr: JsonArray) =>
            for (item in jarr.getItems()) {
                match (item) {
                    case jobj: JsonObject => result.add(Claim.fromJson(jobj))
                    case _ => ()
                }
            }
        case _ => ()
    }
    return result.toArray()
}

// ---------------------------------------------------------------------------
// KeyAttestationJWT
// Ported from iOS KeyAttestations/KeyAttestationJWT.swift.
// Structural holder for key attestation JWTs.
// Full JWS signature verification of the attestation is the issuer's responsibility.
// ---------------------------------------------------------------------------

public class KeyAttestationJWT {
    public static let TYPE = "key-attestation+jwt"

    public let compact: String    // compact JWS string

    public init(compact: String) {
        if (compact.isEmpty()) {
            throw ValidationError.Error("KeyAttestationJWT: compact JWT cannot be empty")
        }
        this.compact = compact
    }
}

// ---------------------------------------------------------------------------
// MsoMdocCredentialConfiguration
// Ported from iOS MsoMdocFormat.CredentialConfiguration.
// format = "mso_mdoc"
// ---------------------------------------------------------------------------

public class MsoMdocCredentialConfiguration {
    public static let FORMAT = "mso_mdoc"

    public let format: String
    public let scope: Option<String>
    public let docType: String
    public let cryptographicBindingMethodsSupported: Array<CryptographicBindingMethod>
    public let credentialSigningAlgValuesSupported: Array<String>
    public let proofTypesSupported: HashMap<String, ProofTypeSupportedMeta>
    public let display: Array<Display>
    public let claims: Array<Claim>

    public init(
        format: String,
        scope: Option<String>,
        docType: String,
        cryptographicBindingMethodsSupported: Array<CryptographicBindingMethod>,
        credentialSigningAlgValuesSupported: Array<String>,
        proofTypesSupported: HashMap<String, ProofTypeSupportedMeta>,
        display: Array<Display>,
        claims: Array<Claim>
    ) {
        this.format = format
        this.scope = scope
        this.docType = docType
        this.cryptographicBindingMethodsSupported = cryptographicBindingMethodsSupported
        this.credentialSigningAlgValuesSupported = credentialSigningAlgValuesSupported
        this.proofTypesSupported = proofTypesSupported
        this.display = display
        this.claims = claims
    }

    public static func fromJson(obj: JsonObject): MsoMdocCredentialConfiguration {
        let docType: String = match (obj.get("doctype")) {
            case Some(js: JsonString) => js.getValue()
            case _ => throw ValidationError.Error("MsoMdoc: missing 'doctype'")
        }
        let scope = optJsonStr(obj, "scope")
        let bindingMethods = parseCryptographicBindingMethods(obj)
        let signingAlgs = parseSigningAlgs(obj)
        let proofTypes = parseProofTypes(obj)
        let displays = parseDisplays(obj)
        let claimsList = parseClaims(obj)
        return MsoMdocCredentialConfiguration(
            MsoMdocCredentialConfiguration.FORMAT,
            scope,
            docType,
            bindingMethods,
            signingAlgs,
            proofTypes,
            displays,
            claimsList
        )
    }
}

// ---------------------------------------------------------------------------
// SdJwtVcCredentialDefinition
// Ported from iOS SdJwtVcFormat.CredentialDefinition.
// ---------------------------------------------------------------------------

public class SdJwtVcCredentialDefinition {
    public let vcType: String    // "type" field (vct in SD-JWT-VC spec)
    public let claims: Array<Claim>

    public init(vcType: String, claims: Array<Claim>) {
        this.vcType = vcType
        this.claims = claims
    }

    public static func fromJson(obj: JsonObject): SdJwtVcCredentialDefinition {
        let vcType: String = match (obj.get("type")) {
            case Some(js: JsonString) => js.getValue()
            case _ => ""
        }
        let claims = parseClaims(obj)
        return SdJwtVcCredentialDefinition(vcType, claims)
    }
}

// ---------------------------------------------------------------------------
// SdJwtVcCredentialConfiguration
// Ported from iOS SdJwtVcFormat.CredentialConfiguration.
// format = "dc+sd-jwt" (or legacy "vc+sd-jwt")
// ---------------------------------------------------------------------------

public class SdJwtVcCredentialConfiguration {
    public static let FORMAT = "dc+sd-jwt"
    public static let LEGACY_FORMAT = "vc+sd-jwt"

    public let format: String
    public let scope: Option<String>
    public let vct: Option<String>
    public let cryptographicBindingMethodsSupported: Array<CryptographicBindingMethod>
    public let credentialSigningAlgValuesSupported: Array<String>
    public let proofTypesSupported: HashMap<String, ProofTypeSupportedMeta>
    public let credentialDefinition: SdJwtVcCredentialDefinition
    public let display: Array<Display>

    public init(
        format: String,
        scope: Option<String>,
        vct: Option<String>,
        cryptographicBindingMethodsSupported: Array<CryptographicBindingMethod>,
        credentialSigningAlgValuesSupported: Array<String>,
        proofTypesSupported: HashMap<String, ProofTypeSupportedMeta>,
        credentialDefinition: SdJwtVcCredentialDefinition,
        display: Array<Display>
    ) {
        this.format = format
        this.scope = scope
        this.vct = vct
        this.cryptographicBindingMethodsSupported = cryptographicBindingMethodsSupported
        this.credentialSigningAlgValuesSupported = credentialSigningAlgValuesSupported
        this.proofTypesSupported = proofTypesSupported
        this.credentialDefinition = credentialDefinition
        this.display = display
    }

    public static func fromJson(obj: JsonObject): SdJwtVcCredentialConfiguration {
        let format: String = match (obj.get("format")) {
            case Some(js: JsonString) => js.getValue()
            case _ => SdJwtVcCredentialConfiguration.FORMAT
        }
        let scope = optJsonStr(obj, "scope")
        let vct = optJsonStr(obj, "vct")
        let bindingMethods = parseCryptographicBindingMethods(obj)
        let signingAlgs = parseSigningAlgs(obj)
        let proofTypes = parseProofTypes(obj)
        let displays = parseDisplays(obj)

        // credential_definition sub-object
        let credDef: SdJwtVcCredentialDefinition = match (obj.get("credential_definition")) {
            case Some(jobj: JsonObject) => SdJwtVcCredentialDefinition.fromJson(jobj)
            case _ =>
                // fallback: vct as type
                let fallbackType = match (vct) { case Some(v) => v; case None => "" }
                SdJwtVcCredentialDefinition(fallbackType, [])
        }

        return SdJwtVcCredentialConfiguration(
            format,
            scope,
            vct,
            bindingMethods,
            signingAlgs,
            proofTypes,
            credDef,
            displays
        )
    }
}

// ---------------------------------------------------------------------------
// W3CCredentialDefinition
// Shared by W3CJsonLdSignedJwt (jwt_vc_json-ld) and W3CJsonLdDataIntegrity (ldp_vc).
// ---------------------------------------------------------------------------

public class W3CCredentialDefinition {
    public let context: Array<String>    // @context
    public let credType: Array<String>   // type
    public let claims: Array<Claim>

    public init(context: Array<String>, credType: Array<String>, claims: Array<Claim>) {
        this.context = context
        this.credType = credType
        this.claims = claims
    }

    public static func fromJson(obj: JsonObject): W3CCredentialDefinition {
        let context = parseStringList(obj, "@context")
        let credType = parseStringList(obj, "type")
        let claims = parseClaims(obj)
        return W3CCredentialDefinition(context, credType, claims)
    }
}

// ---------------------------------------------------------------------------
// W3CJsonLdSignedJwtCredentialConfiguration
// format = "jwt_vc_json-ld"
// Ported from iOS W3CJsonLdSignedJwtFormat.CredentialConfiguration.
// ---------------------------------------------------------------------------

public class W3CJsonLdSignedJwtCredentialConfiguration {
    public static let FORMAT = "jwt_vc_json-ld"

    public let format: String
    public let scope: Option<String>
    public let context: Array<String>
    public let cryptographicBindingMethodsSupported: Array<CryptographicBindingMethod>
    public let credentialSigningAlgValuesSupported: Array<String>
    public let proofTypesSupported: HashMap<String, ProofTypeSupportedMeta>
    public let credentialDefinition: W3CCredentialDefinition
    public let display: Array<Display>

    public init(
        format: String,
        scope: Option<String>,
        context: Array<String>,
        cryptographicBindingMethodsSupported: Array<CryptographicBindingMethod>,
        credentialSigningAlgValuesSupported: Array<String>,
        proofTypesSupported: HashMap<String, ProofTypeSupportedMeta>,
        credentialDefinition: W3CCredentialDefinition,
        display: Array<Display>
    ) {
        this.format = format
        this.scope = scope
        this.context = context
        this.cryptographicBindingMethodsSupported = cryptographicBindingMethodsSupported
        this.credentialSigningAlgValuesSupported = credentialSigningAlgValuesSupported
        this.proofTypesSupported = proofTypesSupported
        this.credentialDefinition = credentialDefinition
        this.display = display
    }

    public static func fromJson(obj: JsonObject): W3CJsonLdSignedJwtCredentialConfiguration {
        let scope = optJsonStr(obj, "scope")
        let context = parseStringList(obj, "@context")
        let bindingMethods = parseCryptographicBindingMethods(obj)
        let signingAlgs = parseSigningAlgs(obj)
        let proofTypes = parseProofTypes(obj)
        let displays = parseDisplays(obj)
        let credDef: W3CCredentialDefinition = match (obj.get("credential_definition")) {
            case Some(jobj: JsonObject) => W3CCredentialDefinition.fromJson(jobj)
            case _ => W3CCredentialDefinition([], [], [])
        }
        return W3CJsonLdSignedJwtCredentialConfiguration(
            W3CJsonLdSignedJwtCredentialConfiguration.FORMAT,
            scope,
            context,
            bindingMethods,
            signingAlgs,
            proofTypes,
            credDef,
            displays
        )
    }
}

// ---------------------------------------------------------------------------
// W3CJsonLdDataIntegrityCredentialConfiguration
// format = "ldp_vc"
// Ported from iOS W3CJsonLdDataIntegrityFormat.CredentialConfiguration.
// ---------------------------------------------------------------------------

public class W3CJsonLdDataIntegrityCredentialConfiguration {
    public static let FORMAT = "ldp_vc"

    public let format: String
    public let scope: Option<String>
    public let context: Array<String>
    public let credType: Array<String>
    public let cryptographicBindingMethodsSupported: Array<CryptographicBindingMethod>
    public let credentialSigningAlgValuesSupported: Array<String>
    public let proofTypesSupported: HashMap<String, ProofTypeSupportedMeta>
    public let credentialDefinition: W3CCredentialDefinition
    public let display: Array<Display>

    public init(
        format: String,
        scope: Option<String>,
        context: Array<String>,
        credType: Array<String>,
        cryptographicBindingMethodsSupported: Array<CryptographicBindingMethod>,
        credentialSigningAlgValuesSupported: Array<String>,
        proofTypesSupported: HashMap<String, ProofTypeSupportedMeta>,
        credentialDefinition: W3CCredentialDefinition,
        display: Array<Display>
    ) {
        this.format = format
        this.scope = scope
        this.context = context
        this.credType = credType
        this.cryptographicBindingMethodsSupported = cryptographicBindingMethodsSupported
        this.credentialSigningAlgValuesSupported = credentialSigningAlgValuesSupported
        this.proofTypesSupported = proofTypesSupported
        this.credentialDefinition = credentialDefinition
        this.display = display
    }

    public static func fromJson(obj: JsonObject): W3CJsonLdDataIntegrityCredentialConfiguration {
        let scope = optJsonStr(obj, "scope")
        let context = parseStringList(obj, "@context")
        let credType = parseStringList(obj, "type")
        let bindingMethods = parseCryptographicBindingMethods(obj)
        let signingAlgs = parseSigningAlgs(obj)
        let proofTypes = parseProofTypes(obj)
        let displays = parseDisplays(obj)
        let credDef: W3CCredentialDefinition = match (obj.get("credential_definition")) {
            case Some(jobj: JsonObject) => W3CCredentialDefinition.fromJson(jobj)
            case _ => W3CCredentialDefinition([], [], [])
        }
        return W3CJsonLdDataIntegrityCredentialConfiguration(
            W3CJsonLdDataIntegrityCredentialConfiguration.FORMAT,
            scope,
            context,
            credType,
            bindingMethods,
            signingAlgs,
            proofTypes,
            credDef,
            displays
        )
    }
}

// ---------------------------------------------------------------------------
// W3CSignedJwtCredentialConfiguration
// format = "jwt_vc_json"
// Ported from iOS W3CSignedJwtFormat.CredentialConfiguration.
// ---------------------------------------------------------------------------

public class W3CSignedJwtCredentialConfiguration {
    public static let FORMAT = "jwt_vc_json"

    public let format: String
    public let scope: Option<String>
    public let cryptographicBindingMethodsSupported: Array<CryptographicBindingMethod>
    public let credentialSigningAlgValuesSupported: Array<String>
    public let proofTypesSupported: HashMap<String, ProofTypeSupportedMeta>
    public let credentialDefinition: W3CCredentialDefinition
    public let display: Array<Display>

    public init(
        format: String,
        scope: Option<String>,
        cryptographicBindingMethodsSupported: Array<CryptographicBindingMethod>,
        credentialSigningAlgValuesSupported: Array<String>,
        proofTypesSupported: HashMap<String, ProofTypeSupportedMeta>,
        credentialDefinition: W3CCredentialDefinition,
        display: Array<Display>
    ) {
        this.format = format
        this.scope = scope
        this.cryptographicBindingMethodsSupported = cryptographicBindingMethodsSupported
        this.credentialSigningAlgValuesSupported = credentialSigningAlgValuesSupported
        this.proofTypesSupported = proofTypesSupported
        this.credentialDefinition = credentialDefinition
        this.display = display
    }

    public static func fromJson(obj: JsonObject): W3CSignedJwtCredentialConfiguration {
        let scope = optJsonStr(obj, "scope")
        let bindingMethods = parseCryptographicBindingMethods(obj)
        let signingAlgs = parseSigningAlgs(obj)
        let proofTypes = parseProofTypes(obj)
        let displays = parseDisplays(obj)
        let credDef: W3CCredentialDefinition = match (obj.get("credential_definition")) {
            case Some(jobj: JsonObject) => W3CCredentialDefinition.fromJson(jobj)
            case _ => W3CCredentialDefinition([], [], [])
        }
        return W3CSignedJwtCredentialConfiguration(
            W3CSignedJwtCredentialConfiguration.FORMAT,
            scope,
            bindingMethods,
            signingAlgs,
            proofTypes,
            credDef,
            displays
        )
    }
}

// ---------------------------------------------------------------------------
// CredentialConfigurationSupported — union of all format variants
// Ported from iOS CredentialSupported enum.
// ---------------------------------------------------------------------------

public enum CredentialConfigurationSupported {
    | MsoMdoc(MsoMdocCredentialConfiguration)
    | SdJwtVc(SdJwtVcCredentialConfiguration)
    | W3CSignedJwt(W3CSignedJwtCredentialConfiguration)             // jwt_vc_json
    | W3CJsonLdSignedJwt(W3CJsonLdSignedJwtCredentialConfiguration)  // jwt_vc_json-ld
    | W3CJsonLdDataIntegrity(W3CJsonLdDataIntegrityCredentialConfiguration)  // ldp_vc
    | Unknown(String, JsonObject)    // format string + raw JSON for unknown formats

    /*
     * Parse from a JSON object, dispatching on the "format" field.
     * Returns Unknown() for unrecognized formats — interop-friendly.
     */
    public static func fromJson(obj: JsonObject): CredentialConfigurationSupported {
        let format: String = match (obj.get("format")) {
            case Some(js: JsonString) => js.getValue()
            case _ => "unknown"
        }
        match (format) {
            case "mso_mdoc" =>
                try {
                    CredentialConfigurationSupported.MsoMdoc(
                        MsoMdocCredentialConfiguration.fromJson(obj)
                    )
                } catch (_: Exception) {
                    CredentialConfigurationSupported.Unknown(format, obj)
                }
            case "dc+sd-jwt" | "vc+sd-jwt" =>
                CredentialConfigurationSupported.SdJwtVc(
                    SdJwtVcCredentialConfiguration.fromJson(obj)
                )
            case "jwt_vc_json" =>
                CredentialConfigurationSupported.W3CSignedJwt(
                    W3CSignedJwtCredentialConfiguration.fromJson(obj)
                )
            case "jwt_vc_json-ld" =>
                CredentialConfigurationSupported.W3CJsonLdSignedJwt(
                    W3CJsonLdSignedJwtCredentialConfiguration.fromJson(obj)
                )
            case "ldp_vc" =>
                CredentialConfigurationSupported.W3CJsonLdDataIntegrity(
                    W3CJsonLdDataIntegrityCredentialConfiguration.fromJson(obj)
                )
            case _ =>
                CredentialConfigurationSupported.Unknown(format, obj)
        }
    }

    public func format(): String {
        match (this) {
            case MsoMdoc(_) => "mso_mdoc"
            case SdJwtVc(c) => c.format
            case W3CSignedJwt(_) => "jwt_vc_json"
            case W3CJsonLdSignedJwt(_) => "jwt_vc_json-ld"
            case W3CJsonLdDataIntegrity(_) => "ldp_vc"
            case Unknown(f, _) => f
        }
    }

    public func scope(): Option<String> {
        match (this) {
            case MsoMdoc(c) => c.scope
            case SdJwtVc(c) => c.scope
            case W3CSignedJwt(c) => c.scope
            case W3CJsonLdSignedJwt(c) => c.scope
            case W3CJsonLdDataIntegrity(c) => c.scope
            case Unknown(_, _) => Option<String>.None
        }
    }
}
