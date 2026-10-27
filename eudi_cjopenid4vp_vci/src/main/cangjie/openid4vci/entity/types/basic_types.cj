/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * basic_types.cj — Core value types for OpenID4VCI.
 * Ported from iOS:
 *   - Sources/Entities/Types/Types.swift
 *   - Sources/Entities/Types/Display.swift
 *   - Sources/Entities/Types/Grants.swift
 *   - Sources/Entities/Types/StateValue.swift
 *   - Sources/Entities/Types/CredentialConfigurationIdentifier.swift
 *   - Sources/Entities/Types/CredentialIdentifier.swift
 *   - Sources/Entities/Types/TransactionId.swift
 *
 * iOS async → sync; iOS Codable → manual JSON encode/decode.
 * Note: stdx.encoding.json uses class hierarchy, NOT enum constructors.
 *   Correct match: `case Some(jv: JsonString) => jv.getValue()`
 *   Wrong:         `case Some(JsonString(v)) =>` (causes compile error)
 */
package ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.types

import eudi_lib_core_crypto.Rng
import eudi_lib_core_crypto.Base64Url
import std.collection.*
import stdx.encoding.json.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.error.ValidationError

// ---------------------------------------------------------------------------
// Nonce
// ---------------------------------------------------------------------------

public class Nonce {
    public let value: String

    public init(value: String) {
        this.value = value
    }
}

// ---------------------------------------------------------------------------
// Scope
// ---------------------------------------------------------------------------

public class Scope {
    public let value: String

    public init(value: Option<String>) {
        if (value.isNone()) {
            throw ValidationError.Error("Scope cannot be nil")
        }
        let v = value.getOrThrow()
        if (v.isEmpty()) {
            throw ValidationError.Error("Scope cannot be empty")
        }
        this.value = v
    }

    public init(str: String) {
        if (str.isEmpty()) {
            throw ValidationError.Error("Scope cannot be empty")
        }
        this.value = str
    }
}

// ---------------------------------------------------------------------------
// StateValue — random opaque state for OAuth2 CSRF protection
// ---------------------------------------------------------------------------

public class StateValue {
    public let value: String

    public init() {
        // 16 random bytes → base64url → 22 chars
        let bytes = Rng.bytes(16)
        this.value = Base64Url.encode(bytes)
    }

    public init(value: String) {
        this.value = value
    }
}

// ---------------------------------------------------------------------------
// CredentialConfigurationIdentifier
// ---------------------------------------------------------------------------

public class CredentialConfigurationIdentifier {
    public let value: String

    public init(value: String) {
        this.value = value
    }
}

// ---------------------------------------------------------------------------
// CredentialIdentifier
// ---------------------------------------------------------------------------

public class CredentialIdentifier {
    public let value: String

    public init(value: String) {
        if (value.isEmpty()) {
            throw ValidationError.Error("CredentialIdentifier cannot be empty")
        }
        this.value = value
    }
}

// ---------------------------------------------------------------------------
// TransactionId
// ---------------------------------------------------------------------------

public class TransactionId {
    public let value: String

    public init(value: String) {
        if (value.isEmpty()) {
            throw ValidationError.Error("TransactionId cannot be empty")
        }
        this.value = value
    }
}

// ---------------------------------------------------------------------------
// AccessToken
// ---------------------------------------------------------------------------

public class AccessToken {
    public let value: String

    public init(value: Option<String>) {
        if (value.isNone()) {
            throw ValidationError.Error("Nil access token")
        }
        let v = value.getOrThrow()
        if (v.isEmpty()) {
            throw ValidationError.Error("Empty access token")
        }
        this.value = v
    }

    public init(str: String) {
        if (str.isEmpty()) {
            throw ValidationError.Error("Empty access token")
        }
        this.value = str
    }
}

// ---------------------------------------------------------------------------
// RefreshToken
// ---------------------------------------------------------------------------

public class RefreshToken {
    public let value: String

    public init(value: Option<String>) {
        if (value.isNone()) {
            throw ValidationError.Error("Nil refresh token")
        }
        let v = value.getOrThrow()
        if (v.isEmpty()) {
            throw ValidationError.Error("Empty refresh token")
        }
        this.value = v
    }

    public init(str: String) {
        if (str.isEmpty()) {
            throw ValidationError.Error("Empty refresh token")
        }
        this.value = str
    }
}

// ---------------------------------------------------------------------------
// TxCodeInputMode
// ---------------------------------------------------------------------------

public enum TxCodeInputMode {
    | Numeric
    | Text

    public func rawValue(): String {
        match (this) {
            case Numeric => "numeric"
            case Text => "text"
        }
    }

    public static func of(str: String): TxCodeInputMode {
        match (str) {
            case "numeric" => Numeric
            case "text" => Text
            case _ => Numeric  // default per iOS
        }
    }
}

// ---------------------------------------------------------------------------
// TxCode
// ---------------------------------------------------------------------------

public class TxCode {
    public let inputMode: TxCodeInputMode
    public let length: Option<Int64>
    public let description: Option<String>

    public init(
        inputMode: TxCodeInputMode,
        length: Option<Int64>,
        description: Option<String>
    ) {
        this.inputMode = inputMode
        this.length = length
        this.description = description
    }

    // Parse from JSON object
    // stdx.encoding.json: type-bound patterns, NOT enum-constructor patterns
    public static func fromJson(obj: JsonObject): TxCode {
        let mode: TxCodeInputMode
        let modeOpt = obj.get("input_mode")
        if (!modeOpt.isNone()) {
            let mv = modeOpt.getOrThrow()
            match (mv) {
                case jstr: JsonString => mode = TxCodeInputMode.of(jstr.getValue())
                case _ => mode = TxCodeInputMode.Numeric
            }
        } else {
            mode = TxCodeInputMode.Numeric
        }

        let len: Option<Int64>
        let lenOpt = obj.get("length")
        if (!lenOpt.isNone()) {
            let lv = lenOpt.getOrThrow()
            match (lv) {
                case ji: JsonInt => len = Option<Int64>.Some(ji.getValue())
                case _ => len = Option<Int64>.None
            }
        } else {
            len = Option<Int64>.None
        }

        let desc: Option<String>
        let descOpt = obj.get("description")
        if (!descOpt.isNone()) {
            let dv = descOpt.getOrThrow()
            match (dv) {
                case jstr: JsonString => desc = Option<String>.Some(jstr.getValue())
                case _ => desc = Option<String>.None
            }
        } else {
            desc = Option<String>.None
        }

        return TxCode(mode, len, desc)
    }
}

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

public class Policy {
    public let batchSize: Option<Int64>
    public let oneTimeUse: Option<Bool>

    public init(batchSize: Option<Int64>, oneTimeUse: Option<Bool>) {
        this.batchSize = batchSize
        this.oneTimeUse = oneTimeUse
    }

    public static func fromJson(obj: JsonObject): Policy {
        let batchSize: Option<Int64>
        let bsOpt = obj.get("batch_size")
        if (!bsOpt.isNone()) {
            let bv = bsOpt.getOrThrow()
            match (bv) {
                case ji: JsonInt => batchSize = Option<Int64>.Some(ji.getValue())
                case _ => batchSize = Option<Int64>.None
            }
        } else {
            batchSize = Option<Int64>.None
        }

        let oneTimeUse: Option<Bool>
        let otuOpt = obj.get("one_time_use")
        if (!otuOpt.isNone()) {
            let ov = otuOpt.getOrThrow()
            match (ov) {
                case jb: JsonBool => oneTimeUse = Option<Bool>.Some(jb.getValue())
                case _ => oneTimeUse = Option<Bool>.None
            }
        } else {
            oneTimeUse = Option<Bool>.None
        }

        return Policy(batchSize, oneTimeUse)
    }
}

// ---------------------------------------------------------------------------
// Display and Logo
// ---------------------------------------------------------------------------

public class DisplayLogo {
    public let uri: Option<String>
    public let alternativeText: Option<String>

    public init(uri: Option<String>, alternativeText: Option<String>) {
        this.uri = uri
        this.alternativeText = alternativeText
    }

    public static func fromJson(obj: JsonObject): DisplayLogo {
        let uri = optJsonString(obj, "uri")
        let alt = optJsonString(obj, "alt_text")
        return DisplayLogo(uri, alt)
    }
}

public class Display {
    public let name: Option<String>
    public let locale: Option<String>
    public let logo: Option<DisplayLogo>
    public let description: Option<String>
    public let backgroundColor: Option<String>
    public let backgroundImageUri: Option<String>
    public let textColor: Option<String>

    public init(
        name: Option<String>,
        locale: Option<String>,
        logo: Option<DisplayLogo>,
        description: Option<String>,
        backgroundColor: Option<String>,
        backgroundImageUri: Option<String>,
        textColor: Option<String>
    ) {
        this.name = name
        this.locale = locale
        this.logo = logo
        this.description = description
        this.backgroundColor = backgroundColor
        this.backgroundImageUri = backgroundImageUri
        this.textColor = textColor
    }

    public static func fromJson(obj: JsonObject): Display {
        let name = optJsonString(obj, "name")
        let locale = optJsonString(obj, "locale")

        let logo: Option<DisplayLogo>
        let logoOpt = obj.get("logo")
        if (!logoOpt.isNone()) {
            let lv = logoOpt.getOrThrow()
            match (lv) {
                case jobj: JsonObject => logo = Option<DisplayLogo>.Some(DisplayLogo.fromJson(jobj))
                case _ => logo = Option<DisplayLogo>.None
            }
        } else {
            logo = Option<DisplayLogo>.None
        }

        let desc = optJsonString(obj, "description")
        let bgColor = optJsonString(obj, "background_color")

        let bgImageUri: Option<String>
        let bgImgOpt = obj.get("background_image")
        if (!bgImgOpt.isNone()) {
            let bgv = bgImgOpt.getOrThrow()
            match (bgv) {
                case jobj: JsonObject => bgImageUri = optJsonString(jobj, "uri")
                case _ => bgImageUri = Option<String>.None
            }
        } else {
            bgImageUri = Option<String>.None
        }

        let textColor = optJsonString(obj, "text_color")
        return Display(name, locale, logo, desc, bgColor, bgImageUri, textColor)
    }
}

// ---------------------------------------------------------------------------
// Grants
// ---------------------------------------------------------------------------

public class AuthorizationCode {
    public let issuerState: Option<String>
    public let authorizationServer: Option<String>

    public init(issuerState: Option<String>, authorizationServer: Option<String>) {
        if (!issuerState.isNone()) {
            let s = issuerState.getOrThrow()
            if (s.isEmpty()) {
                throw ValidationError.Error("issuerState cannot be blank")
            }
        }
        this.issuerState = issuerState
        this.authorizationServer = authorizationServer
    }
}

public class PreAuthorizedCode {
    public let preAuthorizedCode: Option<String>
    public let txCode: Option<TxCode>
    public let authorizationServer: Option<String>

    public init(
        preAuthorizedCode: Option<String>,
        txCode: Option<TxCode>,
        authorizationServer: Option<String>
    ) {
        this.preAuthorizedCode = preAuthorizedCode
        this.txCode = txCode
        this.authorizationServer = authorizationServer
    }
}

public enum Grants {
    | AuthCode(AuthorizationCode)
    | PreAuthCode(PreAuthorizedCode)
    | Both(AuthorizationCode, PreAuthorizedCode)
}

// ---------------------------------------------------------------------------
// GenericErrorResponse — server error body
// ---------------------------------------------------------------------------

public class GenericErrorResponse {
    public let error: String
    public let errorDescription: Option<String>
    public let interval: Option<Float64>

    public init(
        error: String,
        errorDescription: Option<String>,
        interval: Option<Float64>
    ) {
        this.error = error
        this.errorDescription = errorDescription
        this.interval = interval
    }

    public static func fromJson(obj: JsonObject): GenericErrorResponse {
        let error: String
        let errOpt = obj.get("error")
        if (!errOpt.isNone()) {
            let ev = errOpt.getOrThrow()
            match (ev) {
                case js: JsonString => error = js.getValue()
                case _ => error = "unknown_error"
            }
        } else {
            error = "unknown_error"
        }

        let desc = optJsonString(obj, "error_description")

        let interval: Option<Float64>
        let intOpt = obj.get("interval")
        if (!intOpt.isNone()) {
            let iv = intOpt.getOrThrow()
            match (iv) {
                case jf: JsonFloat => interval = Option<Float64>.Some(jf.getValue())
                case ji: JsonInt => interval = Option<Float64>.Some(Float64(ji.getValue()))
                case _ => interval = Option<Float64>.None
            }
        } else {
            interval = Option<Float64>.None
        }

        return GenericErrorResponse(error, desc, interval)
    }
}

// ---------------------------------------------------------------------------
// ProofsTO — credential proof transfer object
// ---------------------------------------------------------------------------

public class ProofsTO {
    public let jwtProofs: Option<Array<String>>
    public let attestationProofs: Option<Array<String>>

    public init(jwtProofs: Option<Array<String>>, attestationProofs: Option<Array<String>>) {
        this.jwtProofs = jwtProofs
        this.attestationProofs = attestationProofs
    }

    public static func forJwt(proofs: Array<String>): ProofsTO {
        if (proofs.isEmpty()) {
            throw Exception("jwtProofs must be non-empty")
        }
        return ProofsTO(Option<Array<String>>.Some(proofs), Option<Array<String>>.None)
    }

    public static func forAttestation(proofs: Array<String>): ProofsTO {
        if (proofs.isEmpty()) {
            throw Exception("attestationProofs must be non-empty")
        }
        return ProofsTO(Option<Array<String>>.None, Option<Array<String>>.Some(proofs))
    }

    public func toJsonObject(): JsonObject {
        let obj = JsonObject()
        if (!jwtProofs.isNone()) {
            let proofs = jwtProofs.getOrThrow()
            let arr = JsonArray()
            for (p in proofs) { arr.add(JsonString(p)) }
            obj.put("jwt", arr)
        }
        if (!attestationProofs.isNone()) {
            let proofs = attestationProofs.getOrThrow()
            let arr = JsonArray()
            for (p in proofs) { arr.add(JsonString(p)) }
            obj.put("attestation", arr)
        }
        return obj
    }
}

// ---------------------------------------------------------------------------
// DeferredIssuanceRequestTO
// ---------------------------------------------------------------------------

public class DeferredIssuanceRequestTO {
    public let transactionId: String

    public init(transactionId: String) {
        this.transactionId = transactionId
    }

    public func toJsonObject(): JsonObject {
        let obj = JsonObject()
        obj.put("transaction_id", JsonString(transactionId))
        return obj
    }
}

// ---------------------------------------------------------------------------
// JSON helpers (package-internal)
// ---------------------------------------------------------------------------

func optJsonString(obj: JsonObject, key: String): Option<String> {
    let vOpt = obj.get(key)
    if (vOpt.isNone()) {
        return Option<String>.None
    }
    let v = vOpt.getOrThrow()
    match (v) {
        case js: JsonString => return Option<String>.Some(js.getValue())
        case _ => return Option<String>.None
    }
}
