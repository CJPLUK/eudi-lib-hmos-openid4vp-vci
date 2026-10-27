/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * access_token.cj — Issuance access/refresh token types.
 * Ported from iOS:
 *   - Sources/Entities/IssuanceAccessToken.swift
 *   - Sources/Entities/IssuanceRefreshToken.swift
 *   - Sources/Entities/AuthorizationToken.swift (TokenType)
 *   - Sources/Entities/IssuanceAuthorization.swift
 *
 * iOS Codable → manual JSON parse; iOS async → sync.
 */
package ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.access

import stdx.encoding.json.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.error.ValidationError
import eudi_lib_core_crypto.Base64Url
import kit.PerformanceAnalysisKit.Hilog

/*
 * Diagnostics: the resource server derives the user (username), scopes and
 * client status from this token via introspection, so log the response shape
 * and the token's own claims (a Keycloak access token is a JWS). The token
 * value itself is never logged.
 */
func logTokenResponseDiagnostics(obj: JsonObject, accessToken: String): Unit {
    var fields = ""
    for ((k, v) in obj.getFields()) {
        if (k == "access_token" || k == "refresh_token" || k == "id_token") {
            fields = fields + " " + k + "=<len " + v.toJsonString().size.toString() + ">"
        } else {
            fields = fields + " " + k + "=" + v.toJsonString()
        }
    }
    Hilog.info(0, "VCI-TOKEN", "token response:" + fields)
    let parts = accessToken.split(".")
    if (parts.size != 3) {
        Hilog.info(0, "VCI-TOKEN", "access token is opaque (parts=" + parts.size.toString() + ")")
        return
    }
    try {
        let claimsJson = String.fromUtf8(Base64Url.decode(parts[1]))
        match (JsonValue.fromStr(claimsJson)) {
            case claims: JsonObject =>
                var s = ""
                for ((k, v) in claims.getFields()) {
                    let rendered = v.toJsonString()
                    let clipped = if (rendered.size > 200) { String.fromUtf8(rendered.toArray()[0..200]) + "…" } else { rendered }
                    s = s + " " + k + "=" + clipped
                }
                Hilog.info(0, "VCI-TOKEN", "access token claims:" + s)
            case _ => Hilog.info(0, "VCI-TOKEN", "access token payload is not a JSON object")
        }
    } catch (e: Exception) {
        Hilog.warn(0, "VCI-TOKEN", "access token claims decode failed: " + e.message)
    }
}

// ---------------------------------------------------------------------------
// TokenType
// ---------------------------------------------------------------------------

public enum TokenType {
    | Bearer
    | DPoP
    | Other(String)

    public func rawValue(): String {
        match (this) {
            case Bearer => "Bearer"
            case DPoP => "DPoP"
            case Other(v) => v
        }
    }

    public static func fromString(s: String): Option<TokenType> {
        match (s) {
            case "Bearer" => Option<TokenType>.Some(TokenType.Bearer)
            case "DPoP" => Option<TokenType>.Some(TokenType.DPoP)
            case "" => Option<TokenType>.None
            case other => Option<TokenType>.Some(TokenType.Other(other))
        }
    }
}

// ---------------------------------------------------------------------------
// IssuanceAccessToken
// ---------------------------------------------------------------------------

public class IssuanceAccessToken {
    public let accessToken: String
    public let tokenType: Option<TokenType>
    public let expiresIn: Float64    // seconds, 0 if not provided

    public init(
        accessToken: String,
        tokenType: Option<TokenType>,
        expiresIn: Float64
    ) {
        if (accessToken.isEmpty()) {
            throw ValidationError.Error("Empty access token")
        }
        this.accessToken = accessToken
        this.tokenType = tokenType
        this.expiresIn = expiresIn
    }

    /*
     * Parse from token endpoint JSON response.
     * Keys: access_token, token_type, expires_in
     */
    public static func fromJsonObject(obj: JsonObject): IssuanceAccessToken {
        let token: String = match (obj.get("access_token")) {
            case Some(js: JsonString) => js.getValue()
            case _ => throw ValidationError.Error("access_token missing from token response")
        }
        let tokenType: Option<TokenType> = match (obj.get("token_type")) {
            case Some(js: JsonString) => TokenType.fromString(js.getValue())
            case _ => Option<TokenType>.None
        }
        let expiresIn: Float64 = match (obj.get("expires_in")) {
            case Some(ji: JsonInt) => Float64(ji.getValue())
            case Some(jf: JsonFloat) => jf.getValue()
            case _ => 0.0
        }
        logTokenResponseDiagnostics(obj, token)
        return IssuanceAccessToken(token, tokenType, expiresIn)
    }
}

// ---------------------------------------------------------------------------
// IssuanceRefreshToken
// ---------------------------------------------------------------------------

public class IssuanceRefreshToken {
    public let refreshToken: Option<String>

    public init(refreshToken: Option<String>) {
        this.refreshToken = refreshToken
    }

    public static func fromJsonObject(obj: JsonObject): IssuanceRefreshToken {
        let token: Option<String> = match (obj.get("refresh_token")) {
            case Some(js: JsonString) => Option<String>.Some(js.getValue())
            case _ => Option<String>.None
        }
        return IssuanceRefreshToken(token)
    }
}

// ---------------------------------------------------------------------------
// IssuanceAuthorization — either a pre-auth code or an auth code
// ---------------------------------------------------------------------------

public enum IssuanceAuthorization {
    | PreAuthorizationCode(String, Option<String>)  // (code, txCode)
    | AuthorizationCode(String)

    public func isPreAuth(): Bool {
        match (this) {
            case PreAuthorizationCode(_, _) => true
            case _ => false
        }
    }
}

// ---------------------------------------------------------------------------
// AuthorizationCode (used in OAuth2 auth code flow)
// ---------------------------------------------------------------------------

public class AuthorizationCodeValue {
    public let value: String

    public init(value: String) {
        if (value.isEmpty()) {
            throw ValidationError.Error("AuthorizationCode cannot be empty")
        }
        this.value = value
    }
}
