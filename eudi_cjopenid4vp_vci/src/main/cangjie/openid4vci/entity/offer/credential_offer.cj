/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * credential_offer.cj — Credential offer model.
 * Ported from iOS:
 *   - Sources/Entities/CredentialOffer/CredentialOffer.swift
 *   - Sources/Entities/CredentialOffer/CredentialOfferRequest.swift
 *   - Sources/Entities/CredentialOffer/CredentialOfferRequestObject.swift
 *   - Sources/Entities/Types/GrantsDTO.swift
 *
 * iOS async → sync; Codable → manual JSON parse.
 * JSON pattern note: stdx.encoding.json uses class hierarchy.
 *   Correct: `case Some(jobj: JsonObject) =>` (type-bound pattern)
 *   Wrong:   `case Some(JsonObject(x)) =>` (enum-constructor pattern)
 */
package ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.offer

import std.collection.*
import stdx.encoding.json.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.types.{
    Grants, AuthorizationCode, PreAuthorizedCode, TxCode, CredentialConfigurationIdentifier
}
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.issuer.{
    CredentialIssuerId, CredentialIssuerMetadata
}
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.error.{
    CredentialOfferRequestError, CredentialOfferRequestValidationError, ValidationError
}

// ---------------------------------------------------------------------------
// GrantsDTO — wire transfer object parsed from credential_offer JSON
// ---------------------------------------------------------------------------

public class GrantsDTO {
    public let authorizationCode: Option<AuthorizationCodeDTO>
    public let preAuthorizationCode: Option<PreAuthorizationCodeDTO>

    public init(
        authorizationCode: Option<AuthorizationCodeDTO>,
        preAuthorizationCode: Option<PreAuthorizationCodeDTO>
    ) {
        this.authorizationCode = authorizationCode
        this.preAuthorizationCode = preAuthorizationCode
    }

    public static func fromJsonObject(obj: JsonObject): GrantsDTO {
        let authCode: Option<AuthorizationCodeDTO> = match (obj.get("authorization_code")) {
            case Some(jobj: JsonObject) =>
                Option<AuthorizationCodeDTO>.Some(AuthorizationCodeDTO.fromJsonObject(jobj))
            case _ => Option<AuthorizationCodeDTO>.None
        }
        let preAuth: Option<PreAuthorizationCodeDTO> = match (obj.get("urn:ietf:params:oauth:grant-type:pre-authorized_code")) {
            case Some(jobj: JsonObject) =>
                Option<PreAuthorizationCodeDTO>.Some(PreAuthorizationCodeDTO.fromJsonObject(jobj))
            case _ => Option<PreAuthorizationCodeDTO>.None
        }
        return GrantsDTO(authCode, preAuth)
    }

    // Convert DTO → domain Grants enum
    public func toDomain(): Grants {
        if (!authorizationCode.isNone() && !preAuthorizationCode.isNone()) {
            let authCode = authorizationCode.getOrThrow()
            let preCode = preAuthorizationCode.getOrThrow()
            let domainAc = AuthorizationCode(authCode.issuerState, authCode.authorizationServer)
            let domainPac = PreAuthorizedCode(preCode.preAuthorizedCode, preCode.txCode, preCode.authorizationServer)
            return Grants.Both(domainAc, domainPac)
        } else if (!authorizationCode.isNone()) {
            let authCode = authorizationCode.getOrThrow()
            return Grants.AuthCode(AuthorizationCode(authCode.issuerState, authCode.authorizationServer))
        } else if (!preAuthorizationCode.isNone()) {
            let preCode = preAuthorizationCode.getOrThrow()
            return Grants.PreAuthCode(PreAuthorizedCode(preCode.preAuthorizedCode, preCode.txCode, preCode.authorizationServer))
        } else {
            throw ValidationError.Error("Invalid Grants DTO")
        }
    }
}

public class AuthorizationCodeDTO {
    public let issuerState: Option<String>
    public let authorizationServer: Option<String>

    public init(issuerState: Option<String>, authorizationServer: Option<String>) {
        this.issuerState = issuerState
        this.authorizationServer = authorizationServer
    }

    public static func fromJsonObject(obj: JsonObject): AuthorizationCodeDTO {
        let issuerState: Option<String> = match (obj.get("issuer_state")) {
            case Some(js: JsonString) => Option<String>.Some(js.getValue())
            case _ => Option<String>.None
        }
        let authServer: Option<String> = match (obj.get("authorization_server")) {
            case Some(js: JsonString) => Option<String>.Some(js.getValue())
            case _ => Option<String>.None
        }
        return AuthorizationCodeDTO(issuerState, authServer)
    }
}

public class PreAuthorizationCodeDTO {
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

    public static func fromJsonObject(obj: JsonObject): PreAuthorizationCodeDTO {
        let code: Option<String> = match (obj.get("pre-authorized_code")) {
            case Some(js: JsonString) => Option<String>.Some(js.getValue())
            case _ => Option<String>.None
        }
        let txCode: Option<TxCode> = match (obj.get("tx_code")) {
            case Some(jobj: JsonObject) => Option<TxCode>.Some(TxCode.fromJson(jobj))
            case _ => Option<TxCode>.None
        }
        let authServer: Option<String> = match (obj.get("authorization_server")) {
            case Some(js: JsonString) => Option<String>.Some(js.getValue())
            case _ => Option<String>.None
        }
        return PreAuthorizationCodeDTO(code, txCode, authServer)
    }
}

// ---------------------------------------------------------------------------
// CredentialOfferRequestObject — the raw offer JSON
// ---------------------------------------------------------------------------

public class CredentialOfferRequestObject {
    public let credentialIssuer: String
    public let credentialConfigurationIds: ArrayList<String>
    public let grants: Option<GrantsDTO>

    public init(
        credentialIssuer: String,
        credentialConfigurationIds: ArrayList<String>,
        grants: Option<GrantsDTO>
    ) {
        this.credentialIssuer = credentialIssuer
        this.credentialConfigurationIds = credentialConfigurationIds
        this.grants = grants
    }

    public static func fromJsonString(jsonStr: String): CredentialOfferRequestObject {
        let jv = JsonValue.fromStr(jsonStr)
        match (jv) {
            case jobj: JsonObject => return fromJsonObject(jobj)
            case _ => throw CredentialOfferRequestError.NonParseableCredentialOffer("root not JSON object")
        }
    }

    public static func fromJsonObject(root: JsonObject): CredentialOfferRequestObject {
        let issuer: String = match (root.get("credential_issuer")) {
            case Some(js: JsonString) => js.getValue()
            case _ => throw CredentialOfferRequestError.NonParseableCredentialOffer("credential_issuer missing")
        }

        let ids = ArrayList<String>()
        match (root.get("credential_configuration_ids")) {
            case Some(jarr: JsonArray) =>
                for (item in jarr.getItems()) {
                    match (item) {
                        case js: JsonString => ids.add(js.getValue())
                        case _ => ()
                    }
                }
            case _ => ()
        }

        let grants: Option<GrantsDTO> = match (root.get("grants")) {
            case Some(jobj: JsonObject) =>
                Option<GrantsDTO>.Some(GrantsDTO.fromJsonObject(jobj))
            case _ => Option<GrantsDTO>.None
        }

        return CredentialOfferRequestObject(issuer, ids, grants)
    }
}

// ---------------------------------------------------------------------------
// CredentialOffer — resolved domain offer with metadata
// ---------------------------------------------------------------------------

public class CredentialOffer {
    public let credentialIssuerIdentifier: CredentialIssuerId
    public let credentialIssuerMetadata: CredentialIssuerMetadata
    public let credentialConfigurationIdentifiers: Array<CredentialConfigurationIdentifier>
    public let grants: Option<Grants>

    public init(
        credentialIssuerIdentifier: CredentialIssuerId,
        credentialIssuerMetadata: CredentialIssuerMetadata,
        credentialConfigurationIdentifiers: Array<CredentialConfigurationIdentifier>,
        grants: Option<Grants>
    ) {
        if (credentialConfigurationIdentifiers.isEmpty()) {
            throw CredentialOfferRequestError.EmptyCredentialsError()
        }
        this.credentialIssuerIdentifier = credentialIssuerIdentifier
        this.credentialIssuerMetadata = credentialIssuerMetadata
        this.credentialConfigurationIdentifiers = credentialConfigurationIdentifiers
        this.grants = grants
    }
}
