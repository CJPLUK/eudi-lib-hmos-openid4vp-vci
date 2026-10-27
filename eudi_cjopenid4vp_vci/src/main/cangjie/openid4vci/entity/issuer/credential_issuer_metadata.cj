/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * credential_issuer_metadata.cj — Credential issuer metadata model.
 * Ported from iOS Sources/Entities/CredentialIssuer/CredentialIssuerMetadata.swift.
 *
 * stdx.encoding.json class hierarchy note:
 *   Type-bound match: `case Some(jobj: JsonObject) => jobj`
 *   NOT:              `case Some(JsonObject(x)) =>`
 *
 * Degradation: CredentialSupported types represented as raw JsonObject;
 *   full format dispatch deferred to block 2.
 */
package ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.issuer

import std.collection.*
import stdx.encoding.json.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.types.{Display, Policy}
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.error.ValidationError

// ---------------------------------------------------------------------------
// BatchCredentialIssuance
// ---------------------------------------------------------------------------

public class BatchCredentialIssuance {
    public let batchSize: Int64

    public init(batchSize: Int64) {
        this.batchSize = batchSize
    }

    public static func fromJson(obj: JsonObject): BatchCredentialIssuance {
        let size: Int64 = match (obj.get("batch_size")) {
            case Some(ji: JsonInt) => ji.getValue()
            case _ => 1
        }
        return BatchCredentialIssuance(size)
    }
}

// ---------------------------------------------------------------------------
// CredentialResponseEncryption enum
// ---------------------------------------------------------------------------

public enum CredentialResponseEncryption {
    | NotSupported
    | SupportedNotRequired(Array<String>, Array<String>)
    | Required(Array<String>, Array<String>)

    public func isNotSupported(): Bool {
        match (this) {
            case NotSupported => true
            case _ => false
        }
    }

    public func isRequired(): Bool {
        match (this) {
            case Required(_, _) => true
            case _ => false
        }
    }
}

// ---------------------------------------------------------------------------
// CredentialRequestEncryption enum
// ---------------------------------------------------------------------------

public enum CredentialRequestEncryption {
    | NotSupported
    | Supported(Array<String>, Array<String>)
}

// ---------------------------------------------------------------------------
// IssuerInfo / IssuerInfoAttestation
// Ported from iOS Sources/RegistrationCertificate/IssuerInfo.swift (v0.53.1):
// the `issuer_info` member of the Credential Issuer Metadata (ETSI TS 119 472-3)
// carries attestations about the issuer; a "registration_cert"-format entry
// holds the WRP Registration Certificate (WRPRC) as a compact-serialized JWT.
// ---------------------------------------------------------------------------

/**
 * A single entry inside `issuer_info` — declares its `format` and carries the
 * attestation `data` (for WRPRC, a compact-serialized signed JWT).
 */
public class IssuerInfoAttestation {
    public let format: String
    public let data: String

    public init(format: String, data: String) {
        this.format = format
        this.data = data
    }
}

/**
 * The `issuer_info` container. Tolerant decoding mirrors iOS:
 * an attestation object, an array of attestation objects, or a bare JWT
 * string (treated as a single "registration_cert" attestation).
 */
public class IssuerInfo {
    /** Format identifier for a WRPRC attestation inside issuer_info (ETSI TS 119 472-3). */
    public static let REGISTRATION_CERT_FORMAT: String = "registration_cert"

    public let attestations: Array<IssuerInfoAttestation>

    public init(attestations: Array<IssuerInfoAttestation>) {
        this.attestations = attestations
    }

    /**
     * Parse from the raw `issuer_info` JSON value.
     * Returns None when the value has none of the accepted shapes.
     */
    public static func fromJsonValue(value: JsonValue): Option<IssuerInfo> {
        match (value) {
            case arr: JsonArray =>
                let acc = ArrayList<IssuerInfoAttestation>()
                for (item in arr.getItems()) {
                    match (item) {
                        case obj: JsonObject =>
                            match (attestationFromJson(obj)) {
                                case Some(att) => acc.add(att)
                                case None => ()
                            }
                        case _ => ()
                    }
                }
                if (acc.isEmpty()) { return Option<IssuerInfo>.None }
                return Option<IssuerInfo>.Some(IssuerInfo(acc.toArray()))
            case obj: JsonObject =>
                match (attestationFromJson(obj)) {
                    case Some(att) => Option<IssuerInfo>.Some(IssuerInfo([att]))
                    case None => Option<IssuerInfo>.None
                }
            case s: JsonString =>
                // Tolerant: bare JWT string is treated as a WRPRC attestation.
                let jwt = s.getValue()
                if (jwt.isEmpty()) { return Option<IssuerInfo>.None }
                Option<IssuerInfo>.Some(IssuerInfo(
                    [IssuerInfoAttestation(IssuerInfo.REGISTRATION_CERT_FORMAT, jwt)]))
            case _ => Option<IssuerInfo>.None
        }
    }

    static func attestationFromJson(obj: JsonObject): Option<IssuerInfoAttestation> {
        let fmt: String = match (obj.get("format")) {
            case Some(js: JsonString) => js.getValue()
            case _ => return Option<IssuerInfoAttestation>.None
        }
        let dataStr: String = match (obj.get("data")) {
            case Some(js: JsonString) => js.getValue()
            case _ => return Option<IssuerInfoAttestation>.None
        }
        return Option<IssuerInfoAttestation>.Some(IssuerInfoAttestation(fmt, dataStr))
    }
}

// ---------------------------------------------------------------------------
// CredentialIssuerMetadata
// ---------------------------------------------------------------------------

public class CredentialIssuerMetadata {
    public let credentialIssuerIdentifier: CredentialIssuerId
    public let authorizationServers: Array<String>
    public let credentialEndpoint: CredentialIssuerEndpoint
    public let deferredCredentialEndpoint: Option<CredentialIssuerEndpoint>
    public let nonceEndpoint: Option<CredentialIssuerEndpoint>
    public let notificationEndpoint: Option<CredentialIssuerEndpoint>
    public let credentialResponseEncryption: CredentialResponseEncryption
    public let credentialRequestEncryption: Option<CredentialRequestEncryption>
    public let credentialConfigurationsRaw: HashMap<String, JsonObject>
    public let display: Array<Display>
    public let credentialIdentifiersSupported: Option<Bool>
    public let batchCredentialIssuance: Option<BatchCredentialIssuance>
    /**
     * The `issuer_info` container (ETSI TS 119 472-3), if the metadata carries
     * one. A "registration_cert"-format entry holds the issuer's WRPRC.
     */
    public let issuerInfo: Option<IssuerInfo>
    /**
     * The WRP Access Certificate — base64 DER of the LEAF certificate of the
     * `x5c` header that signed the issuer metadata JWT. A runtime artifact of
     * signed-metadata verification (set by MetadataFetcher), never decoded from
     * the metadata JSON itself. Mirrors iOS CredentialIssuerMetadata.wrpac.
     */
    public var wrpac: Option<String> = None

    public init(
        credentialIssuerIdentifier: CredentialIssuerId,
        authorizationServers: Array<String>,
        credentialEndpoint: CredentialIssuerEndpoint,
        deferredCredentialEndpoint: Option<CredentialIssuerEndpoint>,
        nonceEndpoint: Option<CredentialIssuerEndpoint>,
        notificationEndpoint: Option<CredentialIssuerEndpoint>,
        credentialResponseEncryption: CredentialResponseEncryption,
        credentialRequestEncryption: Option<CredentialRequestEncryption>,
        credentialConfigurationsRaw: HashMap<String, JsonObject>,
        display: Array<Display>,
        credentialIdentifiersSupported: Option<Bool>,
        batchCredentialIssuance: Option<BatchCredentialIssuance>,
        issuerInfo!: Option<IssuerInfo> = None
    ) {
        this.credentialIssuerIdentifier = credentialIssuerIdentifier
        this.authorizationServers = authorizationServers
        this.credentialEndpoint = credentialEndpoint
        this.deferredCredentialEndpoint = deferredCredentialEndpoint
        this.nonceEndpoint = nonceEndpoint
        this.notificationEndpoint = notificationEndpoint
        this.credentialResponseEncryption = credentialResponseEncryption
        this.credentialRequestEncryption = credentialRequestEncryption
        this.credentialConfigurationsRaw = credentialConfigurationsRaw
        this.display = display
        this.credentialIdentifiersSupported = credentialIdentifiersSupported
        this.batchCredentialIssuance = batchCredentialIssuance
        this.issuerInfo = issuerInfo
    }

    public static func fromJsonString(jsonStr: String): CredentialIssuerMetadata {
        let jv = JsonValue.fromStr(jsonStr)
        match (jv) {
            case jobj: JsonObject => return fromJsonObject(jobj)
            case _ => throw ValidationError.Error("CredentialIssuerMetadata: root is not JSON object")
        }
    }

    public static func fromJsonObject(root: JsonObject): CredentialIssuerMetadata {
        // credential_issuer
        let issuerIdStr: String = match (root.get("credential_issuer")) {
            case Some(js: JsonString) => js.getValue()
            case _ => throw ValidationError.Error("credential_issuer missing or invalid")
        }
        let issuerId = CredentialIssuerId(issuerIdStr)

        // authorization_servers
        let authServers = parseStringArray(root, "authorization_servers")
        let finalAuthServers: Array<String>
        if (authServers.isEmpty()) {
            finalAuthServers = [issuerIdStr]
        } else {
            finalAuthServers = authServers
        }

        // credential_endpoint
        let credEndpointStr: String = match (root.get("credential_endpoint")) {
            case Some(js: JsonString) => js.getValue()
            case _ => throw ValidationError.Error("credential_endpoint missing or invalid")
        }
        let credEndpoint = CredentialIssuerEndpoint(credEndpointStr)

        // deferred_credential_endpoint (optional)
        let deferredEndpoint: Option<CredentialIssuerEndpoint> = match (root.get("deferred_credential_endpoint")) {
            case Some(js: JsonString) => Option<CredentialIssuerEndpoint>.Some(CredentialIssuerEndpoint(js.getValue()))
            case _ => Option<CredentialIssuerEndpoint>.None
        }

        // nonce_endpoint (optional)
        let nonceEndpoint: Option<CredentialIssuerEndpoint> = match (root.get("nonce_endpoint")) {
            case Some(js: JsonString) => Option<CredentialIssuerEndpoint>.Some(CredentialIssuerEndpoint(js.getValue()))
            case _ => Option<CredentialIssuerEndpoint>.None
        }

        // notification_endpoint (optional)
        let notifEndpoint: Option<CredentialIssuerEndpoint> = match (root.get("notification_endpoint")) {
            case Some(js: JsonString) => Option<CredentialIssuerEndpoint>.Some(CredentialIssuerEndpoint(js.getValue()))
            case _ => Option<CredentialIssuerEndpoint>.None
        }

        let respEncryption = parseCredentialResponseEncryption(root)
        let reqEncryption = parseCredentialRequestEncryption(root)

        // credential_configurations_supported (raw)
        let configsRaw = HashMap<String, JsonObject>()
        match (root.get("credential_configurations_supported")) {
            case Some(jobj: JsonObject) =>
                for ((key, value) in jobj.getFields()) {
                    match (value) {
                        case credObj: JsonObject => configsRaw.add(key, credObj)
                        case _ => ()
                    }
                }
            case _ => ()
        }

        let displays = parseDisplayArray(root)

        let credIdSupported: Option<Bool> = match (root.get("credential_identifiers_supported")) {
            case Some(jb: JsonBool) => Option<Bool>.Some(jb.getValue())
            case _ => Option<Bool>.None
        }

        let batchIssuance: Option<BatchCredentialIssuance> = match (root.get("batch_credential_issuance")) {
            case Some(jobj: JsonObject) =>
                Option<BatchCredentialIssuance>.Some(BatchCredentialIssuance.fromJson(jobj))
            case _ => Option<BatchCredentialIssuance>.None
        }

        // issuer_info (optional, tolerant — invalid shapes decode to None)
        let issuerInfo: Option<IssuerInfo> = match (root.get("issuer_info")) {
            case Some(v) => IssuerInfo.fromJsonValue(v)
            case None => Option<IssuerInfo>.None
        }

        return CredentialIssuerMetadata(
            issuerId,
            finalAuthServers,
            credEndpoint,
            deferredEndpoint,
            nonceEndpoint,
            notifEndpoint,
            respEncryption,
            reqEncryption,
            configsRaw,
            displays,
            credIdSupported,
            batchIssuance,
            issuerInfo: issuerInfo
        )
    }
}

// ---------------------------------------------------------------------------
// Private parse helpers
// ---------------------------------------------------------------------------

func parseCredentialResponseEncryption(root: JsonObject): CredentialResponseEncryption {
    let algKey = "credential_response_encryption_alg_values_supported"
    let encKey = "credential_response_encryption_enc_values_supported"
    let reqKey = "require_credential_response_encryption"

    let algs = parseStringArray(root, algKey)
    let encs = parseStringArray(root, encKey)
    let required: Bool = match (root.get(reqKey)) {
        case Some(jb: JsonBool) => jb.getValue()
        case _ => false
    }

    if (algs.isEmpty() && encs.isEmpty()) {
        return CredentialResponseEncryption.NotSupported
    }
    if (required) {
        return CredentialResponseEncryption.Required(algs, encs)
    }
    return CredentialResponseEncryption.SupportedNotRequired(algs, encs)
}

func parseCredentialRequestEncryption(root: JsonObject): Option<CredentialRequestEncryption> {
    match (root.get("credential_request_encryption")) {
        case Some(jobj: JsonObject) =>
            let algs = parseStringArray(jobj, "alg_values_supported")
            let encs = parseStringArray(jobj, "enc_values_supported")
            if (algs.isEmpty() && encs.isEmpty()) {
                return Option<CredentialRequestEncryption>.None
            }
            return Option<CredentialRequestEncryption>.Some(
                CredentialRequestEncryption.Supported(algs, encs)
            )
        case _ => return Option<CredentialRequestEncryption>.None
    }
}

func parseDisplayArray(root: JsonObject): Array<Display> {
    match (root.get("display")) {
        case Some(jarr: JsonArray) =>
            let result = ArrayList<Display>()
            for (item in jarr.getItems()) {
                match (item) {
                    case jobj: JsonObject => result.add(Display.fromJson(jobj))
                    case _ => ()
                }
            }
            return result.toArray()
        case _ => return []
    }
}

func parseStringArray(obj: JsonObject, key: String): Array<String> {
    match (obj.get(key)) {
        case Some(jarr: JsonArray) =>
            let result = ArrayList<String>()
            for (item in jarr.getItems()) {
                match (item) {
                    case js: JsonString => result.add(js.getValue())
                    case _ => ()
                }
            }
            return result.toArray()
        case _ => return []
    }
}
