/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * validated_request.cj — Validated authorization request data.
 * Ported from iOS: ValidatedRequestData.swift, VpTokenRequest (nested struct),
 * TransactionData.swift (VP side).
 *
 * iOS Codable/SwiftyJSON → Cangjie stdx.encoding.json.
 * Base64URL decode → std.crypto.digest / manual base64 (stdx doesn't expose base64url).
 */
package ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.entity.request

import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.error.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.entity.types.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.entity.dcql.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.entity.client.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.entity.metadata.*
import std.collection.*
import stdx.encoding.json.*

// ---------------------------------------------------------------------------
// TransactionData — mirrors iOS TransactionData
// Base64URL-encoded JSON blob; decoded lazily.
// ---------------------------------------------------------------------------

public class TransactionData {
    public let value: String  // base64url-encoded string

    public init(value: String) {
        this.value = value
    }

    // Build a TransactionData from type + credentialIds (base64url-encoded JSON)
    public static func create(
        dataType: TransactionDataType,
        credentialIds: Array<QueryId>,
        hashAlgorithms!: Option<Array<HashAlgorithm>> = None
    ): TransactionData {
        var obj = JsonObject()
        obj.put(OpenId4VPSpec.TRANSACTION_DATA_TYPE, JsonString(dataType.toString()))
        var idsArr = JsonArray()
        for (qid in credentialIds) {
            idsArr.add(JsonString(qid.value))
        }
        obj.put(OpenId4VPSpec.TRANSACTION_DATA_CREDENTIAL_IDS, idsArr)
        match (hashAlgorithms) {
            case Some(algs) =>
                if (!algs.isEmpty()) {
                    var algArr = JsonArray()
                    for (a in algs) {
                        algArr.add(JsonString(a.name))
                    }
                    obj.put(OpenId4VPSpec.TRANSACTION_DATA_HASH_ALGORITHMS, algArr)
                }
            case None => ()
        }
        let jsonStr = obj.toJsonString()
        let encoded = base64UrlEncode(jsonStr.toArray())
        return TransactionData(encoded)
    }

    // Decode and parse the inner JSON
    public func decode(): JsonObject {
        let decoded = base64UrlDecode(value)
        let jsonStr = String.fromUtf8(decoded)
        let parsed = JsonValue.fromStr(jsonStr)
        match (parsed) {
            case obj: JsonObject => obj
            case _ => throw VpValidationError.ValidationError("Unable to decode transaction data")
        }
    }

    public func dataType(): TransactionDataType {
        let obj = decode()
        let typeStr = match (obj.get(OpenId4VPSpec.TRANSACTION_DATA_TYPE)) {
            case Some(s: JsonString) => s.getValue()
            case _ => throw VpValidationError.ValidationError("TransactionData missing type")
        }
        TransactionDataType(typeStr)
    }

    public func credentialIds(): Array<QueryId> {
        let obj = decode()
        let arr = match (obj.get(OpenId4VPSpec.TRANSACTION_DATA_CREDENTIAL_IDS)) {
            case Some(a: JsonArray) => a
            case _ => throw VpValidationError.ValidationError("TransactionData missing credential_ids")
        }
        var result = ArrayList<QueryId>()
        for (item in arr.getItems()) {
            match (item) {
                case s: JsonString => result.add(QueryId(s.getValue()))
                case _ => ()
            }
        }
        return result.toArray()
    }

    public func hashAlgorithms(): Array<HashAlgorithm> {
        let obj = decode()
        match (obj.get(OpenId4VPSpec.TRANSACTION_DATA_HASH_ALGORITHMS)) {
            case Some(arr: JsonArray) =>
                var result = ArrayList<HashAlgorithm>()
                for (item in arr.getItems()) {
                    match (item) {
                        case s: JsonString => result.add(HashAlgorithm(s.getValue()))
                        case _ => ()
                    }
                }
                return result.toArray()
            case _ => [HashAlgorithm.sha256]
        }
    }

    // Parse from a base64url string, validating type and credential IDs
    public static func parse(
        s: String,
        supportedTypes: Array<SupportedTransactionDataType>,
        presentationQuery: PresentationQuery
    ): Option<TransactionData> {
        let td = TransactionData(s)
        // Validate type
        var actualTypeOpt: Option<TransactionDataType> = None
        try {
            actualTypeOpt = Some(td.dataType())
        } catch (_: Exception) {
            return None
        }
        let actualType = actualTypeOpt.getOrThrow()
        var typeSupported = false
        for (st in supportedTypes) {
            if (st.dataType == actualType) {
                typeSupported = true
                break
            }
        }
        if (!typeSupported) { return None }
        // Validate credential IDs
        let knownIds: Array<String> = match (presentationQuery) {
            case q: DCQLQuery => q.dcql.credentials.map<String> { c => c.queryId.value }
            case _ => Array<String>()
        }
        var requestedIdsOpt: Option<Array<QueryId>> = None
        try {
            requestedIdsOpt = Some(td.credentialIds())
        } catch (_: Exception) {
            return None
        }
        let requestedIds = requestedIdsOpt.getOrThrow()
        for (reqId in requestedIds) {
            var found = false
            for (known in knownIds) {
                if (known == reqId.value) { found = true; break }
            }
            if (!found) { return None }
        }
        return Some(td)
    }
}

// ---------------------------------------------------------------------------
// Base64URL encode/decode utilities
// (stdx.encoding.base64 is standard base64; we adapt for base64url here)
// ---------------------------------------------------------------------------

func base64UrlEncode(bytes: Array<UInt8>): String {
    // Standard base64 alphabet + pad, then replace and strip padding
    let b64 = base64Encode(bytes)
    var result = ""
    for (c in b64.runes()) {
        match (c) {
            case '+' => result = result + "-"
            case '/' => result = result + "_"
            case '=' => ()  // strip padding
            case other => result = result + String(other)
        }
    }
    return result
}

public func base64UrlDecode(encoded: String): Array<UInt8> {
    // Restore standard base64 alphabet + padding
    var b64 = ""
    for (c in encoded.runes()) {
        match (c) {
            case '-' => b64 = b64 + "+"
            case '_' => b64 = b64 + "/"
            case other => b64 = b64 + String(other)
        }
    }
    // Add padding
    let rem = b64.size % 4
    if (rem == 2) { b64 = b64 + "==" }
    else if (rem == 3) { b64 = b64 + "=" }
    return base64Decode(b64)
}

// Simple base64 encode (RFC 4648 standard alphabet)
func base64Encode(bytes: Array<UInt8>): String {
    let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".toArray()
    var result = ""
    var i = 0
    while (i < bytes.size) {
        let b0 = Int64(bytes[i])
        let b1 = if (i + 1 < bytes.size) { Int64(bytes[i + 1]) } else { 0i64 }
        let b2 = if (i + 2 < bytes.size) { Int64(bytes[i + 2]) } else { 0i64 }
        let c0 = b0 >> 2
        let c1 = ((b0 & 3) << 4) | (b1 >> 4)
        let c2 = ((b1 & 15) << 2) | (b2 >> 6)
        let c3 = b2 & 63
        result = result + String.fromUtf8([alphabet[c0]])
        result = result + String.fromUtf8([alphabet[c1]])
        if (i + 1 < bytes.size) {
            result = result + String.fromUtf8([alphabet[c2]])
        } else {
            result = result + "="
        }
        if (i + 2 < bytes.size) {
            result = result + String.fromUtf8([alphabet[c3]])
        } else {
            result = result + "="
        }
        i += 3
    }
    return result
}

// Simple base64 decode (RFC 4648 standard alphabet)
func base64Decode(encoded: String): Array<UInt8> {
    func charVal(c: Rune): Int64 {
        let i = Int64(UInt32(c))
        if (i >= 65 && i <= 90) { return i - 65 }           // A-Z
        if (i >= 97 && i <= 122) { return i - 97 + 26 }     // a-z
        if (i >= 48 && i <= 57) { return i - 48 + 52 }      // 0-9
        if (i == 43) { return 62 }   // +
        if (i == 47) { return 63 }   // /
        return -1
    }
    var result = ArrayList<UInt8>()
    let chars = encoded.toRuneArray()
    var i = 0
    while (i + 3 < chars.size) {
        let v0 = charVal(chars[i])
        let v1 = charVal(chars[i + 1])
        let v2 = charVal(chars[i + 2])
        let v3 = charVal(chars[i + 3])
        if (v0 < 0 || v1 < 0) { break }
        result.add(UInt8((v0 << 2) | (v1 >> 4)))
        if (v2 >= 0) { result.add(UInt8(((v1 & 15) << 4) | (v2 >> 2))) }
        if (v3 >= 0) { result.add(UInt8(((v2 & 3) << 6) | v3)) }
        i += 4
    }
    return result.toArray()
}

// ---------------------------------------------------------------------------
// VpTokenRequest — mirrors iOS ValidatedRequestData.VpTokenRequest (nested)
// ---------------------------------------------------------------------------

public class VpTokenRequest {
    public let querySource: QuerySource
    public let clientMetaDataSource: Option<ClientMetaDataSource>
    public let clientId: String
    public let client: Client
    public let nonce: String
    public let responseMode: Option<ResponseMode>
    public let requestUriMethod: RequestUriMethod
    public let state: Option<String>
    public let vpFormatsSupported: VpFormatsSupported
    public let transactionData: Option<Array<String>>  // raw base64url strings
    public let verifierInfoJsons: Option<Array<String>>  // raw JSON strings

    public init(
        querySource!: QuerySource,
        clientMetaDataSource!: Option<ClientMetaDataSource> = None,
        clientId!: String,
        client!: Client,
        nonce!: String,
        responseMode!: Option<ResponseMode> = None,
        requestUriMethod!: RequestUriMethod = RequestUriMethod.GET,
        state!: Option<String> = None,
        vpFormatsSupported!: VpFormatsSupported,
        transactionData!: Option<Array<String>> = None,
        verifierInfoJsons!: Option<Array<String>> = None
    ) {
        this.querySource = querySource
        this.clientMetaDataSource = clientMetaDataSource
        this.clientId = clientId
        this.client = client
        this.nonce = nonce
        this.responseMode = responseMode
        this.requestUriMethod = requestUriMethod
        this.state = state
        this.vpFormatsSupported = vpFormatsSupported
        this.transactionData = transactionData
        this.verifierInfoJsons = verifierInfoJsons
    }
}

// ---------------------------------------------------------------------------
// ValidatedRequestData — mirrors iOS ValidatedRequestData
// ---------------------------------------------------------------------------

public class ValidatedRequestData {
    let request: VpTokenRequest

    public init(request: VpTokenRequest) {
        this.request = request
    }

    public func responseMode(): Option<ResponseMode> { request.responseMode }
    public func nonce(): String { request.nonce }
    public func state(): Option<String> { request.state }
    public func clientId(): VerifierId { request.client.id() }

    // Build ValidatedRequestData from a plain (non-JWT) UnvalidatedRequestObject
    // This implements the core validation flow.
    public static func fromPlainRequest(
        requestObject: UnvalidatedRequestObject,
        client: Client
    ): ValidatedRequestData {
        // Validate nonce
        let nonce = match (requestObject.nonce) {
            case Some(n) => n
            case None => throw VpValidationError.MissingNonce()
        }

        // Validate response_type
        let responseTypeStr = match (requestObject.responseType) {
            case Some(rt) => rt
            case None => throw VpValidationError.MissingResponseType()
        }
        match (ResponseType.fromRawValue(responseTypeStr)) {
            case None => throw VpValidationError.UnsupportedResponseType(responseTypeStr)
            case Some(ResponseType.VpToken) => ()  // only vp_token supported
            case Some(ResponseType.Code) => throw VpValidationError.UnsupportedResponseType(responseTypeStr)
        }

        // Parse response mode (optional for plain requests)
        let responseMode = requestObject.validatedResponseMode()

        // Parse DCQL query
        let querySource: QuerySource = match (requestObject.dcqlQueryJson) {
            case Some(dcqlJson) =>
                let dcql = DCQL.fromJsonString(dcqlJson)
                DcqlQuerySource(dcql)
            case None =>
                // Scope-based lookup not yet supported
                throw VpValidationError.MissingRequiredField("dcql_query")
        }

        // Parse requestUriMethod
        let requestUriMethod = RequestUriMethod.fromString(requestObject.requestUriMethod)

        // Parse vpFormatsSupported from client metadata (if available)
        let vpFormats: VpFormatsSupported = match (requestObject.clientMetaData) {
            case Some(metaStr) =>
                let meta = ClientMetaData.fromJsonString(metaStr)
                match (meta.vpFormatsSupported) {
                    case Some(f) => f
                    case None => VpFormatsSupported.makeDefault()
                }
            case None => VpFormatsSupported.makeDefault()
        }

        // Build client metadata source
        let clientMetaDataSource: Option<ClientMetaDataSource> = match (requestObject.clientMetaData) {
            case Some(metaStr) => Some(PassByValueSource(metaStr))
            case None => None
        }

        let vpTokenRequest = VpTokenRequest(
            querySource: querySource,
            clientMetaDataSource: clientMetaDataSource,
            clientId: match (requestObject.clientId) { case Some(id) => id; case None => "" },
            client: client,
            nonce: nonce,
            responseMode: responseMode,
            requestUriMethod: requestUriMethod,
            state: requestObject.state,
            vpFormatsSupported: vpFormats,
            transactionData: requestObject.transactionData,
            verifierInfoJsons: requestObject.verifierInfoJsons
        )

        return ValidatedRequestData(vpTokenRequest)
    }
}
