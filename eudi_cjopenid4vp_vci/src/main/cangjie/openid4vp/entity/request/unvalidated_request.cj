/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * unvalidated_request.cj — Unvalidated authorization request types.
 * Ported from iOS: UnvalidatedRequest.swift, UnvalidatedRequestObject.swift,
 * VerifierInfo.swift, FetchedRequest.swift.
 *
 * iOS URL parsing → Cangjie String-based URL (no Foundation.URL).
 * iOS SwiftyJSON (dcqlQuery: JSON) → Cangjie String (serialized JSON snippet).
 * iOS async → sync.
 */
package ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.entity.request

import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.error.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.entity.types.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.entity.dcql.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.entity.client.*
import std.collection.*
import stdx.encoding.json.*

// ---------------------------------------------------------------------------
// VerifierInfo — mirrors iOS VerifierInfo
// ---------------------------------------------------------------------------

public class VerifierInfo {
    public let format: String
    // data stored as raw JSON string
    public let dataJson: String
    public let credentialIds: Option<Array<QueryId>>

    public init(
        format!: String,
        dataJson!: String,
        credentialIds!: Option<Array<QueryId>> = None
    ) {
        this.format = format
        this.dataJson = dataJson
        this.credentialIds = credentialIds
    }

    public static func fromJson(obj: JsonObject): VerifierInfo {
        let fmt = match (obj.get("format")) {
            case Some(s: JsonString) => s.getValue()
            case _ => throw VpValidationError.InvalidVerifierAttestationFormat()
        }
        let dataVal = match (obj.get("data")) {
            case Some(v) => v.toJsonString()
            case None => "{}"
        }
        let credIds: Option<Array<QueryId>> = match (obj.get("credentialIds")) {
            case Some(arr: JsonArray) =>
                var ids = ArrayList<QueryId>()
                for (item in arr.getItems()) {
                    match (item) {
                        case s: JsonString => ids.add(QueryId(s.getValue()))
                        case _ => ()
                    }
                }
                Some(ids.toArray())
            case _ => None
        }
        return VerifierInfo(format: fmt, dataJson: dataVal, credentialIds: credIds)
    }

    // Validate verifier info credential IDs against known DCQL credentials
    public static func validatedVerifierInfo(
        attestations: Option<Array<VerifierInfo>>,
        dcql: DCQL
    ): Option<Array<VerifierInfo>> {
        match (attestations) {
            case None => None
            case Some(atts) =>
                var validIds = HashSet<String>()
                for (cq in dcql.credentials) {
                    validIds.add(cq.queryId.value)
                }
                for (att in atts) {
                    match (att.credentialIds) {
                        case Some(ids) =>
                            for (id in ids) {
                                if (!validIds.contains(id.value)) {
                                    throw VpValidationError.InvalidVerifierAttestationCredentialIds()
                                }
                            }
                        case None => ()
                    }
                }
                Some(atts)
        }
    }
}

// ---------------------------------------------------------------------------
// UnvalidatedRequestObject — mirrors iOS UnvalidatedRequestObject
// All fields are Option<String> (mirrors Swift optionals).
// dcqlQuery stored as raw JSON string.
// verifierInfo stored as Array of raw JSON strings.
// ---------------------------------------------------------------------------

public class UnvalidatedRequestObject {
    public let responseType: Option<String>
    public let responseUri: Option<String>
    public let redirectUri: Option<String>
    public let dcqlQueryJson: Option<String>     // raw JSON string
    public let request: Option<String>           // JWT string (pass-by-value)
    public let requestUri: Option<String>        // URI for pass-by-reference
    public let requestUriMethod: Option<String>
    public let clientMetaData: Option<String>    // raw JSON string
    public let clientId: Option<String>
    public let clientMetadataUri: Option<String>
    public let clientIdScheme: Option<String>
    public let nonce: Option<String>
    public let scope: Option<String>
    public let responseMode: Option<String>
    public let state: Option<String>
    public let supportedAlgorithm: Option<String>
    public let transactionData: Option<Array<String>>
    public let verifierInfoJsons: Option<Array<String>>  // raw JSON strings

    public init(
        responseType!: Option<String> = None,
        responseUri!: Option<String> = None,
        redirectUri!: Option<String> = None,
        dcqlQueryJson!: Option<String> = None,
        request!: Option<String> = None,
        requestUri!: Option<String> = None,
        requestUriMethod!: Option<String> = None,
        clientMetaData!: Option<String> = None,
        clientId!: Option<String> = None,
        clientMetadataUri!: Option<String> = None,
        clientIdScheme!: Option<String> = None,
        nonce!: Option<String> = None,
        scope!: Option<String> = None,
        responseMode!: Option<String> = None,
        state!: Option<String> = None,
        supportedAlgorithm!: Option<String> = None,
        transactionData!: Option<Array<String>> = None,
        verifierInfoJsons!: Option<Array<String>> = None
    ) {
        this.responseType = responseType
        this.responseUri = responseUri
        this.redirectUri = redirectUri
        this.dcqlQueryJson = dcqlQueryJson
        this.request = request
        this.requestUri = requestUri
        this.requestUriMethod = requestUriMethod
        this.clientMetaData = clientMetaData
        this.clientId = clientId
        this.clientMetadataUri = clientMetadataUri
        this.clientIdScheme = clientIdScheme
        this.nonce = nonce
        this.scope = scope
        this.responseMode = responseMode
        this.state = state
        this.supportedAlgorithm = supportedAlgorithm
        this.transactionData = transactionData
        this.verifierInfoJsons = verifierInfoJsons
    }

    public func hasClientMetaData(): Bool {
        clientMetaData.isSome() || clientMetadataUri.isSome()
    }

    public func hasRequests(): Bool {
        request.isSome() || requestUri.isSome()
    }

    public func hasConflicts(): Bool {
        hasClientMetaData() && hasRequests()
    }

    // Parse from URL query string (mirrors iOS UnvalidatedRequestObject.init?(from url: URL))
    public static func fromQueryString(queryString: String): Option<UnvalidatedRequestObject> {
        let params = parseQueryParams(queryString)

        func getParam(name: String): Option<String> {
            match (params.get(name)) {
                case Some(v) => if (v.isEmpty()) { None } else { Some(v) }
                case None => None
            }
        }

        // Parse transaction_data as JSON array of strings
        let transactionData: Option<Array<String>> = match (getParam("transaction_data")) {
            case None => None
            case Some(raw) =>
                try {
                    let parsed = JsonValue.fromStr(raw)
                    match (parsed) {
                        case arr: JsonArray =>
                            var result = ArrayList<String>()
                            for (item in arr.getItems()) {
                                match (item) {
                                    case s: JsonString => result.add(s.getValue())
                                    case _ => ()
                                }
                            }
                            Some(result.toArray())
                        case _ => None
                    }
                } catch (_: Exception) {
                    None
                }
        }

        // Parse verifier_info as Array of raw JSON strings
        let verifierInfoJsons: Option<Array<String>> = match (getParam("verifier_info")) {
            case None => None
            case Some(raw) =>
                try {
                    let parsed = JsonValue.fromStr(raw)
                    match (parsed) {
                        case arr: JsonArray =>
                            var result = ArrayList<String>()
                            for (item in arr.getItems()) {
                                result.add(item.toJsonString())
                            }
                            Some(result.toArray())
                        case _ => None
                    }
                } catch (_: Exception) {
                    None
                }
        }

        return Some(UnvalidatedRequestObject(
            responseType: getParam("response_type"),
            responseUri: getParam("response_uri"),
            redirectUri: getParam("redirect_uri"),
            dcqlQueryJson: getParam("dcql_query"),
            request: getParam("request"),
            requestUri: getParam("request_uri"),
            requestUriMethod: getParam("request_uri_method"),
            clientMetaData: getParam("client_metadata"),
            clientId: getParam("client_id"),
            clientMetadataUri: getParam("client_metadata_uri"),
            clientIdScheme: getParam("client_id_scheme"),
            nonce: getParam("nonce"),
            scope: getParam("scope"),
            responseMode: getParam("response_mode"),
            state: getParam("state"),
            supportedAlgorithm: getParam("supported_algorithm"),
            transactionData: transactionData,
            verifierInfoJsons: verifierInfoJsons
        ))
    }

    // Parse from JsonObject (for JWT payload parsing)
    public static func fromJsonObject(obj: JsonObject): UnvalidatedRequestObject {
        func getStr(key: String): Option<String> {
            match (obj.get(key)) {
                case Some(s: JsonString) => Some(s.getValue())
                case _ => None
            }
        }
        func getStrArray(key: String): Option<Array<String>> {
            match (obj.get(key)) {
                case Some(arr: JsonArray) =>
                    var result = ArrayList<String>()
                    for (item in arr.getItems()) {
                        match (item) {
                            case s: JsonString => result.add(s.getValue())
                            case _ => ()
                        }
                    }
                    Some(result.toArray())
                case _ => None
            }
        }
        func getJsonArrayAsStrings(key: String): Option<Array<String>> {
            match (obj.get(key)) {
                case Some(arr: JsonArray) =>
                    var result = ArrayList<String>()
                    for (item in arr.getItems()) {
                        result.add(item.toJsonString())
                    }
                    Some(result.toArray())
                case _ => None
            }
        }
        let dcqlQueryJson: Option<String> = match (obj.get("dcql_query")) {
            case Some(v) => Some(v.toJsonString())
            case None => None
        }
        // In a signed request (JAR) client_metadata is an embedded JSON object,
        // not a string parameter — serialize it (getStr returned None and the
        // resolver silently fell back to makeDefault, losing the response
        // encryption spec that direct_post.jwt requires).
        let clientMetaDataJson: Option<String> = match (obj.get("client_metadata")) {
            case Some(s: JsonString) => Some(s.getValue())
            case Some(v) => Some(v.toJsonString())
            case None => None
        }

        return UnvalidatedRequestObject(
            responseType: getStr("response_type"),
            responseUri: getStr("response_uri"),
            redirectUri: getStr("redirect_uri"),
            dcqlQueryJson: dcqlQueryJson,
            request: getStr("request"),
            requestUri: getStr("request_uri"),
            requestUriMethod: getStr("request_uri_method"),
            clientMetaData: clientMetaDataJson,
            clientId: getStr("client_id"),
            clientMetadataUri: getStr("client_metadata_uri"),
            clientIdScheme: getStr("client_id_scheme"),
            nonce: getStr("nonce"),
            scope: getStr("scope"),
            responseMode: getStr("response_mode"),
            state: getStr("state"),
            supportedAlgorithm: getStr("supported_algorithm"),
            transactionData: getStrArray("transaction_data"),
            verifierInfoJsons: getJsonArrayAsStrings("verifier_info")
        )
    }

    // Get the response mode (nullable variant — used in dispatcher logic)
    public func validatedResponseMode(): Option<ResponseMode> {
        parseResponseMode(
            this.responseMode,
            this.responseUri,
            this.redirectUri
        )
    }
}

// ---------------------------------------------------------------------------
// UnvalidatedRequest — mirrors iOS UnvalidatedRequest enum
// ---------------------------------------------------------------------------

public abstract sealed class UnvalidatedRequest {
    // Factory: parse from a URI string (mirrors iOS UnvalidatedRequest.make(from:))
    public static func make(uriStr: String): UnvalidatedRequest {
        // Extract query string portion
        let qsOpt = extractQueryString(uriStr)
        let qs = match (qsOpt) { case Some(q) => q; case None => "" }
        let params = parseQueryParams(qs)

        func getParam(name: String): Option<String> {
            match (params.get(name)) {
                case Some(v) => if (v.isEmpty()) { None } else { Some(v) }
                case None => None
            }
        }

        let requestOpt = getParam("request")
        let requestUriOpt = getParam("request_uri")
        let methodOpt: Option<RequestUriMethod> = match (getParam("request_uri_method")) {
            case None => None
            case Some(m) =>
                match (m.toAsciiLower()) {
                    case "get" => Some(RequestUriMethod.GET)
                    case "post" => Some(RequestUriMethod.POST)
                    case _ => throw VpValidationError.InvalidRequestUriMethod()
                }
        }

        let hasRequest = match (requestOpt) { case Some(r) => !r.isEmpty(); case None => false }
        let hasRequestUri = match (requestUriOpt) { case Some(r) => !r.isEmpty(); case None => false }

        if (hasRequest && !hasRequestUri) {
            if (methodOpt.isSome()) {
                throw VpValidationError.InvalidRequestUriMethod()
            }
            let clientId = match (getParam("client_id")) {
                case Some(id) => id
                case None => throw VpValidationError.MissingClientId()
            }
            return JwtSecuredPassByValue(clientId, requestOpt.getOrThrow())
        } else if (!hasRequest && hasRequestUri) {
            let clientId = match (getParam("client_id")) {
                case Some(id) => id
                case None => throw VpValidationError.MissingClientId()
            }
            return JwtSecuredPassByReference(clientId, requestUriOpt.getOrThrow(), methodOpt)
        } else if (!hasRequest && !hasRequestUri) {
            let obj = match (UnvalidatedRequestObject.fromQueryString(qs)) {
                case Some(o) => o
                case None => throw VpValidationError.InvalidAuthorizationData()
            }
            return Plain(obj)
        } else {
            throw VpValidationError.InvalidUseOfBothRequestAndRequestUri()
        }
    }
}

public class Plain <: UnvalidatedRequest {
    public let requestObject: UnvalidatedRequestObject
    public init(obj: UnvalidatedRequestObject) { this.requestObject = obj }
}

public class JwtSecuredPassByValue <: UnvalidatedRequest {
    public let clientId: String
    public let jwt: String  // compact JWT string
    public init(cid: String, jwt: String) {
        this.clientId = cid
        this.jwt = jwt
    }
}

public class JwtSecuredPassByReference <: UnvalidatedRequest {
    public let clientId: String
    public let jwtUri: String  // URI as String (no Foundation.URL)
    public let requestUriMethod: Option<RequestUriMethod>
    public init(cid: String, uri: String, method: Option<RequestUriMethod>) {
        this.clientId = cid
        this.jwtUri = uri
        this.requestUriMethod = method
    }
}

// ---------------------------------------------------------------------------
// FetchedRequest — mirrors iOS FetchedRequest (internal)
// ---------------------------------------------------------------------------

public abstract sealed class FetchedRequest {}

public class PlainFetched <: FetchedRequest {
    public let requestObject: UnvalidatedRequestObject
    public init(obj: UnvalidatedRequestObject) { this.requestObject = obj }
}

public class JwtSecuredFetched <: FetchedRequest {
    public let clientId: String
    public let jwt: String
    public init(cid: String, j: String) {
        this.clientId = cid
        this.jwt = j
    }
}

// ---------------------------------------------------------------------------
// Utility: URL query string parsing
// ---------------------------------------------------------------------------

// Parse application/x-www-form-urlencoded or URL query string into HashMap
public func parseQueryParams(queryString: String): HashMap<String, String> {
    var result = HashMap<String, String>()
    if (queryString.isEmpty()) { return result }
    let pairs = queryString.split("&")
    for (pair in pairs) {
        let eqIdx = pair.indexOf("=")
        match (eqIdx) {
            case None =>
                let key = urlDecodeComponent(pair.trimAscii())
                if (!key.isEmpty()) { result.add(key, "") }
            case Some(idx) =>
                let key = urlDecodeComponent(pair[0..idx].trimAscii())
                let val = urlDecodeComponent(pair[(idx + 1)..].trimAscii())
                if (!key.isEmpty()) { result.add(key, val) }
        }
    }
    return result
}

// Extract query string from a URI (after '?', before '#')
public func extractQueryString(uri: String): Option<String> {
    let qIdx = uri.indexOf("?")
    match (qIdx) {
        case None => None
        case Some(qi) =>
            let after = uri[(qi + 1)..]
            let hashIdx = after.indexOf("#")
            match (hashIdx) {
                case None => Some(after)
                case Some(hi) => Some(after[0..hi])
            }
    }
}

// Percent-decode URL component (replaces %XX sequences and + with space)
public func urlDecodeComponent(encoded: String): String {
    var result = ""
    var bytes = encoded.toArray()
    var i = 0
    while (i < bytes.size) {
        let b = bytes[i]
        if (b == 43u8) {   // '+'
            result = result + " "
            i += 1
        } else if (b == 37u8 && i + 2 < bytes.size) {   // '%'
            let hi = hexVal(bytes[i + 1])
            let lo = hexVal(bytes[i + 2])
            if (hi >= 0 && lo >= 0) {
                let decoded = UInt8(hi * 16 + lo)
                result = result + String.fromUtf8([decoded])
                i += 3
            } else {
                result = result + "%"
                i += 1
            }
        } else {
            result = result + String.fromUtf8([b])
            i += 1
        }
    }
    return result
}

func hexVal(b: UInt8): Int32 {
    let i = Int32(b)
    if (i >= 48 && i <= 57) { return i - 48 }       // 0-9
    if (i >= 65 && i <= 70) { return i - 55 }       // A-F
    if (i >= 97 && i <= 102) { return i - 87 }      // a-f
    return -1
}
