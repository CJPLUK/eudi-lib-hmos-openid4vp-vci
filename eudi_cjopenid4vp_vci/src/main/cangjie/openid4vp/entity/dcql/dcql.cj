/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * dcql.cj — DCQL (Digital Credentials Query Language) data models.
 * Ported from iOS: DCQL.swift, TrustedAuthorityType.swift, ClaimPath.swift,
 * QueryId.swift (VPAliases.swift).
 *
 * iOS Codable JSON → Cangjie stdx.encoding.json JsonObject parsing.
 * Swift Set<QueryId> → Cangjie HashSet<String> (QueryId wraps a validated String).
 */
package ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.entity.dcql

import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.error.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.entity.types.*
import std.collection.*
import stdx.encoding.json.*

// ---------------------------------------------------------------------------
// QueryId — mirrors iOS QueryId
// ---------------------------------------------------------------------------

public class QueryId <: Equatable<QueryId> & Hashable & ToString {
    public let value: String

    public init(value: String) {
        this.value = DCQLId.ensureValid(value)
    }

    public func toString(): String { value }

    public operator func ==(other: QueryId): Bool {
        this.value == other.value
    }

    public func hashCode(): Int64 {
        this.value.hashCode()
    }
}

// ---------------------------------------------------------------------------
// DCQLId — internal validator (mirrors iOS DCQLId)
// ---------------------------------------------------------------------------

class DCQLId {
    static func ensureValid(value: String): String {
        if (value.isEmpty()) {
            throw VpValidationError.EmptyValue()
        }
        // Validate: [a-zA-Z0-9_-]+
        for (b in value.toArray()) {
            if (!isAlphaNumericOrIdByte(b)) {
                throw VpValidationError.InvalidFormat()
            }
        }
        return value
    }

    static func isAlphaNumericOrIdByte(b: UInt8): Bool {
        let i = Int32(b)
        // a-z
        if (i >= 97 && i <= 122) { return true }
        // A-Z
        if (i >= 65 && i <= 90) { return true }
        // 0-9
        if (i >= 48 && i <= 57) { return true }
        // _ = 95, - = 45
        if (i == 95 || i == 45) { return true }
        return false
    }
}

// ---------------------------------------------------------------------------
// ClaimId — mirrors iOS ClaimId (same validation as DCQLId)
// ---------------------------------------------------------------------------

public class ClaimId <: Equatable<ClaimId> & Hashable & ToString {
    public let id: String

    public init(id: String) {
        this.id = DCQLId.ensureValid(id)
    }

    public func toString(): String { id }

    public operator func ==(other: ClaimId): Bool {
        this.id == other.id
    }

    public func hashCode(): Int64 {
        this.id.hashCode()
    }
}

// ---------------------------------------------------------------------------
// ClaimPathElement — mirrors iOS ClaimPathElement
// ---------------------------------------------------------------------------

public abstract sealed class ClaimPathElement <: Equatable<ClaimPathElement> & Hashable {
    public static func allArrayElements(): AllArrayElements { AllArrayElements() }
    public static func arrayElement(index: Int64): ArrayElement { ArrayElement(index) }
    public static func claim(name: String): ClaimName { ClaimName(name) }

    public operator func ==(other: ClaimPathElement): Bool {
        match ((this, other)) {
            case (_: AllArrayElements, _: AllArrayElements) => true
            case (a: ArrayElement, b: ArrayElement) => a.index == b.index
            case (a: ClaimName, b: ClaimName) => a.name == b.name
            case _ => false
        }
    }

    public func hashCode(): Int64 {
        match (this) {
            case _: AllArrayElements => 0i64
            case e: ArrayElement => e.index
            case e: ClaimName => e.name.hashCode()
            case _ => 0i64
        }
    }

    // Check if this element contains (is superset of) the other
    public func contains(other: ClaimPathElement): Bool {
        match ((this, other)) {
            case (_: AllArrayElements, _: AllArrayElements) => true
            case (_: AllArrayElements, _: ArrayElement) => true
            case (_: AllArrayElements, _: ClaimName) => false
            case (a: ArrayElement, b: ArrayElement) => a.index == b.index
            case (a: ClaimName, b: ClaimName) => a.name == b.name
            case _ => false
        }
    }

    public func description(): String {
        match (this) {
            case _: AllArrayElements => "null"
            case e: ArrayElement => e.index.toString()
            case e: ClaimName => e.name
            case _ => ""
        }
    }
}

public class AllArrayElements <: ClaimPathElement {
    public init() {}
}

public class ArrayElement <: ClaimPathElement {
    public let index: Int64
    public init(idx: Int64) {
        this.index = idx
    }
}

public class ClaimName <: ClaimPathElement {
    public let name: String
    public init(n: String) {
        this.name = n
    }
}

// ---------------------------------------------------------------------------
// ClaimPath — mirrors iOS ClaimPath
// ---------------------------------------------------------------------------

public class ClaimPath <: Equatable<ClaimPath> & Hashable {
    public let value: Array<ClaimPathElement>

    public init(value: Array<ClaimPathElement>) {
        this.value = value
    }

    public static func claim(name: String): ClaimPath {
        ClaimPath([ClaimPathElement.claim(name)])
    }

    public func claimAppend(name: String): ClaimPath {
        var next = ArrayList<ClaimPathElement>()
        for (e in value) { next.add(e) }
        next.add(ClaimPathElement.claim(name))
        return ClaimPath(next.toArray())
    }

    public func arrayElementAppend(index: Int64): ClaimPath {
        var next = ArrayList<ClaimPathElement>()
        for (e in value) { next.add(e) }
        next.add(ClaimPathElement.arrayElement(index))
        return ClaimPath(next.toArray())
    }

    public func allArrayElementsAppend(): ClaimPath {
        var next = ArrayList<ClaimPathElement>()
        for (e in value) { next.add(e) }
        next.add(ClaimPathElement.allArrayElements())
        return ClaimPath(next.toArray())
    }

    public func contains(that: ClaimPath): Bool {
        if (that.value.size > this.value.size) { return false }
        for (i in 0..that.value.size) {
            if (!this.value[i].contains(that.value[i])) { return false }
        }
        return true
    }

    // Wildcard-aware element-wise containment over the common prefix.
    // Mirrors iOS wallet-kit `ClaimPath.contains2(_:)`:
    //   zip(self.value, that.value).allSatisfy { $0.contains($1) }
    // The zip truncates to the shorter path, so an ancestor policy path
    // contains all of its descendants and AllArrayElements matches any index.
    public func contains2(that: ClaimPath): Bool {
        let n = if (this.value.size < that.value.size) { this.value.size } else { that.value.size }
        for (i in 0..n) {
            if (!this.value[i].contains(that.value[i])) { return false }
        }
        return true
    }

    public operator func ==(other: ClaimPath): Bool {
        if (this.value.size != other.value.size) { return false }
        for (i in 0..this.value.size) {
            if (!(this.value[i] == other.value[i])) { return false }
        }
        return true
    }

    public func hashCode(): Int64 {
        var h = 0i64
        for (e in value) {
            h = h * 31i64 + e.hashCode()
        }
        return h
    }

    // Parse ClaimPath from JSON array — element is null→allArrayElements, int→arrayElement, string→claim
    public static func fromJsonArray(arr: JsonArray): ClaimPath {
        var elements = ArrayList<ClaimPathElement>()
        for (item in arr.getItems()) {
            match (item) {
                case n: JsonNull => elements.add(ClaimPathElement.allArrayElements())
                case n: JsonInt => elements.add(ClaimPathElement.arrayElement(n.getValue()))
                case n: JsonString => elements.add(ClaimPathElement.claim(n.getValue()))
                case _ => elements.add(ClaimPathElement.claim(item.toJsonString()))
            }
        }
        return ClaimPath(elements.toArray())
    }
}

// ---------------------------------------------------------------------------
// TrustedAuthorityType — mirrors iOS TrustedAuthorityType
// ---------------------------------------------------------------------------

public class TrustedAuthorityType <: Equatable<TrustedAuthorityType> & Hashable & ToString {
    public let value: String

    public init(value: String) {
        let trimmed = value.trimAscii()
        if (trimmed.isEmpty()) {
            throw VpValidationError.BlankTrustedAuthorityType()
        }
        this.value = value
    }

    public static let authorityKeyIdentifier: TrustedAuthorityType =
        TrustedAuthorityType(OpenId4VPSpec.DCQL_TRUSTED_AUTHORITY_TYPE_AKI)
    public static let trustedList: TrustedAuthorityType =
        TrustedAuthorityType(OpenId4VPSpec.DCQL_TRUSTED_AUTHORITY_TYPE_ETSI_TL)
    public static let openIdFederation: TrustedAuthorityType =
        TrustedAuthorityType(OpenId4VPSpec.DCQL_TRUSTED_AUTHORITY_TYPE_OPENID_FEDERATION)

    public func toString(): String { value }

    public operator func ==(other: TrustedAuthorityType): Bool {
        this.value == other.value
    }

    public func hashCode(): Int64 {
        this.value.hashCode()
    }
}

// ---------------------------------------------------------------------------
// TrustedAuthority — mirrors iOS TrustedAuthority
// ---------------------------------------------------------------------------

public class TrustedAuthority {
    public let authorityType: TrustedAuthorityType
    public let values: Array<String>

    public init(authorityType: TrustedAuthorityType, values: Array<String>) {
        if (values.isEmpty()) {
            throw VpValidationError.ValidationError("TrustedAuthority values cannot be empty")
        }
        for (v in values) {
            if (v.trimAscii().isEmpty()) {
                throw VpValidationError.ValidationError("TrustedAuthority values cannot contain blank strings")
            }
        }
        this.authorityType = authorityType
        this.values = values
    }

    public static func authorityKeyIdentifiers(values: Array<String>): TrustedAuthority {
        TrustedAuthority(TrustedAuthorityType.authorityKeyIdentifier, values)
    }

    public static func trustedLists(values: Array<String>): TrustedAuthority {
        TrustedAuthority(TrustedAuthorityType.trustedList, values)
    }

    public static func federatedEntities(values: Array<String>): TrustedAuthority {
        TrustedAuthority(TrustedAuthorityType.openIdFederation, values)
    }

    // Parse from JsonObject
    public static func fromJson(obj: JsonObject): TrustedAuthority {
        let typeVal = match (obj.get("trusted_authority_type")) {
            case Some(v: JsonString) => v.getValue()
            case _ => throw VpValidationError.ValidationError("TrustedAuthority missing type")
        }
        let authorityType = TrustedAuthorityType(typeVal)
        let valuesArr = match (obj.get("trusted_authority_values")) {
            case Some(arr: JsonArray) => arr
            case _ => throw VpValidationError.ValidationError("TrustedAuthority missing values")
        }
        var vals = ArrayList<String>()
        for (item in valuesArr.getItems()) {
            match (item) {
                case s: JsonString => vals.add(s.getValue())
                case _ => throw VpValidationError.ValidationError("TrustedAuthority value is not a string")
            }
        }
        return TrustedAuthority(authorityType, vals.toArray())
    }
}

// ---------------------------------------------------------------------------
// Format — mirrors iOS Format
// ---------------------------------------------------------------------------

public class Format <: Equatable<Format> & Hashable & ToString {
    public let format: String

    public init(format: String) {
        let trimmed = format.trimAscii()
        if (trimmed.isEmpty()) {
            throw VpValidationError.ValidationError("Format cannot be blank")
        }
        this.format = format
    }

    public static func msoMdoc(): Format { Format(OpenId4VPSpec.FORMAT_MSO_MDOC) }
    public static func sdJwtVc(): Format { Format(OpenId4VPSpec.FORMAT_SD_JWT_VC) }
    public static func w3cJwtVcJson(): Format { Format(OpenId4VPSpec.FORMAT_W3C_SIGNED_JWT) }

    public func toString(): String { format }

    public operator func ==(other: Format): Bool {
        this.format == other.format
    }

    public func hashCode(): Int64 {
        this.format.hashCode()
    }
}

// ---------------------------------------------------------------------------
// ClaimsQuery — mirrors iOS ClaimsQuery
// ---------------------------------------------------------------------------

public class ClaimsQuery {
    public let claimId: Option<ClaimId>
    public let path: ClaimPath
    public let values: Option<Array<String>>
    public let intentToRetain: Option<Bool>

    public init(
        claimId!: Option<ClaimId> = None,
        path!: ClaimPath,
        values!: Option<Array<String>> = None,
        intentToRetain!: Option<Bool> = None
    ) {
        this.claimId = claimId
        this.path = path
        this.values = values
        this.intentToRetain = intentToRetain
    }

    // Factory for SD-JWT VC claims (no intent_to_retain)
    public static func sdJwtVc(
        claimId!: Option<ClaimId> = None,
        path!: ClaimPath,
        values!: Option<Array<String>> = None
    ): ClaimsQuery {
        let q = ClaimsQuery(claimId: claimId, path: path, values: values)
        ensureNotMsoMdoc(q)
        return q
    }

    // Factory for MSO MDOC claims (namespace + claimName)
    public static func mdoc(
        claimId!: Option<ClaimId> = None,
        namespace!: String,
        claimName!: String,
        values!: Option<Array<String>> = None,
        intentToRetain!: Option<Bool> = None
    ): ClaimsQuery {
        let path = ClaimPath.claim(namespace).claimAppend(claimName)
        let q = ClaimsQuery(claimId: claimId, path: path, values: values, intentToRetain: intentToRetain)
        ensureMsoMdoc(q)
        return q
    }

    // Parse from JsonObject
    public static func fromJson(obj: JsonObject): ClaimsQuery {
        let claimId: Option<ClaimId> = match (obj.get("id")) {
            case Some(s: JsonString) => Some(ClaimId(s.getValue()))
            case _ => None
        }
        let pathArr = match (obj.get("path")) {
            case Some(arr: JsonArray) => arr
            case _ => throw VpValidationError.ValidationError("ClaimsQuery missing path")
        }
        let path = ClaimPath.fromJsonArray(pathArr)
        let values: Option<Array<String>> = match (obj.get("values")) {
            case Some(arr: JsonArray) =>
                var vs = ArrayList<String>()
                for (item in arr.getItems()) {
                    match (item) {
                        case s: JsonString => vs.add(s.getValue())
                        case _ => ()
                    }
                }
                Some(vs.toArray())
            case _ => None
        }
        let intentToRetain: Option<Bool> = match (obj.get("intent_to_retain")) {
            case Some(b: JsonBool) => Some(b.getValue())
            case _ => None
        }
        return ClaimsQuery(claimId: claimId, path: path, values: values, intentToRetain: intentToRetain)
    }
}

// Validation helpers
func ensureMsoMdoc(q: ClaimsQuery): Unit {
    if (q.path.value.size < 2) {
        throw DCQLError.Error(
            "Claim paths for mso mdoc must have at least two elements (namespace and element identifier)"
        )
    }
    for (i in 0..2) {
        match (q.path.value[i]) {
            case _: ClaimName => ()
            case _ => throw DCQLError.Error(
                "The first two elements of an MSO MDoc ClaimPath must be Claim elements"
            )
        }
    }
}

func ensureNotMsoMdoc(q: ClaimsQuery): Unit {
    match (q.intentToRetain) {
        case Some(_) => throw DCQLError.Error(
            OpenId4VPSpec.DCQL_MSO_MDOC_INTENT_TO_RETAIN + " can only be used with mso mdoc formats"
        )
        case None => ()
    }
}

// ---------------------------------------------------------------------------
// CredentialQuery — mirrors iOS CredentialQuery
// ---------------------------------------------------------------------------

public class CredentialQuery {
    public let queryId: QueryId
    public let format: Format
    // meta stored as raw JSON string (since SwiftyJSON maps to stdx JSON)
    public let metaJson: Option<String>
    public let claims: Option<Array<ClaimsQuery>>
    public let claimSets: Option<Array<Array<String>>>  // Set<ClaimId> → Array<String>
    public let multiple: Option<Bool>
    public let trustedAuthorities: Option<Array<TrustedAuthority>>
    public let requireCryptographicHolderBinding: Option<Bool>

    public init(
        queryId!: QueryId,
        format!: Format,
        metaJson!: Option<String> = None,
        claims!: Option<Array<ClaimsQuery>> = None,
        claimSets!: Option<Array<Array<String>>> = None,
        multiple!: Option<Bool> = None,
        trustedAuthorities!: Option<Array<TrustedAuthority>> = None,
        requireCryptographicHolderBinding!: Option<Bool> = None
    ) {
        match (trustedAuthorities) {
            case Some(ta) =>
                if (ta.isEmpty()) {
                    throw VpValidationError.ValidationError("Empty TrustedAuthorities")
                }
            case None => ()
        }
        this.queryId = queryId
        this.format = format
        this.metaJson = metaJson
        this.claims = claims
        this.claimSets = claimSets
        this.multiple = multiple
        this.trustedAuthorities = trustedAuthorities
        this.requireCryptographicHolderBinding = requireCryptographicHolderBinding
    }

    // Parse from JsonObject
    public static func fromJson(obj: JsonObject): CredentialQuery {
        let idStr = match (obj.get("id")) {
            case Some(s: JsonString) => s.getValue()
            case _ => throw VpValidationError.ValidationError("CredentialQuery missing id")
        }
        let queryId = QueryId(idStr)

        let fmtStr = match (obj.get("format")) {
            case Some(s: JsonString) => s.getValue()
            case _ => throw VpValidationError.ValidationError("CredentialQuery missing format")
        }
        let format = Format(fmtStr)

        let metaJson: Option<String> = match (obj.get("meta")) {
            case Some(v) => Some(v.toJsonString())
            case None => None
        }

        let claims: Option<Array<ClaimsQuery>> = match (obj.get("claims")) {
            case Some(arr: JsonArray) =>
                var cqs = ArrayList<ClaimsQuery>()
                for (item in arr.getItems()) {
                    match (item) {
                        case cObj: JsonObject => cqs.add(ClaimsQuery.fromJson(cObj))
                        case _ => ()
                    }
                }
                Some(cqs.toArray())
            case _ => None
        }

        let multiple: Option<Bool> = match (obj.get("multiple")) {
            case Some(b: JsonBool) => Some(b.getValue())
            case _ => None
        }

        let requireCryptoHB: Option<Bool> = match (obj.get("require_cryptographic_holder_binding")) {
            case Some(b: JsonBool) => Some(b.getValue())
            case _ => None
        }

        let trustedAuthorities: Option<Array<TrustedAuthority>> = match (obj.get("trusted_authorities")) {
            case Some(arr: JsonArray) =>
                var tas = ArrayList<TrustedAuthority>()
                for (item in arr.getItems()) {
                    match (item) {
                        case taObj: JsonObject => tas.add(TrustedAuthority.fromJson(taObj))
                        case _ => ()
                    }
                }
                if (tas.isEmpty()) { None } else { Some(tas.toArray()) }
            case _ => None
        }

        return CredentialQuery(
            queryId: queryId,
            format: format,
            metaJson: metaJson,
            claims: claims,
            multiple: multiple,
            trustedAuthorities: trustedAuthorities,
            requireCryptographicHolderBinding: requireCryptoHB
        )
    }
}

// ---------------------------------------------------------------------------
// CredentialSetQuery — mirrors iOS CredentialSetQuery
// ---------------------------------------------------------------------------

public class CredentialSetQuery {
    // options: Array of Array<QueryId> (Set<QueryId> → Array)
    public let options: Array<Array<QueryId>>
    public let required: Option<Bool>

    public static let defaultRequiredValue: Bool = true

    public init(options: Array<Array<QueryId>>, required!: Option<Bool> = None) {
        for (credSet in options) {
            if (credSet.isEmpty()) {
                throw DCQLError.EmptyCredentialSet()
            }
        }
        this.options = options
        this.required = required
    }

    // Parse from JsonObject
    public static func fromJson(obj: JsonObject): CredentialSetQuery {
        let optionsArr = match (obj.get("options")) {
            case Some(arr: JsonArray) => arr
            case _ => throw VpValidationError.ValidationError("CredentialSetQuery missing options")
        }
        var opts = ArrayList<Array<QueryId>>()
        for (item in optionsArr.getItems()) {
            match (item) {
                case setArr: JsonArray =>
                    var set = ArrayList<QueryId>()
                    for (elem in setArr.getItems()) {
                        match (elem) {
                            case s: JsonString => set.add(QueryId(s.getValue()))
                            case _ => ()
                        }
                    }
                    opts.add(set.toArray())
                case _ => ()
            }
        }
        let required: Option<Bool> = match (obj.get("required")) {
            case Some(b: JsonBool) => Some(b.getValue())
            case _ => None
        }
        return CredentialSetQuery(opts.toArray(), required: required)
    }
}

// ---------------------------------------------------------------------------
// DCQL — mirrors iOS DCQL
// ---------------------------------------------------------------------------

public class DCQL {
    public let credentials: Array<CredentialQuery>
    public let credentialSets: Option<Array<CredentialSetQuery>>

    public init(
        credentials: Array<CredentialQuery>,
        credentialSets!: Option<Array<CredentialSetQuery>> = None
    ) {
        if (credentials.isEmpty()) {
            throw DCQLError.EmptyCredentials()
        }
        // Ensure unique IDs
        var seen = HashSet<String>()
        for (cq in credentials) {
            if (seen.contains(cq.queryId.value)) {
                throw DCQLError.DuplicateQueryId()
            }
            seen.add(cq.queryId.value)
        }
        // Validate credential sets reference known IDs
        match (credentialSets) {
            case Some(sets) =>
                for (cs in sets) {
                    for (optionSet in cs.options) {
                        for (qid in optionSet) {
                            if (!seen.contains(qid.value)) {
                                throw DCQLError.UnknownQueryId()
                            }
                        }
                    }
                }
            case None => ()
        }
        this.credentials = credentials
        this.credentialSets = credentialSets
    }

    // Parse from JsonObject (mirrors iOS DCQL.init(from json: JSON))
    public static func fromJson(obj: JsonObject): DCQL {
        let credArr = match (obj.get("credentials")) {
            case Some(arr: JsonArray) => arr
            case _ => throw VpValidationError.ValidationError("DCQL missing credentials")
        }
        var creds = ArrayList<CredentialQuery>()
        for (item in credArr.getItems()) {
            match (item) {
                case cObj: JsonObject => creds.add(CredentialQuery.fromJson(cObj))
                case _ => ()
            }
        }

        var credSets: Option<Array<CredentialSetQuery>> = None
        match (obj.get("credential_sets")) {
            case Some(arr: JsonArray) =>
                var sets = ArrayList<CredentialSetQuery>()
                for (item in arr.getItems()) {
                    match (item) {
                        case csObj: JsonObject => sets.add(CredentialSetQuery.fromJson(csObj))
                        case _ => ()
                    }
                }
                credSets = Some(sets.toArray())
            case _ => ()
        }

        return DCQL(creds.toArray(), credentialSets: credSets)
    }

    // Parse DCQL from a JSON string (used from query params)
    public static func fromJsonString(jsonStr: String): DCQL {
        let parsed = JsonValue.fromStr(jsonStr)
        match (parsed) {
            case obj: JsonObject => DCQL.fromJson(obj)
            case _ => throw VpValidationError.ValidationError("DCQL JSON is not an object")
        }
    }
}

// ---------------------------------------------------------------------------
// PresentationQuery — mirrors iOS PresentationQuery
// ---------------------------------------------------------------------------

public abstract sealed class PresentationQuery {
    public static func byDigitalCredentialsQuery(dcql: DCQL): DCQLQuery { DCQLQuery(dcql) }
}

public class DCQLQuery <: PresentationQuery {
    public let dcql: DCQL
    public init(d: DCQL) { this.dcql = d }
}

// ---------------------------------------------------------------------------
// QuerySource — mirrors iOS QuerySource
// ---------------------------------------------------------------------------

public abstract sealed class QuerySource {
    public static func dcqlQuery(dcql: DCQL): DcqlQuerySource { DcqlQuerySource(dcql) }
    public static func byScope(scope: String): ByScopeSource { ByScopeSource(scope) }
}

public class DcqlQuerySource <: QuerySource {
    public let dcql: DCQL
    public init(d: DCQL) { this.dcql = d }
}

public class ByScopeSource <: QuerySource {
    public let scope: String
    public init(s: String) { this.scope = s }
}

// ---------------------------------------------------------------------------
// VpContent — mirrors iOS VpContent (block 5 will use for response building)
// ---------------------------------------------------------------------------

public abstract sealed class VerifiablePresentation {
    public static func generic(value: String): GenericPresentation { GenericPresentation(value) }
    public static func json(jsonStr: String): JsonPresentation { JsonPresentation(jsonStr) }
}

public class GenericPresentation <: VerifiablePresentation {
    public let value: String
    public init(v: String) { this.value = v }
}

public class JsonPresentation <: VerifiablePresentation {
    public let jsonStr: String
    public init(j: String) { this.jsonStr = j }
}
