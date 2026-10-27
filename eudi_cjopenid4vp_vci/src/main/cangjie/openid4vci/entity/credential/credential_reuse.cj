/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * credential_reuse.cj — Credential reuse policy model and validator.
 *
 * Ported from iOS:
 *   - Sources/Entities/CredentialReuse/ReuseMethod.swift
 *   - Sources/Entities/CredentialReuse/ReusePolicy.swift
 *   - Sources/Entities/CredentialReuse/ReusePolicyOption.swift
 *   - Sources/Entities/CredentialReuse/CredentialReusePolicy.swift
 *   - Sources/Entities/CredentialReuse/SupportedCredentialReusePolicies.swift
 *   - Sources/Main/Validators/CredentialReusePolicyValidator.swift
 *
 * iOS Swift Set → Cangjie: HashSet not available in stdx, use Array<ReuseMethod>
 * with linear contains check.
 * iOS Codable → manual JSON parse.
 */
package ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.credential

import std.collection.*
import stdx.encoding.json.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.error.{ValidationError, CredentialReusePolicyError}

// ---------------------------------------------------------------------------
// ReuseMethod
// Ported from iOS enum ReuseMethod.
// ---------------------------------------------------------------------------

public enum ReuseMethod {
    | OnceOnly           // "once_only"
    | LimitedTime        // "limited_time"
    | RotatingBatch      // "rotating-batch"
    | PerRelyingParty    // "per-relying-party"

    public func rawValue(): String {
        match (this) {
            case OnceOnly => "once_only"
            case LimitedTime => "limited_time"
            case RotatingBatch => "rotating-batch"
            case PerRelyingParty => "per-relying-party"
        }
    }

    public static func of(s: String): ReuseMethod {
        match (s) {
            case "once_only" => ReuseMethod.OnceOnly
            case "limited_time" => ReuseMethod.LimitedTime
            case "rotating-batch" => ReuseMethod.RotatingBatch
            case "per-relying-party" => ReuseMethod.PerRelyingParty
            case _ => throw ValidationError.Error("Unknown ReuseMethod: " + s)
        }
    }

    public func equals(other: ReuseMethod): Bool {
        this.rawValue() == other.rawValue()
    }
}

// ---------------------------------------------------------------------------
// ReusePolicy
// Ported from iOS enum ReusePolicy.
// ---------------------------------------------------------------------------

public enum ReusePolicy {
    | OnceOnly(Int64, Int64)                    // (batchSize, reissueTriggerUnused)
    | LimitedTime(Int64)                        // reissueTriggerLifetimeLeft
    | RotatingBatch(Int64, Int64)               // (batchSize, reissueTriggerLifetimeLeft)
    | PerRelyingParty(Int64, Int64, Int64)      // (batchSize, reissueTriggerUnused, reissueTriggerLifetimeLeft)

    public func method(): ReuseMethod {
        match (this) {
            case OnceOnly(_, _) => ReuseMethod.OnceOnly
            case LimitedTime(_) => ReuseMethod.LimitedTime
            case RotatingBatch(_, _) => ReuseMethod.RotatingBatch
            case PerRelyingParty(_, _, _) => ReuseMethod.PerRelyingParty
        }
    }

    public func batchSize(): Option<Int64> {
        match (this) {
            case OnceOnly(bs, _) => Option<Int64>.Some(bs)
            case LimitedTime(_) => Option<Int64>.None
            case RotatingBatch(bs, _) => Option<Int64>.Some(bs)
            case PerRelyingParty(bs, _, _) => Option<Int64>.Some(bs)
        }
    }

    public func validate(): Unit {
        match (this) {
            case OnceOnly(batchSize, reissueTriggerUnused) =>
                if (batchSize <= 0) {
                    throw CredentialReusePolicyError.MissingRequiredField("batch_size must be > 0")
                }
                if (reissueTriggerUnused <= 0) {
                    throw CredentialReusePolicyError.MissingRequiredField("reissue_trigger_unused must be > 0")
                }
                if (reissueTriggerUnused >= batchSize) {
                    throw CredentialReusePolicyError.MissingRequiredField("reissue_trigger_unused must be < batch_size")
                }
            case LimitedTime(reissueTriggerLifetimeLeft) =>
                if (reissueTriggerLifetimeLeft <= 0) {
                    throw CredentialReusePolicyError.MissingRequiredField("reissue_trigger_lifetime_left must be > 0")
                }
            case RotatingBatch(batchSize, reissueTriggerLifetimeLeft) =>
                if (batchSize <= 0) {
                    throw CredentialReusePolicyError.MissingRequiredField("batch_size must be > 0")
                }
                if (reissueTriggerLifetimeLeft <= 0) {
                    throw CredentialReusePolicyError.MissingRequiredField("reissue_trigger_lifetime_left must be > 0")
                }
            case PerRelyingParty(batchSize, reissueTriggerUnused, reissueTriggerLifetimeLeft) =>
                if (batchSize <= 0) {
                    throw CredentialReusePolicyError.MissingRequiredField("batch_size must be > 0")
                }
                if (reissueTriggerUnused <= 0) {
                    throw CredentialReusePolicyError.MissingRequiredField("reissue_trigger_unused must be > 0")
                }
                if (reissueTriggerUnused >= batchSize) {
                    throw CredentialReusePolicyError.MissingRequiredField("reissue_trigger_unused must be < batch_size")
                }
                if (reissueTriggerLifetimeLeft <= 0) {
                    throw CredentialReusePolicyError.MissingRequiredField("reissue_trigger_lifetime_left must be > 0")
                }
        }
    }

    /*
     * Factory: expand details array into concrete ReusePolicy instances.
     * Ported from iOS ReusePolicy.fromDetails(_:batchSize:reissueTriggerUnused:reissueTriggerLifetimeLeft:).
     */
    public static func fromDetails(
        details: Array<ReuseMethod>,
        batchSize: Option<Int64>,
        reissueTriggerUnused: Option<Int64>,
        reissueTriggerLifetimeLeft: Option<Int64>
    ): Array<ReusePolicy> {
        if (details.isEmpty()) {
            throw CredentialReusePolicyError.InvalidPolicyStructure("details array is empty")
        }

        let hasOnceOnly = containsMethod(details, ReuseMethod.OnceOnly)
        let hasLimitedTime = containsMethod(details, ReuseMethod.LimitedTime)

        // ARF Annex II lets an option stand alone on rotating-batch or
        // per-relying-party (the reference issuer's mDL policy leads with
        // ["rotating-batch"]); iOS only rejects the once_only + limited_time
        // combination.
        if (hasOnceOnly && hasLimitedTime) {
            throw CredentialReusePolicyError.InvalidPolicyStructure(
                "details cannot contain both once_only and limited_time"
            )
        }

        let policies = ArrayList<ReusePolicy>()
        for (method in details) {
            let policy: ReusePolicy = match (method) {
                case ReuseMethod.OnceOnly =>
                    let bs = match (batchSize) {
                        case Some(v) => v
                        case None => throw CredentialReusePolicyError.MissingRequiredField("batch_size required for once_only")
                    }
                    let rtu = match (reissueTriggerUnused) {
                        case Some(v) => v
                        case None => throw CredentialReusePolicyError.MissingRequiredField("reissue_trigger_unused required for once_only")
                    }
                    ReusePolicy.OnceOnly(bs, rtu)
                case ReuseMethod.LimitedTime =>
                    let rtl = match (reissueTriggerLifetimeLeft) {
                        case Some(v) => v
                        case None => throw CredentialReusePolicyError.MissingRequiredField("reissue_trigger_lifetime_left required for limited_time")
                    }
                    ReusePolicy.LimitedTime(rtl)
                case ReuseMethod.RotatingBatch =>
                    let bs = match (batchSize) {
                        case Some(v) => v
                        case None => throw CredentialReusePolicyError.MissingRequiredField("batch_size required for rotating-batch")
                    }
                    let rtl = match (reissueTriggerLifetimeLeft) {
                        case Some(v) => v
                        case None => throw CredentialReusePolicyError.MissingRequiredField("reissue_trigger_lifetime_left required for rotating-batch")
                    }
                    ReusePolicy.RotatingBatch(bs, rtl)
                case ReuseMethod.PerRelyingParty =>
                    let bs = match (batchSize) {
                        case Some(v) => v
                        case None => throw CredentialReusePolicyError.MissingRequiredField("batch_size required for per-relying-party")
                    }
                    let rtu = match (reissueTriggerUnused) {
                        case Some(v) => v
                        case None => throw CredentialReusePolicyError.MissingRequiredField("reissue_trigger_unused required for per-relying-party")
                    }
                    let rtl = match (reissueTriggerLifetimeLeft) {
                        case Some(v) => v
                        case None => throw CredentialReusePolicyError.MissingRequiredField("reissue_trigger_lifetime_left required for per-relying-party")
                    }
                    ReusePolicy.PerRelyingParty(bs, rtu, rtl)
            }
            policy.validate()
            policies.add(policy)
        }
        return policies.toArray()
    }
}

// ---------------------------------------------------------------------------
// Helper: linear contains for Array<ReuseMethod>
// ---------------------------------------------------------------------------

func containsMethod(methods: Array<ReuseMethod>, target: ReuseMethod): Bool {
    for (m in methods) {
        if (m.rawValue() == target.rawValue()) {
            return true
        }
    }
    return false
}

// ---------------------------------------------------------------------------
// ReusePolicyOption
// JSON intermediate struct used for decoding credential_reuse_policy options.
// Ported from iOS struct ReusePolicyOption.
// ---------------------------------------------------------------------------

public class ReusePolicyOption {
    public let details: Array<ReuseMethod>
    public let batchSize: Option<Int64>
    public let reissueTriggerUnused: Option<Int64>
    public let reissueTriggerLifetimeLeft: Option<Int64>

    public init(
        details: Array<ReuseMethod>,
        batchSize: Option<Int64>,
        reissueTriggerUnused: Option<Int64>,
        reissueTriggerLifetimeLeft: Option<Int64>
    ) {
        this.details = details
        this.batchSize = batchSize
        this.reissueTriggerUnused = reissueTriggerUnused
        this.reissueTriggerLifetimeLeft = reissueTriggerLifetimeLeft
    }

    public static func fromJson(obj: JsonObject): ReusePolicyOption {
        // details: ["once_only", "rotating-batch", ...]
        let details = ArrayList<ReuseMethod>()
        match (obj.get("details")) {
            case Some(jarr: JsonArray) =>
                for (item in jarr.getItems()) {
                    match (item) {
                        case js: JsonString =>
                            try {
                                details.add(ReuseMethod.of(js.getValue()))
                            } catch (_: ValidationError) {
                                // skip unknown
                            }
                        case _ => ()
                    }
                }
            case _ => ()
        }

        let batchSize: Option<Int64> = match (obj.get("batch_size")) {
            case Some(ji: JsonInt) => Option<Int64>.Some(ji.getValue())
            case _ => Option<Int64>.None
        }
        let reissueTriggerUnused: Option<Int64> = match (obj.get("reissue_trigger_unused")) {
            case Some(ji: JsonInt) => Option<Int64>.Some(ji.getValue())
            case _ => Option<Int64>.None
        }
        let reissueTriggerLifetimeLeft: Option<Int64> = match (obj.get("reissue_trigger_lifetime_left")) {
            case Some(ji: JsonInt) => Option<Int64>.Some(ji.getValue())
            case _ => Option<Int64>.None
        }

        return ReusePolicyOption(
            details.toArray(),
            batchSize,
            reissueTriggerUnused,
            reissueTriggerLifetimeLeft
        )
    }
}

// ---------------------------------------------------------------------------
// CredentialReusePolicy
// Ported from iOS struct CredentialReusePolicy.
// ---------------------------------------------------------------------------

public class CredentialReusePolicy {
    public let id: String
    public let options: Array<ReusePolicy>

    public init(id: String, options: Array<ReusePolicy>) {
        if (options.isEmpty()) {
            throw CredentialReusePolicyError.InvalidPolicyStructure("options array cannot be empty after expansion")
        }
        this.id = id
        this.options = options
    }

    public static func fromJson(obj: JsonObject): CredentialReusePolicy {
        let id: String = match (obj.get("id")) {
            case Some(js: JsonString) => js.getValue()
            case _ => throw ValidationError.Error("CredentialReusePolicy: missing 'id'")
        }

        let expandedPolicies = ArrayList<ReusePolicy>()
        match (obj.get("options")) {
            case Some(jarr: JsonArray) =>
                for (item in jarr.getItems()) {
                    match (item) {
                        case jobj: JsonObject =>
                            let opt = ReusePolicyOption.fromJson(jobj)
                            let policies = ReusePolicy.fromDetails(
                                opt.details,
                                opt.batchSize,
                                opt.reissueTriggerUnused,
                                opt.reissueTriggerLifetimeLeft
                            )
                            for (p in policies) {
                                expandedPolicies.add(p)
                            }
                        case _ => ()
                    }
                }
            case _ => ()
        }

        return CredentialReusePolicy(id, expandedPolicies.toArray())
    }
}

// ---------------------------------------------------------------------------
// SupportedCredentialReusePolicies
// Ported from iOS enum SupportedCredentialReusePolicies.
// iOS Set<ReuseMethod> → Array<ReuseMethod> (Cangjie has no built-in HashSet).
// ---------------------------------------------------------------------------

public enum SupportedCredentialReusePolicies {
    | Supported(Array<ReuseMethod>)    // wallet supports these, not mandatory
    | Required(Array<ReuseMethod>)     // wallet requires issuer to have one of these
    | NotSupported                     // wallet ignores reuse policies

    public func validate(): Unit {
        match (this) {
            case Supported(methods) =>
                if (methods.isEmpty()) {
                    throw CredentialReusePolicyError.InvalidPolicyStructure("policyTypes cannot be empty")
                }
                let hasBase = containsMethod(methods, ReuseMethod.OnceOnly) ||
                              containsMethod(methods, ReuseMethod.LimitedTime)
                if (!hasBase) {
                    throw CredentialReusePolicyError.InvalidPolicyStructure(
                        "policyTypes must contain at least onceOnly or limitedTime"
                    )
                }
            case Required(methods) =>
                if (methods.isEmpty()) {
                    throw CredentialReusePolicyError.InvalidPolicyStructure("policyTypes cannot be empty")
                }
                let hasBase2 = containsMethod(methods, ReuseMethod.OnceOnly) ||
                               containsMethod(methods, ReuseMethod.LimitedTime)
                if (!hasBase2) {
                    throw CredentialReusePolicyError.InvalidPolicyStructure(
                        "policyTypes must contain at least onceOnly or limitedTime"
                    )
                }
            case NotSupported => ()
        }
    }

    public func supports(method: ReuseMethod): Bool {
        match (this) {
            case Supported(methods) =>
                containsMethod(methods, method)
            case Required(methods) =>
                containsMethod(methods, method)
            case NotSupported => false
        }
    }

    public func supportedMethods(): Option<Array<ReuseMethod>> {
        match (this) {
            case Supported(m) => Option<Array<ReuseMethod>>.Some(m)
            case Required(m) => Option<Array<ReuseMethod>>.Some(m)
            case NotSupported => Option<Array<ReuseMethod>>.None
        }
    }

    public func isRequired(): Bool {
        match (this) {
            case Required(_) => true
            case _ => false
        }
    }
}

// ---------------------------------------------------------------------------
// CredentialReusePolicyValidator
// Ported from iOS struct CredentialReusePolicyValidator.
// ---------------------------------------------------------------------------

public class CredentialReusePolicyValidator {

    /*
     * Validates issuer policy against wallet capabilities and selects best matching option.
     * Returns None if no policy present and not required.
     */
    public static func selectMatchingPolicy(
        issuerPolicy: Option<CredentialReusePolicy>,
        walletSupported: SupportedCredentialReusePolicies
    ): Option<ReusePolicy> {
        walletSupported.validate()

        match (issuerPolicy) {
            case None =>
                match (walletSupported) {
                    case SupportedCredentialReusePolicies.Required(_) =>
                        throw CredentialReusePolicyError.NoSupportedPolicyFound()
                    case _ => return Option<ReusePolicy>.None
                }
            case Some(policy) =>
                match (walletSupported) {
                    case SupportedCredentialReusePolicies.NotSupported =>
                        // Issuer has policy but wallet doesn't support → ignore, continue
                        return Option<ReusePolicy>.None
                    case _ => ()
                }

                if (policy.id != "arf_annex_ii") {
                    throw CredentialReusePolicyError.UnsupportedPolicyId(policy.id)
                }

                if (policy.options.isEmpty()) {
                    throw CredentialReusePolicyError.InvalidPolicyStructure("options array is empty")
                }

                let walletMethods: Array<ReuseMethod> = match (walletSupported.supportedMethods()) {
                    case Some(m) => m
                    case None => throw CredentialReusePolicyError.NoSupportedPolicyFound()
                }

                // Find first policy that wallet supports (respecting issuer's priority order)
                for (option in policy.options) {
                    if (containsMethod(walletMethods, option.method())) {
                        return Option<ReusePolicy>.Some(option)
                    }
                }

                throw CredentialReusePolicyError.NoSupportedPolicyFound()
        }
    }

    /*
     * Determines the batch size to use for credential issuance.
     * Priority: reuse policy batch size > batch_credential_issuance from metadata.
     */
    public static func determineBatchSize(
        selectedPolicy: Option<ReusePolicy>,
        issuerBatchSize: Option<Int64>
    ): Option<Int64> {
        match (selectedPolicy) {
            case Some(policy) =>
                match (policy.batchSize()) {
                    case Some(bs) => return Option<Int64>.Some(bs)
                    case None => ()
                }
            case None => ()
        }
        return issuerBatchSize
    }

    /*
     * Validates that the number of proofs matches the required batch size.
     */
    public static func validateProofCount(
        proofCount: Int64,
        requiredBatchSize: Option<Int64>
    ): Unit {
        match (requiredBatchSize) {
            case None => ()
            case Some(required) =>
                if (proofCount != required) {
                    throw CredentialReusePolicyError.BatchSizeMismatch(required, proofCount)
                }
        }
    }
}
