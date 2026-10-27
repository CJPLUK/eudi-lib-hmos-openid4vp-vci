/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * vp_errors.cj — VP-side error types.
 * Ported from iOS: ValidationError (VP variant), ResolvedAuthorisationError,
 * AuthorizationError, DCQLError.
 *
 * iOS enum-based errors → Cangjie class <: Exception with static factories.
 * iOS async/actor → Cangjie sync/class (no Swift concurrency).
 */
package ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.error

// ---------------------------------------------------------------------------
// VpValidationError — mirrors iOS ValidationError (VP variant)
// ---------------------------------------------------------------------------

public class VpValidationError <: Exception {
    public init(msg: String) {
        super(msg)
    }

    public static func ValidationError(message: String): VpValidationError {
        VpValidationError("ValidationError: " + message)
    }
    public static func UnsupportedClientIdScheme(scheme: String): VpValidationError {
        VpValidationError("unsupportedClientIdScheme: " + scheme)
    }
    public static func UnsupportedResponseType(responseType: String): VpValidationError {
        VpValidationError("unsupportedResponseType: " + responseType)
    }
    public static func UnsupportedResponseMode(mode: String): VpValidationError {
        VpValidationError("unsupportedResponseMode: " + mode)
    }
    public static func InvalidResponseType(): VpValidationError {
        VpValidationError("invalidResponseType")
    }
    public static func NoAuthorizationData(): VpValidationError {
        VpValidationError("noAuthorizationData")
    }
    public static func InvalidAuthorizationData(): VpValidationError {
        VpValidationError("invalidAuthorizationData")
    }
    public static func InvalidConfiguration(): VpValidationError {
        VpValidationError("invalidConfiguration")
    }
    public static func InvalidClientMetadata(): VpValidationError {
        VpValidationError("invalidClientMetadata")
    }
    public static func InvalidJWTWebKeySet(): VpValidationError {
        VpValidationError("invalidJWTWebKeySet")
    }
    public static func MissingRequiredField(field: String): VpValidationError {
        VpValidationError("missingRequiredField: " + field)
    }
    public static func InvalidJwtPayload(): VpValidationError {
        VpValidationError("invalidJwtPayload")
    }
    public static func InvalidRequestUri(uri: String): VpValidationError {
        VpValidationError("invalidRequestUri: " + uri)
    }
    public static func InvalidRequest(): VpValidationError {
        VpValidationError("invalidRequest")
    }
    public static func ConflictingData(): VpValidationError {
        VpValidationError("conflictingData")
    }
    public static func NotSupportedOperation(): VpValidationError {
        VpValidationError("notSupportedOperation")
    }
    public static func InvalidFormat(): VpValidationError {
        VpValidationError("invalidFormat")
    }
    public static func ClientIdMismatch(lhs: String, rhs: String): VpValidationError {
        VpValidationError("clientIdMismatch: " + lhs + " != " + rhs)
    }
    public static func InvalidClientId(): VpValidationError {
        VpValidationError("invalidClientId")
    }
    public static func EmptyValue(): VpValidationError {
        VpValidationError("emptyValue")
    }
    public static func MultipleQuerySources(): VpValidationError {
        VpValidationError("multipleQuerySources")
    }
    public static func InvalidQuerySource(): VpValidationError {
        VpValidationError("invalidQuerySource")
    }
    public static func InvalidUri(): VpValidationError {
        VpValidationError("invalidUri")
    }
    public static func InvalidRequestUriMethod(): VpValidationError {
        VpValidationError("invalidRequestUriMethod")
    }
    public static func InvalidUseOfBothRequestAndRequestUri(): VpValidationError {
        VpValidationError("invalidUseOfBothRequestAndRequestUri")
    }
    public static func MissingClientId(): VpValidationError {
        VpValidationError("missingClientId")
    }
    public static func MissingResponseType(): VpValidationError {
        VpValidationError("missingResponseType")
    }
    public static func MissingNonce(): VpValidationError {
        VpValidationError("missingNonce")
    }
    public static func InvalidVerifierAttestationFormat(): VpValidationError {
        VpValidationError("invalidVerifierAttestationFormat")
    }
    public static func InvalidVerifierAttestationCredentialIds(): VpValidationError {
        VpValidationError("invalidVerifierAttestationCredentialIds")
    }
    public static func BlankTrustedAuthorityType(): VpValidationError {
        VpValidationError("TrustedAuthorityType cannot be blank")
    }
    /**
     * Mirrors iOS ValidationError.authorizationPolicyNotMet(PolicyViolation):
     * the WRP registration certificate policy returned `.notGranted`.
     * Callers can detect this case via `isAuthorizationPolicyNotMet()`.
     */
    public static func AuthorizationPolicyNotMet(violation: String): VpValidationError {
        VpValidationError("authorizationPolicyNotMet: " + violation)
    }

    /** True when this error was produced by `AuthorizationPolicyNotMet`. */
    public func isAuthorizationPolicyNotMet(): Bool {
        this.message.startsWith("authorizationPolicyNotMet: ")
    }
}

// ---------------------------------------------------------------------------
// DCQLError — mirrors iOS DCQLError
// ---------------------------------------------------------------------------

public class DCQLError <: Exception {
    public init(msg: String) {
        super(msg)
    }

    public static func EmptyCredentials(): DCQLError {
        DCQLError("emptyCredentials")
    }
    public static func DuplicateQueryId(): DCQLError {
        DCQLError("duplicateQueryId")
    }
    public static func UnknownQueryId(): DCQLError {
        DCQLError("unknownQueryId")
    }
    public static func EmptyCredentialSet(): DCQLError {
        DCQLError("emptyCredentialSet")
    }
    public static func EmptyNamespace(): DCQLError {
        DCQLError("emptyNamespace")
    }
    public static func EmptyClaimName(): DCQLError {
        DCQLError("emptyClaimName")
    }
    public static func EmptyDocType(): DCQLError {
        DCQLError("emptyDocType")
    }
    public static func Error(message: String): DCQLError {
        DCQLError(message)
    }
}

// ---------------------------------------------------------------------------
// ResolvedAuthorisationError — mirrors iOS ResolvedAuthorisationError
// ---------------------------------------------------------------------------

public class ResolvedAuthorisationError <: Exception {
    public init(msg: String) {
        super(msg)
    }

    public static func InvalidClientData(): ResolvedAuthorisationError {
        ResolvedAuthorisationError("invalidClientData")
    }
    public static func UnsupportedResponseType(responseType: String): ResolvedAuthorisationError {
        ResolvedAuthorisationError("unsupportedResponseType: " + responseType)
    }
    public static func InvalidQueryDataForScope(scope: String): ResolvedAuthorisationError {
        ResolvedAuthorisationError("invalidQueryData for scope: " + scope)
    }
}
