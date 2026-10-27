/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * errors.cj — VCI error types.
 * Ported from iOS: CredentialError, CredentialIssuanceError, CredentialIssuerMetadataError,
 * CredentialOfferRequestError, ValidationError, JOSEError, JSONParseError.
 *
 * Cangjie constraint: enum cannot extend class (only implement interface).
 * Pattern: each iOS error enum → Cangjie class <: Exception with a static factory,
 * and a companion enum for match dispatch.
 *
 * iOS actor/async → Cangjie class/sync (no Swift concurrency model).
 */
package ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.error

// ---------------------------------------------------------------------------
// CredentialError
// ---------------------------------------------------------------------------

public enum CredentialErrorKind {
    | GenericError
    | IssuerDoesNotSupportDeferredIssuance
    | ExtraneousQueryComponents
    | InvalidScheme
}

public class CredentialError <: Exception {
    public let kind: CredentialErrorKind

    public init(kind: CredentialErrorKind) {
        super(CredentialError.kindMessage(kind))
        this.kind = kind
    }

    static func kindMessage(k: CredentialErrorKind): String {
        match (k) {
            case CredentialErrorKind.GenericError => "Something went wrong"
            case CredentialErrorKind.IssuerDoesNotSupportDeferredIssuance =>
                "Issuer does not support deferred issuance"
            case CredentialErrorKind.ExtraneousQueryComponents => "Extraneous query components"
            case CredentialErrorKind.InvalidScheme => "Invalid scheme"
        }
    }

    public static func GenericError(): CredentialError {
        CredentialError(CredentialErrorKind.GenericError)
    }
    public static func IssuerDoesNotSupportDeferredIssuance(): CredentialError {
        CredentialError(CredentialErrorKind.IssuerDoesNotSupportDeferredIssuance)
    }
    public static func ExtraneousQueryComponents(): CredentialError {
        CredentialError(CredentialErrorKind.ExtraneousQueryComponents)
    }
    public static func InvalidScheme(): CredentialError {
        CredentialError(CredentialErrorKind.InvalidScheme)
    }
}

// ---------------------------------------------------------------------------
// CredentialIssuanceError
// ---------------------------------------------------------------------------

public class CredentialIssuanceError <: Exception {
    public init(msg: String) {
        super(msg)
    }

    public static func PushedAuthorizationRequestFailed(
        error: String, desc: Option<String>
    ): CredentialIssuanceError {
        CredentialIssuanceError(match (desc) { case Some(d) => d; case None => "pushedAuthorizationRequestFailed: " + error })
    }
    public static func AccessTokenRequestFailed(
        error: String, desc: Option<String>
    ): CredentialIssuanceError {
        CredentialIssuanceError(match (desc) { case Some(d) => d; case None => "accessTokenRequestFailed: " + error })
    }
    public static func ResponseUnparsable(details: String): CredentialIssuanceError {
        CredentialIssuanceError("Response is unparsable. Details: " + details)
    }
    public static func InvalidIssuanceRequest(details: String): CredentialIssuanceError {
        CredentialIssuanceError("Invalid issuance request. Details: " + details)
    }
    public static func CryptographicSuiteNotSupported(name: String): CredentialIssuanceError {
        CredentialIssuanceError("Cryptographic suite not supported: " + name)
    }
    public static func CryptographicBindingMethodNotSupported(): CredentialIssuanceError {
        CredentialIssuanceError("Cryptographic binding method not supported.")
    }
    public static func ProofTypeNotSupported(): CredentialIssuanceError {
        CredentialIssuanceError("Proof type not supported")
    }
    public static func CryptographicAlgorithmNotSupported(): CredentialIssuanceError {
        CredentialIssuanceError("Cryptographic algorithm not supported.")
    }
    public static func IssuerDoesNotSupportEncryptedResponses(): CredentialIssuanceError {
        CredentialIssuanceError("Issuer does not support encrypted responses.")
    }
    public static func ResponseEncryptionAlgorithmNotSupportedByIssuer(): CredentialIssuanceError {
        CredentialIssuanceError("Response encryption algorithm not supported by issuer.")
    }
    public static func ResponseEncryptionMethodNotSupportedByIssuer(): CredentialIssuanceError {
        CredentialIssuanceError("Response encryption method not supported by issuer.")
    }
    public static func ResponseCompressionMethodNotSupportedByIssuer(): CredentialIssuanceError {
        CredentialIssuanceError("Response compression method not supported by issuer.")
    }
    public static func RequestEncryptionNotSupportedByIssuer(): CredentialIssuanceError {
        CredentialIssuanceError("Encrypted request not supported by issuer.")
    }
    public static func RequestEncryptionAlgorithmNotSupportedByIssuer(): CredentialIssuanceError {
        CredentialIssuanceError("Requested encryption algorithm not supported by issuer.")
    }
    public static func RequestEncryptionMethodNotSupportedByIssuer(): CredentialIssuanceError {
        CredentialIssuanceError("Requested encryption method not supported by issuer.")
    }
    public static func RequestCompressionMethodNotSupportedByIssuer(): CredentialIssuanceError {
        CredentialIssuanceError("Requested compression method not supported by issuer.")
    }
    public static func RequestEncryptionRequiredByIssuer(): CredentialIssuanceError {
        CredentialIssuanceError("Request encryption is required by the issuer.")
    }
    public static func InvalidToken(): CredentialIssuanceError {
        CredentialIssuanceError("Invalid token.")
    }
    public static func RequestFailed(
        code: Int64, error: String, desc: Option<String>
    ): CredentialIssuanceError {
        let descStr = match (desc) { case Some(d) => d; case None => "N/A" }
        CredentialIssuanceError("Issuance request failed with code: " + code.toString() +
            ". Error: " + error + ". " + descStr)
    }
    public static func InvalidTransactionId(): CredentialIssuanceError {
        CredentialIssuanceError("Invalid transaction ID.")
    }
    public static func UnsupportedCredentialType(): CredentialIssuanceError {
        CredentialIssuanceError("Unsupported credential type.")
    }
    public static func UnsupportedCredentialFormat(): CredentialIssuanceError {
        CredentialIssuanceError("Unsupported credential format.")
    }
    public static func InvalidEncryptionParameters(): CredentialIssuanceError {
        CredentialIssuanceError("Invalid encryption parameters.")
    }
    public static func InvalidProof(desc: Option<String>): CredentialIssuanceError {
        CredentialIssuanceError(match (desc) { case Some(d) => d; case None => "Invalid proof" })
    }
    public static func DeferredCredentialIssuancePending(
        interval: Option<Float64>
    ): CredentialIssuanceError {
        let msg = match (interval) {
            case Some(i) => "Deferred credential issuance pending. Retry in " + i.toString() + " seconds."
            case None => "Deferred credential issuance pending."
        }
        CredentialIssuanceError(msg)
    }
    public static func NotificationFailed(reason: String): CredentialIssuanceError {
        CredentialIssuanceError("Notification failed: " + reason)
    }
    public static func ProofTypeKeyAttestationRequired(): CredentialIssuanceError {
        CredentialIssuanceError("Proof type key attestation required.")
    }
    public static func CombinationOfBindingKeys(): CredentialIssuanceError {
        CredentialIssuanceError("Combination of binding keys")
    }
}

// ---------------------------------------------------------------------------
// CredentialIssuerMetadataError
// ---------------------------------------------------------------------------

public class CredentialIssuerMetadataError <: Exception {
    public init(msg: String) {
        super(msg)
    }

    public static func UnableToFetchCredentialIssuerMetadata(cause: String): CredentialIssuerMetadataError {
        CredentialIssuerMetadataError("Unable to fetch credential issuer metadata: " + cause)
    }
    public static func NonParseableCredentialIssuerMetadata(cause: String): CredentialIssuerMetadataError {
        CredentialIssuerMetadataError("Non-parseable credential issuer metadata: " + cause)
    }
    public static func InvalidCredentialIssuerId(): CredentialIssuerMetadataError {
        CredentialIssuerMetadataError("Invalid credential issuer id")
    }
    public static func CredentialResponseAsymmetricEncryptionAlgorithmsRequired(): CredentialIssuerMetadataError {
        CredentialIssuerMetadataError("Credential response asymmetric encryption algorithms required")
    }
    public static func CredentialRequestEncryptionMustExistIfCredentialResponseEncryptionExists(): CredentialIssuerMetadataError {
        CredentialIssuerMetadataError("Credential request encryption must exist if credential response encryption exists")
    }
    public static func UnsupportedRequestEncryptionMethods(): CredentialIssuerMetadataError {
        CredentialIssuerMetadataError("Unsupported request encryption methods")
    }
    public static func UnsupportedResponseEncryptionMethods(): CredentialIssuerMetadataError {
        CredentialIssuerMetadataError("Unsupported response encryption methods")
    }
    public static func MissingSignedMetadata(): CredentialIssuerMetadataError {
        CredentialIssuerMetadataError("Credential Issuer does not provide signed metadata")
    }
    public static func MissingContentType(ct: String): CredentialIssuerMetadataError {
        CredentialIssuerMetadataError("Missing content type: " + ct)
    }
    public static func MissingRightContentTypeHeader(): CredentialIssuerMetadataError {
        CredentialIssuerMetadataError("Missing right content type header")
    }
    public static func InvalidSignedMetadata(msg: String): CredentialIssuerMetadataError {
        CredentialIssuerMetadataError("Invalid signed metadata: " + msg)
    }
    public static func InvalidJOSEHeader(msg: String): CredentialIssuerMetadataError {
        CredentialIssuerMetadataError("Invalid JOSE header: " + msg)
    }
    public static func InvalidJWTClaims(msg: String): CredentialIssuerMetadataError {
        CredentialIssuerMetadataError("Invalid JWT claims: " + msg)
    }
    public static func NonParseableSignedMetadata(): CredentialIssuerMetadataError {
        CredentialIssuerMetadataError("Non-parseable signed metadata")
    }
    public static func InvalidIssuerTrust(): CredentialIssuerMetadataError {
        CredentialIssuerMetadataError("Invalid issuer trust")
    }
}

// ---------------------------------------------------------------------------
// CredentialIssuerMetadataValidationError
// ---------------------------------------------------------------------------

public class CredentialIssuerMetadataValidationError <: Exception {
    public init(msg: String) {
        super(msg)
    }

    public static func InvalidCredentialIssuerId(reason: String): CredentialIssuerMetadataValidationError {
        CredentialIssuerMetadataValidationError("Invalid credential issuer id: " + reason)
    }
    public static func InvalidAuthorizationServer(reason: String): CredentialIssuerMetadataValidationError {
        CredentialIssuerMetadataValidationError("Invalid authorization server: " + reason)
    }
    public static func InvalidCredentialEndpoint(reason: String): CredentialIssuerMetadataValidationError {
        CredentialIssuerMetadataValidationError("Invalid credential endpoint: " + reason)
    }
    public static func InvalidDeferredCredentialEndpoint(reason: String): CredentialIssuerMetadataValidationError {
        CredentialIssuerMetadataValidationError("Invalid deferred credential endpoint: " + reason)
    }
    public static func InvalidCredentialResponseEncryptionAlgorithmsSupported(reason: String): CredentialIssuerMetadataValidationError {
        CredentialIssuerMetadataValidationError("Invalid credential response encryption algorithms supported: " + reason)
    }
    public static func InvalidCredentialResponseEncryptionMethodsSupported(reason: String): CredentialIssuerMetadataValidationError {
        CredentialIssuerMetadataValidationError("Invalid credential response encryption methods supported: " + reason)
    }
    public static func CredentialResponseEncryptionAlgorithmsRequired(): CredentialIssuerMetadataValidationError {
        CredentialIssuerMetadataValidationError("Credential response encryption algorithms required")
    }
    public static func InvalidCredentialsSupported(reason: String): CredentialIssuerMetadataValidationError {
        CredentialIssuerMetadataValidationError("Invalid credentials supported: " + reason)
    }
    public static func CredentialsSupportedRequired(): CredentialIssuerMetadataValidationError {
        CredentialIssuerMetadataValidationError("Credentials supported required")
    }
    public static func InvalidDisplay(reason: String): CredentialIssuerMetadataValidationError {
        CredentialIssuerMetadataValidationError("Invalid display: " + reason)
    }
    public static func InvalidNotificationEndpoint(): CredentialIssuerMetadataValidationError {
        CredentialIssuerMetadataValidationError("Invalid notification endpoint")
    }
}

// ---------------------------------------------------------------------------
// CredentialOfferRequestError
// ---------------------------------------------------------------------------

public class CredentialOfferRequestError <: Exception {
    public init(msg: String) {
        super(msg)
    }

    public static func GenericError(): CredentialOfferRequestError {
        CredentialOfferRequestError("CredentialOfferRequestError:error: genericError")
    }
    public static func EmptyCredentialsError(): CredentialOfferRequestError {
        CredentialOfferRequestError("CredentialOfferRequestError:error: emptyCredentialsError")
    }
    public static func NonParsableCredentialOfferEndpointUrl(reason: String): CredentialOfferRequestError {
        CredentialOfferRequestError("CredentialOfferRequestError:error: " + reason)
    }
    public static func UnableToFetchCredentialOffer(reason: String): CredentialOfferRequestError {
        CredentialOfferRequestError("CredentialOfferRequestError:error: " + reason)
    }
    public static func NonParseableCredentialOffer(reason: String): CredentialOfferRequestError {
        CredentialOfferRequestError("CredentialOfferRequestError:error: " + reason)
    }
    public static func UnableToResolveCredentialIssuerMetadata(reason: String): CredentialOfferRequestError {
        CredentialOfferRequestError("CredentialOfferRequestError:error: " + reason)
    }
    public static func UnableToResolveAuthorizationServerMetadata(reason: String): CredentialOfferRequestError {
        CredentialOfferRequestError("CredentialOfferRequestError:error: " + reason)
    }
}

// ---------------------------------------------------------------------------
// CredentialOfferRequestValidationError
// ---------------------------------------------------------------------------

public class CredentialOfferRequestValidationError <: Exception {
    public init(msg: String) {
        super(msg)
    }

    public static func OneOfCredentialOfferOrCredentialOfferUri(): CredentialOfferRequestValidationError {
        CredentialOfferRequestValidationError("One of credential_offer or credential_offer_uri is required")
    }
    public static func InvalidCredentialOfferUri(msg: String): CredentialOfferRequestValidationError {
        CredentialOfferRequestValidationError("Invalid credential offer URI: " + msg)
    }
    public static func InvalidCredentialIssuerId(): CredentialOfferRequestValidationError {
        CredentialOfferRequestValidationError("Invalid credential issuer id")
    }
    public static func InvalidCredentials(): CredentialOfferRequestValidationError {
        CredentialOfferRequestValidationError("Invalid credentials")
    }
    public static func InvalidGrants(): CredentialOfferRequestValidationError {
        CredentialOfferRequestValidationError("Invalid grants")
    }
}

// ---------------------------------------------------------------------------
// ValidationError
// ---------------------------------------------------------------------------

public class ValidationError <: Exception {
    public init(msg: String) {
        super(msg)
    }

    public static func Error(reason: String): ValidationError {
        ValidationError("ValidationError:error: " + reason)
    }
    public static func NonHttpsUrl(url: String): ValidationError {
        ValidationError("ValidationError:nonHttpsUrl: " + url)
    }
    public static func InvalidUrl(url: String): ValidationError {
        ValidationError("ValidationError:invalidUrl: " + url)
    }
    public static func InvalidBatchSize(size: Int64): ValidationError {
        ValidationError("ValidationError:invalidBatchSize: " + size.toString())
    }
    public static func IssuerBatchSizeLimitExceeded(size: Int64): ValidationError {
        ValidationError("ValidationError:issuerBatchSizeLimitExceeded: " + size.toString())
    }
    public static func RetryFailedAfterDpopNonce(): ValidationError {
        ValidationError("retryFailedAfterDpopNonce")
    }
    public static func RetryFailedAfterUseAttestationNonce(): ValidationError {
        ValidationError("retryFailedAfterUseAttestationNonce")
    }
    public static func DpopRequired(): ValidationError {
        ValidationError("dpopRequired")
    }
    public static func ParRequired(): ValidationError {
        ValidationError("parRequired")
    }
    public static func StateMismatch(l: String, r: String): ValidationError {
        ValidationError("stateMismatch: " + l + " != " + r)
    }
}

// ---------------------------------------------------------------------------
// JSONParseError
// ---------------------------------------------------------------------------

public class JSONParseError <: Exception {
    public init(msg: String) {
        super(msg)
    }

    public static func FileNotFound(filename: String): JSONParseError {
        JSONParseError(".fileNotFound " + filename)
    }
    public static func DataInitialisation(error: String): JSONParseError {
        JSONParseError(".dataInitialisation " + error)
    }
    public static func JsonSerialization(error: String): JSONParseError {
        JSONParseError(".jsonSerialization " + error)
    }
    public static func MappingFail(value: String, toType: String): JSONParseError {
        JSONParseError(".mappingFail from: " + value + " to: " + toType)
    }
    public static func InvalidJSON(): JSONParseError {
        JSONParseError(".invalidJSON")
    }
    public static func InvalidJWT(): JSONParseError {
        JSONParseError(".invalidJWT")
    }
    public static func NotSupportedOperation(): JSONParseError {
        JSONParseError(".notSupportedOperation")
    }
}

// ---------------------------------------------------------------------------
// JOSEError
// ---------------------------------------------------------------------------

public class JOSEError <: Exception {
    public init(msg: String) {
        super(msg)
    }

    public static func NotSupportedRequest(): JOSEError { JOSEError(".notSupportedRequest") }
    public static func InvalidIdTokenRequest(): JOSEError { JOSEError(".invalidIdTokenRequest") }
    public static func InvalidPublicKey(): JOSEError { JOSEError(".invalidPublicKey") }
    public static func InvalidJWS(): JOSEError { JOSEError(".invalidJWS") }
    public static func InvalidSigner(): JOSEError { JOSEError(".invalidSigner") }
    public static func InvalidVerifier(): JOSEError { JOSEError(".invalidVerifier") }
    public static func InvalidDidIdentifier(): JOSEError { JOSEError(".invalidDidIdentifier") }
    public static func InvalidObjectType(): JOSEError { JOSEError(".invalidObjectType") }
}

// ---------------------------------------------------------------------------
// KeyAttestationError
// ---------------------------------------------------------------------------

public class KeyAttestationError <: Exception {
    public init(msg: String) {
        super(msg)
    }

    public static func InvalidSignature(): KeyAttestationError {
        KeyAttestationError("JWT must be signed with an asymmetric algorithm (not MAC).")
    }
    public static func InvalidType(): KeyAttestationError {
        KeyAttestationError("JWT 'typ' header must be 'key-attestation+jwt'.")
    }
    public static func InvalidPayload(): KeyAttestationError {
        KeyAttestationError("JWT payload is not valid JSON.")
    }
    public static func MissingIAT(): KeyAttestationError {
        KeyAttestationError("Missing 'iat' (issued at) claim.")
    }
    public static func MissingOrEmptyAttestedKeys(): KeyAttestationError {
        KeyAttestationError("'attested_keys' claim is missing or empty.")
    }
    public static func KeyIsPrivate(index: Int64): KeyAttestationError {
        KeyAttestationError("Key at index " + index.toString() + " is a symmetric key; must be a public key.")
    }
    public static func InvalidJWK(index: Int64, error: String): KeyAttestationError {
        KeyAttestationError("Failed to parse JWK at index " + index.toString() + ": " + error)
    }
}

// ---------------------------------------------------------------------------
// CredentialReusePolicyError
// ---------------------------------------------------------------------------

public class CredentialReusePolicyError <: Exception {
    public init(msg: String) {
        super(msg)
    }

    public static func InvalidPolicyStructure(reason: String): CredentialReusePolicyError {
        CredentialReusePolicyError("Invalid credential reuse policy structure: " + reason)
    }
    public static func UnsupportedPolicyId(id: String): CredentialReusePolicyError {
        CredentialReusePolicyError("Unsupported policy ID: " + id + ". Expected 'arf_annex_ii'")
    }
    public static func MissingRequiredField(field: String): CredentialReusePolicyError {
        CredentialReusePolicyError("Missing required field: " + field)
    }
    public static func BatchSizeMismatch(required: Int64, provided: Int64): CredentialReusePolicyError {
        CredentialReusePolicyError("Batch size mismatch. Required: " + required.toString() +
            ", Provided: " + provided.toString())
    }
    public static func NoSupportedPolicyFound(): CredentialReusePolicyError {
        CredentialReusePolicyError("No supported reuse policy found in issuer metadata")
    }
    public static func UnsupportedReuseMethod(method: String): CredentialReusePolicyError {
        CredentialReusePolicyError("Reuse method '" + method + "' is not supported in this version")
    }
}

// ---------------------------------------------------------------------------
// WRPRCError
// Ported from iOS Sources/RegistrationCertificate/WRPRCError.swift (v0.53.1):
// errors raised while extracting or enforcing the WRP Registration Certificate
// (ETSI TS 119 475) during issuance authorization.
// ---------------------------------------------------------------------------

public enum WRPRCErrorKind {
    /** issuer_info container missing from issuer metadata, or empty. */
    | MissingIssuerInfo
    /** issuer_info exists but carries no registration_cert-format entry. */
    | MissingRequiredRegistrationCertificate
    /** More than one registration_cert entry found; exactly one is required. */
    | MultipleRegistrationCertificates
    /** Metadata carries a WRPRC but no WRPAC was captured during resolution. */
    | MissingWrpac
    /** Policy evaluation returned notGranted. */
    | PolicyNotMet
}

public class WRPRCError <: Exception {
    public let kind: WRPRCErrorKind

    public init(kind: WRPRCErrorKind, msg: String) {
        super(msg)
        this.kind = kind
    }

    public static func MissingIssuerInfo(): WRPRCError {
        WRPRCError(WRPRCErrorKind.MissingIssuerInfo,
            "Issuer metadata does not carry an `issuer_info` container, or the container is empty")
    }
    public static func MissingRequiredRegistrationCertificate(): WRPRCError {
        WRPRCError(WRPRCErrorKind.MissingRequiredRegistrationCertificate,
            "No WRP Registration Certificate found in issuer metadata issuer_info")
    }
    public static func MultipleRegistrationCertificates(): WRPRCError {
        WRPRCError(WRPRCErrorKind.MultipleRegistrationCertificates,
            "More than one WRP Registration Certificate found in issuer_info; exactly one is required")
    }
    public static func MissingWrpac(): WRPRCError {
        WRPRCError(WRPRCErrorKind.MissingWrpac,
            "WRPAC is not available on the issuer metadata; " +
            "ensure the issuer metadata policy is RequireSigned (by certificate chain).")
    }
    public static func PolicyNotMet(violation: String): WRPRCError {
        WRPRCError(WRPRCErrorKind.PolicyNotMet, "WRPRC policy not met: " + violation)
    }
}
