/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * client_types.cj — VP client identity types.
 * Ported from iOS: ClientIdPrefix.swift, Client.swift, VerifierId.swift,
 * ClientMetaDataSource.swift, SupportedClientIdPrefix.swift,
 * Certificate+Extensions.swift (extractSanDnsNames via cjx509).
 *
 * X.509 support uses cjx509 (eudi_cjx509): Cert.fromPem, verifyChain,
 * extensionValue, extractSanDnsNames. Organization extracted from Subject DN.
 */
package ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.entity.client

import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.error.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.entity.types.*
import ohos_app_cangjie_eudi_cjx509.x509.core.{Cert, CertError, verifyChain, getPublicKeyX963}
import ohos_app_cangjie_eudi_cjx509.x509.crl.{extensionValue}
import ohos_app_cangjie_eudi_cjjose.jose.{JoseJws, EcPublicKey}
import eudi_lib_core_crypto.Digest
import stdx.crypto.keys.{ECDSAPublicKey, ECDSAPrivateKey}
import stdx.crypto.common.DerBlob
import std.collection.ArrayList

// ---------------------------------------------------------------------------
// ClientIdPrefix — mirrors iOS ClientIdPrefix enum
// ---------------------------------------------------------------------------

public enum ClientIdPrefix <: ToString & Equatable<ClientIdPrefix> {
    | PreRegistered
    | RedirectUri
    | OpenidFederation
    | DecentralizedIdentifier
    | X509SanDns
    | X509Hash
    | VerifierAttestation

    public func toString(): String {
        match (this) {
            case PreRegistered => OpenId4VPSpec.CLIENT_ID_SCHEME_PRE_REGISTERED
            case RedirectUri => OpenId4VPSpec.CLIENT_ID_SCHEME_REDIRECT_URI
            case OpenidFederation => OpenId4VPSpec.CLIENT_ID_SCHEME_OPENID_FEDERATION
            case DecentralizedIdentifier => OpenId4VPSpec.CLIENT_ID_SCHEME_DID
            case X509SanDns => OpenId4VPSpec.CLIENT_ID_SCHEME_X509_SAN_DNS
            case X509Hash => OpenId4VPSpec.CLIENT_ID_SCHEME_X509_HASH
            case VerifierAttestation => OpenId4VPSpec.CLIENT_ID_SCHEME_VERIFIER_ATTESTATION
        }
    }

    public static func fromRawValue(raw: String): Option<ClientIdPrefix> {
        match (raw) {
            case "pre-registered" => Some(PreRegistered)
            case "redirect_uri" => Some(RedirectUri)
            case "openid_federation" => Some(OpenidFederation)
            case "decentralized_identifier" => Some(DecentralizedIdentifier)
            case "x509_san_dns" => Some(X509SanDns)
            case "x509_hash" => Some(X509Hash)
            case "verifier_attestation" => Some(VerifierAttestation)
            case _ => None
        }
    }

    // Parse from client_id_scheme in request object, throw on unsupported
    public static func fromSchemeOrThrow(scheme: Option<String>): ClientIdPrefix {
        let raw = match (scheme) {
            case Some(s) => s
            case None => "pre-registered"  // default
        }
        match (ClientIdPrefix.fromRawValue(raw)) {
            case Some(p) => p
            case None => throw VpValidationError.UnsupportedClientIdScheme(raw)
        }
    }

    public operator func ==(other: ClientIdPrefix): Bool {
        this.toString() == other.toString()
    }

    public operator func !=(other: ClientIdPrefix): Bool {
        !(this == other)
    }
}

// ---------------------------------------------------------------------------
// VerifierId — mirrors iOS VerifierId
// ---------------------------------------------------------------------------

public class VerifierId {
    public let scheme: ClientIdPrefix
    public let originalClientId: String

    public init(scheme!: ClientIdPrefix, originalClientId!: String = "") {
        this.scheme = scheme
        this.originalClientId = originalClientId
    }

    public func clientId(): String {
        let prefix: Option<String> = match (scheme) {
            case ClientIdPrefix.RedirectUri => Some(OpenId4VPSpec.CLIENT_ID_SCHEME_REDIRECT_URI)
            case ClientIdPrefix.X509SanDns => Some(OpenId4VPSpec.CLIENT_ID_SCHEME_X509_SAN_DNS)
            case ClientIdPrefix.VerifierAttestation => Some(OpenId4VPSpec.CLIENT_ID_SCHEME_VERIFIER_ATTESTATION)
            case ClientIdPrefix.DecentralizedIdentifier => Some(OpenId4VPSpec.CLIENT_ID_SCHEME_DID)
            case ClientIdPrefix.OpenidFederation => Some(OpenId4VPSpec.CLIENT_ID_SCHEME_OPENID_FEDERATION)
            case _ => None
        }
        match (prefix) {
            case Some(p) => p + ":" + originalClientId
            case None => originalClientId
        }
    }

    public func toString(): String { clientId() }

    // Parse clientId string (mirrors iOS VerifierId.parse)
    public static func parse(clientId: String): VerifierId {
        // Handle DID scheme (contains "did:")
        if (clientId.startsWith(OpenId4VPSpec.CLIENT_ID_SCHEME_DID_WITH_SEPARATOR)) {
            return VerifierId(scheme: ClientIdPrefix.PreRegistered, originalClientId: clientId)
        }
        // No separator → pre-registered
        if (!clientId.contains(":")) {
            return VerifierId(scheme: ClientIdPrefix.PreRegistered, originalClientId: clientId)
        }
        // Split at first colon
        let sepIdx = clientId.indexOf(":")
        match (sepIdx) {
            case None =>
                return VerifierId(scheme: ClientIdPrefix.PreRegistered, originalClientId: clientId)
            case Some(idx) =>
                let schemeStr = clientId[0..idx]
                let rest = clientId[(idx + 1)..]
                match (ClientIdPrefix.fromRawValue(schemeStr)) {
                    case None =>
                        return VerifierId(scheme: ClientIdPrefix.PreRegistered, originalClientId: clientId)
                    case Some(ClientIdPrefix.PreRegistered) =>
                        return VerifierId(scheme: ClientIdPrefix.PreRegistered, originalClientId: clientId)
                    case Some(scheme) =>
                        return VerifierId(scheme: scheme, originalClientId: rest)
                }
        }
    }
}

// ---------------------------------------------------------------------------
// Client — mirrors iOS Client enum (sealed class hierarchy)
// X.509 certificate: parsed via cjx509 (Cert.fromPem / Cert.fromDer).
// Leaf Cert stored in X509SanDnsClient.cert / X509HashClient.cert.
// ---------------------------------------------------------------------------

public abstract sealed class Client {
    public func id(): VerifierId {
        match (this) {
            case c: PreRegisteredClient =>
                VerifierId(scheme: ClientIdPrefix.PreRegistered, originalClientId: c.clientId)
            case c: RedirectUriClient =>
                VerifierId(scheme: ClientIdPrefix.RedirectUri, originalClientId: c.clientId)
            case c: X509SanDnsClient =>
                VerifierId(scheme: ClientIdPrefix.X509SanDns, originalClientId: c.clientId)
            case c: X509HashClient =>
                VerifierId(scheme: ClientIdPrefix.X509Hash, originalClientId: c.clientId)
            case c: DidClient =>
                VerifierId(scheme: ClientIdPrefix.DecentralizedIdentifier, originalClientId: c.did)
            case c: AttestedClient =>
                VerifierId(scheme: ClientIdPrefix.VerifierAttestation, originalClientId: c.clientId)
            case _ => VerifierId(scheme: ClientIdPrefix.PreRegistered, originalClientId: "")
        }
    }

    public func legalName(): Option<String> {
        match (this) {
            // Note: field is clientLegalName to avoid conflict with this method name
            case c: PreRegisteredClient => Some(c.clientLegalName)
            case c: X509SanDnsClient =>
                match (c.cert) {
                    case Some(leaf) => Some(extractOrgFromSubject(leaf.subject))
                    case None =>
                        if (c.certPem.isEmpty()) { None } else { Some(extractOrgFromPem(c.certPem)) }
                }
            case c: X509HashClient =>
                match (c.cert) {
                    case Some(leaf) => Some(extractOrgFromSubject(leaf.subject))
                    case None =>
                        if (c.certPem.isEmpty()) { None } else { Some(extractOrgFromPem(c.certPem)) }
                }
            case _ => None
        }
    }

    // Verifier display name = the leaf certificate subject's CN (Common Name),
    // e.g. "Verifier Signer dev" — mirrors iOS OpenId4VpService
    // (getCN(from: x509.subject.description)). Distinct from legalName(), which
    // surfaces the Organization (O=). None when no cert / no CN.
    public func commonName(): Option<String> {
        match (this) {
            case c: PreRegisteredClient => Some(c.clientLegalName)
            case c: X509SanDnsClient =>
                match (c.cert) {
                    case Some(leaf) => Some(extractCNFromSubject(leaf.subject))
                    case None =>
                        if (c.certPem.isEmpty()) { None } else { Some(extractCNFromPem(c.certPem)) }
                }
            case c: X509HashClient =>
                match (c.cert) {
                    case Some(leaf) => Some(extractCNFromSubject(leaf.subject))
                    case None =>
                        if (c.certPem.isEmpty()) { None } else { Some(extractCNFromPem(c.certPem)) }
                }
            case _ => None
        }
    }

    // The verifier's leaf authentication certificate (WRPAC), when the client
    // was authenticated via an x509_* scheme. Mirrors iOS `extractWRPAC(from:)`
    // in RequestAuthenticator/RequestAuthorizer: only x509SanDns / x509Hash
    // clients carry an authentication certificate. Falls back to parsing the
    // stored PEM when the parsed Cert is not present.
    public func leafCertificate(): Option<Cert> {
        match (this) {
            case c: X509SanDnsClient =>
                match (c.cert) {
                    case Some(leaf) => Some(leaf)
                    case None => leafCertFromPem(c.certPem)
                }
            case c: X509HashClient =>
                match (c.cert) {
                    case Some(leaf) => Some(leaf)
                    case None => leafCertFromPem(c.certPem)
                }
            case _ => None
        }
    }
}

// Parse the first certificate from a PEM string; None when absent/invalid.
func leafCertFromPem(pem: String): Option<Cert> {
    if (pem.isEmpty()) { return None }
    try {
        let certs = Cert.fromPem(pem)
        if (certs.size < 1) { return None }
        return Some(certs[0])
    } catch (_: Exception) {
        return None
    }
}

public class PreRegisteredClient <: Client {
    public let clientId: String
    // Renamed from legalName to avoid conflict with parent class method legalName()
    public let clientLegalName: String
    public init(clientId!: String, legalName!: String = "") {
        this.clientId = clientId
        this.clientLegalName = legalName
    }
}

public class RedirectUriClient <: Client {
    public let clientId: String
    public init(clientId!: String) {
        this.clientId = clientId
    }
}

// X509SanDnsClient stores the parsed leaf certificate (from x5c JWT header).
// The `cert` field is None when the client was constructed without a JWT
// (plain request with x509_san_dns scheme — chain validation deferred to
// the JwtSecured path in authorization_resolver).
public class X509SanDnsClient <: Client {
    public let clientId: String
    public let certPem: String
    public let cert: Option<Cert>
    public init(clientId!: String, certPem!: String = "", cert!: Option<Cert> = None) {
        this.clientId = clientId
        this.certPem = certPem
        this.cert = cert
    }
}

// X509HashClient stores the parsed leaf certificate (from x5c JWT header).
public class X509HashClient <: Client {
    public let clientId: String
    public let certPem: String
    public let cert: Option<Cert>
    public init(clientId!: String, certPem!: String = "", cert!: Option<Cert> = None) {
        this.clientId = clientId
        this.certPem = certPem
        this.cert = cert
    }
}

public class DidClient <: Client {
    public let did: String
    public init(did!: String) {
        this.did = did
    }
}

public class AttestedClient <: Client {
    public let clientId: String
    public init(clientId!: String) {
        this.clientId = clientId
    }
}

// ---------------------------------------------------------------------------
// X.509 helper: extract Organization (O=) from a PEM-encoded certificate.
// Uses cjx509 Cert.fromPem to parse, then reads subject DN.
// Mirrors iOS Certificate.legaName which extracts organizationName from issuer.
// ---------------------------------------------------------------------------
func extractOrgFromPem(pem: String): String {
    try {
        let certs = Cert.fromPem(pem)
        if (certs.size < 1) { return "" }
        return extractOrgFromSubject(certs[0].subject)
    } catch (_: Exception) {
        return ""
    }
}

func extractCNFromPem(pem: String): String {
    try {
        let certs = Cert.fromPem(pem)
        if (certs.size < 1) { return "" }
        return extractCNFromSubject(certs[0].subject)
    } catch (_: Exception) {
        return ""
    }
}

// Extract the CN= (commonName) value from a DN string. Matches "CN=" (not the
// "C=" country attribute) case-insensitively, prev char being ',' or start.
// Returns "" if not found.
func extractCNFromSubject(dn: String): String {
    let arr = dn.toArray()
    let n = arr.size
    var i: Int64 = 0
    while (i < n) {
        // Match 'C' (0x43) or 'c' (0x63) at position i
        if (arr[i] == 0x43u8 || arr[i] == 0x63u8) {
            let prevIsComma: Bool = (i == 0) || (arr[i - 1] == 0x2Cu8)  // ','
            // next must be 'N'/'n' then '='
            if (prevIsComma && i + 2 < n
                && (arr[i + 1] == 0x4Eu8 || arr[i + 1] == 0x6Eu8)      // 'N'/'n'
                && arr[i + 2] == 0x3Du8) {                             // '='
                var j = i + 3
                while (j < n && arr[j] != 0x2Cu8) {
                    j++
                }
                return String.fromUtf8(arr[i + 3..j])
            }
        }
        i++
    }
    ""
}

// Extract the O= (organizationName) value from a DN string.
// stdx X509Certificate.subject.toString() uses lowercase attribute names:
//   "cn=Test Leaf,o=Test Org,c=DE"
// RFC 4514 / OpenSSL may use uppercase:
//   "CN=Test Leaf,O=Test Org,C=DE"
// This function handles both cases.
// Returns "" if not found.
func extractOrgFromSubject(dn: String): String {
    let arr = dn.toArray()
    // Scan for byte pattern: comma (or start) then ('O' or 'o') then '='
    let n = arr.size
    var i: Int64 = 0
    while (i < n) {
        // Match 'O' (0x4F) or 'o' (0x6F) at position i
        if (arr[i] == 0x4Fu8 || arr[i] == 0x6Fu8) {
            let prevIsComma: Bool = (i == 0) || (arr[i - 1] == 0x2Cu8)  // ','
            if (prevIsComma && i + 1 < n && arr[i + 1] == 0x3Du8) {  // '='
                // collect value until next comma or end
                var j = i + 2
                while (j < n && arr[j] != 0x2Cu8) {
                    j++
                }
                return String.fromUtf8(arr[i + 2..j])
            }
        }
        i++
    }
    ""
}

// ---------------------------------------------------------------------------
// X.509 SAN: extract dnsName entries from a certificate's Subject Alternative
// Name extension (OID 2.5.29.17).
//
// SAN value DER layout (RFC 5280 §4.2.1.6):
//   GeneralNames ::= SEQUENCE OF GeneralName
//   GeneralName  ::= CHOICE {
//     dnsName [2] IMPLICIT IA5String   (tag 0x82)
//     ...
//   }
// The OCTET STRING wrapper around GeneralNames is already stripped by
// extensionValue(), so the bytes start with the outer SEQUENCE tag 0x30.
// ---------------------------------------------------------------------------
public func extractSanDnsNames(cert: Cert): Array<String> {
    let SAN_OID = "2.5.29.17"
    let extBytesOpt = try {
        extensionValue(cert, SAN_OID)
    } catch (_: Exception) {
        return []
    }
    let extBytes: Array<Byte> = match (extBytesOpt) {
        case None => return []
        case Some(b) => b
    }
    // extBytes is the raw value of the OCTET STRING wrapper: it contains the
    // DER encoding of GeneralNames (outer SEQUENCE).
    let result = ArrayList<String>()
    let n = extBytes.size
    if (n < 2 || extBytes[0] != 0x30u8) { return [] }
    var offset: Int64 = 1
    // read length of outer SEQUENCE
    let (seqLen, off1) = sanReadLength(extBytes, offset)
    offset = off1
    let seqEnd = offset + seqLen
    while (offset < seqEnd) {
        if (offset >= n) { break }
        let tag = extBytes[offset]
        offset++
        let (entLen, off2) = sanReadLength(extBytes, offset)
        offset = off2
        if (tag == 0x82u8) {
            // dnsName [2] IMPLICIT IA5String
            if (offset + entLen <= n) {
                let s = String.fromUtf8(extBytes[offset..offset + entLen])
                result.add(s)
            }
        }
        offset += entLen
    }
    result.toArray()
}

// Minimal DER length reader (same logic as in crl.cj, duplicated here to avoid
// cross-package internal function access).
func sanReadLength(bytes: Array<Byte>, startOffset: Int64): (Int64, Int64) {
    if (startOffset >= bytes.size) { return (0, startOffset) }
    let first = bytes[startOffset]
    if ((first & 0x80u8) == 0u8) {
        return (Int64(first), startOffset + 1)
    }
    let numBytes = Int64(first & 0x7fu8)
    if (numBytes == 0) { return (0, startOffset + 1) }
    let end = startOffset + 1 + numBytes
    if (end > bytes.size) { return (0, end) }
    var len: Int64 = 0
    var i = startOffset + 1
    while (i < end) {
        len = (len << 8) | Int64(bytes[i])
        i++
    }
    (len, end)
}

// ---------------------------------------------------------------------------
// X.509 chain verification helpers used by authorization_resolver.
// Exposed as public so resolver can call without duplicating logic.
// ---------------------------------------------------------------------------

// Parse a list of base64-encoded DER certificates (x5c header format).
// Each entry is raw base64 (not PEM). Returns parsed Cert array; ignores
// entries that fail to parse.
public func parseCertsFromX5c(x5cEntries: Array<String>): Array<Cert> {
    let result = ArrayList<Cert>()
    for (b64 in x5cEntries) {
        try {
            let derBytes = x509Base64Decode(b64)
            let c = Cert.fromDer(derBytes)
            result.add(c)
        } catch (_: Exception) {
            ()  // skip malformed entries
        }
    }
    result.toArray()
}

// Base64 standard decode (for x5c DER bytes — standard base64, not url-safe).
// Uses the same approach as VCI's Base64Url but without the url-safe transform.
func x509Base64Decode(b64: String): Array<Byte> {
    // Convert standard base64 to url-safe then use existing Base64Url infra
    // from the core-crypto package (available via eudi_lib_core_crypto).
    // Reimplement here to avoid cross-package function access of internal helpers.
    let padded = x509AddPadding(b64)
    let arr = padded.toArray()
    let n = arr.size
    if (n % 4 != 0) {
        throw Exception("x509Base64Decode: invalid base64 length ${n}")
    }
    let outputLen = (n / 4) * 3 - x509CountPad(padded)
    let out = Array<Byte>(outputLen) { _ => 0u8 }
    var i: Int64 = 0
    var j: Int64 = 0
    while (i < n) {
        let a = x509B64Val(arr[i])
        let b = x509B64Val(arr[i + 1])
        let c = x509B64Val(arr[i + 2])
        let d = x509B64Val(arr[i + 3])
        if (j < outputLen) { out[j] = UInt8((a << 2) | (b >> 4)); j++ }
        if (j < outputLen) { out[j] = UInt8(((b & 0x0F) << 4) | (c >> 2)); j++ }
        if (j < outputLen) { out[j] = UInt8(((c & 0x03) << 6) | d); j++ }
        i += 4
    }
    out
}

func x509B64Val(c: Byte): Int64 {
    let ch = Int64(c)
    if (ch >= 65 && ch <= 90)  { return ch - 65 }        // A-Z: 0-25
    if (ch >= 97 && ch <= 122) { return ch - 71 }         // a-z: 26-51
    if (ch >= 48 && ch <= 57)  { return ch + 4 }          // 0-9: 52-61
    if (ch == 43 || ch == 45)  { return 62 }               // + or - → 62
    if (ch == 47 || ch == 95)  { return 63 }               // / or _ → 63
    if (ch == 61)               { return 0 }                // = padding
    throw Exception("x509B64Val: invalid base64 char ${ch}")
}

func x509AddPadding(s: String): String {
    let r = s.size % 4
    if (r == 0) { return s }
    if (r == 2) { return s + "==" }
    if (r == 3) { return s + "=" }
    return s
}

func x509CountPad(s: String): Int64 {
    let arr = s.toArray()
    var count: Int64 = 0
    let n = arr.size
    if (n >= 1 && arr[n - 1] == 0x3Du8) { count++ }
    if (n >= 2 && arr[n - 2] == 0x3Du8) { count++ }
    count
}

// Compute SHA-256 hash of certificate DER bytes as URL-safe base64 (no padding).
// Used for x509_hash scheme: clientId == base64url(sha256(leafCertDer)).
public func certSha256Base64Url(cert: Cert): String {
    // Use stdx Digest from core-crypto package via eudi_lib_core_crypto
    // Import path: eudi_lib_core_crypto package provides Digest
    // However to avoid extra imports, use stdx.crypto.digest directly.
    // The eudi_cjcrypto package wraps stdx; call stdx directly here.
    let der = cert.toDer()
    // stdx.crypto.digest.{Digest, HashAlgorithm} is available in stdx
    let sha256 = stdxSha256(der)
    x509Base64UrlEncode(sha256)
}

// SHA-256 via eudi_lib_core_crypto.Digest (already a dependency of this module).
func stdxSha256(data: Array<Byte>): Array<Byte> {
    Digest.sha256(data)
}

// ---------------------------------------------------------------------------
// JWS / X.509 cryptographic verification helpers.
//
// These give the authorization resolver the missing security-critical
// primitives:
//   - verifyJwsWithCert: cryptographically verify a compact ES256 JWS against
//     the public key carried in an X.509 leaf certificate. This is what the
//     iOS AccessValidator.validateX509 does via JOSESwift + leaf public key.
//   - parseRootsFromPem / verifyX5cChain: real PKIX chain validation against a
//     wallet-supplied set of trust anchors (iOS X509CertificateTrust).
//
// Fail-closed: when no roots are supplied, verifyX5cChain returns false (the
// chain is NOT trusted). The resolver turns that into a rejection.
// ---------------------------------------------------------------------------

// Cryptographically verify a compact ES256 JWS using the EC public key of a
// leaf certificate. Returns true only if the signature is valid AND the JWS
// header declares alg=ES256 (algorithm-confusion defense lives inside
// JoseJws.verifyEs256 / core-crypto Jws.verifyEs256).
//
// Returns false (never throws) on any structural problem (non-EC key, bad SPKI,
// undecodable signature, etc.) so the caller can uniformly reject.
public func verifyJwsWithCert(compactJws: String, leaf: Cert): Bool {
    let pub: ECDSAPublicKey
    try {
        // cert.publicKeyDer is the full SubjectPublicKeyInfo DER; ECDSAPublicKey
        // decodes the SPKI directly.
        pub = ECDSAPublicKey.decodeDer(DerBlob(leaf.publicKeyDer))
    } catch (_: Exception) {
        return false
    }
    try {
        return JoseJws.verifyEs256(compactJws, pub)
    } catch (_: Exception) {
        return false
    }
}

// Verify a compact ES256 JWS against a raw SubjectPublicKeyInfo DER (the SPKI
// of a P-256 EC public key). Returns false on any failure.
public func verifyJwsWithSpki(compactJws: String, spkiDer: Array<UInt8>): Bool {
    let pub: ECDSAPublicKey
    try {
        pub = ECDSAPublicKey.decodeDer(DerBlob(spkiDer))
    } catch (_: Exception) {
        return false
    }
    try {
        return JoseJws.verifyEs256(compactJws, pub)
    } catch (_: Exception) {
        return false
    }
}

// Test/integration support: sign a compact ES256 JWS. headerJson MUST declare
// "alg":"ES256". Exposed so other packages (and tests in the entry module that
// only depend on this library) can construct genuinely-signed request objects
// without re-importing the jose / core-crypto packages directly.
public func signEs256Jws(headerJson: String, payload: Array<UInt8>, priv: ECDSAPrivateKey): String {
    return JoseJws.signEs256(headerJson, payload, priv)
}

// Test/integration support: derive the uncompressed P-256 SPKI DER for a private
// key's public half, so callers can verify a JWS they just signed via
// verifyJwsWithSpki without importing core-crypto's EcdsaP256 directly.
public func publicSpkiOf(priv: ECDSAPrivateKey): Array<UInt8> {
    let pub = ECDSAPublicKey(priv)
    return pub.encodeToDer().body
}

// Test/integration support: build a P-256 JWK JSON ({crv,kty,x,y}) for the
// public half of a private key. Used to exercise IssuerTrust.ByPublicKey paths.
public func ecJwkJsonOf(priv: ECDSAPrivateKey): String {
    let spki = publicSpkiOf(priv)
    // SPKI = 26-byte fixed P-256 prefix + 65-byte uncompressed point.
    let point = Array<UInt8>(65, repeat: 0)
    let off = spki.size - 65
    for (i in 0..65) {
        point[i] = spki[off + i]
    }
    return EcPublicKey.fromHuksUncompressed(point).toJson()
}

// Wrap a 65-byte uncompressed P-256 EC point (0x04||X||Y) into a complete
// SubjectPublicKeyInfo DER so it can be decoded by ECDSAPublicKey.decodeDer.
// The AlgorithmIdentifier prefix for id-ecPublicKey + prime256v1 is a fixed
// 26-byte header followed by the BIT STRING wrapping the point.
public func buildP256Spki(point: Array<UInt8>): Array<UInt8> {
    // SEQUENCE(0x30) len=0x59 {
    //   SEQUENCE(0x30) len=0x13 { OID ecPublicKey, OID prime256v1 }
    //   BIT STRING(0x03) len=0x42 00 <65-byte point>
    // }
    let prefix: Array<UInt8> = [
        0x30u8, 0x59u8, 0x30u8, 0x13u8, 0x06u8, 0x07u8, 0x2au8, 0x86u8,
        0x48u8, 0xceu8, 0x3du8, 0x02u8, 0x01u8, 0x06u8, 0x08u8, 0x2au8,
        0x86u8, 0x48u8, 0xceu8, 0x3du8, 0x03u8, 0x01u8, 0x07u8, 0x03u8,
        0x42u8, 0x00u8
    ]
    let out = Array<UInt8>(prefix.size + point.size, repeat: 0)
    for (i in 0..prefix.size) {
        out[i] = prefix[i]
    }
    for (i in 0..point.size) {
        out[prefix.size + i] = point[i]
    }
    return out
}

// Parse zero or more root CA certificates from a PEM string. Returns an empty
// array on parse failure or when the input is None/empty.
public func parseRootsFromPem(pem: Option<String>): Array<Cert> {
    match (pem) {
        case None => return Array<Cert>()
        case Some(s) =>
            if (s.isEmpty()) { return Array<Cert>() }
            try {
                return Cert.fromPem(s)
            } catch (_: Exception) {
                return Array<Cert>()
            }
    }
}

// Real PKIX chain validation of an x5c chain (leaf = certs[0]) against
// wallet-supplied trust anchors. Returns false when there are no roots
// (fail-closed) or the chain does not verify.
public func verifyX5cChain(certs: Array<Cert>, roots: Array<Cert>): Bool {
    if (certs.size < 1) { return false }
    // Fail-closed: with no trust anchors there is nothing to anchor trust to.
    if (roots.size < 1) { return false }
    let leaf = certs[0]
    let intermediates: Array<Cert> = if (certs.size > 1) {
        certs[1..certs.size]
    } else {
        Array<Cert>()
    }
    try {
        return verifyChain(leaf, intermediates, roots)
    } catch (_: Exception) {
        return false
    }
}

func x509Base64UrlEncode(bytes: Array<Byte>): String {
    let B64URL: Array<Byte> = [
        0x41u8, 0x42u8, 0x43u8, 0x44u8, 0x45u8, 0x46u8, 0x47u8, 0x48u8,
        0x49u8, 0x4Au8, 0x4Bu8, 0x4Cu8, 0x4Du8, 0x4Eu8, 0x4Fu8, 0x50u8,
        0x51u8, 0x52u8, 0x53u8, 0x54u8, 0x55u8, 0x56u8, 0x57u8, 0x58u8,
        0x59u8, 0x5Au8, 0x61u8, 0x62u8, 0x63u8, 0x64u8, 0x65u8, 0x66u8,
        0x67u8, 0x68u8, 0x69u8, 0x6Au8, 0x6Bu8, 0x6Cu8, 0x6Du8, 0x6Eu8,
        0x6Fu8, 0x70u8, 0x71u8, 0x72u8, 0x73u8, 0x74u8, 0x75u8, 0x76u8,
        0x77u8, 0x78u8, 0x79u8, 0x7Au8, 0x30u8, 0x31u8, 0x32u8, 0x33u8,
        0x34u8, 0x35u8, 0x36u8, 0x37u8, 0x38u8, 0x39u8, 0x2Du8, 0x5Fu8
    ]
    let n = bytes.size
    let outLen = ((n + 2) / 3) * 4
    let out = Array<Byte>(outLen) { _ => 0x3Du8 }  // '='
    var i: Int64 = 0
    var j: Int64 = 0
    while (i < n) {
        let b0 = Int64(bytes[i])
        let b1 = if (i + 1 < n) { Int64(bytes[i + 1]) } else { 0 }
        let b2 = if (i + 2 < n) { Int64(bytes[i + 2]) } else { 0 }
        out[j] = B64URL[b0 >> 2]
        out[j + 1] = B64URL[((b0 & 3) << 4) | (b1 >> 4)]
        if (i + 1 < n) { out[j + 2] = B64URL[((b1 & 0xF) << 2) | (b2 >> 6)] }
        if (i + 2 < n) { out[j + 3] = B64URL[b2 & 0x3F] }
        i += 3
        j += 4
    }
    // Strip trailing '=' padding for URL-safe base64
    var end = outLen
    while (end > 0 && out[end - 1] == 0x3Du8) { end-- }
    String.fromUtf8(out[0..end])
}

// ---------------------------------------------------------------------------
// ClientMetaDataSource — mirrors iOS ClientMetaDataSource
// (passByValue only — clientMetadataUri (remote) is block 5 scope)
// ---------------------------------------------------------------------------

public abstract sealed class ClientMetaDataSource {}

public class PassByValueSource <: ClientMetaDataSource {
    public let metaDataJson: String  // raw JSON string of client_metadata
    public init(json: String) {
        this.metaDataJson = json
    }
}
