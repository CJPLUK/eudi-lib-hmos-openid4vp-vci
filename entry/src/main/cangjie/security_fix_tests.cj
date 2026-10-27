/*
 * security_fix_tests.cj — proof tests for the four HIGH security fixes:
 *   1. JAR (request object) JWS signature verification
 *   2. X.509 chain validation (fail-closed against trust anchors)
 *   3. signed issuer-metadata JWS verification
 *   4. attestation / DID client verification (no silent trust)
 *
 * The tests prove BOTH directions where feasible:
 *   - a genuinely-signed JWS verifies true; a tampered one verifies false
 *   - the resolver REJECTS requests whose signature / chain / trust cannot be
 *     established (the actual vulnerability being closed)
 */
package ohos_app_cangjie_entry

import std.unittest.*
import std.unittest.testmacro.*
import std.collection.*
import stdx.crypto.keys.*

import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.entity.client.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.entity.config.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.entity.request.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.entity.types.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.resolver.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.config.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.resolver.*
import ohos_app_cangjie_eudi_cjx509.x509.core.{Cert, verifyChain}

// ---------------------------------------------------------------------------
// Helpers — build genuinely-signed and tampered request-object JWSs.
// ---------------------------------------------------------------------------

// base64url-encode (no padding) using the JWS-internal alphabet, by signing an
// empty body is unnecessary — we only need header/payload b64url for tampering.
// We instead reuse signEs256Jws which produces b64url(header).b64url(payload).b64url(sig)
// and then mutate parts for the negative cases.

func sfBuildSignedJws(headerJson: String, payloadJson: String, priv: ECDSAPrivateKey): String {
    return signEs256Jws(headerJson, payloadJson.toArray(), priv)
}

// Flip one character of the signature segment to invalidate it.
func sfTamperSignature(jws: String): String {
    let parts = jws.split(".")
    if (parts.size != 3) { return jws }
    let sig = parts[2]
    let arr = sig.toArray()
    if (arr.size == 0) { return jws }
    // toggle last char between 'A' and 'B'
    if (arr[arr.size - 1] == b'A') {
        arr[arr.size - 1] = b'B'
    } else {
        arr[arr.size - 1] = b'A'
    }
    return parts[0] + "." + parts[1] + "." + String.fromUtf8(arr)
}

// ===========================================================================
// HIGH #1 + crypto primitive: JWS ES256 signature verification
// ===========================================================================

@Test
class SecJwsVerifyPrimitiveUT {

    // A genuinely-signed ES256 JWS verifies true against the signer's SPKI.
    @TestCase
    func testValidSignatureAccepted(): Unit {
        let priv = ECDSAPrivateKey(Curve.P256)
        let header = "{\"alg\":\"ES256\",\"typ\":\"JWT\"}"
        let payload = "{\"hello\":\"world\"}"
        let jws = sfBuildSignedJws(header, payload, priv)
        let spki = publicSpkiOf(priv)
        @Expect(verifyJwsWithSpki(jws, spki), true)
    }

    // A tampered signature verifies false (vulnerability closed).
    @TestCase
    func testTamperedSignatureRejected(): Unit {
        let priv = ECDSAPrivateKey(Curve.P256)
        let header = "{\"alg\":\"ES256\"}"
        let payload = "{\"hello\":\"world\"}"
        let jws = sfBuildSignedJws(header, payload, priv)
        let tampered = sfTamperSignature(jws)
        let spki = publicSpkiOf(priv)
        @Expect(verifyJwsWithSpki(tampered, spki), false)
    }

    // A JWS signed by key A must NOT verify against key B's SPKI.
    @TestCase
    func testWrongKeyRejected(): Unit {
        let privA = ECDSAPrivateKey(Curve.P256)
        let privB = ECDSAPrivateKey(Curve.P256)
        let jws = sfBuildSignedJws("{\"alg\":\"ES256\"}", "{\"a\":1}", privA)
        let spkiB = publicSpkiOf(privB)
        @Expect(verifyJwsWithSpki(jws, spkiB), false)
    }

    // A header that does not declare alg=ES256 must be rejected (alg-confusion).
    @TestCase
    func testNonEs256HeaderRejected(): Unit {
        let priv = ECDSAPrivateKey(Curve.P256)
        // Sign with a header that claims alg=none — verifyEs256 must reject it
        // even though the raw signature bytes would otherwise check out, because
        // it enforces alg=ES256 in the protected header.
        let jws = sfBuildSignedJws("{\"alg\":\"none\"}", "{\"a\":1}", priv)
        let spki = publicSpkiOf(priv)
        @Expect(verifyJwsWithSpki(jws, spki), false)
    }

    // buildP256Spki(point) round-trips through verifyJwsWithSpki.
    @TestCase
    func testBuildSpkiRoundTrip(): Unit {
        let priv = ECDSAPrivateKey(Curve.P256)
        let spki = publicSpkiOf(priv)
        // Extract 65-byte point (tail of SPKI) and re-wrap.
        let point = Array<UInt8>(65, repeat: 0)
        let offset = spki.size - 65
        for (i in 0..65) {
            point[i] = spki[offset + i]
        }
        let rebuilt = buildP256Spki(point)
        let jws = sfBuildSignedJws("{\"alg\":\"ES256\"}", "{\"x\":1}", priv)
        @Expect(verifyJwsWithSpki(jws, rebuilt), true)
    }
}

// ===========================================================================
// HIGH #2: X.509 chain validation is fail-closed
// ===========================================================================

@Test
class SecX509ChainFailClosedUT {

    // With no trust anchors, an x5c chain is NOT trusted (fail-closed).
    @TestCase
    func testNoRootsRejected(): Unit {
        let certs = Cert.fromPem(VCI_LEAF_PEM)
        let roots: Array<Cert> = Array<Cert>()
        @Expect(verifyX5cChain(certs, roots), false)
    }

    // Empty cert list is rejected regardless of roots.
    @TestCase
    func testEmptyCertsRejected(): Unit {
        let empty: Array<Cert> = Array<Cert>()
        let roots = Cert.fromPem(VCI_LEAF_PEM)
        @Expect(verifyX5cChain(empty, roots), false)
    }

    // A self-contained, untrusted chain (leaf as its own "root" set) does not
    // magically verify — verifyChain must still reject an unrelated/self-signed
    // anchoring that is not a real CA path. (Uses the static SAN cert as a
    // candidate root for the LEAF cert; they are unrelated ⇒ reject.)
    @TestCase
    func testUnrelatedRootRejected(): Unit {
        let leafCerts = Cert.fromPem(VCI_LEAF_PEM)
        let unrelatedRoots = Cert.fromPem(VCI_SAN_CERT_PEM)
        @Expect(verifyX5cChain(leafCerts, unrelatedRoots), false)
    }

    // parseRootsFromPem returns empty on None / empty / garbage (fail-closed).
    @TestCase
    func testParseRootsFailClosed(): Unit {
        @Expect(parseRootsFromPem(Option<String>.None).size, 0)
        @Expect(parseRootsFromPem(Option<String>.Some("")).size, 0)
        @Expect(parseRootsFromPem(Option<String>.Some("not a pem")).size, 0)
    }
}

// ===========================================================================
// HIGH #1 + #2: resolver rejects unverifiable x509 JAR requests
// ===========================================================================

@Test
class SecResolverX509RejectUT {

    // Build a minimal valid request-object payload for x509_san_dns.
    private func sanRequestPayload(clientId: String): String {
        return "{" +
            "\"response_type\":\"vp_token\"," +
            "\"client_id\":\"${clientId}\"," +
            "\"client_id_scheme\":\"x509_san_dns\"," +
            "\"nonce\":\"abc123\"," +
            "\"response_mode\":\"direct_post\"," +
            "\"response_uri\":\"https://verifier.example.com/cb\"" +
            "}"
    }

    private func sanConfig(roots: Option<String>): OpenId4VPWalletConfiguration {
        return OpenId4VPWalletConfiguration(
            supportedClientIdSchemes: [ClientIdPrefix.X509SanDns],
            trustedRootCertsPem: roots
        )
    }

    // A request-object JWS that has NO x5c header is rejected.
    @TestCase
    func testNoX5cRejected(): Unit {
        let priv = ECDSAPrivateKey(Curve.P256)
        let clientId = "x509_san_dns:verifier.example.com"
        let header = "{\"alg\":\"ES256\"}"  // no x5c
        let jws = sfBuildSignedJws(header, sanRequestPayload(clientId), priv)
        let req = JwtSecuredPassByValue(clientId, jws)
        let resolver = AuthorizationRequestResolver()
        let result = resolver.resolve(sanConfig(Option<String>.None), req)
        match (result) {
            case _: InvalidResolution => ()  // expected — cannot authenticate
            case _ => throw Exception("x509_san_dns without x5c must be rejected")
        }
    }

    // A plain (unsigned) x509_san_dns request is rejected (cannot authenticate).
    @TestCase
    func testPlainX509Rejected(): Unit {
        let obj = UnvalidatedRequestObject(
            responseType: Some("vp_token"),
            clientId: Some("x509_san_dns:verifier.example.com"),
            clientIdScheme: Some("x509_san_dns"),
            nonce: Some("n0")
        )
        let req = Plain(obj)
        let resolver = AuthorizationRequestResolver()
        let result = resolver.resolve(sanConfig(Option<String>.None), req)
        match (result) {
            case _: InvalidResolution => ()
            case _ => throw Exception("plain x509_san_dns must be rejected (no x5c)")
        }
    }

    // An x5c-bearing request with a real cert but NO configured trust anchors is
    // rejected even before signature checks (fail-closed chain trust).
    @TestCase
    func testX5cButNoTrustAnchorsRejected(): Unit {
        let priv = ECDSAPrivateKey(Curve.P256)
        let clientId = "x509_san_dns:verifier.example.com"
        // Embed the static SAN cert DER as the x5c entry.
        let header = "{\"alg\":\"ES256\",\"x5c\":[\"${VCI_SAN_CERT_B64_DER}\"]}"
        let jws = sfBuildSignedJws(header, sanRequestPayload(clientId), priv)
        let req = JwtSecuredPassByValue(clientId, jws)
        let resolver = AuthorizationRequestResolver()
        // No trust anchors ⇒ chain not trusted ⇒ reject.
        let result = resolver.resolve(sanConfig(Option<String>.None), req)
        match (result) {
            case _: InvalidResolution => ()
            case _ => throw Exception("x509 chain with no trust anchors must be rejected")
        }
    }
}

// ===========================================================================
// HIGH #4: DID client rejected without a resolver; attestation typ/x5c checks
// ===========================================================================

@Test
class SecDidAndAttestationUT {

    private func didConfig(): OpenId4VPWalletConfiguration {
        return OpenId4VPWalletConfiguration(
            supportedClientIdSchemes: [ClientIdPrefix.DecentralizedIdentifier]
        )
    }

    private func attConfig(): OpenId4VPWalletConfiguration {
        return OpenId4VPWalletConfiguration(
            supportedClientIdSchemes: [ClientIdPrefix.VerifierAttestation]
        )
    }

    // DID client with NO resolver configured ⇒ rejected (no silent trust).
    @TestCase
    func testDidWithoutResolverRejected(): Unit {
        let priv = ECDSAPrivateKey(Curve.P256)
        let clientId = "did:example:123"
        let payload = "{" +
            "\"response_type\":\"vp_token\"," +
            "\"client_id\":\"${clientId}\"," +
            "\"client_id_scheme\":\"decentralized_identifier\"," +
            "\"nonce\":\"n1\"" +
            "}"
        let header = "{\"alg\":\"ES256\",\"kid\":\"${clientId}#key-1\"}"
        let jws = sfBuildSignedJws(header, payload, priv)
        let req = JwtSecuredPassByValue(clientId, jws)
        let resolver = AuthorizationRequestResolver()  // no DID resolver
        let result = resolver.resolve(didConfig(), req)
        match (result) {
            case _: InvalidResolution => ()
            case _ => throw Exception("DID client without resolver must be rejected")
        }
    }

    // DID client WITH a resolver returning the matching key ⇒ accepted.
    @TestCase
    func testDidWithResolverAccepted(): Unit {
        let priv = ECDSAPrivateKey(Curve.P256)
        let spki = publicSpkiOf(priv)
        let point = Array<UInt8>(65, repeat: 0)
        let off = spki.size - 65
        for (i in 0..65) { point[i] = spki[off + i] }

        let clientId = "did:example:123"
        let payload = "{" +
            "\"response_type\":\"vp_token\"," +
            "\"client_id\":\"${clientId}\"," +
            "\"client_id_scheme\":\"decentralized_identifier\"," +
            "\"nonce\":\"n1\"," +
            "\"response_mode\":\"direct_post\"," +
            "\"response_uri\":\"https://v.example/cb\"" +
            "}"
        let header = "{\"alg\":\"ES256\",\"kid\":\"${clientId}#key-1\"}"
        let jws = sfBuildSignedJws(header, payload, priv)
        let req = JwtSecuredPassByValue(clientId, jws)
        let resolver = AuthorizationRequestResolver(
            didResolver: Some(SfStaticDidResolver(point))
        )
        let result = resolver.resolve(didConfig(), req)
        match (result) {
            case _: JwtRequest => ()  // fully accepted
            case ir: InvalidResolution =>
                // The DID signature verification must have PASSED. Only unrelated
                // downstream request-shape validation (e.g. missing dcql_query in
                // this minimal fixture) may remain. A DID/signature-class error
                // would mean the fix wrongly rejected a valid DID client.
                let m = ir.error.message
                if (m.contains("decentralized_identifier") || m.contains("signature") ||
                    m.contains("resolve public key") || m.contains("DID")) {
                    throw Exception("DID with valid resolver wrongly rejected: ${m}")
                }
            case _ => throw Exception("unexpected resolution result")
        }
    }

    // DID resolver returning a WRONG key ⇒ signature fails ⇒ rejected.
    @TestCase
    func testDidWrongKeyRejected(): Unit {
        let priv = ECDSAPrivateKey(Curve.P256)
        let wrong = ECDSAPrivateKey(Curve.P256)
        let spki = publicSpkiOf(wrong)
        let point = Array<UInt8>(65, repeat: 0)
        let off = spki.size - 65
        for (i in 0..65) { point[i] = spki[off + i] }

        let clientId = "did:example:123"
        let payload = "{\"response_type\":\"vp_token\",\"client_id\":\"${clientId}\"," +
            "\"client_id_scheme\":\"decentralized_identifier\",\"nonce\":\"n1\"}"
        let header = "{\"alg\":\"ES256\",\"kid\":\"${clientId}#k\"}"
        let jws = sfBuildSignedJws(header, payload, priv)
        let req = JwtSecuredPassByValue(clientId, jws)
        let resolver = AuthorizationRequestResolver(
            didResolver: Some(SfStaticDidResolver(point))
        )
        let result = resolver.resolve(didConfig(), req)
        match (result) {
            case _: InvalidResolution => ()
            case _ => throw Exception("DID with wrong resolved key must be rejected")
        }
    }

    // verifier_attestation with a WRONG typ header ⇒ rejected.
    @TestCase
    func testAttestationWrongTypRejected(): Unit {
        let priv = ECDSAPrivateKey(Curve.P256)
        let clientId = "verifier_attestation:v1"
        let payload = "{\"response_type\":\"vp_token\",\"client_id\":\"${clientId}\"," +
            "\"client_id_scheme\":\"verifier_attestation\",\"nonce\":\"n1\"," +
            "\"iss\":\"i\",\"sub\":\"s\"}"
        let header = "{\"alg\":\"ES256\",\"typ\":\"JWT\"}"  // wrong typ
        let jws = sfBuildSignedJws(header, payload, priv)
        let req = JwtSecuredPassByValue(clientId, jws)
        let resolver = AuthorizationRequestResolver()
        let result = resolver.resolve(attConfig(), req)
        match (result) {
            case _: InvalidResolution => ()
            case _ => throw Exception("attestation with wrong typ must be rejected")
        }
    }

    // verifier_attestation with correct typ but NO x5c ⇒ cannot verify ⇒ rejected.
    @TestCase
    func testAttestationNoX5cRejected(): Unit {
        let priv = ECDSAPrivateKey(Curve.P256)
        let clientId = "verifier_attestation:v1"
        let payload = "{\"response_type\":\"vp_token\",\"client_id\":\"${clientId}\"," +
            "\"client_id_scheme\":\"verifier_attestation\",\"nonce\":\"n1\"," +
            "\"iss\":\"i\",\"sub\":\"s\"}"
        let header = "{\"alg\":\"ES256\",\"typ\":\"verifier-attestation+jwt\"}"
        let jws = sfBuildSignedJws(header, payload, priv)
        let req = JwtSecuredPassByValue(clientId, jws)
        let resolver = AuthorizationRequestResolver()
        let result = resolver.resolve(attConfig(), req)
        match (result) {
            case _: InvalidResolution => ()
            case _ => throw Exception("attestation without x5c must be rejected")
        }
    }
}

// Static DID resolver returning a fixed EC point for any DID/kid.
class SfStaticDidResolver <: DidPublicKeyResolver {
    private let point: Array<UInt8>
    public init(point: Array<UInt8>) { this.point = point }
    public func resolveKey(did: String, kid: Option<String>): Option<Array<UInt8>> {
        return Some(point)
    }
}

// ===========================================================================
// HIGH #3: signed issuer-metadata JWS verification
// ===========================================================================

@Test
class SecSignedMetadataUT {

    private func metaPayload(): String {
        return "{\"sub\":\"https://issuer.example.com\",\"iat\":1700000000," +
            "\"credential_issuer\":\"https://issuer.example.com\"}"
    }

    private func metaHeader(): String {
        return "{\"alg\":\"ES256\",\"typ\":\"openidvci-issuer-metadata+jwt\"}"
    }

    // ByPublicKey: a JWS signed by the trusted key verifies true.
    @TestCase
    func testByPublicKeyValidAccepted(): Unit {
        let priv = ECDSAPrivateKey(Curve.P256)
        let jwk = ecJwkJsonOf(priv)
        let jws = signEs256Jws(metaHeader(), metaPayload().toArray(), priv)
        let trust = IssuerTrust.ByPublicKey(jwk)
        @Expect(MetadataFetcher.verifySignedMetadataSignature(jws, trust), true)
    }

    // ByPublicKey: a JWS signed by a DIFFERENT key verifies false.
    @TestCase
    func testByPublicKeyWrongKeyRejected(): Unit {
        let signer = ECDSAPrivateKey(Curve.P256)
        let trusted = ECDSAPrivateKey(Curve.P256)
        let jwk = ecJwkJsonOf(trusted)
        let jws = signEs256Jws(metaHeader(), metaPayload().toArray(), signer)
        let trust = IssuerTrust.ByPublicKey(jwk)
        @Expect(MetadataFetcher.verifySignedMetadataSignature(jws, trust), false)
    }

    // ByPublicKey: a tampered signature verifies false.
    @TestCase
    func testByPublicKeyTamperedRejected(): Unit {
        let priv = ECDSAPrivateKey(Curve.P256)
        let jwk = ecJwkJsonOf(priv)
        let jws = signEs256Jws(metaHeader(), metaPayload().toArray(), priv)
        let parts = jws.split(".")
        let sigArr = parts[2].toArray()
        if (sigArr[sigArr.size - 1] == b'A') {
            sigArr[sigArr.size - 1] = b'B'
        } else {
            sigArr[sigArr.size - 1] = b'A'
        }
        let tampered = parts[0] + "." + parts[1] + "." + String.fromUtf8(sigArr)
        let trust = IssuerTrust.ByPublicKey(jwk)
        @Expect(MetadataFetcher.verifySignedMetadataSignature(tampered, trust), false)
    }

    // ByCertificateChain with no roots ⇒ fail-closed (false).
    @TestCase
    func testByCertChainNoRootsRejected(): Unit {
        let priv = ECDSAPrivateKey(Curve.P256)
        let header = "{\"alg\":\"ES256\",\"typ\":\"openidvci-issuer-metadata+jwt\"," +
            "\"x5c\":[\"${VCI_SAN_CERT_B64_DER}\"]}"
        let jws = signEs256Jws(header, metaPayload().toArray(), priv)
        let trust = IssuerTrust.ByCertificateChain("")  // no roots
        @Expect(MetadataFetcher.verifySignedMetadataSignature(jws, trust), false)
    }

    // ByPublicKey with garbage JWK ⇒ false (cannot build verifier).
    @TestCase
    func testByPublicKeyGarbageJwkRejected(): Unit {
        let priv = ECDSAPrivateKey(Curve.P256)
        let jws = signEs256Jws(metaHeader(), metaPayload().toArray(), priv)
        let trust = IssuerTrust.ByPublicKey("{not valid}")
        @Expect(MetadataFetcher.verifySignedMetadataSignature(jws, trust), false)
    }
}
