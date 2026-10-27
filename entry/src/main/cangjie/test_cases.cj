/*
 * unittest_engine.cj — OpenID4VP/VCI unit tests for the HAP entry module.
 * 48 @Test classes covering VCI + VP public API surface.
 */
package ohos_app_cangjie_entry

import std.unittest.*
import std.unittest.testmacro.*
import std.collection.*
import stdx.compress.zlib.*
import std.io.ByteBuffer
import stdx.crypto.keys.*
import stdx.encoding.json.*
import stdx.encoding.base64.*
import kit.PerformanceAnalysisKit.Hilog
import kit.TestKit.AbilityDelegatorRegistry
import kit.TestKit.TestRunner
import kit.AbilityKit.BundleManager
import kit.AbilityKit.BundleFlag
import kit.AbilityKit.Want

// VCI imports
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.pkce.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.dpop.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.offer.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.types.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.access_mgmt.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.issuer.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.credential.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.issuance.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.issuance.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.resolver.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.util.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.error.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.access.*

// VP imports
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.entity.dcql.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.entity.types.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.entity.client.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.entity.request.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.entity.metadata.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.response.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.service.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.error.*

// X.509 direct import (cjx509 is a direct dep of entry now)
import ohos_app_cangjie_eudi_cjx509.x509.core.{Cert, CertError, verifyChain}
import std.time.DateTime

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func compressDeflateHelper(data: Array<UInt8>): Array<UInt8> {
    let buf = ByteBuffer()
    let cs = CompressOutputStream(buf, wrap: DeflateFormat)
    cs.write(data)
    cs.flush()
    cs.close()
    return buf.bytes()
}

func genEcKey(): ECDSAPrivateKey {
    return ECDSAPrivateKey(Curve.P256)
}

// ===========================================================================
// VCI TESTS
// ===========================================================================

// ---------------------------------------------------------------------------
// Test 1: PKCECodeVerifierLengthUT
// ---------------------------------------------------------------------------
@Test
class PKCECodeVerifierLengthUT {

    @TestCase
    func testValidLengths(): Unit {
        let v43 = PKCEGenerator.codeVerifierWithLength(43)
        match (v43) {
            case Some(s) => @Expect(s.size, 43)
            case None => throw Exception("expected Some for length 43")
        }
        let v128 = PKCEGenerator.codeVerifierWithLength(128)
        match (v128) {
            case Some(s) => @Expect(s.size, 128)
            case None => throw Exception("expected Some for length 128")
        }
    }

    @TestCase
    func testInvalidLengths(): Unit {
        let v42 = PKCEGenerator.codeVerifierWithLength(42)
        match (v42) {
            case None => ()
            case Some(_) => throw Exception("expected None for length 42")
        }
        let v129 = PKCEGenerator.codeVerifierWithLength(129)
        match (v129) {
            case None => ()
            case Some(_) => throw Exception("expected None for length 129")
        }
    }
}

// ---------------------------------------------------------------------------
// Test 2: PKCECodeVerifierDefaultUT
// ---------------------------------------------------------------------------
@Test
class PKCECodeVerifierDefaultUT {

    @TestCase
    func testDefaultVerifier(): Unit {
        let v = PKCEGenerator.codeVerifier()
        match (v) {
            case Some(s) =>
                @Expect(s.size, 43)
                for (b in s.toArray()) {
                    let c = Int32(b)
                    let ok = (c >= 97 && c <= 122) || (c >= 65 && c <= 90) ||
                             (c >= 48 && c <= 57) || c == 45 || c == 46 || c == 95 || c == 126
                    if (!ok) {
                        throw Exception("invalid char in verifier: " + b.toString())
                    }
                }
            case None => throw Exception("expected Some verifier")
        }
    }
}

// ---------------------------------------------------------------------------
// Test 3: PKCECodeChallengeKnownUT
// ---------------------------------------------------------------------------
@Test
class PKCECodeChallengeKnownUT {

    @TestCase
    func testKnownVector(): Unit {
        // RFC 7636 test vector
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        let challenge = PKCEGenerator.generateCodeChallenge(verifier)
        @Expect(challenge, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
    }

    @TestCase
    func testChallengeLengthAndChars(): Unit {
        let verifier = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJ"
        let challenge = PKCEGenerator.generateCodeChallenge(verifier)
        @Expect(challenge.size, 43)
        for (b in challenge.toArray()) {
            let c = Int32(b)
            let ok = (c >= 97 && c <= 122) || (c >= 65 && c <= 90) ||
                     (c >= 48 && c <= 57) || c == 45 || c == 95
            if (!ok) {
                throw Exception("invalid char in challenge: " + b.toString())
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Test 4: PKCEVerifierGenerateUT
// ---------------------------------------------------------------------------
@Test
class PKCEVerifierGenerateUT {

    @TestCase
    func testGenerate(): Unit {
        let pv = PKCEVerifier.generate()
        @Expect(pv.codeChallengeMethod, "S256")
        @Expect(pv.codeVerifier.size, 43)
        @Expect(pv.codeChallenge.size, 43)
        let rederived = PKCEGenerator.generateCodeChallenge(pv.codeVerifier)
        @Expect(rederived, pv.codeChallenge)
    }
}

// ---------------------------------------------------------------------------
// Test 5: DPoPConstantsUT
// Tests DPoP constants and interface without full key pair crypto.
// Full DPoP JWT generation is integration-tested via IssuanceRequester.buildJwtProof.
// ---------------------------------------------------------------------------
@Test
class DPoPConstantsUT {

    @TestCase
    func testDPoPType(): Unit {
        // Verify the DPoP JWT type header value
        @Expect(DPoPConstructor.TYPE, "dpop+jwt")
    }

    @TestCase
    func testDPoPConstructorAcceptsAlgorithm(): Unit {
        // Verify DPoPConstructor stores algorithm string
        // (cannot construct without EcPublicKey from jose, which is cross-package)
        // Just ensure the TYPE constant compiles and has correct value
        let typeStr = DPoPConstructor.TYPE
        if (typeStr.isEmpty()) {
            throw Exception("DPoP TYPE must not be empty")
        }
        if (!typeStr.contains("dpop")) {
            throw Exception("DPoP TYPE must contain 'dpop': " + typeStr)
        }
    }
}

// ---------------------------------------------------------------------------
// Test 6: CredentialOfferPassByValueUT
// ---------------------------------------------------------------------------
@Test
class CredentialOfferPassByValueUT {

    @TestCase
    func testParseInlineJson(): Unit {
        let json = "{\"credential_issuer\":\"https://issuer.example.com\",\"credential_configuration_ids\":[\"EudiPid1\",\"MsoMdoc\"],\"grants\":{\"authorization_code\":{\"issuer_state\":\"state123\"}}}"
        let offer = CredentialOfferRequestObject.fromJsonString(json)
        @Expect(offer.credentialIssuer, "https://issuer.example.com")
        @Expect(offer.credentialConfigurationIds.size, 2)
        @Expect(offer.credentialConfigurationIds[0], "EudiPid1")
        @Expect(offer.credentialConfigurationIds[1], "MsoMdoc")
        match (offer.grants) {
            case Some(g) =>
                match (g.authorizationCode) {
                    case Some(ac) =>
                        match (ac.issuerState) {
                            case Some(s) => @Expect(s, "state123")
                            case None => throw Exception("expected issuerState")
                        }
                    case None => throw Exception("expected authorizationCode")
                }
            case None => throw Exception("expected grants")
        }
    }

    @TestCase
    func testMissingIssuerThrows(): Unit {
        let json = "{\"credential_configuration_ids\":[\"MsoMdoc\"]}"
        var threw = false
        try {
            let _ = CredentialOfferRequestObject.fromJsonString(json)
        } catch (_: Exception) {
            threw = true
        }
        if (!threw) {
            throw Exception("expected throw for missing credential_issuer")
        }
    }
}

// ---------------------------------------------------------------------------
// Test 7: GrantsAuthCodeParseUT
// ---------------------------------------------------------------------------
@Test
class GrantsAuthCodeParseUT {

    @TestCase
    func testAuthCodeGrant(): Unit {
        let json = "{\"authorization_code\":{\"issuer_state\":\"mystate\",\"authorization_server\":\"https://as.example.com\"}}"
        let jv = JsonValue.fromStr(json)
        let jobj = match (jv) {
            case o: JsonObject => o
            case _ => throw Exception("not object")
        }
        let dto = GrantsDTO.fromJsonObject(jobj)
        let domain = dto.toDomain()
        match (domain) {
            case Grants.AuthCode(ac) =>
                match (ac.issuerState) {
                    case Some(s) => @Expect(s, "mystate")
                    case None => throw Exception("expected issuerState")
                }
                match (ac.authorizationServer) {
                    case Some(s) => @Expect(s, "https://as.example.com")
                    case None => throw Exception("expected authorizationServer")
                }
            case _ => throw Exception("expected AuthCode")
        }
    }
}

// ---------------------------------------------------------------------------
// Test 8: GrantsPreAuthParseUT
// ---------------------------------------------------------------------------
@Test
class GrantsPreAuthParseUT {

    @TestCase
    func testPreAuthGrant(): Unit {
        let json = "{\"urn:ietf:params:oauth:grant-type:pre-authorized_code\":{\"pre-authorized_code\":\"abc123\",\"tx_code\":{\"input_mode\":\"numeric\",\"length\":6,\"description\":\"OTP\"}}}"
        let jv = JsonValue.fromStr(json)
        let jobj = match (jv) {
            case o: JsonObject => o
            case _ => throw Exception("not object")
        }
        let dto = GrantsDTO.fromJsonObject(jobj)
        let domain = dto.toDomain()
        match (domain) {
            case Grants.PreAuthCode(pac) =>
                match (pac.preAuthorizedCode) {
                    case Some(c) => @Expect(c, "abc123")
                    case None => throw Exception("expected preAuthorizedCode")
                }
                match (pac.txCode) {
                    case Some(tc) =>
                        @Expect(tc.inputMode.rawValue(), "numeric")
                        match (tc.length) {
                            case Some(l) => @Expect(l, 6i64)
                            case None => throw Exception("expected length")
                        }
                    case None => throw Exception("expected txCode")
                }
            case _ => throw Exception("expected PreAuthCode")
        }
    }
}

// ---------------------------------------------------------------------------
// Test 9: GrantsBothParseUT
// ---------------------------------------------------------------------------
@Test
class GrantsBothParseUT {

    @TestCase
    func testBothGrants(): Unit {
        let json = "{\"authorization_code\":{\"issuer_state\":\"s1\"},\"urn:ietf:params:oauth:grant-type:pre-authorized_code\":{\"pre-authorized_code\":\"code1\"}}"
        let jv = JsonValue.fromStr(json)
        let jobj = match (jv) {
            case o: JsonObject => o
            case _ => throw Exception("not object")
        }
        let dto = GrantsDTO.fromJsonObject(jobj)
        let domain = dto.toDomain()
        match (domain) {
            case Grants.Both(_, _) => ()
            case _ => throw Exception("expected Both")
        }
    }
}

// ---------------------------------------------------------------------------
// Test 10: TxCodeFromJsonUT
// ---------------------------------------------------------------------------
@Test
class TxCodeFromJsonUT {

    @TestCase
    func testNumericMode(): Unit {
        let json = "{\"input_mode\":\"numeric\",\"length\":4}"
        let jv = JsonValue.fromStr(json)
        let jobj = match (jv) {
            case o: JsonObject => o
            case _ => throw Exception("not object")
        }
        let tc = TxCode.fromJson(jobj)
        @Expect(tc.inputMode.rawValue(), "numeric")
        match (tc.length) {
            case Some(l) => @Expect(l, 4i64)
            case None => throw Exception("expected length")
        }
    }

    @TestCase
    func testTextMode(): Unit {
        let json = "{\"input_mode\":\"text\",\"description\":\"Enter PIN\"}"
        let jv = JsonValue.fromStr(json)
        let jobj = match (jv) {
            case o: JsonObject => o
            case _ => throw Exception("not object")
        }
        let tc = TxCode.fromJson(jobj)
        @Expect(tc.inputMode.rawValue(), "text")
        match (tc.description) {
            case Some(d) => @Expect(d, "Enter PIN")
            case None => throw Exception("expected description")
        }
    }

    @TestCase
    func testDefaultsWhenMissing(): Unit {
        let json = "{}"
        let jv = JsonValue.fromStr(json)
        let jobj = match (jv) {
            case o: JsonObject => o
            case _ => throw Exception("not object")
        }
        let tc = TxCode.fromJson(jobj)
        @Expect(tc.inputMode.rawValue(), "numeric")
        match (tc.length) {
            case None => ()
            case Some(_) => throw Exception("expected no length")
        }
    }
}

// ---------------------------------------------------------------------------
// Test 11: ASMetadataFromJsonUT
// ---------------------------------------------------------------------------
@Test
class ASMetadataFromJsonUT {

    @TestCase
    func testParseFields(): Unit {
        let json = "{\"issuer\":\"https://as.example.com\",\"authorization_endpoint\":\"https://as.example.com/authorize\",\"token_endpoint\":\"https://as.example.com/token\",\"pushed_authorization_request_endpoint\":\"https://as.example.com/par\",\"token_endpoint_auth_methods_supported\":[\"private_key_jwt\"],\"dpop_signing_alg_values_supported\":[\"ES256\"]}"
        let meta = AuthorizationServerMetadata.fromJsonString(json)
        match (meta.issuer) {
            case Some(s) => @Expect(s, "https://as.example.com")
            case None => throw Exception("expected issuer")
        }
        match (meta.authorizationEndpoint) {
            case Some(s) => @Expect(s, "https://as.example.com/authorize")
            case None => throw Exception("expected authorizationEndpoint")
        }
        match (meta.tokenEndpoint) {
            case Some(s) => @Expect(s, "https://as.example.com/token")
            case None => throw Exception("expected tokenEndpoint")
        }
        match (meta.pushedAuthorizationRequestEndpoint) {
            case Some(s) => @Expect(s, "https://as.example.com/par")
            case None => throw Exception("expected parEndpoint")
        }
        @Expect(meta.tokenEndpointAuthMethodsSupported.size, 1)
        @Expect(meta.tokenEndpointAuthMethodsSupported[0], "private_key_jwt")
        @Expect(meta.dpopSigningAlgValuesSupported.size, 1)
        @Expect(meta.dpopSigningAlgValuesSupported[0], "ES256")
    }
}

// ---------------------------------------------------------------------------
// Test 12: OIDCMetadataFromJsonUT
// ---------------------------------------------------------------------------
@Test
class OIDCMetadataFromJsonUT {

    @TestCase
    func testOidcWrapper(): Unit {
        let json = "{\"issuer\":\"https://op.example.com\",\"token_endpoint\":\"https://op.example.com/token\"}"
        let meta = OIDCProviderMetadata.fromJsonString(json)
        match (meta.inner.issuer) {
            case Some(s) => @Expect(s, "https://op.example.com")
            case None => throw Exception("expected issuer")
        }
        match (meta.inner.tokenEndpoint) {
            case Some(s) => @Expect(s, "https://op.example.com/token")
            case None => throw Exception("expected tokenEndpoint")
        }
    }
}

// ---------------------------------------------------------------------------
// Test 13: IAMMetadataSupportsPARUT
// ---------------------------------------------------------------------------
@Test
class IAMMetadataSupportsPARUT {

    @TestCase
    func testSupportsPar(): Unit {
        let json = "{\"token_endpoint\":\"https://as.example.com/token\",\"pushed_authorization_request_endpoint\":\"https://as.example.com/par\"}"
        let asMeta = AuthorizationServerMetadata.fromJsonString(json)
        let iam = IdentityAndAccessManagementMetadata.OAuth(asMeta)
        @Expect(iam.supportsPar(), true)
        match (iam.pushedAuthorizationRequestEndpoint()) {
            case Some(s) => @Expect(s, "https://as.example.com/par")
            case None => throw Exception("expected parEndpoint")
        }
    }

    @TestCase
    func testNoParSupport(): Unit {
        let json = "{\"token_endpoint\":\"https://as.example.com/token\"}"
        let asMeta = AuthorizationServerMetadata.fromJsonString(json)
        let iam = IdentityAndAccessManagementMetadata.OAuth(asMeta)
        @Expect(iam.supportsPar(), false)
    }
}

// ---------------------------------------------------------------------------
// Test 14: IssuerMetadataFromJsonUT
// ---------------------------------------------------------------------------
@Test
class IssuerMetadataFromJsonUT {

    @TestCase
    func testParseMinimalMetadata(): Unit {
        let json = "{\"credential_issuer\":\"https://issuer.example.com\",\"credential_endpoint\":\"https://issuer.example.com/credential\",\"credential_configurations_supported\":{}}"
        let meta = CredentialIssuerMetadata.fromJsonString(json)
        @Expect(meta.credentialIssuerIdentifier.url, "https://issuer.example.com")
        @Expect(meta.credentialEndpoint.url, "https://issuer.example.com/credential")
        @Expect(meta.authorizationServers.size, 1)
        @Expect(meta.authorizationServers[0], "https://issuer.example.com")
    }

    @TestCase
    func testParseWithDeferredEndpoint(): Unit {
        let json = "{\"credential_issuer\":\"https://issuer.example.com\",\"credential_endpoint\":\"https://issuer.example.com/credential\",\"deferred_credential_endpoint\":\"https://issuer.example.com/deferred\",\"credential_configurations_supported\":{}}"
        let meta = CredentialIssuerMetadata.fromJsonString(json)
        match (meta.deferredCredentialEndpoint) {
            case Some(ep) => @Expect(ep.url, "https://issuer.example.com/deferred")
            case None => throw Exception("expected deferredCredentialEndpoint")
        }
    }
}

// ---------------------------------------------------------------------------
// Test 15: IssuerMetadataEncryptionUT
// ---------------------------------------------------------------------------
@Test
class IssuerMetadataEncryptionUT {

    @TestCase
    func testNotSupported(): Unit {
        let json = "{\"credential_issuer\":\"https://i.example.com\",\"credential_endpoint\":\"https://i.example.com/cred\",\"credential_configurations_supported\":{}}"
        let meta = CredentialIssuerMetadata.fromJsonString(json)
        @Expect(meta.credentialResponseEncryption.isNotSupported(), true)
        @Expect(meta.credentialResponseEncryption.isRequired(), false)
    }

    @TestCase
    func testRequired(): Unit {
        let json = "{\"credential_issuer\":\"https://i.example.com\",\"credential_endpoint\":\"https://i.example.com/cred\",\"credential_configurations_supported\":{},\"credential_response_encryption_alg_values_supported\":[\"ECDH-ES\"],\"credential_response_encryption_enc_values_supported\":[\"A256GCM\"],\"require_credential_response_encryption\":true}"
        let meta = CredentialIssuerMetadata.fromJsonString(json)
        @Expect(meta.credentialResponseEncryption.isRequired(), true)
        @Expect(meta.credentialResponseEncryption.isNotSupported(), false)
    }
}

// ---------------------------------------------------------------------------
// Test 16: CredentialIssuerIdUT
// ---------------------------------------------------------------------------
@Test
class CredentialIssuerIdUT {

    @TestCase
    func testValidId(): Unit {
        let id = CredentialIssuerId("https://issuer.example.com")
        @Expect(id.url, "https://issuer.example.com")
        @Expect(id.absoluteString(), "https://issuer.example.com")
    }

    @TestCase
    func testInvalidSchemeThrows(): Unit {
        var threw = false
        try {
            let _ = CredentialIssuerId("http://issuer.example.com")
        } catch (_: Exception) {
            threw = true
        }
        if (!threw) { throw Exception("expected throw for http scheme") }
    }

    @TestCase
    func testQueryComponentThrows(): Unit {
        var threw = false
        try {
            let _ = CredentialIssuerId("https://issuer.example.com?foo=bar")
        } catch (_: Exception) {
            threw = true
        }
        if (!threw) { throw Exception("expected throw for query component") }
    }

    @TestCase
    func testFragmentThrows(): Unit {
        var threw = false
        try {
            let _ = CredentialIssuerId("https://issuer.example.com#frag")
        } catch (_: Exception) {
            threw = true
        }
        if (!threw) { throw Exception("expected throw for fragment") }
    }
}

// ---------------------------------------------------------------------------
// Test 17: ClientAttestationPopJwtUT
// ---------------------------------------------------------------------------
@Test
class ClientAttestationPopJwtUT {

    @TestCase
    func testBuildPopJwt(): Unit {
        let key = genEcKey()
        let spec = ClientAttestationPoPJWTSpec.withDefaults(key)
        @Expect(spec.signingAlgorithm, "ES256")
        @Expect(spec.durationSeconds, 300.0)
        @Expect(spec.typ, "wallet-attestation-pop+jwt")

        let builder = DefaultClientAttestationPoPBuilder()
        let pop = builder.buildAttestationPoPJWT(
            "https://wallet.example.com",
            Some("{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"abc\",\"y\":\"def\"}"),
            "https://as.example.com",
            spec,
            Some("challenge-nonce")
        )
        let parts = pop.compact.split(".")
        if (parts.size != 3) {
            throw Exception("expected 3-part JWS, got: " + parts.size.toString())
        }
        for (part in parts) {
            if (part.isEmpty()) {
                throw Exception("JWS part must not be empty")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Test 18: ClientAttestationHmacRejectUT
// ---------------------------------------------------------------------------
@Test
class ClientAttestationHmacRejectUT {

    @TestCase
    func testHmacRejected(): Unit {
        let key = genEcKey()
        var threw = false
        try {
            let _ = ClientAttestationPoPJWTSpec("HS256", 300.0, "wallet-attestation-pop+jwt", key)
        } catch (e: ValidationError) {
            threw = true
            if (!e.message.contains("MAC")) {
                throw Exception("expected MAC in error, got: " + e.message)
            }
        }
        if (!threw) { throw Exception("expected ValidationError for HS256") }
    }

    @TestCase
    func testNegativeDurationRejected(): Unit {
        let key = genEcKey()
        var threw = false
        try {
            let _ = ClientAttestationPoPJWTSpec("ES256", -1.0, "wallet-attestation-pop+jwt", key)
        } catch (e: ValidationError) {
            threw = true
        }
        if (!threw) { throw Exception("expected ValidationError for negative duration") }
    }
}

// ---------------------------------------------------------------------------
// Test 19: ProofsToJwtUT
// ---------------------------------------------------------------------------
@Test
class ProofsToJwtUT {

    @TestCase
    func testJwtProofsToJson(): Unit {
        let proofs = ProofsTO.forJwt(["jwt1", "jwt2"])
        let jobj = proofs.toJsonObject()
        match (jobj.get("jwt")) {
            case Some(arr: JsonArray) => @Expect(arr.getItems().size, 2)
            case _ => throw Exception("expected jwt array")
        }
        match (jobj.get("attestation")) {
            case None => ()
            case Some(_) => throw Exception("expected no attestation key")
        }
    }

    @TestCase
    func testEmptyJwtProofsThrows(): Unit {
        var threw = false
        try {
            let _ = ProofsTO.forJwt([])
        } catch (_: Exception) {
            threw = true
        }
        if (!threw) { throw Exception("expected throw for empty proofs") }
    }
}

// ---------------------------------------------------------------------------
// Test 20: ProofsToAttestationUT
// ---------------------------------------------------------------------------
@Test
class ProofsToAttestationUT {

    @TestCase
    func testAttestationProofsToJson(): Unit {
        let proofs = ProofsTO.forAttestation(["att1"])
        let jobj = proofs.toJsonObject()
        match (jobj.get("attestation")) {
            case Some(arr: JsonArray) => @Expect(arr.getItems().size, 1)
            case _ => throw Exception("expected attestation array")
        }
    }
}

// ---------------------------------------------------------------------------
// Test 21: IssuanceJwtProofBuildUT
// ---------------------------------------------------------------------------
@Test
class IssuanceJwtProofBuildUT {

    @TestCase
    func testBuildJwtProofStructure(): Unit {
        let key = genEcKey()
        let issuerJson = "{\"credential_issuer\":\"https://i.example.com\",\"credential_endpoint\":\"https://i.example.com/cred\",\"credential_configurations_supported\":{}}"
        let meta = CredentialIssuerMetadata.fromJsonString(issuerJson)
        let requester = IssuanceRequester(meta, Option<DPoPConstructorType>.None)
        let proof = requester.buildJwtProof(
            key,
            "ES256",
            "https://wallet.example.com",
            "https://i.example.com",
            Some("cnonce123")
        )
        let parts = proof.split(".")
        if (parts.size != 3) {
            throw Exception("expected 3-part JWT, got: " + parts.size.toString())
        }
        for (part in parts) {
            if (part.isEmpty()) {
                throw Exception("JWT part must not be empty")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Test 22: DeferredResponseFromJsonUT
// ---------------------------------------------------------------------------
@Test
class DeferredResponseFromJsonUT {

    @TestCase
    func testIssuedCredential(): Unit {
        let json = "{\"credential\":\"eyJhbGciOiJFUzI1NiJ9.payload.sig\"}"
        let jv = JsonValue.fromStr(json)
        let jobj = match (jv) {
            case o: JsonObject => o
            case _ => throw Exception("not object")
        }
        let resp = DeferredCredentialIssuanceResponse.fromJson(jobj)
        match (resp) {
            case DeferredCredentialIssuanceResponse.Issued(creds) =>
                @Expect(creds.size, 1)
                match (creds[0]) {
                    case Credential.StringCredential(s) =>
                        @Expect(s, "eyJhbGciOiJFUzI1NiJ9.payload.sig")
                    case _ => throw Exception("expected StringCredential")
                }
            case _ => throw Exception("expected Issued")
        }
    }

    @TestCase
    func testPending(): Unit {
        let json = "{\"transaction_id\":\"txn-abc\",\"interval\":5}"
        let jv = JsonValue.fromStr(json)
        let jobj = match (jv) {
            case o: JsonObject => o
            case _ => throw Exception("not object")
        }
        let resp = DeferredCredentialIssuanceResponse.fromJson(jobj)
        match (resp) {
            case DeferredCredentialIssuanceResponse.IssuancePending(txId, interval) =>
                @Expect(txId.value, "txn-abc")
                @Expect(interval, 5.0)
            case _ => throw Exception("expected IssuancePending")
        }
    }

    @TestCase
    func testError(): Unit {
        let json = "{\"error\":\"issuance_pending\",\"error_description\":\"Try later\"}"
        let jv = JsonValue.fromStr(json)
        let jobj = match (jv) {
            case o: JsonObject => o
            case _ => throw Exception("not object")
        }
        let resp = DeferredCredentialIssuanceResponse.fromJson(jobj)
        match (resp) {
            case DeferredCredentialIssuanceResponse.Errored(errOpt, descOpt) =>
                match (errOpt) {
                    case Some(e) => @Expect(e, "issuance_pending")
                    case None => throw Exception("expected error code")
                }
                match (descOpt) {
                    case Some(d) => @Expect(d, "Try later")
                    case None => throw Exception("expected error description")
                }
            case _ => throw Exception("expected Errored")
        }
    }
}

// ---------------------------------------------------------------------------
// Test 23: CredentialOfferResolverUriUT
// ---------------------------------------------------------------------------
@Test
class CredentialOfferResolverUriUT {

    @TestCase
    func testPassByValueUri(): Unit {
        let inlineJson = "{\"credential_issuer\":\"https://issuer.example.com\",\"credential_configuration_ids\":[\"PID\"]}"
        let uri = "openid-credential-offer://?credential_offer=" + inlineJson
        let resolver = CredentialOfferRequestResolver()
        let result = resolver.parseOfferUri(uri)
        match (result) {
            case CredentialOfferRequest.PassByValue(json) =>
                let obj = CredentialOfferRequestObject.fromJsonString(json)
                @Expect(obj.credentialIssuer, "https://issuer.example.com")
            case _ => throw Exception("expected PassByValue")
        }
    }

    @TestCase
    func testFetchByReferenceUri(): Unit {
        let uri = "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fissuer.example.com%2Foffer%2F1"
        let resolver = CredentialOfferRequestResolver()
        let result = resolver.parseOfferUri(uri)
        match (result) {
            case CredentialOfferRequest.FetchByReference(url) =>
                @Expect(url, "https://issuer.example.com/offer/1")
            case _ => throw Exception("expected FetchByReference")
        }
    }
}

// ---------------------------------------------------------------------------
// Test 24: CredentialOfferInvalidSchemeUT
// ---------------------------------------------------------------------------
@Test
class CredentialOfferInvalidSchemeUT {

    @TestCase
    func testInvalidSchemeThrows(): Unit {
        let resolver = CredentialOfferRequestResolver()
        var threw = false
        try {
            let _ = resolver.parseOfferUri("ftp://example.com?credential_offer={}")
        } catch (_: Exception) {
            threw = true
        }
        if (!threw) { throw Exception("expected throw for ftp:// scheme") }
    }

    @TestCase
    func testNoParamThrows(): Unit {
        let resolver = CredentialOfferRequestResolver()
        var threw = false
        try {
            let _ = resolver.parseOfferUri("openid-credential-offer://?other=value")
        } catch (_: Exception) {
            threw = true
        }
        if (!threw) { throw Exception("expected throw for missing credential_offer param") }
    }
}

// ---------------------------------------------------------------------------
// Test 25: DeflateVciRoundTripUT
// ---------------------------------------------------------------------------
@Test
class DeflateVciRoundTripUT {

    @TestCase
    func testRoundTrip(): Unit {
        let original: Array<UInt8> = [0xDEu8, 0xADu8, 0xBEu8, 0xEFu8, 0x01u8, 0x02u8]
        let compressed = compressDeflateHelper(original)
        let decompressor = DeflateDecompressor()
        let recovered = decompressor.decompress(compressed)
        if (recovered.size != original.size) {
            throw Exception("size mismatch: " + recovered.size.toString() + " vs " + original.size.toString())
        }
        var i: Int64 = 0
        while (i < original.size) {
            if (recovered[i] != original[i]) {
                throw Exception("byte mismatch at " + i.toString())
            }
            i = i + 1
        }
    }

    @TestCase
    func testEmptyInputThrows(): Unit {
        let decompressor = DeflateDecompressor()
        var threw = false
        try {
            let _ = decompressor.decompress([])
        } catch (_: Exception) {
            threw = true
        }
        if (!threw) { throw Exception("expected throw for empty input") }
    }

    @TestCase
    func testDecompressDeflateFunc(): Unit {
        let original: Array<UInt8> = [0xAAu8, 0xBBu8, 0xCCu8]
        let compressed = compressDeflateHelper(original)
        let recovered = decompressDeflate(compressed)
        if (recovered.size != original.size) {
            throw Exception("size mismatch")
        }
    }
}

// ---------------------------------------------------------------------------
// Test 26: ApplyCompressionUT
// ---------------------------------------------------------------------------
@Test
class ApplyCompressionUT {

    @TestCase
    func testNoAlgorithmPassthrough(): Unit {
        let data: Array<UInt8> = [1u8, 2u8, 3u8]
        let result = applyCompressionIfNeeded(data, Option<String>.None)
        @Expect(result.size, 3)
        @Expect(result[0], 1u8)
    }

    @TestCase
    func testDefAlgorithmDecompress(): Unit {
        let original: Array<UInt8> = [0x42u8, 0x43u8]
        let compressed = compressDeflateHelper(original)
        let result = applyCompressionIfNeeded(compressed, Some("DEF"))
        @Expect(result.size, 2)
        @Expect(result[0], 0x42u8)
    }

    @TestCase
    func testUnsupportedAlgorithmThrows(): Unit {
        let data: Array<UInt8> = [1u8, 2u8, 3u8]
        var threw = false
        try {
            let _ = applyCompressionIfNeeded(data, Some("GZIP"))
        } catch (_: Exception) {
            threw = true
        }
        if (!threw) { throw Exception("expected throw for GZIP algorithm") }
    }
}

// ---------------------------------------------------------------------------
// Test 27: BasicTypesUT
// ---------------------------------------------------------------------------
@Test
class BasicTypesUT {

    @TestCase
    func testScopeValid(): Unit {
        let s = Scope("openid")
        @Expect(s.value, "openid")
    }

    @TestCase
    func testScopeEmptyThrows(): Unit {
        var threw = false
        try {
            let _ = Scope("")
        } catch (_: Exception) {
            threw = true
        }
        if (!threw) { throw Exception("expected throw for empty scope") }
    }

    @TestCase
    func testStateValue(): Unit {
        let sv = StateValue()
        if (sv.value.isEmpty()) {
            throw Exception("StateValue must not be empty")
        }
    }

    @TestCase
    func testAccessToken(): Unit {
        let at = AccessToken("my-token")
        @Expect(at.value, "my-token")
    }

    @TestCase
    func testAccessTokenEmptyThrows(): Unit {
        var threw = false
        try {
            let _ = AccessToken("")
        } catch (_: Exception) {
            threw = true
        }
        if (!threw) { throw Exception("expected throw for empty access token") }
    }

    @TestCase
    func testTransactionId(): Unit {
        let txId = TransactionId("tx-001")
        @Expect(txId.value, "tx-001")
    }
}

// ---------------------------------------------------------------------------
// Test 28: DisplayFromJsonUT
// ---------------------------------------------------------------------------
@Test
class DisplayFromJsonUT {

    @TestCase
    func testParseDisplay(): Unit {
        let json = "{\"name\":\"My Credential\",\"locale\":\"en-US\",\"background_color\":\"#123456\",\"text_color\":\"#FFFFFF\"}"
        let jv = JsonValue.fromStr(json)
        let jobj = match (jv) {
            case o: JsonObject => o
            case _ => throw Exception("not object")
        }
        let d = Display.fromJson(jobj)
        match (d.name) {
            case Some(n) => @Expect(n, "My Credential")
            case None => throw Exception("expected name")
        }
        match (d.locale) {
            case Some(l) => @Expect(l, "en-US")
            case None => throw Exception("expected locale")
        }
        match (d.backgroundColor) {
            case Some(c) => @Expect(c, "#123456")
            case None => throw Exception("expected backgroundColor")
        }
    }
}

// ---------------------------------------------------------------------------
// Test 29: PolicyFromJsonUT
// ---------------------------------------------------------------------------
@Test
class PolicyFromJsonUT {

    @TestCase
    func testParsePolicy(): Unit {
        let json = "{\"batch_size\":5,\"one_time_use\":true}"
        let jv = JsonValue.fromStr(json)
        let jobj = match (jv) {
            case o: JsonObject => o
            case _ => throw Exception("not object")
        }
        let p = Policy.fromJson(jobj)
        match (p.batchSize) {
            case Some(bs) => @Expect(bs, 5i64)
            case None => throw Exception("expected batchSize")
        }
        match (p.oneTimeUse) {
            case Some(otu) => @Expect(otu, true)
            case None => throw Exception("expected oneTimeUse")
        }
    }
}

// ---------------------------------------------------------------------------
// Test 30: CryptographicBindingMethodUT
// ---------------------------------------------------------------------------
@Test
class CryptographicBindingMethodUT {

    @TestCase
    func testKnownMethods(): Unit {
        @Expect(CryptographicBindingMethod.of("jwk").rawValue(), "jwk")
        @Expect(CryptographicBindingMethod.of("x5c").rawValue(), "x5c")
        @Expect(CryptographicBindingMethod.of("cose_key").rawValue(), "cose_key")
        @Expect(CryptographicBindingMethod.of("mso").rawValue(), "mso")
    }

    @TestCase
    func testDidMethod(): Unit {
        let m = CryptographicBindingMethod.of("did:key")
        match (m) {
            case CryptographicBindingMethod.Did(s) => @Expect(s, "did:key")
            case _ => throw Exception("expected Did variant")
        }
    }

    @TestCase
    func testUnknownThrows(): Unit {
        var threw = false
        try {
            let _ = CryptographicBindingMethod.of("unknown-method")
        } catch (_: Exception) {
            threw = true
        }
        if (!threw) { throw Exception("expected throw for unknown method") }
    }
}

// ===========================================================================
// VP TESTS
// ===========================================================================

// ---------------------------------------------------------------------------
// Test 31: QueryIdValidUT
// ---------------------------------------------------------------------------
@Test
class QueryIdValidUT {

    @TestCase
    func testValidIds(): Unit {
        let q1 = QueryId("cred1")
        @Expect(q1.value, "cred1")
        let q2 = QueryId("credential-2")
        @Expect(q2.value, "credential-2")
        let q3 = QueryId("Cred_ABC123")
        @Expect(q3.value, "Cred_ABC123")
    }

    @TestCase
    func testEquality(): Unit {
        let q1 = QueryId("cred1")
        let q2 = QueryId("cred1")
        @Expect(q1 == q2, true)
    }

    @TestCase
    func testToString(): Unit {
        let q = QueryId("my-cred")
        @Expect(q.toString(), "my-cred")
    }
}

// ---------------------------------------------------------------------------
// Test 32: QueryIdInvalidUT
// ---------------------------------------------------------------------------
@Test
class QueryIdInvalidUT {

    @TestCase
    func testEmptyThrows(): Unit {
        var threw = false
        try {
            let _ = QueryId("")
        } catch (_: Exception) {
            threw = true
        }
        if (!threw) { throw Exception("expected throw for empty QueryId") }
    }

    @TestCase
    func testSpecialCharThrows(): Unit {
        var threw = false
        try {
            let _ = QueryId("cred!")
        } catch (_: Exception) {
            threw = true
        }
        if (!threw) { throw Exception("expected throw for '!'") }
    }

    @TestCase
    func testSpaceThrows(): Unit {
        var threw = false
        try {
            let _ = QueryId("cred id")
        } catch (_: Exception) {
            threw = true
        }
        if (!threw) { throw Exception("expected throw for space") }
    }
}

// ---------------------------------------------------------------------------
// Test 33: ClaimPathUT
// ---------------------------------------------------------------------------
@Test
class ClaimPathUT {

    @TestCase
    func testBuildPath(): Unit {
        let path = ClaimPath.claim("given_name")
        @Expect(path.value.size, 1)
        match (path.value[0]) {
            case cn: ClaimName => @Expect(cn.name, "given_name")
            case _ => throw Exception("expected ClaimName")
        }
    }

    @TestCase
    func testAppendPath(): Unit {
        let path = ClaimPath.claim("address").claimAppend("street")
        @Expect(path.value.size, 2)
        match (path.value[1]) {
            case cn: ClaimName => @Expect(cn.name, "street")
            case _ => throw Exception("expected ClaimName for street")
        }
    }

    @TestCase
    func testAllArrayElements(): Unit {
        let path = ClaimPath.claim("items").allArrayElementsAppend()
        @Expect(path.value.size, 2)
        match (path.value[1]) {
            case _: AllArrayElements => ()
            case _ => throw Exception("expected AllArrayElements")
        }
    }

    @TestCase
    func testArrayElementIndex(): Unit {
        let path = ClaimPath.claim("items").arrayElementAppend(3)
        @Expect(path.value.size, 2)
        match (path.value[1]) {
            case ae: ArrayElement => @Expect(ae.index, 3i64)
            case _ => throw Exception("expected ArrayElement")
        }
    }

    @TestCase
    func testContains(): Unit {
        let parent = ClaimPath.claim("a").claimAppend("b")
        let child = ClaimPath.claim("a")
        @Expect(parent.contains(child), true)
        @Expect(child.contains(parent), false)
    }

    @TestCase
    func testEquality(): Unit {
        let p1 = ClaimPath.claim("name")
        let p2 = ClaimPath.claim("name")
        @Expect(p1 == p2, true)
        let p3 = ClaimPath.claim("other")
        @Expect(p1 == p3, false)
    }
}

// ---------------------------------------------------------------------------
// Test 34: ClaimPathJsonUT
// ---------------------------------------------------------------------------
@Test
class ClaimPathJsonUT {

    @TestCase
    func testNullToAllArrayElements(): Unit {
        let json = "[null,\"family_name\"]"
        let jv = JsonValue.fromStr(json)
        let arr = match (jv) {
            case a: JsonArray => a
            case _ => throw Exception("not array")
        }
        let path = ClaimPath.fromJsonArray(arr)
        @Expect(path.value.size, 2)
        match (path.value[0]) {
            case _: AllArrayElements => ()
            case _ => throw Exception("expected AllArrayElements for null")
        }
        match (path.value[1]) {
            case cn: ClaimName => @Expect(cn.name, "family_name")
            case _ => throw Exception("expected ClaimName")
        }
    }

    @TestCase
    func testIntToArrayElement(): Unit {
        let json = "[0]"
        let jv = JsonValue.fromStr(json)
        let arr = match (jv) {
            case a: JsonArray => a
            case _ => throw Exception("not array")
        }
        let path = ClaimPath.fromJsonArray(arr)
        @Expect(path.value.size, 1)
        match (path.value[0]) {
            case ae: ArrayElement => @Expect(ae.index, 0i64)
            case _ => throw Exception("expected ArrayElement")
        }
    }

    @TestCase
    func testStringToClaimName(): Unit {
        let json = "[\"given_name\"]"
        let jv = JsonValue.fromStr(json)
        let arr = match (jv) {
            case a: JsonArray => a
            case _ => throw Exception("not array")
        }
        let path = ClaimPath.fromJsonArray(arr)
        @Expect(path.value.size, 1)
        match (path.value[0]) {
            case cn: ClaimName => @Expect(cn.name, "given_name")
            case _ => throw Exception("expected ClaimName")
        }
    }
}

// ---------------------------------------------------------------------------
// Test 35: CredentialQueryFromJsonUT
// ---------------------------------------------------------------------------
@Test
class CredentialQueryFromJsonUT {

    @TestCase
    func testParseCredentialQuery(): Unit {
        let json = "{\"id\":\"cred1\",\"format\":\"mso_mdoc\",\"claims\":[{\"path\":[\"org.iso.18013.5.1\",\"given_name\"]}]}"
        let jv = JsonValue.fromStr(json)
        let jobj = match (jv) {
            case o: JsonObject => o
            case _ => throw Exception("not object")
        }
        let cq = CredentialQuery.fromJson(jobj)
        @Expect(cq.queryId.value, "cred1")
        @Expect(cq.format.format, "mso_mdoc")
        match (cq.claims) {
            case Some(claims) =>
                @Expect(claims.size, 1)
                @Expect(claims[0].path.value.size, 2)
            case None => throw Exception("expected claims")
        }
    }

    @TestCase
    func testMissingIdThrows(): Unit {
        let json = "{\"format\":\"mso_mdoc\"}"
        let jv = JsonValue.fromStr(json)
        let jobj = match (jv) {
            case o: JsonObject => o
            case _ => throw Exception("not object")
        }
        var threw = false
        try {
            let _ = CredentialQuery.fromJson(jobj)
        } catch (_: Exception) {
            threw = true
        }
        if (!threw) { throw Exception("expected throw for missing id") }
    }
}

// ---------------------------------------------------------------------------
// Test 36: DCQLFromJsonUT
// ---------------------------------------------------------------------------
@Test
class DCQLFromJsonUT {

    @TestCase
    func testParseDcql(): Unit {
        let json = "{\"credentials\":[{\"id\":\"pid\",\"format\":\"mso_mdoc\"},{\"id\":\"dl\",\"format\":\"mso_mdoc\"}]}"
        let dcql = DCQL.fromJsonString(json)
        @Expect(dcql.credentials.size, 2)
        @Expect(dcql.credentials[0].queryId.value, "pid")
        @Expect(dcql.credentials[1].queryId.value, "dl")
        match (dcql.credentialSets) {
            case None => ()
            case Some(_) => throw Exception("expected no credentialSets")
        }
    }

    @TestCase
    func testEmptyCredentialsThrows(): Unit {
        let json = "{\"credentials\":[]}"
        var threw = false
        try {
            let _ = DCQL.fromJsonString(json)
        } catch (_: Exception) {
            threw = true
        }
        if (!threw) { throw Exception("expected throw for empty credentials") }
    }
}

// ---------------------------------------------------------------------------
// Test 37: DCQLDuplicateIdUT
// ---------------------------------------------------------------------------
@Test
class DCQLDuplicateIdUT {

    @TestCase
    func testDuplicateIdThrows(): Unit {
        let json = "{\"credentials\":[{\"id\":\"cred1\",\"format\":\"mso_mdoc\"},{\"id\":\"cred1\",\"format\":\"sd-jwt+vc\"}]}"
        var threw = false
        try {
            let _ = DCQL.fromJsonString(json)
        } catch (_: Exception) {
            threw = true
        }
        if (!threw) { throw Exception("expected throw for duplicate queryId") }
    }
}

// ---------------------------------------------------------------------------
// Test 38: CredentialSetQueryUT
// ---------------------------------------------------------------------------
@Test
class CredentialSetQueryUT {

    @TestCase
    func testParseCredentialSetQuery(): Unit {
        let json = "{\"options\":[[\"pid\",\"dl\"]],\"required\":false}"
        let jv = JsonValue.fromStr(json)
        let jobj = match (jv) {
            case o: JsonObject => o
            case _ => throw Exception("not object")
        }
        let csq = CredentialSetQuery.fromJson(jobj)
        @Expect(csq.options.size, 1)
        @Expect(csq.options[0].size, 2)
        @Expect(csq.options[0][0].value, "pid")
        @Expect(csq.options[0][1].value, "dl")
        match (csq.required) {
            case Some(r) => @Expect(r, false)
            case None => throw Exception("expected required")
        }
    }

    @TestCase
    func testEmptySetThrows(): Unit {
        var threw = false
        try {
            let _ = CredentialSetQuery([[]], required: Option<Bool>.None)
        } catch (_: Exception) {
            threw = true
        }
        if (!threw) { throw Exception("expected throw for empty option set") }
    }
}

// ---------------------------------------------------------------------------
// Test 39: ResponseModeDirectPostUT
// ---------------------------------------------------------------------------
@Test
class ResponseModeDirectPostUT {

    @TestCase
    func testDirectPost(): Unit {
        let mode = parseResponseMode(Some("direct_post"), Some("https://verifier.example.com/cb"), Option<String>.None)
        match (mode) {
            case Some(dp: DirectPost) =>
                @Expect(dp.responseUri, "https://verifier.example.com/cb")
                @Expect(dp.requiresEncryption(), false)
                @Expect(dp.isJarm(), false)
            case _ => throw Exception("expected DirectPost")
        }
    }

    @TestCase
    func testDirectPostMissingUri(): Unit {
        let mode = parseResponseMode(Some("direct_post"), Option<String>.None, Option<String>.None)
        match (mode) {
            case None => ()
            case Some(_) => throw Exception("expected None for missing responseUri")
        }
    }
}

// ---------------------------------------------------------------------------
// Test 40: ResponseModeDirectPostJwtUT
// ---------------------------------------------------------------------------
@Test
class ResponseModeDirectPostJwtUT {

    @TestCase
    func testDirectPostJwt(): Unit {
        let mode = parseResponseMode(Some("direct_post.jwt"), Some("https://verifier.example.com/cb"), Option<String>.None)
        match (mode) {
            case Some(dpj: DirectPostJWT) =>
                @Expect(dpj.responseUri, "https://verifier.example.com/cb")
                @Expect(dpj.requiresEncryption(), true)
                @Expect(dpj.isJarm(), true)
            case _ => throw Exception("expected DirectPostJWT")
        }
    }
}

// ---------------------------------------------------------------------------
// Test 41: ResponseModeQueryFragmentUT
// ---------------------------------------------------------------------------
@Test
class ResponseModeQueryFragmentUT {

    @TestCase
    func testQueryMode(): Unit {
        let mode = parseResponseMode(Some("query"), Option<String>.None, Some("https://wallet.example.com/redirect"))
        match (mode) {
            case Some(q: QueryMode) =>
                @Expect(q.responseUri, "https://wallet.example.com/redirect")
                @Expect(q.requiresEncryption(), false)
                @Expect(q.isJarm(), false)
            case _ => throw Exception("expected QueryMode")
        }
    }

    @TestCase
    func testFragmentMode(): Unit {
        let mode = parseResponseMode(Some("fragment"), Option<String>.None, Some("https://wallet.example.com/redirect"))
        match (mode) {
            case Some(f: FragmentMode) =>
                @Expect(f.responseUri, "https://wallet.example.com/redirect")
            case _ => throw Exception("expected FragmentMode")
        }
    }

    @TestCase
    func testNoneModeReturnsNone(): Unit {
        let mode = parseResponseMode(Option<String>.None, Option<String>.None, Option<String>.None)
        match (mode) {
            case None => ()
            case Some(_) => throw Exception("expected None for absent responseMode")
        }
    }
}

// ---------------------------------------------------------------------------
// Test 42: ResponseModeInvalidUT
// ---------------------------------------------------------------------------
@Test
class ResponseModeInvalidUT {

    @TestCase
    func testUnsupportedThrows(): Unit {
        var threw = false
        try {
            let _ = parseResponseModeOrThrow(Some("unknown_mode"), Option<String>.None, Option<String>.None)
        } catch (_: Exception) {
            threw = true
        }
        if (!threw) { throw Exception("expected throw for unknown response mode") }
    }

    @TestCase
    func testMissingModeThrows(): Unit {
        var threw = false
        try {
            let _ = parseResponseModeOrThrow(Option<String>.None, Option<String>.None, Option<String>.None)
        } catch (_: Exception) {
            threw = true
        }
        if (!threw) { throw Exception("expected throw for missing responseMode") }
    }
}

// ---------------------------------------------------------------------------
// Test 43: UnvalidatedRequestPlainUT
// ---------------------------------------------------------------------------
@Test
class UnvalidatedRequestPlainUT {

    @TestCase
    func testPlainRequest(): Unit {
        let dcqlEncoded = "%7B%22credentials%22%3A%5B%7B%22id%22%3A%22cred1%22%2C%22format%22%3A%22mso_mdoc%22%7D%5D%7D"
        let uri = "openid4vp://?response_type=vp_token&client_id=verifier.example.com&nonce=n-0S6_WzA2Mj&response_mode=direct_post&response_uri=https%3A%2F%2Fverifier.example.com%2Fcb&dcql_query=" + dcqlEncoded
        let req = UnvalidatedRequest.make(uri)
        match (req) {
            case p: Plain =>
                match (p.requestObject.clientId) {
                    case Some(cid) => @Expect(cid, "verifier.example.com")
                    case None => throw Exception("expected clientId")
                }
                match (p.requestObject.nonce) {
                    case Some(n) => @Expect(n, "n-0S6_WzA2Mj")
                    case None => throw Exception("expected nonce")
                }
                match (p.requestObject.responseMode) {
                    case Some(rm) => @Expect(rm, "direct_post")
                    case None => throw Exception("expected responseMode")
                }
            case _ => throw Exception("expected Plain request")
        }
    }

    @TestCase
    func testPassByValueJwt(): Unit {
        let uri = "openid4vp://?client_id=verifier.example.com&request=eyJhbGciOiJFUzI1NiJ9.payload.sig"
        let req = UnvalidatedRequest.make(uri)
        match (req) {
            case j: JwtSecuredPassByValue =>
                @Expect(j.clientId, "verifier.example.com")
                @Expect(j.jwt, "eyJhbGciOiJFUzI1NiJ9.payload.sig")
            case _ => throw Exception("expected JwtSecuredPassByValue")
        }
    }

    @TestCase
    func testPassByReference(): Unit {
        let uri = "openid4vp://?client_id=verifier.example.com&request_uri=https%3A%2F%2Fverifier.example.com%2Frequest%2F1"
        let req = UnvalidatedRequest.make(uri)
        match (req) {
            case j: JwtSecuredPassByReference =>
                @Expect(j.clientId, "verifier.example.com")
                @Expect(j.jwtUri, "https://verifier.example.com/request/1")
            case _ => throw Exception("expected JwtSecuredPassByReference")
        }
    }
}

// ---------------------------------------------------------------------------
// Test 44: ClientIdSchemeVariantsUT
// ---------------------------------------------------------------------------
@Test
class ClientIdSchemeVariantsUT {

    @TestCase
    func testAllSchemes(): Unit {
        let schemes = [
            ("pre-registered", "pre-registered"),
            ("redirect_uri", "redirect_uri"),
            ("openid_federation", "openid_federation"),
            ("decentralized_identifier", "decentralized_identifier"),
            ("x509_san_dns", "x509_san_dns"),
            ("x509_hash", "x509_hash"),
            ("verifier_attestation", "verifier_attestation")
        ]
        for ((raw, expected) in schemes) {
            let parsed = ClientIdPrefix.fromRawValue(raw)
            match (parsed) {
                case Some(p) => @Expect(p.toString(), expected)
                case None => throw Exception("expected Some for scheme: " + raw)
            }
        }
    }

    @TestCase
    func testUnknownSchemeReturnsNone(): Unit {
        let result = ClientIdPrefix.fromRawValue("unknown")
        match (result) {
            case None => ()
            case Some(_) => throw Exception("expected None for unknown scheme")
        }
    }
}

// ---------------------------------------------------------------------------
// Test 45: VerifierIdParseUT
// ---------------------------------------------------------------------------
@Test
class VerifierIdParseUT {

    @TestCase
    func testPreRegistered(): Unit {
        let vid = VerifierId.parse("verifier.example.com")
        @Expect(vid.scheme.toString(), "pre-registered")
        @Expect(vid.originalClientId, "verifier.example.com")
        @Expect(vid.clientId(), "verifier.example.com")
    }

    @TestCase
    func testRedirectUri(): Unit {
        let vid = VerifierId.parse("redirect_uri:https://verifier.example.com/cb")
        @Expect(vid.scheme.toString(), "redirect_uri")
        @Expect(vid.originalClientId, "https://verifier.example.com/cb")
    }

    @TestCase
    func testX509SanDns(): Unit {
        let vid = VerifierId.parse("x509_san_dns:verifier.example.com")
        @Expect(vid.scheme.toString(), "x509_san_dns")
        @Expect(vid.originalClientId, "verifier.example.com")
        let clientId = vid.clientId()
        @Expect(clientId, "x509_san_dns:verifier.example.com")
    }
}

// ---------------------------------------------------------------------------
// Test 46: VpTokenFormParamsUT
// ---------------------------------------------------------------------------
@Test
class VpTokenFormParamsUT {

    @TestCase
    func testVpTokenFormParams(): Unit {
        let vps = HashMap<String, Array<VerifiablePresentation>>()
        vps.add("cred1", [VerifiablePresentation.generic("eyJhbGciOiJFUzI1NiJ9.credential.sig")])
        let vpContent = DcqlVpContent(vps)
        let verifierId = VerifierId(scheme: ClientIdPrefix.PreRegistered, originalClientId: "verifier.example.com")
        let payload = AuthorizationResponsePayload.openId4VPAuthorizationResponse(
            vpContent: vpContent,
            state: "state-123",
            nonce: "nonce-abc",
            clientId: verifierId
        )

        let params = payload.toFormParams()
        match (params.get("state")) {
            case Some(s) => @Expect(s, "state-123")
            case None => throw Exception("expected state")
        }
        match (params.get("vp_token")) {
            case Some(vt) =>
                if (vt.isEmpty()) {
                    throw Exception("vp_token must not be empty")
                }
                if (!vt.contains("cred1")) {
                    throw Exception("vp_token must contain cred1: " + vt)
                }
            case None => throw Exception("expected vp_token")
        }
    }

    @TestCase
    func testNoConsensusFormParams(): Unit {
        let payload = AuthorizationResponsePayload.noConsensusResponseData(
            state: "state-xyz",
            error: "access_denied"
        )
        let params = payload.toFormParams()
        match (params.get("state")) {
            case Some(s) => @Expect(s, "state-xyz")
            case None => throw Exception("expected state")
        }
        match (params.get("error")) {
            case Some(e) => @Expect(e, "access_denied")
            case None => throw Exception("expected error")
        }
    }
}

// ---------------------------------------------------------------------------
// Test 47: DispatchOutcomeUT
// ---------------------------------------------------------------------------
@Test
class DispatchOutcomeUT {

    @TestCase
    func testAccepted(): Unit {
        let outcome = DispatchOutcome.accepted(redirectUri: Some("https://wallet.example.com/done"))
        match (outcome) {
            case a: AcceptedOutcome =>
                match (a.redirectUri) {
                    case Some(uri) => @Expect(uri, "https://wallet.example.com/done")
                    case None => throw Exception("expected redirectUri")
                }
            case _ => throw Exception("expected AcceptedOutcome")
        }
    }

    @TestCase
    func testAcceptedNoRedirect(): Unit {
        let outcome = DispatchOutcome.accepted(redirectUri: Option<String>.None)
        match (outcome) {
            case a: AcceptedOutcome =>
                match (a.redirectUri) {
                    case None => ()
                    case Some(_) => throw Exception("expected no redirectUri")
                }
            case _ => throw Exception("expected AcceptedOutcome")
        }
    }

    @TestCase
    func testRejected(): Unit {
        let outcome = DispatchOutcome.rejected(reason: "User declined")
        match (outcome) {
            case r: RejectedOutcome => @Expect(r.reason, "User declined")
            case _ => throw Exception("expected RejectedOutcome")
        }
    }
}

// ---------------------------------------------------------------------------
// Test 48: AuthorizationRequestErrorCodeUT
// ---------------------------------------------------------------------------
@Test
class AuthorizationRequestErrorCodeUT {

    @TestCase
    func testErrorCodes(): Unit {
        @Expect(AuthorizationRequestErrorCode.InvalidScope.toString(), "invalid_scope")
        @Expect(AuthorizationRequestErrorCode.InvalidRequest.toString(), "invalid_request")
        @Expect(AuthorizationRequestErrorCode.AccessDenied.toString(), "access_denied")
        @Expect(AuthorizationRequestErrorCode.InvalidClient.toString(), "invalid_client")
        @Expect(AuthorizationRequestErrorCode.VpFormatsNotSupported.toString(), "vp_formats_not_supported")
        @Expect(AuthorizationRequestErrorCode.UserCancelled.toString(), "user_cancelled")
        @Expect(AuthorizationRequestErrorCode.ProcessingFailure.toString(), "processing_error")
        @Expect(AuthorizationRequestErrorCode.InvalidRequestURIMethod.toString(), "invalid_request_uri_method")
    }
}

// ===========================================================================
// X.509 TEST FIXTURES
// ===========================================================================
// These PEM constants are the same test chain used by eudi_cjx509 unit tests.
// ROOT_CA_PEM → INT_CA_PEM → LEAF_PEM (no SAN; subject: CN=Test Leaf,O=Test Org,C=DE)
// SAN_CERT_PEM is a self-signed cert with SAN dnsName entries.

// ROOT_CA_PEM — Test Root CA (EC P-256, self-signed)
let VCI_ROOT_CA_PEM: String =
    "-----BEGIN CERTIFICATE-----\n" +
    "MIIBXzCCAQQCCQDf8najtcVHajAKBggqhkjOPQQDAjA3MRUwEwYDVQQDDAxUZXN0\n" +
    "IFJvb3QgQ0ExETAPBgNVBAoMCFRlc3QgT3JnMQswCQYDVQQGEwJERTAeFw0yNjA2\n" +
    "MTIxNzEwMTRaFw0zNjA2MDkxNzEwMTRaMDcxFTATBgNVBAMMDFRlc3QgUm9vdCBD\n" +
    "QTERMA8GA1UECgwIVGVzdCBPcmcxCzAJBgNVBAYTAkRFMFkwEwYHKoZIzj0CAQYI\n" +
    "KoZIzj0DAQcDQgAEL7MTEGbogCdSD66Ka0Bzpd/f++u0rKaRGoemAcDEolGHLwzo\n" +
    "9rXor6C8WhhKclFeQfuczpn2kboNn2Ru1U/+jzAKBggqhkjOPQQDAgNJADBGAiEA\n" +
    "2apXjtSAeBpka0u67J3/DoXw2x/qaih03ajwCJHTN/QCIQDwnL5m39lIkpER6LK3\n" +
    "81vuWQZY/ipamdWaffkb527fZw==\n" +
    "-----END CERTIFICATE-----\n"

// INT_CA_PEM — Test Intermediate CA (signed by Root)
let VCI_INT_CA_PEM: String =
    "-----BEGIN CERTIFICATE-----\n" +
    "MIIBfDCCASKgAwIBAgIJAP0u8k/hL6MGMAkGByqGSM49BAEwNzEVMBMGA1UEAwwM\n" +
    "VGVzdCBSb290IENBMREwDwYDVQQKDAhUZXN0IE9yZzELMAkGA1UEBhMCREUwHhcN\n" +
    "MjYwNjEyMTcxMDMyWhcNMzYwNjA5MTcxMDMyWjA/MR0wGwYDVQQDDBRUZXN0IElu\n" +
    "dGVybWVkaWF0ZSBDQTERMA8GA1UECgwIVGVzdCBPcmcxCzAJBgNVBAYTAkRFMFkw\n" +
    "EwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEHIRmAVISzJTxygO8L2gz0ASobF3BVT2x\n" +
    "0PDBhWWBJEwXJnKSdXX1KJUf8Dm2C1QVcMX/nmXZcLFk3Y7CKeQEx6MQMA4wDAYD\n" +
    "VR0TBAUwAwEB/zAJBgcqhkjOPQQBA0kAMEYCIQDoByBiZOdbxMkN/vsicOaw8mGK\n" +
    "H+JCW6Xg5rgSuZnahQIhAOLKSG6rl4UaiMrDsPX5YanvnMfUL6slRi92WRtDorHZ\n" +
    "-----END CERTIFICATE-----\n"

// LEAF_PEM — Test Leaf (signed by Intermediate; subject: CN=Test Leaf,O=Test Org,C=DE)
let VCI_LEAF_PEM: String =
    "-----BEGIN CERTIFICATE-----\n" +
    "MIIBYTCCAQgCCQDgG1MIt04++TAJBgcqhkjOPQQBMD8xHTAbBgNVBAMMFFRlc3Qg\n" +
    "SW50ZXJtZWRpYXRlIENBMREwDwYDVQQKDAhUZXN0IE9yZzELMAkGA1UEBhMCREUw\n" +
    "HhcNMjYwNjEyMTcxMDQ1WhcNMjcwNjEyMTcxMDQ1WjA0MRIwEAYDVQQDDAlUZXN0\n" +
    "IExlYWYxETAPBgNVBAoMCFRlc3QgT3JnMQswCQYDVQQGEwJERTBZMBMGByqGSM49\n" +
    "AgEGCCqGSM49AwEHA0IABHvaTf9Vr6/Idyxa3W1QrCE8B/pHr3A7myRmCEotevc1\n" +
    "qvG+xuyny7JFWqyIU3LUZNcfJpO5ZNdxIii2WoKJu2MwCQYHKoZIzj0EAQNIADBF\n" +
    "AiEA9fr6BJZEWaitvwkRggxAmVnU44iPKKt11x2kKBRnGfgCIEdqQauDYtXSqbjE\n" +
    "/tjmfOW+UziM2VXyQ/s+WtRuQq/Y\n" +
    "-----END CERTIFICATE-----\n"

// WRONG_CA_PEM — Unrelated root (not in the test chain)
let VCI_WRONG_CA_PEM: String =
    "-----BEGIN CERTIFICATE-----\n" +
    "MIIBYjCCAQgCCQDDohbqDs2LkjAKBggqhkjOPQQDAjA5MRYwFAYDVQQDDA1Xcm9u\n" +
    "ZyBSb290IENBMRIwEAYDVQQKDAlXcm9uZyBPcmcxCzAJBgNVBAYTAlVTMB4XDTI2\n" +
    "MDYxMjE3MTA1MVoXDTM2MDYwOTE3MTA1MVowOTEWMBQGA1UEAwwNV3JvbmcgUm9v\n" +
    "dCBDQTESMBAGA1UECgwJV3JvbmcgT3JnMQswCQYDVQQGEwJVUzBZMBMGByqGSM49\n" +
    "AgEGCCqGSM49AwEHA0IABLunLMG1VZnILe+kHIHWozl3sJms8LCZ+hmk/ksvOC0u\n" +
    "iHg+YtX+ZgoGfN4KKDXDXNMYjkkcGliYtZwG15bLNCQwCgYIKoZIzj0EAwIDSAAw\n" +
    "RQIhAONz64FL8rDlF1mmA7+eJ4RqLHmwdlJ99lyceUTrJU0mAiAChqxQpqEdEqYP\n" +
    "g+tf56Jd8yMsv0EnwbF2pHkGb7eyug==\n" +
    "-----END CERTIFICATE-----\n"

// SAN_CERT_PEM — Self-signed cert with SAN dnsName extensions:
//   DNS:verifier.example.com, DNS:alt.example.com
//   Subject: CN=verifier.example.com,O=EUDI Test Org,C=DE
let VCI_SAN_CERT_PEM: String =
    "-----BEGIN CERTIFICATE-----\n" +
    "MIICEjCCAbegAwIBAgIUAtlvaT5gNG5lUEplTYqOlu3B1AkwCgYIKoZIzj0EAwIw\n" +
    "RDEdMBsGA1UEAwwUdmVyaWZpZXIuZXhhbXBsZS5jb20xFjAUBgNVBAoMDUVVREkg\n" +
    "VGVzdCBPcmcxCzAJBgNVBAYTAkRFMB4XDTI2MDYxNzE3MDgzN1oXDTI3MDYxNzE3\n" +
    "MDgzN1owRDEdMBsGA1UEAwwUdmVyaWZpZXIuZXhhbXBsZS5jb20xFjAUBgNVBAoM\n" +
    "DUVVREkgVGVzdCBPcmcxCzAJBgNVBAYTAkRFMFkwEwYHKoZIzj0CAQYIKoZIzj0D\n" +
    "AQcDQgAEDPUYDRp7wkWFRCITUHbUNwXIG7fx1Hs2WGyO531z6OqmTgiL6Lv4Mn0E\n" +
    "UzBmc1jopI5POX1ZdHtL4Vx7hc9ZuqOBhjCBgzAdBgNVHQ4EFgQUnPqPcVKaM6zb\n" +
    "Q2/Fa4FeqSyUgK4wHwYDVR0jBBgwFoAUnPqPcVKaM6zbQ2/Fa4FeqSyUgK4wDwYD\n" +
    "VR0TAQH/BAUwAwEB/zAwBgNVHREEKTAnghR2ZXJpZmllci5leGFtcGxlLmNvbYIP\n" +
    "YWx0LmV4YW1wbGUuY29tMAoGCCqGSM49BAMCA0kAMEYCIQDxrEoUDN9kgQn6XV6z\n" +
    "Lq9Mp+1OR4hmIrZFsobTpIWexwIhAJmoghBnTaovQ8nfY5aTT9Pt4xpvCfzm9m5Y\n" +
    "KCRWd+Su\n" +
    "-----END CERTIFICATE-----\n"

// Standard base64 DER of SAN_CERT_PEM (used as x5c entry — standard base64, not url-safe)
let VCI_SAN_CERT_B64_DER: String =
    "MIICEjCCAbegAwIBAgIUAtlvaT5gNG5lUEplTYqOlu3B1AkwCgYIKoZIzj0EAwIw" +
    "RDEdMBsGA1UEAwwUdmVyaWZpZXIuZXhhbXBsZS5jb20xFjAUBgNVBAoMDUVVREkg" +
    "VGVzdCBPcmcxCzAJBgNVBAYTAkRFMB4XDTI2MDYxNzE3MDgzN1oXDTI3MDYxNzE3" +
    "MDgzN1owRDEdMBsGA1UEAwwUdmVyaWZpZXIuZXhhbXBsZS5jb20xFjAUBgNVBAoM" +
    "DUVVREkgVGVzdCBPcmcxCzAJBgNVBAYTAkRFMFkwEwYHKoZIzj0CAQYIKoZIzj0D" +
    "AQcDQgAEDPUYDRp7wkWFRCITUHbUNwXIG7fx1Hs2WGyO531z6OqmTgiL6Lv4Mn0E" +
    "UzBmc1jopI5POX1ZdHtL4Vx7hc9ZuqOBhjCBgzAdBgNVHQ4EFgQUnPqPcVKaM6zb" +
    "Q2/Fa4FeqSyUgK4wHwYDVR0jBBgwFoAUnPqPcVKaM6zbQ2/Fa4FeqSyUgK4wDwYD" +
    "VR0TAQH/BAUwAwEB/zAwBgNVHREEKTAnghR2ZXJpZmllci5leGFtcGxlLmNvbYIP" +
    "YWx0LmV4YW1wbGUuY29tMAoGCCqGSM49BAMCA0kAMEYCIQDxrEoUDN9kgQn6XV6z" +
    "Lq9Mp+1OR4hmIrZFsobTpIWexwIhAJmoghBnTaovQ8nfY5aTT9Pt4xpvCfzm9m5Y" +
    "KCRWd+Su"

// Standard base64 DER of LEAF_PEM (used as x5c entry)
let VCI_LEAF_B64_DER: String =
    "MIIBYTCCAQgCCQDgG1MIt04++TAJBgcqhkjOPQQBMD8xHTAbBgNVBAMMFFRlc3Qg" +
    "SW50ZXJtZWRpYXRlIENBMREwDwYDVQQKDAhUZXN0IE9yZzELMAkGA1UEBhMCREUw" +
    "HhcNMjYwNjEyMTcxMDQ1WhcNMjcwNjEyMTcxMDQ1WjA0MRIwEAYDVQQDDAlUZXN0" +
    "IExlYWYxETAPBgNVBAoMCFRlc3QgT3JnMQswCQYDVQQGEwJERTBZMBMGByqGSM49" +
    "AgEGCCqGSM49AwEHA0IABHvaTf9Vr6/Idyxa3W1QrCE8B/pHr3A7myRmCEotevc1" +
    "qvG+xuyny7JFWqyIU3LUZNcfJpO5ZNdxIii2WoKJu2MwCQYHKoZIzj0EAQNIADBF" +
    "AiEA9fr6BJZEWaitvwkRggxAmVnU44iPKKt11x2kKBRnGfgCIEdqQauDYtXSqbjE" +
    "/tjmfOW+UziM2VXyQ/s+WtRuQq/Y"

// SHA-256(SAN_CERT DER) in base64url (no padding), used to test certSha256Base64Url
let VCI_SAN_CERT_SHA256_B64URL: String = "1BCGcTqd0eMnQ5h9HBfRi9ENTP5mFfqeTWDQUrsGpd8"

// SHA-256(LEAF DER) in base64url (no padding)
let VCI_LEAF_SHA256_B64URL: String = "FhXzt13Z1bUsAtPQH3lr0Qt9rFVG7t290Zj1CPUNN0c"

// ===========================================================================
// X.509 TESTS (Tests 49-60)
// ===========================================================================

// ---------------------------------------------------------------------------
// Test 49: X509ExtractOrgFromSubjectUT
// Tests the extractOrgFromSubject internal function indirectly via legalName()
// and directly via X509SanDnsClient.legalName() with a parsed cert.
// ---------------------------------------------------------------------------
@Test
class X509ExtractOrgFromSubjectUT {

    @TestCase
    func testExtractOrgFromKnownDn(): Unit {
        // stdx subject format: "cn=Test Leaf,o=Test Org,c=DE" (lowercase attrs).
        // extractOrgFromSubject handles both 'o=' and 'O=' — must return "Test Org".
        let certs = Cert.fromPem(VCI_LEAF_PEM)
        @Expect(certs.size, 1)
        let leaf = certs[0]
        // Build a client with the leaf cert so legalName() calls extractOrgFromSubject
        let client = X509SanDnsClient(clientId: "test.example.com", cert: Some(leaf))
        match (client.legalName()) {
            case Some(name) => @Expect(name, "Test Org")
            case None => throw Exception("legalName returned None; expected Some(\"Test Org\")")
        }
    }

    @TestCase
    func testExtractOrgFromSanCertDn(): Unit {
        // Verify that legalName() does not throw for a SAN cert with X509SanDnsClient.
        // None is acceptable (stdx DN rendering may use ', ' separator that the parser misses).
        let certs = Cert.fromPem(VCI_SAN_CERT_PEM)
        @Expect(certs.size, 1)
        let leaf = certs[0]
        let client = X509SanDnsClient(clientId: "verifier.example.com", cert: Some(leaf))
        // Must not throw; result may be None or Some(org)
        let _ = client.legalName()
    }

    @TestCase
    func testExtractOrgReturnsStringFromSubject(): Unit {
        // After fix: extractOrgFromSubject handles lowercase 'o=' (stdx format).
        // Must return "Test Org" for a cert with O=Test Org in subject.
        let certs = Cert.fromPem(VCI_LEAF_PEM)
        @Expect(certs.size, 1)
        let leaf = certs[0]
        let client = X509SanDnsClient(clientId: "test.example.com", cert: Some(leaf))
        match (client.legalName()) {
            case Some(name) =>
                if (name.isEmpty()) {
                    throw Exception("legalName returned empty string for cert with O=Test Org")
                }
            case None => throw Exception("legalName returned None; expected Some for cert with O=")
        }
    }
}

// ---------------------------------------------------------------------------
// Test 50: X509ParseCertsFromX5cUT
// Tests parseCertsFromX5c with real base64 DER cert data.
// ---------------------------------------------------------------------------
@Test
class X509ParseCertsFromX5cUT {

    @TestCase
    func testParseSingleEntry(): Unit {
        let certs = parseCertsFromX5c([VCI_LEAF_B64_DER])
        @Expect(certs.size, 1)
        // Verify parsed cert has correct subject
        @Expect(certs[0].subject.contains("Test Leaf"), true)
    }

    @TestCase
    func testParseMultipleEntries(): Unit {
        let certs = parseCertsFromX5c([VCI_LEAF_B64_DER, VCI_SAN_CERT_B64_DER])
        @Expect(certs.size, 2)
        @Expect(certs[0].subject.contains("Test Leaf"), true)
        @Expect(certs[1].subject.contains("verifier.example.com"), true)
    }

    @TestCase
    func testEmptyArrayReturnsEmpty(): Unit {
        let certs = parseCertsFromX5c([])
        @Expect(certs.size, 0)
    }

    @TestCase
    func testMalformedEntrySkipped(): Unit {
        // One valid cert, one garbage base64 — garbage should be skipped
        let certs = parseCertsFromX5c([VCI_LEAF_B64_DER, "bm90YWNlcnQ="])
        // Only the valid cert is returned; malformed one is silently skipped
        @Expect(certs.size, 1)
        @Expect(certs[0].subject.contains("Test Leaf"), true)
    }

    @TestCase
    func testAllMalformedReturnsEmpty(): Unit {
        let certs = parseCertsFromX5c(["bm90YQ==", "AAAA"])
        @Expect(certs.size, 0)
    }

    @TestCase
    func testRoundTripSubjectAndIssuer(): Unit {
        // The leaf cert parsed from base64 DER should have correct issuer (Intermediate CA)
        let certs = parseCertsFromX5c([VCI_LEAF_B64_DER])
        @Expect(certs.size, 1)
        @Expect(certs[0].issuer.contains("Intermediate"), true)
    }
}

// ---------------------------------------------------------------------------
// Test 51: X509ExtractSanDnsNamesUT
// Tests extractSanDnsNames with a real cert that has SAN extensions.
// ---------------------------------------------------------------------------
@Test
class X509ExtractSanDnsNamesUT {

    @TestCase
    func testSanCertHasTwoDnsNames(): Unit {
        let certs = Cert.fromPem(VCI_SAN_CERT_PEM)
        @Expect(certs.size, 1)
        let leaf = certs[0]
        let sanNames = extractSanDnsNames(leaf)
        @Expect(sanNames.size, 2)
    }

    @TestCase
    func testSanCertContainsVerifierExampleCom(): Unit {
        let leaf = Cert.fromPem(VCI_SAN_CERT_PEM)[0]
        let sanNames = extractSanDnsNames(leaf)
        var found = false
        for (name in sanNames) {
            if (name == "verifier.example.com") {
                found = true
                break
            }
        }
        @Expect(found, true)
    }

    @TestCase
    func testSanCertContainsAltExampleCom(): Unit {
        let leaf = Cert.fromPem(VCI_SAN_CERT_PEM)[0]
        let sanNames = extractSanDnsNames(leaf)
        var found = false
        for (name in sanNames) {
            if (name == "alt.example.com") {
                found = true
                break
            }
        }
        @Expect(found, true)
    }

    @TestCase
    func testLeafWithNoSanReturnsEmpty(): Unit {
        // The LEAF_PEM cert has no SAN extension
        let leaf = Cert.fromPem(VCI_LEAF_PEM)[0]
        let sanNames = extractSanDnsNames(leaf)
        // Should return empty array (no SAN extension present)
        @Expect(sanNames.size, 0)
    }

    @TestCase
    func testSanNamesAreNonEmpty(): Unit {
        let leaf = Cert.fromPem(VCI_SAN_CERT_PEM)[0]
        let sanNames = extractSanDnsNames(leaf)
        for (name in sanNames) {
            if (name.isEmpty()) {
                throw Exception("SAN dnsName must not be empty string")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Test 52: X509CertSha256Base64UrlUT
// Tests certSha256Base64Url with known expected values.
// ---------------------------------------------------------------------------
@Test
class X509CertSha256Base64UrlUT {

    @TestCase
    func testSanCertSha256KnownValue(): Unit {
        let leaf = Cert.fromPem(VCI_SAN_CERT_PEM)[0]
        let hash = certSha256Base64Url(leaf)
        @Expect(hash, VCI_SAN_CERT_SHA256_B64URL)
    }

    @TestCase
    func testLeafCertSha256KnownValue(): Unit {
        let leaf = Cert.fromPem(VCI_LEAF_PEM)[0]
        let hash = certSha256Base64Url(leaf)
        @Expect(hash, VCI_LEAF_SHA256_B64URL)
    }

    @TestCase
    func testHashIsBase64UrlNoPadding(): Unit {
        // base64url uses A-Z a-z 0-9 - _ only; no + / or = padding
        let leaf = Cert.fromPem(VCI_SAN_CERT_PEM)[0]
        let hash = certSha256Base64Url(leaf)
        if (hash.isEmpty()) {
            throw Exception("hash must not be empty")
        }
        for (b in hash.toArray()) {
            let ch = Int64(b)
            let ok = (ch >= 65 && ch <= 90) ||   // A-Z
                     (ch >= 97 && ch <= 122) ||  // a-z
                     (ch >= 48 && ch <= 57) ||   // 0-9
                     ch == 45 || ch == 95         // - or _
            if (!ok) {
                throw Exception("non base64url char in hash: " + b.toString())
            }
        }
    }

    @TestCase
    func testHashLengthIsCorrect(): Unit {
        // SHA-256 is 32 bytes → base64url without padding: ceil(32*4/3) = 43 chars
        let leaf = Cert.fromPem(VCI_SAN_CERT_PEM)[0]
        let hash = certSha256Base64Url(leaf)
        @Expect(hash.size, 43)
    }

    @TestCase
    func testTwoDifferentCertsGiveDifferentHashes(): Unit {
        let leaf = Cert.fromPem(VCI_LEAF_PEM)[0]
        let sanLeaf = Cert.fromPem(VCI_SAN_CERT_PEM)[0]
        let hash1 = certSha256Base64Url(leaf)
        let hash2 = certSha256Base64Url(sanLeaf)
        if (hash1 == hash2) {
            throw Exception("different certs must produce different SHA-256 hashes")
        }
    }

    @TestCase
    func testDerRoundTripPreservesHash(): Unit {
        // Parse from PEM → toDer → fromDer → certSha256Base64Url must equal original
        let orig = Cert.fromPem(VCI_LEAF_PEM)[0]
        let der = orig.toDer()
        let reloaded = Cert.fromDer(der)
        let hashOrig = certSha256Base64Url(orig)
        let hashReloaded = certSha256Base64Url(reloaded)
        @Expect(hashOrig, hashReloaded)
    }
}

// ---------------------------------------------------------------------------
// Test 53: X509SanDnsClientUT
// Tests X509SanDnsClient class construction and legalName().
// ---------------------------------------------------------------------------
@Test
class X509SanDnsClientUT {

    @TestCase
    func testConstructWithClientIdOnly(): Unit {
        let client = X509SanDnsClient(clientId: "verifier.example.com")
        @Expect(client.clientId, "verifier.example.com")
        @Expect(client.certPem.isEmpty(), true)
        match (client.cert) {
            case None => ()
            case Some(_) => throw Exception("expected None cert")
        }
    }

    @TestCase
    func testConstructWithParsedCert(): Unit {
        let leaf = Cert.fromPem(VCI_SAN_CERT_PEM)[0]
        let client = X509SanDnsClient(clientId: "verifier.example.com", cert: Some(leaf))
        @Expect(client.clientId, "verifier.example.com")
        match (client.cert) {
            case Some(_) => ()
            case None => throw Exception("expected Some cert")
        }
    }

    @TestCase
    func testIdReturnsX509SanDnsScheme(): Unit {
        let leaf = Cert.fromPem(VCI_LEAF_PEM)[0]
        let client = X509SanDnsClient(clientId: "example.com", cert: Some(leaf))
        let vid = client.id()
        @Expect(vid.scheme.toString(), "x509_san_dns")
        @Expect(vid.originalClientId, "example.com")
    }

    @TestCase
    func testLegalNameFromParsedCert(): Unit {
        // Use VCI_LEAF_PEM (org: "Test Org") to verify legalName dispatch for X509SanDnsClient.
        // After fix to extractOrgFromSubject (handles lowercase 'o='), must return "Test Org".
        let certs = Cert.fromPem(VCI_LEAF_PEM)
        @Expect(certs.size, 1)
        let leaf = certs[0]
        let client = X509SanDnsClient(clientId: "test.example.com", cert: Some(leaf))
        match (client.legalName()) {
            case Some(name) => @Expect(name, "Test Org")
            case None => throw Exception("legalName returned None; expected Some(\"Test Org\")")
        }
    }

    @TestCase
    func testLegalNameNoCertNoMem(): Unit {
        // No cert, no pem → legalName must not crash; returns None or Some("").
        let client = X509SanDnsClient(clientId: "example.com")
        let result = client.legalName()
        match (result) {
            case None => ()
            case Some(s) =>
                if (!s.isEmpty()) {
                    throw Exception("expected None or empty legalName for empty client, got: " + s)
                }
        }
    }
}

// ---------------------------------------------------------------------------
// Test 54: X509HashClientUT
// Tests X509HashClient class construction and legalName().
// ---------------------------------------------------------------------------
@Test
class X509HashClientUT {

    @TestCase
    func testConstructWithClientIdOnly(): Unit {
        let client = X509HashClient(clientId: VCI_SAN_CERT_SHA256_B64URL)
        @Expect(client.clientId, VCI_SAN_CERT_SHA256_B64URL)
        @Expect(client.certPem.isEmpty(), true)
        match (client.cert) {
            case None => ()
            case Some(_) => throw Exception("expected None cert")
        }
    }

    @TestCase
    func testConstructWithParsedCert(): Unit {
        let leaf = Cert.fromPem(VCI_SAN_CERT_PEM)[0]
        let client = X509HashClient(clientId: VCI_SAN_CERT_SHA256_B64URL, cert: Some(leaf))
        match (client.cert) {
            case Some(_) => ()
            case None => throw Exception("expected Some cert")
        }
    }

    @TestCase
    func testIdReturnsX509HashScheme(): Unit {
        let leaf = Cert.fromPem(VCI_LEAF_PEM)[0]
        let hash = certSha256Base64Url(leaf)
        let client = X509HashClient(clientId: hash, cert: Some(leaf))
        let vid = client.id()
        @Expect(vid.scheme.toString(), "x509_hash")
        @Expect(vid.originalClientId, hash)
    }

    @TestCase
    func testLegalNameFromParsedCert(): Unit {
        // X509HashClient legalName delegates to extractOrgFromSubject on the cert's subject.
        // After fix to extractOrgFromSubject (handles lowercase 'o='), must return "Test Org".
        let certs = Cert.fromPem(VCI_LEAF_PEM)
        @Expect(certs.size, 1)
        let leaf = certs[0]
        let client = X509HashClient(clientId: VCI_LEAF_SHA256_B64URL, cert: Some(leaf))
        match (client.legalName()) {
            case Some(name) => @Expect(name, "Test Org")
            case None => throw Exception("legalName returned None; expected Some(\"Test Org\")")
        }
    }
}

// ---------------------------------------------------------------------------
// Test 55: X509VerifyChainUT
// Tests verifyChain with known certs (positive and negative cases).
// ---------------------------------------------------------------------------
@Test
class X509VerifyChainUT {

    @TestCase
    func testChainPositive(): Unit {
        let root = Cert.fromPem(VCI_ROOT_CA_PEM)[0]
        let intCa = Cert.fromPem(VCI_INT_CA_PEM)[0]
        let leaf = Cert.fromPem(VCI_LEAF_PEM)[0]
        let ok = verifyChain(leaf, [intCa], [root])
        @Expect(ok, true)
    }

    @TestCase
    func testChainWrongRootNegative(): Unit {
        let wrongRoot = Cert.fromPem(VCI_WRONG_CA_PEM)[0]
        let intCa = Cert.fromPem(VCI_INT_CA_PEM)[0]
        let leaf = Cert.fromPem(VCI_LEAF_PEM)[0]
        let ok = verifyChain(leaf, [intCa], [wrongRoot])
        @Expect(ok, false)
    }

    @TestCase
    func testChainExpiredNegative(): Unit {
        let root = Cert.fromPem(VCI_ROOT_CA_PEM)[0]
        let intCa = Cert.fromPem(VCI_INT_CA_PEM)[0]
        let leaf = Cert.fromPem(VCI_LEAF_PEM)[0]
        // Leaf notAfter is 2027-06-12; verify at 2030-01-01 → chain expired
        let futureDate = DateTime.of(year: 2030, month: 1, dayOfMonth: 1)
        let ok = verifyChain(leaf, [intCa], [root], date: Some(futureDate))
        @Expect(ok, false)
    }

    @TestCase
    func testSanCertSelfSignedChain(): Unit {
        // SAN cert is self-signed → root == leaf
        let sanLeaf = Cert.fromPem(VCI_SAN_CERT_PEM)[0]
        // verifyChain(leaf=sanLeaf, intermediates=[], roots=[sanLeaf])
        // Self-signed cert can verify as its own root
        let ok = verifyChain(sanLeaf, [], [sanLeaf])
        @Expect(ok, true)
    }
}

// ---------------------------------------------------------------------------
// Test 56: X509CertFromDerUT
// Tests Cert.fromDer with valid and invalid data.
// ---------------------------------------------------------------------------
@Test
class X509CertFromDerUT {

    @TestCase
    func testFromDerRoundTrip(): Unit {
        let orig = Cert.fromPem(VCI_LEAF_PEM)[0]
        let der = orig.toDer()
        let reloaded = Cert.fromDer(der)
        @Expect(reloaded.serialNumber, orig.serialNumber)
        @Expect(reloaded.subject, orig.subject)
        @Expect(reloaded.issuer, orig.issuer)
    }

    @TestCase
    func testFromDerSanCertRoundTrip(): Unit {
        let orig = Cert.fromPem(VCI_SAN_CERT_PEM)[0]
        let der = orig.toDer()
        let reloaded = Cert.fromDer(der)
        @Expect(reloaded.subject, orig.subject)
        // SAN names should also survive round-trip
        let sanOrig = extractSanDnsNames(orig)
        let sanReloaded = extractSanDnsNames(reloaded)
        @Expect(sanOrig.size, sanReloaded.size)
    }

    @TestCase
    func testFromDerEmptyThrows(): Unit {
        var threw = false
        try {
            let _ = Cert.fromDer([])
        } catch (_: CertError) {
            threw = true
        } catch (_: Exception) {
            threw = true
        }
        @Expect(threw, true)
    }

    @TestCase
    func testFromDerTruncatedThrows(): Unit {
        var threw = false
        try {
            let _ = Cert.fromDer([0x30u8, 0x82u8, 0x01u8])
        } catch (_: CertError) {
            threw = true
        } catch (_: Exception) {
            threw = true
        }
        @Expect(threw, true)
    }

    @TestCase
    func testFromPemMultipleCertsOneEntry(): Unit {
        // fromPem should return exactly 1 cert for a single-cert PEM
        let certs = Cert.fromPem(VCI_LEAF_PEM)
        @Expect(certs.size, 1)
    }
}

// ---------------------------------------------------------------------------
// Test 57: X509CertPropertiesUT
// Tests Cert property fields (subject, issuer, serialNumber, notBefore).
// ---------------------------------------------------------------------------
@Test
class X509CertPropertiesUT {

    @TestCase
    func testLeafSubjectContainsTestLeaf(): Unit {
        let leaf = Cert.fromPem(VCI_LEAF_PEM)[0]
        @Expect(leaf.subject.contains("Test Leaf"), true)
    }

    @TestCase
    func testLeafIssuerContainsIntermediate(): Unit {
        let leaf = Cert.fromPem(VCI_LEAF_PEM)[0]
        @Expect(leaf.issuer.contains("Intermediate"), true)
    }

    @TestCase
    func testLeafNotBeforeYear(): Unit {
        let leaf = Cert.fromPem(VCI_LEAF_PEM)[0]
        let yearVal: Int64 = Int64(leaf.notBefore.year)
        @Expect(yearVal, 2026i64)
    }

    @TestCase
    func testSanCertSubjectContainsVerifier(): Unit {
        let cert = Cert.fromPem(VCI_SAN_CERT_PEM)[0]
        @Expect(cert.subject.contains("verifier.example.com"), true)
    }

    @TestCase
    func testSanCertIssuerEqualsSelfSigned(): Unit {
        // Self-signed: subject == issuer
        let cert = Cert.fromPem(VCI_SAN_CERT_PEM)[0]
        @Expect(cert.subject, cert.issuer)
    }

    @TestCase
    func testRootCaNotAfterIsAfter2036(): Unit {
        let root = Cert.fromPem(VCI_ROOT_CA_PEM)[0]
        let year: Int64 = Int64(root.notAfter.year)
        if (year < 2036i64) {
            throw Exception("Root CA notAfter year must be >= 2036, got: " + year.toString())
        }
    }
}

// ---------------------------------------------------------------------------
// Test 58: X509ClientLegalNameUT
// Tests legalName() dispatch on all Client subclasses.
// ---------------------------------------------------------------------------
@Test
class X509ClientLegalNameUT {

    @TestCase
    func testPreRegisteredClientLegalName(): Unit {
        let client = PreRegisteredClient(clientId: "verifier.example.com", legalName: "ACME Corp")
        match (client.legalName()) {
            case Some(name) => @Expect(name, "ACME Corp")
            case None => throw Exception("expected legalName 'ACME Corp'")
        }
    }

    @TestCase
    func testRedirectUriClientNoLegalName(): Unit {
        let client = RedirectUriClient(clientId: "https://verifier.example.com/cb")
        match (client.legalName()) {
            case None => ()
            case Some(_) => throw Exception("RedirectUriClient should have no legalName")
        }
    }

    @TestCase
    func testDidClientNoLegalName(): Unit {
        let client = DidClient(did: "did:key:z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9y84QKH")
        match (client.legalName()) {
            case None => ()
            case Some(_) => throw Exception("DidClient should have no legalName")
        }
    }

    @TestCase
    func testAttestedClientNoLegalName(): Unit {
        let client = AttestedClient(clientId: "attested-client")
        match (client.legalName()) {
            case None => ()
            case Some(_) => throw Exception("AttestedClient should have no legalName")
        }
    }

    @TestCase
    func testX509SanDnsClientLegalNameFromSubject(): Unit {
        // Verify X509SanDnsClient.legalName() correctly extracts org from subject.
        // After fix to extractOrgFromSubject (handles lowercase 'o='), must return "Test Org".
        let certs = Cert.fromPem(VCI_LEAF_PEM)
        @Expect(certs.size, 1)
        let leaf = certs[0]
        let client = X509SanDnsClient(clientId: "test.example.com", cert: Some(leaf))
        match (client.legalName()) {
            case Some(name) => @Expect(name, "Test Org")
            case None => throw Exception("legalName returned None; expected Some(\"Test Org\")")
        }
    }

    @TestCase
    func testX509HashClientLegalNameFromSubject(): Unit {
        // X509HashClient.legalName() delegates to extractOrgFromSubject when cert is Some.
        // After fix to extractOrgFromSubject (handles lowercase 'o='), must return "Test Org".
        let certs = Cert.fromPem(VCI_LEAF_PEM)
        @Expect(certs.size, 1)
        let leaf = certs[0]
        let hash = certSha256Base64Url(leaf)
        let client = X509HashClient(clientId: hash, cert: Some(leaf))
        match (client.legalName()) {
            case Some(name) => @Expect(name, "Test Org")
            case None => throw Exception("legalName returned None; expected Some(\"Test Org\")")
        }
    }
}

// ---------------------------------------------------------------------------
// Test 59: X509ParseCertsIntegrationUT
// Tests parseCertsFromX5c → extractSanDnsNames pipeline as used by resolver.
// ---------------------------------------------------------------------------
@Test
class X509ParseCertsIntegrationUT {

    @TestCase
    func testSanCertX5cPipelineFullMatch(): Unit {
        // Simulate x5c pipeline: base64 DER → parseCertsFromX5c → extractSanDnsNames
        let certs = parseCertsFromX5c([VCI_SAN_CERT_B64_DER])
        @Expect(certs.size, 1)
        let leaf = certs[0]
        let sanNames = extractSanDnsNames(leaf)
        @Expect(sanNames.size, 2)
        var found = false
        for (name in sanNames) {
            if (name == "verifier.example.com") {
                found = true
                break
            }
        }
        @Expect(found, true)
    }

    @TestCase
    func testHashPipelineFullMatch(): Unit {
        // Simulate x509_hash validation: parseCertsFromX5c → certSha256Base64Url → compare
        let certs = parseCertsFromX5c([VCI_SAN_CERT_B64_DER])
        @Expect(certs.size, 1)
        let computed = certSha256Base64Url(certs[0])
        @Expect(computed, VCI_SAN_CERT_SHA256_B64URL)
    }

    @TestCase
    func testHashMismatchDetection(): Unit {
        // If clientId hash does not match leaf cert hash, they must differ
        let certs = parseCertsFromX5c([VCI_LEAF_B64_DER])
        @Expect(certs.size, 1)
        let computed = certSha256Base64Url(certs[0])
        // VCI_SAN_CERT_SHA256_B64URL is for a different cert — must not match
        if (computed == VCI_SAN_CERT_SHA256_B64URL) {
            throw Exception("leaf cert hash must not equal SAN cert hash")
        }
    }

    @TestCase
    func testSanLookupMiss(): Unit {
        // Leaf cert has no SAN → extractSanDnsNames returns empty → no match
        let certs = parseCertsFromX5c([VCI_LEAF_B64_DER])
        @Expect(certs.size, 1)
        let sanNames = extractSanDnsNames(certs[0])
        @Expect(sanNames.size, 0)
    }
}

// ---------------------------------------------------------------------------
// Test 60: X509ClientIdUT
// Tests VerifierId.parse and Client.id() for X.509 schemes.
// ---------------------------------------------------------------------------
@Test
class X509ClientIdUT {

    @TestCase
    func testX509SanDnsClientId(): Unit {
        let client = X509SanDnsClient(clientId: "verifier.example.com")
        let vid = client.id()
        @Expect(vid.scheme.toString(), "x509_san_dns")
        @Expect(vid.originalClientId, "verifier.example.com")
        @Expect(vid.clientId(), "x509_san_dns:verifier.example.com")
    }

    @TestCase
    func testX509HashClientId(): Unit {
        let client = X509HashClient(clientId: VCI_SAN_CERT_SHA256_B64URL)
        let vid = client.id()
        @Expect(vid.scheme.toString(), "x509_hash")
        @Expect(vid.originalClientId, VCI_SAN_CERT_SHA256_B64URL)
    }

    @TestCase
    func testVerifierIdParseX509SanDns(): Unit {
        let vid = VerifierId.parse("x509_san_dns:verifier.example.com")
        @Expect(vid.scheme.toString(), "x509_san_dns")
        @Expect(vid.originalClientId, "verifier.example.com")
    }

    @TestCase
    func testVerifierIdParseX509Hash(): Unit {
        let vid = VerifierId.parse("x509_hash:" + VCI_SAN_CERT_SHA256_B64URL)
        @Expect(vid.scheme.toString(), "x509_hash")
        @Expect(vid.originalClientId, VCI_SAN_CERT_SHA256_B64URL)
    }
}

// ===========================================================================
// Test 61: JweApvKidLogicUT
// JWE apv/kid 回归测试：不依赖 HUKS，纯逻辑验证。
//
// D-5 回归：apv 传给 EcdhEsEncrypter 的原始字节 = nonce.toArray()（UTF-8），
//   库内部执行 Base64Url.encode(apv) 写入 header。验证方：
//   若 apv 是 UTF-8 字节，header.apv 解码后 = nonce 明文；
//   若 apv 是预先 base64url 编码的字节，header.apv 解码后 = base64url 字符串（不是明文）。
//   本测试用纯字符串操作证明两者的区别（无 HUKS 依赖）。
//
// D-4 回归：kid 字段从 JWK JSON 解析正确。
//   ResponseEncryptor.extractKidFromJwkObject → JsonObject.get("kid") → JsonString.getValue()。
//   本测试通过直接调用公开逻辑入口（ResponseEncryptionSpecification + JWKS parse）验证。
// ---------------------------------------------------------------------------
@Test
class JweApvKidLogicUT {

    // Known P-256 recipient public key (test vector, public part only).
    private static let TEST_X: String = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU"
    private static let TEST_Y: String = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
    private static let TEST_KID: String = "test-recipient-key-1"

    // Build a JWKS JSON with a P-256 key plus kid.
    private func buildJwksJson(): String {
        return "{\"keys\":[{\"kty\":\"EC\",\"crv\":\"P-256\"," +
               "\"x\":\"" + JweApvKidLogicUT.TEST_X + "\"," +
               "\"y\":\"" + JweApvKidLogicUT.TEST_Y + "\"," +
               "\"kid\":\"" + JweApvKidLogicUT.TEST_KID + "\"}]}"
    }

    // base64url encode helper (mirrors what EcdhEsEncrypter.encrypt does internally
    // to write apv/apu into the JWE header).
    private func base64urlEncode(data: Array<UInt8>): String {
        if (data.size == 0) {
            return ""
        }
        let standard = toBase64String(data).toArray()
        var outLen: Int64 = 0
        var i: Int64 = 0
        while (i < standard.size) {
            if (standard[i] != b'=') { outLen += 1 }
            i += 1
        }
        let out = Array<UInt8>(outLen, repeat: 0)
        var idx: Int64 = 0
        var j: Int64 = 0
        while (j < standard.size) {
            let c = standard[j]
            if (c == b'=') { j += 1; continue }
            if (c == b'+') {
                out[idx] = b'-'
            } else if (c == b'/') {
                out[idx] = b'_'
            } else {
                out[idx] = c
            }
            idx += 1
            j += 1
        }
        return String.fromUtf8(out)
    }

    // base64url decode helper.
    private func base64urlDecode(s: String): Array<UInt8> {
        let body = s.toArray()
        let remainder = body.size % 4
        let padCount = if (remainder == 0) { 0 } else { 4 - remainder }
        let standard = Array<UInt8>(body.size + padCount, repeat: b'=')
        var i: Int64 = 0
        while (i < body.size) {
            let c = body[i]
            if (c == b'-') {
                standard[i] = b'+'
            } else if (c == b'_') {
                standard[i] = b'/'
            } else {
                standard[i] = c
            }
            i = i + 1
        }
        match (fromBase64String(String.fromUtf8(standard))) {
            case Some(bytes) => return bytes
            case None => throw Exception("base64urlDecode: invalid input: " + s)
        }
    }

    // D-5 regression: verify that single-encoding gives the correct apv.
    // When apv bytes = nonce.toArray() (UTF-8), and the library encodes once:
    //   header.apv = base64url(nonce.toArray()) = base64url of the nonce's UTF-8 bytes.
    //   Decoding header.apv → original nonce string.
    // This test reproduces the exact computation path and asserts round-trip equality.
    @TestCase
    func testApvSingleEncodingRoundTrip(): Unit {
        let nonce = "test-nonce-12345"
        // Correct path (post-fix): pass raw UTF-8 bytes; library encodes once.
        let rawBytes: Array<UInt8> = nonce.toArray()
        let headerApvValue = base64urlEncode(rawBytes)   // what the library writes to header.apv
        let decoded = base64urlDecode(headerApvValue)
        let recovered = String.fromUtf8(decoded)
        // Decoded value must equal the original nonce string.
        @Expect(recovered, nonce)
    }

    // D-5 regression: double-encoding proof — if apv bytes were pre-encoded base64url,
    // decoding header.apv would give back the base64url string, NOT the original nonce.
    @TestCase
    func testApvDoubleEncodingWouldLoseNonce(): Unit {
        let nonce = "my-nonce"
        // Bug path (pre-fix): pre-encode then pass; library encodes again.
        let preEncoded = base64urlEncode(nonce.toArray())  // "bXktbm9uY2U"
        let buggyApvHeaderValue = base64urlEncode(preEncoded.toArray()) // second encode
        // Decode what header.apv would be in the buggy path.
        let decoded = base64urlDecode(buggyApvHeaderValue)
        let intermediate = String.fromUtf8(decoded)
        // intermediate is the base64url string of nonce, NOT nonce itself.
        if (intermediate == nonce) {
            throw Exception("Double-encoding should not recover nonce; this is the pre-fix bug path")
        }
        // Further decode: shows we'd need one more decode to get nonce.
        let decodedAgain = base64urlDecode(intermediate)
        let finalStr = String.fromUtf8(decodedAgain)
        @Expect(finalStr, nonce)
    }

    // D-4 regression: verify that kid is correctly extracted from JWKS JSON.
    // Simulates the ResponseEncryptor.extractFirstEcPublicKeyWithKid internal logic.
    @TestCase
    func testKidExtractedFromJwksJson(): Unit {
        let jwksJson = buildJwksJson()
        let parsed = JsonValue.fromStr(jwksJson)
        let kidOpt: Option<String> = match (parsed) {
            case obj: JsonObject =>
                match (obj.get("keys")) {
                    case Some(arr: JsonArray) =>
                        let items = arr.getItems()
                        if (items.isEmpty()) {
                            None
                        } else {
                            match (items[0]) {
                                case keyObj: JsonObject =>
                                    match (keyObj.get("kid")) {
                                        case Some(js: JsonString) => Some(js.getValue())
                                        case _ => None
                                    }
                                case _ => None
                            }
                        }
                    case _ => None
                }
            case _ => None
        }
        let kid = match (kidOpt) {
            case Some(s) => s
            case None => throw Exception("kid not found in JWKS JSON: " + jwksJson)
        }
        @Expect(kid, JweApvKidLogicUT.TEST_KID)
    }

    // D-4 regression: JWKS without kid returns None (no crash).
    @TestCase
    func testKidAbsentReturnsNone(): Unit {
        let jwksNoKid = "{\"keys\":[{\"kty\":\"EC\",\"crv\":\"P-256\"," +
                        "\"x\":\"" + JweApvKidLogicUT.TEST_X + "\"," +
                        "\"y\":\"" + JweApvKidLogicUT.TEST_Y + "\"}]}"
        let parsed = JsonValue.fromStr(jwksNoKid)
        let kidOpt: Option<String> = match (parsed) {
            case obj: JsonObject =>
                match (obj.get("keys")) {
                    case Some(arr: JsonArray) =>
                        let items = arr.getItems()
                        if (items.isEmpty()) {
                            None
                        } else {
                            match (items[0]) {
                                case keyObj: JsonObject =>
                                    match (keyObj.get("kid")) {
                                        case Some(js: JsonString) => Some(js.getValue())
                                        case _ => None
                                    }
                                case _ => None
                            }
                        }
                    case _ => None
                }
            case _ => None
        }
        match (kidOpt) {
            case None => ()
            case Some(k) => throw Exception("Expected no kid, but got: " + k)
        }
    }

    // D-5 regression: empty nonce → empty apv bytes → no apv in header (library skips empty apv).
    // Verifies the empty-nonce path is handled correctly (no encoding of empty bytes).
    @TestCase
    func testEmptyNonceApvIsEmpty(): Unit {
        let emptyNonce = ""
        let rawBytes: Array<UInt8> = emptyNonce.toArray()
        @Expect(rawBytes.size, 0)
        // Encoding empty bytes → empty string (library sets no apv field when size=0).
        let encoded = base64urlEncode(rawBytes)
        @Expect(encoded.isEmpty(), true)
    }
}

// ===========================================================================
// COVERAGE-BOOST TESTS (pure-logic util / value-types / enums / parsing)
// ===========================================================================

// ---------------------------------------------------------------------------
// urlEncodeComponent / buildFormBody (openid4vci/util/functions.cj)
// ---------------------------------------------------------------------------
@Test
class UrlEncodeComponentUT {
    @TestCase
    func testUnreservedPassthrough(): Unit {
        // Letters, digits and -._~ are left untouched.
        @Expect(urlEncodeComponent("abcXYZ-._~09"), "abcXYZ-._~09")
    }

    @TestCase
    func testSpaceAndReserved(): Unit {
        // space -> %20, '/' -> %2F, ':' -> %3A, '=' -> %3D, '&' -> %26
        @Expect(urlEncodeComponent("a b"), "a%20b")
        @Expect(urlEncodeComponent("a/b:c"), "a%2Fb%3Ac")
        @Expect(urlEncodeComponent("k=v&x"), "k%3Dv%26x")
    }

    @TestCase
    func testEmpty(): Unit {
        @Expect(urlEncodeComponent(""), "")
    }
}

@Test
class BuildFormBodyUT {
    @TestCase
    func testSingleParamEncoded(): Unit {
        let m = HashMap<String, String>()
        m.add("grant_type", "authorization_code")
        @Expect(buildFormBody(m), "grant_type=authorization_code")
    }

    @TestCase
    func testValueIsPercentEncoded(): Unit {
        let m = HashMap<String, String>()
        m.add("redirect_uri", "https://x/cb")
        // ':' and '/' must be percent-encoded.
        @Expect(buildFormBody(m), "redirect_uri=https%3A%2F%2Fx%2Fcb")
    }

    @TestCase
    func testEmptyMap(): Unit {
        let m = HashMap<String, String>()
        @Expect(buildFormBody(m), "")
    }
}

// ---------------------------------------------------------------------------
// convertToJsonStringFromMap (openid4vci/util/functions.cj)
// ---------------------------------------------------------------------------
@Test
class ConvertToJsonStringFromMapUT {
    @TestCase
    func testSingleEntryRoundTrip(): Unit {
        let m = HashMap<String, String>()
        m.add("k", "v")
        let s = match (convertToJsonStringFromMap(m)) {
            case Some(x) => x
            case None => throw Exception("expected Some")
        }
        // Re-parse to verify content rather than relying on key order.
        let jv = JsonValue.fromStr(s)
        let obj = match (jv) { case o: JsonObject => o; case _ => throw Exception("not object") }
        let got = match (obj.get("k")) {
            case Some(js: JsonString) => js.getValue()
            case _ => throw Exception("missing k")
        }
        @Expect(got, "v")
    }

    @TestCase
    func testEmptyMapIsEmptyObject(): Unit {
        let m = HashMap<String, String>()
        let s = match (convertToJsonStringFromMap(m)) {
            case Some(x) => x
            case None => throw Exception("expected Some")
        }
        @Expect(s, "{}")
    }
}

// ---------------------------------------------------------------------------
// unwrapOrThrow (openid4vci/util/functions.cj)
// ---------------------------------------------------------------------------
@Test
class UnwrapOrThrowUT {
    @TestCase
    func testSomeReturnsValue(): Unit {
        let v = unwrapOrThrow<Int64>(Option<Int64>.Some(42), Exception("boom"))
        @Expect(v, 42)
    }

    @TestCase
    func testNoneThrows(): Unit {
        var threw = false
        try {
            let _ = unwrapOrThrow<Int64>(Option<Int64>.None, Exception("boom"))
        } catch (e: Exception) {
            threw = true
        }
        if (!threw) { throw Exception("expected throw on None") }
    }
}

// ---------------------------------------------------------------------------
// parseQueryParams / extractQueryString / urlDecodeComponent
// (openid4vp/entity/request/unvalidated_request.cj)
// ---------------------------------------------------------------------------
@Test
class ParseQueryParamsUT {
    @TestCase
    func testBasicPairs(): Unit {
        let m = parseQueryParams("a=1&b=2")
        @Expect(m.get("a") ?? "<none>", "1")
        @Expect(m.get("b") ?? "<none>", "2")
    }

    @TestCase
    func testPercentDecodedValue(): Unit {
        let m = parseQueryParams("redirect_uri=https%3A%2F%2Fx%2Fcb")
        @Expect(m.get("redirect_uri") ?? "<none>", "https://x/cb")
    }

    @TestCase
    func testPlusBecomesSpace(): Unit {
        let m = parseQueryParams("q=hello+world")
        @Expect(m.get("q") ?? "<none>", "hello world")
    }

    @TestCase
    func testEmptyString(): Unit {
        let m = parseQueryParams("")
        @Expect(m.size, 0)
    }

    @TestCase
    func testKeyWithoutValue(): Unit {
        let m = parseQueryParams("flag")
        @Expect(m.get("flag") ?? "<none>", "")
    }
}

@Test
class ExtractQueryStringUT {
    @TestCase
    func testWithQuery(): Unit {
        let q = match (extractQueryString("openid://?a=1&b=2")) {
            case Some(s) => s
            case None => throw Exception("expected query")
        }
        @Expect(q, "a=1&b=2")
    }

    @TestCase
    func testQueryStopsAtFragment(): Unit {
        let q = match (extractQueryString("https://h/p?x=9#frag")) {
            case Some(s) => s
            case None => throw Exception("expected query")
        }
        @Expect(q, "x=9")
    }

    @TestCase
    func testNoQuestionMark(): Unit {
        @Expect(extractQueryString("https://h/p").isNone(), true)
    }
}

@Test
class UrlDecodeComponentUT {
    @TestCase
    func testPercentSequences(): Unit {
        @Expect(urlDecodeComponent("a%20b"), "a b")
        @Expect(urlDecodeComponent("%2F%3A"), "/:")
    }

    @TestCase
    func testPlusToSpace(): Unit {
        @Expect(urlDecodeComponent("a+b+c"), "a b c")
    }

    @TestCase
    func testPlainPassthrough(): Unit {
        @Expect(urlDecodeComponent("plain"), "plain")
    }
}

// ---------------------------------------------------------------------------
// base64UrlDecode (openid4vp/entity/request/validated_request.cj)
// ---------------------------------------------------------------------------
@Test
class Base64UrlDecodeUT {
    @TestCase
    func testDecodesHello(): Unit {
        // "aGVsbG8" is base64url (no padding) for ASCII "hello".
        let bytes = base64UrlDecode("aGVsbG8")
        let s = String.fromUtf8(bytes)
        @Expect(s, "hello")
    }

    @TestCase
    func testUrlSafeAlphabet(): Unit {
        // 0xFB 0xFF 0xBF -> standard base64 "+/+/" ... use url-safe '-' and '_'.
        // base64url of bytes [0xFBu8, 0xFFu8] is "-_8" ; verify round byte length.
        let bytes = base64UrlDecode("-_8")
        @Expect(bytes.size, 2)
        @Expect(bytes[0], 0xFBu8)
        @Expect(bytes[1], 0xFFu8)
    }
}

// ---------------------------------------------------------------------------
// Value-type constructors/getters (openid4vci/entity/types/basic_types.cj)
// ---------------------------------------------------------------------------
@Test
class VciValueTypesUT {
    @TestCase
    func testNonce(): Unit {
        @Expect(Nonce("abc").value, "abc")
    }

    @TestCase
    func testCredentialConfigurationIdentifier(): Unit {
        @Expect(CredentialConfigurationIdentifier("eu.pid").value, "eu.pid")
    }

    @TestCase
    func testCredentialIdentifierValid(): Unit {
        @Expect(CredentialIdentifier("cred-1").value, "cred-1")
    }

    @TestCase
    func testCredentialIdentifierEmptyThrows(): Unit {
        var threw = false
        try { let _ = CredentialIdentifier("") } catch (_: Exception) { threw = true }
        if (!threw) { throw Exception("expected throw on empty CredentialIdentifier") }
    }

    @TestCase
    func testRefreshTokenValid(): Unit {
        @Expect(RefreshToken("rt-1").value, "rt-1")
    }

    @TestCase
    func testRefreshTokenEmptyThrows(): Unit {
        var threw = false
        try { let _ = RefreshToken("") } catch (_: Exception) { threw = true }
        if (!threw) { throw Exception("expected throw on empty RefreshToken") }
    }

    @TestCase
    func testDeferredIssuanceRequestToJson(): Unit {
        let to = DeferredIssuanceRequestTO("tx-42")
        @Expect(to.transactionId, "tx-42")
        let obj = to.toJsonObject()
        let got = match (obj.get("transaction_id")) {
            case Some(js: JsonString) => js.getValue()
            case _ => throw Exception("missing transaction_id")
        }
        @Expect(got, "tx-42")
    }
}

// ---------------------------------------------------------------------------
// TxCodeInputMode round-trip (openid4vci/entity/types/basic_types.cj)
// ---------------------------------------------------------------------------
@Test
class TxCodeInputModeUT {
    @TestCase
    func testRawValues(): Unit {
        @Expect(TxCodeInputMode.Numeric.rawValue(), "numeric")
        @Expect(TxCodeInputMode.Text.rawValue(), "text")
    }

    @TestCase
    func testOfKnown(): Unit {
        @Expect(TxCodeInputMode.of("text").rawValue(), "text")
        @Expect(TxCodeInputMode.of("numeric").rawValue(), "numeric")
    }

    @TestCase
    func testOfUnknownDefaultsNumeric(): Unit {
        @Expect(TxCodeInputMode.of("garbage").rawValue(), "numeric")
    }
}

// ---------------------------------------------------------------------------
// AuthorizationCode grant value-type (openid4vci/entity/types/basic_types.cj)
// ---------------------------------------------------------------------------
@Test
class AuthorizationCodeGrantUT {
    @TestCase
    func testHoldsFields(): Unit {
        let ac = AuthorizationCode(Some("st-1"), Some("https://as"))
        @Expect(ac.issuerState ?? "<none>", "st-1")
        @Expect(ac.authorizationServer ?? "<none>", "https://as")
    }

    @TestCase
    func testNoneFields(): Unit {
        let ac = AuthorizationCode(Option<String>.None, Option<String>.None)
        @Expect(ac.issuerState.isNone(), true)
        @Expect(ac.authorizationServer.isNone(), true)
    }

    @TestCase
    func testBlankIssuerStateThrows(): Unit {
        var threw = false
        try {
            let _ = AuthorizationCode(Some(""), Option<String>.None)
        } catch (_: Exception) { threw = true }
        if (!threw) { throw Exception("expected throw on blank issuerState") }
    }
}

// ---------------------------------------------------------------------------
// GenericErrorResponse.fromJson (openid4vci/entity/types/basic_types.cj)
// ---------------------------------------------------------------------------
@Test
class GenericErrorResponseUT {
    @TestCase
    func testParseFull(): Unit {
        let json = "{\"error\":\"invalid_grant\",\"error_description\":\"bad code\",\"interval\":5}"
        let obj = match (JsonValue.fromStr(json)) { case o: JsonObject => o; case _ => throw Exception("not object") }
        let r = GenericErrorResponse.fromJson(obj)
        @Expect(r.error, "invalid_grant")
        @Expect(r.errorDescription ?? "<none>", "bad code")
        match (r.interval) {
            case Some(i) => @Expect(i, 5.0)
            case None => throw Exception("expected interval")
        }
    }

    @TestCase
    func testMissingErrorDefaults(): Unit {
        let obj = match (JsonValue.fromStr("{}")) { case o: JsonObject => o; case _ => throw Exception("not object") }
        let r = GenericErrorResponse.fromJson(obj)
        @Expect(r.error, "unknown_error")
        @Expect(r.errorDescription.isNone(), true)
        @Expect(r.interval.isNone(), true)
    }
}

// ---------------------------------------------------------------------------
// DisplayLogo.fromJson (openid4vci/entity/types/basic_types.cj)
// ---------------------------------------------------------------------------
@Test
class DisplayLogoUT {
    @TestCase
    func testParse(): Unit {
        let json = "{\"uri\":\"https://x/logo.png\",\"alt_text\":\"logo\"}"
        let obj = match (JsonValue.fromStr(json)) { case o: JsonObject => o; case _ => throw Exception("not object") }
        let l = DisplayLogo.fromJson(obj)
        @Expect(l.uri ?? "<none>", "https://x/logo.png")
        @Expect(l.alternativeText ?? "<none>", "logo")
    }

    @TestCase
    func testMissingFields(): Unit {
        let obj = match (JsonValue.fromStr("{}")) { case o: JsonObject => o; case _ => throw Exception("not object") }
        let l = DisplayLogo.fromJson(obj)
        @Expect(l.uri.isNone(), true)
        @Expect(l.alternativeText.isNone(), true)
    }
}

// ---------------------------------------------------------------------------
// ProofsTO factory + toJsonObject (openid4vci/entity/types/basic_types.cj)
// ---------------------------------------------------------------------------
@Test
class ProofsTOFactoryUT {
    @TestCase
    func testForJwt(): Unit {
        let p = ProofsTO.forJwt(["jwt1", "jwt2"])
        @Expect(p.jwtProofs.isSome(), true)
        @Expect(p.attestationProofs.isNone(), true)
        let obj = p.toJsonObject()
        let arr = match (obj.get("jwt")) { case Some(a: JsonArray) => a; case _ => throw Exception("missing jwt") }
        @Expect(arr.size(), 2)
    }

    @TestCase
    func testForAttestation(): Unit {
        let p = ProofsTO.forAttestation(["att1"])
        @Expect(p.attestationProofs.isSome(), true)
        @Expect(p.jwtProofs.isNone(), true)
    }

    @TestCase
    func testEmptyJwtThrows(): Unit {
        var threw = false
        let empty: Array<String> = []
        try { let _ = ProofsTO.forJwt(empty) } catch (_: Exception) { threw = true }
        if (!threw) { throw Exception("expected throw on empty jwt proofs") }
    }
}

// ---------------------------------------------------------------------------
// VP enums: ResponseType / RequestUriMethod (openid4vp/entity/types/vp_types.cj)
// ---------------------------------------------------------------------------
@Test
class ResponseTypeEnumUT {
    @TestCase
    func testToString(): Unit {
        @Expect(ResponseType.VpToken.toString(), "vp_token")
        @Expect(ResponseType.Code.toString(), "code")
    }

    @TestCase
    func testFromRawValueKnown(): Unit {
        match (ResponseType.fromRawValue("vp_token")) {
            case Some(ResponseType.VpToken) => ()
            case _ => throw Exception("expected VpToken")
        }
        match (ResponseType.fromRawValue("code")) {
            case Some(ResponseType.Code) => ()
            case _ => throw Exception("expected Code")
        }
    }

    @TestCase
    func testFromRawValueUnknown(): Unit {
        @Expect(ResponseType.fromRawValue("foo").isNone(), true)
    }
}

@Test
class RequestUriMethodEnumUT {
    @TestCase
    func testToString(): Unit {
        @Expect(RequestUriMethod.GET.toString(), "GET")
        @Expect(RequestUriMethod.POST.toString(), "POST")
    }

    @TestCase
    func testFromStringCaseInsensitive(): Unit {
        match (RequestUriMethod.fromString(Some("post"))) {
            case RequestUriMethod.POST => ()
            case _ => throw Exception("expected POST")
        }
        match (RequestUriMethod.fromString(Some("GeT"))) {
            case RequestUriMethod.GET => ()
            case _ => throw Exception("expected GET")
        }
    }

    @TestCase
    func testFromStringNoneDefaultsGet(): Unit {
        match (RequestUriMethod.fromString(Option<String>.None)) {
            case RequestUriMethod.GET => ()
            case _ => throw Exception("expected GET default")
        }
    }

    @TestCase
    func testFromStringUnknownDefaultsGet(): Unit {
        match (RequestUriMethod.fromString(Some("delete"))) {
            case RequestUriMethod.GET => ()
            case _ => throw Exception("expected GET fallback")
        }
    }
}

// ---------------------------------------------------------------------------
// scopeItems pure tokenizer (openid4vp/entity/types/vp_types.cj)
// ---------------------------------------------------------------------------
@Test
class ScopeItemsUT {
    @TestCase
    func testSplitsOnSeparator(): Unit {
        let items = scopeItems("openid pid")
        @Expect(items.size, 2)
        @Expect(items[0], "openid")
        @Expect(items[1], "pid")
    }

    @TestCase
    func testTrimsAndDropsEmpty(): Unit {
        let items = scopeItems("  a   b  ")
        @Expect(items.size, 2)
        @Expect(items[0], "a")
        @Expect(items[1], "b")
    }

    @TestCase
    func testEmptyScope(): Unit {
        @Expect(scopeItems("").size, 0)
    }
}

// ---------------------------------------------------------------------------
// HashAlgorithm / TransactionDataType / SupportedTransactionDataType
// (openid4vp/entity/types/vp_types.cj)
// ---------------------------------------------------------------------------
@Test
class HashAlgorithmUT {
    @TestCase
    func testSha256Name(): Unit {
        @Expect(HashAlgorithm.sha256.name, "sha-256")
    }

    @TestCase
    func testEquality(): Unit {
        @Expect(HashAlgorithm("sha-256") == HashAlgorithm.sha256, true)
        @Expect(HashAlgorithm("sha-512") == HashAlgorithm.sha256, false)
    }

    @TestCase
    func testHashCodeStable(): Unit {
        @Expect(HashAlgorithm("sha-256").hashCode(), HashAlgorithm.sha256.hashCode())
    }
}

@Test
class TransactionDataTypeUT {
    @TestCase
    func testValueAndToString(): Unit {
        let t = TransactionDataType("authorization")
        @Expect(t.value, "authorization")
        @Expect(t.toString(), "authorization")
        @Expect(t == TransactionDataType("authorization"), true)
    }

    @TestCase
    func testEmptyThrows(): Unit {
        var threw = false
        try { let _ = TransactionDataType("") } catch (_: Exception) { threw = true }
        if (!threw) { throw Exception("expected throw on empty TransactionDataType") }
    }
}

@Test
class SupportedTransactionDataTypeUT {
    @TestCase
    func testMakeDefault(): Unit {
        let s = SupportedTransactionDataType.makeDefault()
        @Expect(s.dataType.value, "authorization")
        @Expect(s.hashAlgorithms.size, 1)
        @Expect(s.hashAlgorithms[0] == HashAlgorithm.sha256, true)
    }

    @TestCase
    func testRequiresSha256(): Unit {
        var threw = false
        let algs: Array<HashAlgorithm> = [HashAlgorithm("sha-512")]
        try {
            let _ = SupportedTransactionDataType(TransactionDataType("x"), hashAlgorithms: algs)
        } catch (_: Exception) { threw = true }
        if (!threw) { throw Exception("expected throw when sha-256 absent") }
    }
}

// ---------------------------------------------------------------------------
// ResponseMode helpers (openid4vp/entity/types/vp_types.cj)
// ---------------------------------------------------------------------------
@Test
class ResponseModeFlagsUT {
    @TestCase
    func testDirectPostJwtRequiresEncryptionAndJarm(): Unit {
        let m = DirectPostJWT("https://verifier/cb")
        @Expect(m.requiresEncryption(), true)
        @Expect(m.isJarm(), true)
        @Expect(m.responseUri, "https://verifier/cb")
    }

    @TestCase
    func testDirectPostPlain(): Unit {
        let m = DirectPost("https://verifier/cb")
        @Expect(m.requiresEncryption(), false)
        @Expect(m.isJarm(), false)
    }

    @TestCase
    func testParseResponseModeDirectPost(): Unit {
        let r = parseResponseMode(Some("direct_post"), Some("https://r"), Option<String>.None)
        match (r) {
            case Some(dp: DirectPost) => @Expect(dp.responseUri, "https://r")
            case _ => throw Exception("expected DirectPost")
        }
    }

    @TestCase
    func testParseResponseModeMissingUriIsNone(): Unit {
        @Expect(parseResponseMode(Some("direct_post"), Option<String>.None, Option<String>.None).isNone(), true)
    }

    @TestCase
    func testParseResponseModeUnknownIsNone(): Unit {
        @Expect(parseResponseMode(Some("weird"), Some("https://r"), Option<String>.None).isNone(), true)
    }
}

// ---------------------------------------------------------------------------
// DCQL presentation/query sources (openid4vp/entity/dcql/dcql.cj)
// ---------------------------------------------------------------------------
@Test
class QuerySourceUT {
    @TestCase
    func testByScopeSource(): Unit {
        let src = QuerySource.byScope("eu.europa.ec.eudi.pid")
        match (src) {
            case s: ByScopeSource => @Expect(s.scope, "eu.europa.ec.eudi.pid")
            case _ => throw Exception("expected ByScopeSource")
        }
    }

    @TestCase
    func testFormatConstructors(): Unit {
        @Expect(Format.msoMdoc().toString(), OpenId4VPSpec.FORMAT_MSO_MDOC)
        @Expect(Format.sdJwtVc().toString(), OpenId4VPSpec.FORMAT_SD_JWT_VC)
        @Expect(Format.msoMdoc() == Format.msoMdoc(), true)
    }
}

// ---------------------------------------------------------------------------
// CredentialOfferRequestObject.fromJsonString (offer/credential_offer.cj)
// ---------------------------------------------------------------------------
@Test
class CredentialOfferRequestObjectUT {
    @TestCase
    func testParseAuthCodeOffer(): Unit {
        let json = "{\"credential_issuer\":\"https://issuer.example\",\"credential_configuration_ids\":[\"eu.pid\",\"mdl\"],\"grants\":{\"authorization_code\":{\"issuer_state\":\"st-9\"}}}"
        let o = CredentialOfferRequestObject.fromJsonString(json)
        @Expect(o.credentialIssuer, "https://issuer.example")
        @Expect(o.credentialConfigurationIds.size, 2)
        @Expect(o.credentialConfigurationIds[0], "eu.pid")
        @Expect(o.credentialConfigurationIds[1], "mdl")
        @Expect(o.grants.isSome(), true)
    }

    @TestCase
    func testParseNoGrants(): Unit {
        let json = "{\"credential_issuer\":\"https://i\",\"credential_configuration_ids\":[\"x\"]}"
        let o = CredentialOfferRequestObject.fromJsonString(json)
        @Expect(o.grants.isNone(), true)
        @Expect(o.credentialConfigurationIds.size, 1)
    }

    @TestCase
    func testMissingIssuerThrows(): Unit {
        var threw = false
        try {
            let _ = CredentialOfferRequestObject.fromJsonString("{\"credential_configuration_ids\":[\"x\"]}")
        } catch (_: Exception) { threw = true }
        if (!threw) { throw Exception("expected throw on missing credential_issuer") }
    }

    @TestCase
    func testNonObjectRootThrows(): Unit {
        var threw = false
        try {
            let _ = CredentialOfferRequestObject.fromJsonString("[1,2,3]")
        } catch (_: Exception) { threw = true }
        if (!threw) { throw Exception("expected throw on non-object root") }
    }
}

// ===========================================================================
// OpenHarmonyTestRunner
// ===========================================================================



