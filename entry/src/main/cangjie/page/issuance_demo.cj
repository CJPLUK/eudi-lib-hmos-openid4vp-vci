package ohos_app_cangjie_entry.page

// ---------------------------------------------------------------------------
// issuance_demo.cj — backend helpers for the interactive "Add mDoc" demo page.
//
// Mirrors the iOS ASWebAuthenticationSession flow: the page opens the
// authorization URL in an embedded ArkUI Web component, the user logs in, the
// redirect (eu.europa.ec.euidi://authorization?code=...) is intercepted, and
// the one-time code is exchanged for a token + PID credential.
//
// This file lives in the `page` sub-package alongside index.cj but, crucially,
// does NOT import `kit.ArkUI.*` (which would pollute bare `None`/`Option` and
// break the lib's Option usage). Keeping the ArkUI wildcard out of this file
// lets the VCI lib types compile cleanly. index.cj calls IssuanceDemo.* in the
// same package, so there is no cross-package cycle with ohos_app_cangjie_entry
// (the entry main package imports page.EntryView, so page must not import it
// back).
//
// The full backend chain is lifted from issue_live_suite.cj (IssueLiveUT).
// ---------------------------------------------------------------------------

import std.collection.*
import kit.PerformanceAnalysisKit.Hilog

import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.config.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.types.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.access.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.issuer.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.issuance.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.issuance.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.resolver.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.dpop.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.pkce.*

import eudi_lib_core_crypto.{EcdsaP256, Rng, Base64Url}
import ohos_app_cangjie_eudi_cjjose.jose.EcPublicKey
import stdx.crypto.keys.ECDSAPrivateKey

/**
 * Result of the first leg (PAR). Carries the authorization URL the Web
 * component must load, plus the PKCE verifier that has to be replayed in the
 * token call. `ok=false` means PAR failed and `authUrl` holds the error text.
 */
public class StartIssuanceResult {
    public let ok: Bool
    public let authUrl: String
    public let pkceVerifier: String

    public init(ok: Bool, authUrl: String, pkceVerifier: String) {
        this.ok = ok
        this.authUrl = authUrl
        this.pkceVerifier = pkceVerifier
    }
}

public class IssuanceDemo {
    public static let ISSUER = "https://issuer.eudiw.dev"
    public static let CLIENT_ID = "wallet-dev"
    public static let REDIRECT = "eu.europa.ec.euidi://authorization"
    public static let SCOPE = "eu.europa.ec.eudi.pid_mdoc"
    public static let CONFIG_ID = "eu.europa.ec.eudi.pid_mdoc"
    public static let STATE = "issue-live-fixed-state-0001"

    // The DPoP key must be the SAME across PAR (leg 1) and token (leg 2): eudiw
    // binds the authorization-code session to the DPoP key. Generated in
    // startIssuance, replayed in finishIssuance. (Single issuance at a time.)
    private static var dpopKey: Option<ECDSAPrivateKey> = Option<ECDSAPrivateKey>.None

    // Build a DPoPConstructor (ES256) wrapping the given private key, mirroring
    // iOS DPoPConstructor used for authorizationCodeDPoPBinding.
    private static func makeDpop(key: ECDSAPrivateKey): DPoPConstructorType {
        let pubPoint = EcdsaP256.publicKeyUncompressedOf(key)
        let ecPub = EcPublicKey.fromHuksUncompressed(pubPoint)
        return DPoPConstructor("ES256", ecPub, key)
    }

    private static func head(s: String, n: Int64): String {
        let b = s.toArray()
        if (b.size <= n) {
            return s
        }
        return String.fromUtf8(b[0..n])
    }

    private static func makeConfig(): OpenId4VCIConfig {
        return OpenId4VCIConfig(
            Client(ClientKind.Public(IssuanceDemo.CLIENT_ID)),
            IssuanceDemo.REDIRECT,
            AuthorizeIssuanceConfig.FavorScopes,
            ParUsage.Required(true),
            IssuerMetadataPolicy.IgnoreSigned,
            false
        )
    }

    /**
     * Extract the `code` query parameter from a redirect URL such as
     * `eu.europa.ec.euidi://authorization?code=XYZ&state=...`. Returns "" if
     * absent. Hand-rolled so we do not depend on a URL parser in the page.
     */
    public static func extractCode(redirectUrl: String): String {
        let qIdx = redirectUrl.indexOf("?")
        let query = match (qIdx) {
            case Some(i) => redirectUrl[(i + 1)..]
            case None => redirectUrl
        }
        for (pair in query.split("&")) {
            let eqIdx = pair.indexOf("=")
            match (eqIdx) {
                case Some(j) =>
                    let key = pair[0..j]
                    if (key == "code") {
                        // The code is percent-encoded in the redirect query (the
                        // Fernet token's `=` padding becomes %3D). It MUST be URL-
                        // decoded before going into the token form body, otherwise
                        // it is double-encoded and the issuer rejects it (HTTP 500
                        // 'NoneType' has no session_id). Verified against eudiw.
                        return IssuanceDemo.urlDecode(pair[(j + 1)..])
                    }
                case None => ()
            }
        }
        return ""
    }

    // Minimal percent-decoder for redirect query values: %XX -> byte, '+' -> space.
    private static func urlDecode(s: String): String {
        let bytes = s.toArray()
        let out = ArrayList<UInt8>()
        var i = 0
        func hex(c: UInt8): Int64 {
            if (c >= b'0' && c <= b'9') { return Int64(c - b'0') }
            if (c >= b'A' && c <= b'F') { return Int64(c - b'A') + 10 }
            if (c >= b'a' && c <= b'f') { return Int64(c - b'a') + 10 }
            return -1
        }
        while (i < bytes.size) {
            let c = bytes[i]
            if (c == b'%' && i + 2 < bytes.size) {
                let hi = hex(bytes[i + 1]); let lo = hex(bytes[i + 2])
                if (hi >= 0 && lo >= 0) {
                    out.add(UInt8(hi * 16 + lo)); i += 3; continue
                }
            }
            if (c == b'+') { out.add(b' ') } else { out.add(c) }
            i += 1
        }
        return String.fromUtf8(out.toArray())
    }

    /**
     * Leg 1 — discover + Pushed Authorization Request. Produces the
     * authorization URL the user must open, and the freshly generated PKCE
     * verifier that leg 2 must replay. Blocking network I/O: callers should run
     * this off the UI thread (spawn) or accept a brief first-tap stall.
     */
    public static func startIssuance(): StartIssuanceResult {
        try {
            let credMeta = CredentialIssuerMetadataResolver()
                .resolve(CredentialIssuerId(IssuanceDemo.ISSUER), IssuerMetadataPolicy.IgnoreSigned)
            let asMeta = AuthorizationServerMetadataResolver()
                .resolve(IssuanceDemo.ISSUER)

            let config = IssuanceDemo.makeConfig()
            let asc = AuthorizationServerClient(
                config, asMeta, credMeta.credentialIssuerIdentifier,
                Option<DPoPConstructorType>.None
            )

            // Direct (non-PAR) authorization: the ENTIRE authorization request
            // (incl. the initial GET with all params) happens inside the Web
            // component, so the issuer session is consistent end-to-end. With PAR
            // the native client created the request_uri in a different session
            // than the WebView that consumed it, which broke /oidc/token
            // ('NoneType' has no session_id). Fresh random state (iOS parity).
            let freshState = "wallet-" + Base64Url.encode(Rng.bytes(12))
            let (pkce, authCodeUrl) = asc.authorizationRequestUrl(
                [Scope(IssuanceDemo.SCOPE)],
                Array<CredentialConfigurationIdentifier>(),
                freshState,
                Option<String>.None
            )
            let url = authCodeUrl.url
            Hilog.info(0, "ISSUE-DEMO", "AUTHURL=${url}")
            return StartIssuanceResult(true, url, pkce.codeVerifier)
        } catch (e: Exception) {
            Hilog.error(1, "ISSUE-DEMO", "startIssuance EXC: ${e}")
            return StartIssuanceResult(false, "startIssuance failed: ${e}", "")
        }
    }

    /**
     * Leg 2 — exchange the intercepted `code` for an access token (+ c_nonce),
     * build a real proof-of-possession JWT with an in-memory EcdsaP256 device
     * key, and request the PID credential. Returns a human-readable result
     * string (credential preview or error). Blocking network I/O.
     */
    public static func finishIssuance(authCode: String, codeVerifier: String): String {
        if (authCode.isEmpty()) {
            return "finishIssuance: empty authorization code"
        }
        try {
            let credMeta = CredentialIssuerMetadataResolver()
                .resolve(CredentialIssuerId(IssuanceDemo.ISSUER), IssuerMetadataPolicy.IgnoreSigned)
            let asMeta = AuthorizationServerMetadataResolver()
                .resolve(IssuanceDemo.ISSUER)
            let config = IssuanceDemo.makeConfig()

            // Replay the SAME DPoP key used in the PAR leg (eudiw binds the
            // authorization-code session to it; without it /oidc/token 500s).
            let dpopOpt: Option<DPoPConstructorType> = match (IssuanceDemo.dpopKey) {
                case Some(k) => Option<DPoPConstructorType>.Some(IssuanceDemo.makeDpop(k))
                case None => Option<DPoPConstructorType>.None
            }
            let asc = AuthorizationServerClient(
                config, asMeta, credMeta.credentialIssuerIdentifier,
                dpopOpt
            )

            // 1) Token exchange (public client; replay the PKCE verifier).
            let tokenResult = asc.requestAccessTokenAuthFlow(
                authCode,
                codeVerifier,
                Array<CredentialConfigurationIdentifier>(),
                Option<Nonce>.None,
                2
            )
            let at = tokenResult.accessToken.accessToken
            Hilog.info(0, "ISSUE-DEMO", "TOKEN ok len=${at.size}")

            // 2) Optional c_nonce from a dedicated nonce endpoint.
            let nonceClientOpt: Option<NonceEndpointClient> = match (credMeta.nonceEndpoint) {
                case Some(ep) => Option<NonceEndpointClient>.Some(NonceEndpointClient(ep))
                case None => Option<NonceEndpointClient>.None
            }
            let cNonceOpt: Option<String> = match (nonceClientOpt) {
                case Some(nc) =>
                    let nr = nc.getNonce()
                    Option<String>.Some(nr.cNonce.cNonce)
                case None => Option<String>.None
            }

            // 3) Real proof-of-possession JWT with an in-memory device key.
            let deviceKey = EcdsaP256.generate()
            let requester = IssuanceRequester(credMeta, Option<DPoPConstructorType>.None)
            let proofJwt = requester.buildJwtProof(
                deviceKey,
                "ES256",
                config.client.id(),
                credMeta.credentialIssuerIdentifier.url,
                cNonceOpt
            )
            Hilog.info(0, "ISSUE-DEMO", "PROOF jwt len=${proofJwt.size}")

            // 4) Credential request.
            let payload = IssuanceRequestPayload.ConfigurationBased(
                CredentialConfigurationIdentifier(IssuanceDemo.CONFIG_ID)
            )
            let credResp = requester.placeIssuanceRequest(
                tokenResult.accessToken,
                CredentialConfigurationIdentifier(IssuanceDemo.CONFIG_ID),
                [Proof.JwtProof(proofJwt)],
                payload,
                tokenResult.dPopNonce,
                2
            )

            for (item in credResp.credentialResponses) {
                match (item) {
                    case IssuedCredential.Issued(_, cred, _) =>
                        match (cred.asString()) {
                            case Some(s) =>
                                let credHead = IssuanceDemo.head(s, 120)
                                Hilog.info(0, "ISSUE-DEMO", "CREDENTIAL issued")
                                return "mDoc issued OK\ncredential[0..120]:\n${credHead}"
                            case None =>
                                return "mDoc issued OK (credential is a JSON object)"
                        }
                    case IssuedCredential.Deferred(txId, _) =>
                        return "Issuance deferred. transaction_id=${txId.value}"
                }
            }
            return "Credential response empty"
        } catch (e: Exception) {
            Hilog.error(1, "ISSUE-DEMO", "finishIssuance EXC: ${e}")
            return "finishIssuance failed: ${e}"
        }
    }
}
