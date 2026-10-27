package ohos_app_cangjie_entry

import std.unittest.*
import std.unittest.testmacro.*
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

import eudi_lib_core_crypto.EcdsaP256

// ---------------------------------------------------------------------------
// Live, two-run OpenID4VCI authorization-code issuance against the real EUDI
// dev issuer (https://issuer.eudiw.dev). Mirrors the iOS EudiWalletKit flow:
//   step 1: discover + Pushed Authorization Request -> print authorization URL.
//           (the user logs in interactively in a browser; the redirect carries
//           a one-time ?code=...).
//   step 2: paste that code into AUTH_CODE below, recompile, run -> exchange the
//           code for an access token (+ c_nonce) and request the PID credential
//           with a real proof-of-possession JWT.
//
// PKCE and state are FIXED CONSTANTS so the verifier created in step 1's PAR is
// identical to the verifier replayed in step 2's token call across two separate
// process runs. Do not randomize them.
// ---------------------------------------------------------------------------
@Test
class IssueLiveUT {
    private static let ISSUER = "https://issuer.eudiw.dev"
    private static let CLIENT_ID = "wallet-dev"
    private static let REDIRECT = "eu.europa.ec.euidi://authorization"
    private static let SCOPE = "eu.europa.ec.eudi.pid_mso_mdoc"
    private static let CONFIG_ID = "eu.europa.ec.eudi.pid_mso_mdoc"

    // Fixed PKCE (RFC 7636, 43+ chars, url-safe alphabet) and fixed state. The
    // code_challenge is derived (S256) from CODE_VERIFIER at runtime so the two
    // runs always agree.
    private static let CODE_VERIFIER =
        "eudi-live-fixed-verifier-0123456789-abcdefghijklmnop"
    private static let STATE = "issue-live-fixed-state-0001"

    // Paste the real ?code= value from the browser redirect here, then recompile
    // and run testStep2_tokenAndCredential. Empty string => step 2 self-skips.
    private static let AUTH_CODE = ""

    // Safe ASCII-byte prefix for logging (avoids multibyte slice surprises).
    private static func head(s: String, n: Int64): String {
        let b = s.toArray()
        if (b.size <= n) {
            return s
        }
        return String.fromUtf8(b[0..n])
    }

    private static func fixedPkce(): PKCEVerifier {
        let challenge = PKCEGenerator.generateCodeChallenge(IssueLiveUT.CODE_VERIFIER)
        return PKCEVerifier(IssueLiveUT.CODE_VERIFIER, challenge, "S256")
    }

    private static func makeConfig(): OpenId4VCIConfig {
        return OpenId4VCIConfig(
            Client(ClientKind.Public(IssueLiveUT.CLIENT_ID)),
            IssueLiveUT.REDIRECT,
            AuthorizeIssuanceConfig.FavorScopes,
            ParUsage.Required(true),
            IssuerMetadataPolicy.IgnoreSigned,
            false
        )
    }

    // -----------------------------------------------------------------------
    // Step 1 — discover + PAR, print the authorization URL for browser login.
    // -----------------------------------------------------------------------
    @TestCase
    func testStep1_PAR_printAuthUrl(): Unit {
        var lastErr = "none"
        var attempt = 0
        while (attempt < 3) {
            try {
                let credMeta = CredentialIssuerMetadataResolver()
                    .resolve(CredentialIssuerId(IssueLiveUT.ISSUER), IssuerMetadataPolicy.IgnoreSigned)
                let asMeta = AuthorizationServerMetadataResolver()
                    .resolve(IssueLiveUT.ISSUER)

                let config = IssueLiveUT.makeConfig()
                let asc = AuthorizationServerClient(
                    config, asMeta, credMeta.credentialIssuerIdentifier,
                    Option<DPoPConstructorType>.None
                )

                let par = asc.submitPushedAuthorizationRequestWithPkce(
                    [Scope(IssueLiveUT.SCOPE)],
                    Array<CredentialConfigurationIdentifier>(),
                    IssueLiveUT.STATE,
                    Option<String>.None,
                    Option<String>.Some(IssueLiveUT.ISSUER),
                    IssueLiveUT.fixedPkce(),
                    Option<Nonce>.None,
                    2
                )
                let url = par.authorizationCodeURL.url
                Hilog.info(0, "ISSUE-LIVE", "AUTHURL=${url}")
                Hilog.info(0, "ISSUE-LIVE",
                    "Open AUTHURL in a browser, log in, copy ?code= from the redirect into AUTH_CODE, recompile, run step2.")
                @Assert(url.contains("request_uri"), true)
                @Assert(url.startsWith(IssueLiveUT.ISSUER), true)
                return
            } catch (e: Exception) {
                lastErr = "${e}"
                Hilog.error(1, "ISSUE-LIVE", "step1 attempt=${attempt} EXC: ${lastErr}")
            }
            attempt = attempt + 1
        }
        @Assert("step1-par-failed: " + lastErr, "ok")
    }

    // -----------------------------------------------------------------------
    // Step 2 — exchange AUTH_CODE for a token (+ c_nonce) and request the
    // credential with a real proof-of-possession JWT.
    // -----------------------------------------------------------------------
    @TestCase
    func testStep2_tokenAndCredential(): Unit {
        if (IssueLiveUT.AUTH_CODE.isEmpty()) {
            Hilog.info(0, "ISSUE-LIVE",
                "SKIP step2: AUTH_CODE is empty. Run step1, log in, paste the redirect ?code= into AUTH_CODE, recompile.")
            @Assert(true, true)
            return
        }

        try {
            let credMeta = CredentialIssuerMetadataResolver()
                .resolve(CredentialIssuerId(IssueLiveUT.ISSUER), IssuerMetadataPolicy.IgnoreSigned)
            let asMeta = AuthorizationServerMetadataResolver()
                .resolve(IssueLiveUT.ISSUER)
            let config = IssueLiveUT.makeConfig()

            let asc = AuthorizationServerClient(
                config, asMeta, credMeta.credentialIssuerIdentifier,
                Option<DPoPConstructorType>.None
            )

            // 1) Token exchange (public client, no client_secret; replay fixed verifier).
            let tokenResult = asc.requestAccessTokenAuthFlow(
                IssueLiveUT.AUTH_CODE,
                IssueLiveUT.CODE_VERIFIER,
                Array<CredentialConfigurationIdentifier>(),
                Option<Nonce>.None,
                2
            )
            let at = tokenResult.accessToken.accessToken
            let atPreview = IssueLiveUT.head(at, 12)
            Hilog.info(0, "ISSUE-LIVE", "TOKEN ok len=${at.size} prefix=${atPreview}")

            // 2) c_nonce (from a dedicated nonce endpoint if the issuer advertises one).
            let nonceClientOpt: Option<NonceEndpointClient> = match (credMeta.nonceEndpoint) {
                case Some(ep) => Option<NonceEndpointClient>.Some(NonceEndpointClient(ep))
                case None => Option<NonceEndpointClient>.None
            }
            let cNonceOpt: Option<String> = match (nonceClientOpt) {
                case Some(nc) =>
                    let nr = nc.getNonce()
                    Hilog.info(0, "ISSUE-LIVE", "C_NONCE obtained from nonce endpoint")
                    Option<String>.Some(nr.cNonce.cNonce)
                case None =>
                    Hilog.info(0, "ISSUE-LIVE", "no nonce endpoint advertised; proof built without c_nonce")
                    Option<String>.None
            }

            // 3) Build a real proof-of-possession JWT with an in-memory device key.
            let deviceKey = EcdsaP256.generate()
            let requester = IssuanceRequester(credMeta, Option<DPoPConstructorType>.None)
            let proofJwt = requester.buildJwtProof(
                deviceKey,
                "ES256",
                config.client.id(),
                credMeta.credentialIssuerIdentifier.url,
                cNonceOpt
            )
            let proofPreview = IssueLiveUT.head(proofJwt, 60)
            Hilog.info(0, "ISSUE-LIVE", "PROOF jwt len=${proofJwt.size} head=${proofPreview}")

            // 4) Credential request (uses metadata credential_endpoint, which may be a
            //    different host than the issuer, e.g. backend.issuer.eudiw.dev).
            Hilog.info(0, "ISSUE-LIVE", "CRED endpoint=${credMeta.credentialEndpoint.url}")
            let payload = IssuanceRequestPayload.ConfigurationBased(
                CredentialConfigurationIdentifier(IssueLiveUT.CONFIG_ID)
            )
            let credResp = requester.placeIssuanceRequest(
                tokenResult.accessToken,
                CredentialConfigurationIdentifier(IssueLiveUT.CONFIG_ID),
                [Proof.JwtProof(proofJwt)],
                payload,
                tokenResult.dPopNonce,
                2
            )

            var printed = false
            for (item in credResp.credentialResponses) {
                match (item) {
                    case IssuedCredential.Issued(_, cred, _) =>
                        match (cred.asString()) {
                            case Some(s) =>
                                let credHead = IssueLiveUT.head(s, 80)
                                Hilog.info(0, "ISSUE-LIVE", "CREDENTIAL[0..80]=${credHead}")
                                printed = true
                            case None =>
                                Hilog.info(0, "ISSUE-LIVE", "CREDENTIAL is JSON object (non-string)")
                                printed = true
                        }
                    case IssuedCredential.Deferred(txId, _) =>
                        Hilog.info(0, "ISSUE-LIVE", "DEFERRED transaction_id=${txId.value}")
                        printed = true
                }
            }
            @Assert(printed, true)
        } catch (e: Exception) {
            Hilog.error(1, "ISSUE-LIVE", "step2 EXC: ${e}")
            @Assert("step2-failed: ${e}", "ok")
        }
    }
}
