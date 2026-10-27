package ohos_app_cangjie_entry

import std.unittest.*
import std.unittest.testmacro.*
import std.collection.*
import kit.PerformanceAnalysisKit.Hilog

import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.config.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.types.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.issuer.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.issuance.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.issuance.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.resolver.*
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.dpop.*

// Live end-to-end HTTP chain against the real EUDI dev issuer, up to the point
// the wallet can reach without interactive browser login (same path iOS runs):
//   discover issuer metadata (GET) -> discover AS metadata (GET) -> Pushed
//   Authorization Request (POST). A successful PAR returns an authorization URL
//   embedding request_uri; the next step (user login at the authorization
//   endpoint) is interactive and identical to iOS.
@Test
class ParLiveUT {
    private static let ISSUER = "https://issuer.eudiw.dev"

    @TestCase
    func testDiscoverAndPushAuthorizationRequest(): Unit {
        var lastErr = "none"
        var attempt = 0
        while (attempt < 3) {
            try {
                let credMeta = CredentialIssuerMetadataResolver()
                    .resolve(CredentialIssuerId(ParLiveUT.ISSUER), IssuerMetadataPolicy.IgnoreSigned)
                let asMeta = AuthorizationServerMetadataResolver()
                    .resolve(ParLiveUT.ISSUER)

                let config = OpenId4VCIConfig(
                    Client(ClientKind.Public("wallet-dev")),
                    "eu.europa.ec.euidi://authorization",
                    AuthorizeIssuanceConfig.FavorScopes,
                    ParUsage.Required(true),
                    IssuerMetadataPolicy.IgnoreSigned,
                    false
                )
                let asc = AuthorizationServerClient(
                    config, asMeta, credMeta.credentialIssuerIdentifier,
                    Option<DPoPConstructorType>.None
                )
                let par = asc.submitPushedAuthorizationRequest(
                    [Scope("eu.europa.ec.eudi.pid_mso_mdoc")],
                    Array<CredentialConfigurationIdentifier>(),
                    "state-eudi-live",
                    Option<String>.None,
                    Option<String>.Some("https://issuer.eudiw.dev"),
                    Option<Nonce>.None,
                    2
                )
                let url = par.authorizationCodeURL.url
                Hilog.info(0, "PAR-LIVE", "OK authz url=${url}")
                // PAR succeeded: the authorization URL embeds the request_uri.
                @Assert(url.contains("request_uri"), true)
                @Assert(url.startsWith("https://issuer.eudiw.dev"), true)
                return
            } catch (e: Exception) {
                lastErr = "${e}"
                Hilog.error(1, "PAR-LIVE", "attempt=${attempt} EXC: ${lastErr}")
            }
            attempt = attempt + 1
        }
        @Assert("par-failed: " + lastErr, "ok")
    }
}
