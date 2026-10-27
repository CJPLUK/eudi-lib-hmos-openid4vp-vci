/*
 * network_live_test.cj — Real-network unit tests against the EUDI reference
 * issuer (https://issuer.eudiw.dev).
 *
 * These exercise the network/resolver layer end-to-end over real HTTPS:
 *   - HttpFetcher.fetch / fetchRawWithHeaders
 *   - CredentialIssuerMetadataResolver.resolve
 *   - AuthorizationServerMetadataResolver.resolve
 *   - FetchError path on a 404 well-known
 *
 * Robustness: the EU domain's DNS via the emulator upstream resolver is
 * occasionally slow / transiently fails, so each network case retries up to
 * 3 times (returns on first success) to avoid flakiness.
 *
 * Out of scope (require OAuth code / access token / DPoP + user interaction):
 *   requestCredential / placeIssuanceRequest / token exchange.
 */
package ohos_app_cangjie_eudi_cjopenid4vp_vci_local_test

import std.unittest.*
import std.unittest.testmacro.*
import std.collection.HashMap
import kit.PerformanceAnalysisKit.Hilog

import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.network.{HttpFetcher, FetchError, RawFetchResponse}
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.resolver.{
    CredentialIssuerMetadataResolver, AuthorizationServerMetadataResolver
}
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.issuer.{CredentialIssuerId, CredentialIssuerMetadata}
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.config.IssuerMetadataPolicy
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.access_mgmt.IdentityAndAccessManagementMetadata

let ISSUER_BASE = "https://issuer.eudiw.dev"
let ISSUER_METADATA_URL = "https://issuer.eudiw.dev/.well-known/openid-credential-issuer"

@Test
class NetworkLiveTest {

    // ---------------------------------------------------------------------
    // 1. HttpFetcher.fetch — GET issuer metadata, body contains credential_issuer
    // ---------------------------------------------------------------------
    @TestCase
    func testFetchIssuerMetadataBody() {
        var lastErr = "none"
        var i = 0
        while (i < 3) {
            try {
                let fetcher = HttpFetcher()
                let bytes = fetcher.fetch(ISSUER_METADATA_URL)
                let body = String.fromUtf8(bytes)
                Hilog.info(0, "NET", "fetch len=${bytes.size}")
                @Expect(bytes.size > 0, true)
                @Expect(body.contains("\"credential_issuer\""), true)
                @Expect(body.contains(ISSUER_BASE), true)
                return
            } catch (e: Exception) {
                lastErr = "${e}"
                Hilog.error(1, "NET", "fetch attempt=${i} EXC: ${lastErr}")
            }
            i = i + 1
        }
        @Expect("fetch-failed: ${lastErr}", "ok")
    }

    // ---------------------------------------------------------------------
    // 2. HttpFetcher.fetchRawWithHeaders — with Accept header, status success + data
    // ---------------------------------------------------------------------
    @TestCase
    func testFetchRawWithHeaders() {
        var lastErr = "none"
        var i = 0
        while (i < 3) {
            try {
                let fetcher = HttpFetcher()
                let headers = HashMap<String, String>()
                headers.add("Accept", "application/json")
                // fetchRawWithHeaders throws FetchError unless 2xx, so reaching
                // here already implies a success status.
                let resp: RawFetchResponse = fetcher.fetchRawWithHeaders(ISSUER_METADATA_URL, headers)
                Hilog.info(0, "NET", "raw data=${resp.data.size} headers=${resp.headers.size}")
                @Expect(resp.data.size > 0, true)
                let body = String.fromUtf8(resp.data)
                @Expect(body.contains("\"credential_issuer\""), true)
                return
            } catch (e: Exception) {
                lastErr = "${e}"
                Hilog.error(1, "NET", "raw attempt=${i} EXC: ${lastErr}")
            }
            i = i + 1
        }
        @Expect("fetchRaw-failed: ${lastErr}", "ok")
    }

    // ---------------------------------------------------------------------
    // 3. CredentialIssuerMetadataResolver.resolve — full resolve + assertions
    // ---------------------------------------------------------------------
    @TestCase
    func testResolveCredentialIssuerMetadata() {
        var lastErr = "none"
        var i = 0
        while (i < 3) {
            try {
                let resolver = CredentialIssuerMetadataResolver()
                let issuerId = CredentialIssuerId(ISSUER_BASE)
                let meta: CredentialIssuerMetadata = resolver.resolve(issuerId, IssuerMetadataPolicy.IgnoreSigned)

                Hilog.info(0, "NET", "resolved issuer=${meta.credentialIssuerIdentifier.url}")
                @Expect(meta.credentialIssuerIdentifier.url, ISSUER_BASE)
                @Expect(meta.credentialEndpoint.url.size > 0, true)
                @Expect(meta.credentialEndpoint.url.startsWith("https://"), true)

                // batch_credential_issuance.batch_size == 100
                let batch = meta.batchCredentialIssuance
                @Expect(!batch.isNone(), true)
                @Expect(batch.getOrThrow().batchSize, 100)

                // credential_configurations_supported contains a known config id
                @Expect(meta.credentialConfigurationsRaw.contains("eu.europa.ec.eudi.cor_mdoc"), true)
                @Expect(meta.credentialConfigurationsRaw.size > 0, true)
                return
            } catch (e: Exception) {
                lastErr = "${e}"
                Hilog.error(1, "NET", "resolve-issuer attempt=${i} EXC: ${lastErr}")
            }
            i = i + 1
        }
        @Expect("resolve-issuer-failed: ${lastErr}", "ok")
    }

    // ---------------------------------------------------------------------
    // 4. AuthorizationServerMetadataResolver.resolve — token/authz endpoints https
    // ---------------------------------------------------------------------
    @TestCase
    func testResolveAuthorizationServerMetadata() {
        var lastErr = "none"
        var i = 0
        while (i < 3) {
            try {
                let resolver = AuthorizationServerMetadataResolver()
                let iam: IdentityAndAccessManagementMetadata = resolver.resolve(ISSUER_BASE)

                let token = iam.tokenEndpoint()
                let authz = iam.authorizationEndpoint()
                Hilog.info(0, "NET", "as token-none=${token.isNone()} authz-none=${authz.isNone()}")

                @Expect(!token.isNone(), true)
                @Expect(!authz.isNone(), true)
                let tokenUrl = token.getOrThrow()
                let authzUrl = authz.getOrThrow()
                @Expect(tokenUrl.size > 0, true)
                @Expect(authzUrl.size > 0, true)
                @Expect(tokenUrl.startsWith("https://"), true)
                @Expect(authzUrl.startsWith("https://"), true)
                return
            } catch (e: Exception) {
                lastErr = "${e}"
                Hilog.error(1, "NET", "resolve-as attempt=${i} EXC: ${lastErr}")
            }
            i = i + 1
        }
        @Expect("resolve-as-failed: ${lastErr}", "ok")
    }

    // ---------------------------------------------------------------------
    // 5. Error path — 404 well-known must throw FetchError (InvalidStatusCode)
    // ---------------------------------------------------------------------
    @TestCase
    func testFetch404ThrowsFetchError() {
        let badUrl = "https://issuer.eudiw.dev/.well-known/does-not-exist"
        var lastErr = "none"
        var i = 0
        while (i < 3) {
            try {
                let fetcher = HttpFetcher()
                fetcher.fetch(badUrl)
                // Reaching here means no throw — unexpected for a 404 endpoint.
                Hilog.error(1, "NET", "404 attempt=${i} UNEXPECTED success")
                lastErr = "expected FetchError but fetch returned normally"
            } catch (fe: FetchError) {
                // Expected: non-2xx status surfaces as FetchError.
                Hilog.info(0, "NET", "404 got FetchError: ${fe}")
                @Expect(true, true)
                return
            } catch (e: Exception) {
                // A different exception type (e.g. transient network) — retry.
                lastErr = "non-FetchError exception: ${e}"
                Hilog.error(1, "NET", "404 attempt=${i} EXC: ${lastErr}")
            }
            i = i + 1
        }
        @Expect("404-no-fetcherror: ${lastErr}", "ok")
    }
}
