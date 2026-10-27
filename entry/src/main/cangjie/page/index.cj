package ohos_app_cangjie_entry.page

import kit.ArkUI.*
import ohos.arkui.state_macro_manage.Entry
import ohos.arkui.state_macro_manage.Component
import ohos.arkui.state_macro_manage.State
import ohos.arkui.component.web.*
import ohos.web.webview.*

import kit.PerformanceAnalysisKit.Hilog
import ohos.base.*

// IssuanceDemo lives in this same `page` sub-package (issuance_demo.cj), so no
// import is needed — importing the entry main package would create a cycle.

// ---------------------------------------------------------------------------
// Interactive "Add mDoc" issuance demo, mirroring iOS ASWebAuthenticationSession:
//   tap "Add mDoc" -> run PAR -> open authorization URL in an embedded Web view
//   -> user logs in -> redirect (eu.europa.ec.euidi://) is intercepted ->
//   extract ?code= -> exchange token + request credential -> show result.
//
// Network work (PAR, token, credential) is blocking, so it is run inside
// `spawn { ... }` to keep the UI thread responsive. The onLoadIntercept
// callback only extracts the code and flips phase synchronously, then returns
// true to cancel the OS attempt to open the custom scheme.
// ---------------------------------------------------------------------------
@Entry
@Component
public class EntryView {
    // idle / authorizing / working / done / error
    @State
    var phase: String = "idle"

    @State
    var authUrl: String = ""

    @State
    var result: String = "Press \"Add mDoc\" to start issuance."

    // PKCE verifier from leg 1, replayed in leg 2. Plain field (not UI state).
    var pkceVerifier: String = ""

    private func onAddMdoc(): Unit {
        this.phase = "authorizing"
        this.result = "Starting authorization (PAR)..."
        // PAR is a blocking network call; run it off the UI thread and write
        // back the authorization URL when ready.
        spawn {
            let started = IssuanceDemo.startIssuance()
            // @State writes must happen on the UI thread; marshal back.
            spawn(UIThread) {
                if (started.ok) {
                    this.pkceVerifier = started.pkceVerifier
                    this.authUrl = started.authUrl
                    this.phase = "authorizing"
                    this.result = "Log in in the web view to continue."
                } else {
                    this.result = started.authUrl
                    this.phase = "error"
                }
            }
        }
    }

    // Called from onLoadIntercept on the UI thread once the redirect is seen.
    private func onRedirectCaptured(code: String): Unit {
        this.phase = "working"
        this.result = "Exchanging code for token + credential..."
        let verifier = this.pkceVerifier
        spawn {
            let r = IssuanceDemo.finishIssuance(code, verifier)
            spawn(UIThread) {
                this.result = r
                this.phase = "done"
            }
        }
    }

    func build() {
        Column {
            if (this.phase == "authorizing" && !this.authUrl.isEmpty()) {
                // Embedded authorization web view (iOS ASWebAuthenticationSession
                // analogue). Loads the PAR-produced authorization URL; the user
                // logs in; the redirect to the custom scheme is intercepted.
                Web(src: this.authUrl, controller: WebviewController())
                    .onLoadIntercept({ event =>
                        let url = event.data.getRequestUrl()
                        Hilog.info(0, "ISSUE-DEMO", "intercept url head=${this.head(url)}")
                        if (url.startsWith("eu.europa.ec.euidi://")) {
                            let code = IssuanceDemo.extractCode(url)
                            Hilog.info(0, "ISSUE-DEMO", "redirect captured, code len=${code.size}")
                            this.onRedirectCaptured(code)
                            // Cancel this load so the OS does not open the scheme.
                            return true
                        }
                        return false
                    })
                    .domStorageAccess(true)
                    .imageAccess(true)
                    .onlineImageAccess(true)
                    .mixedMode(MixedMode.All)
                    .width(100.percent)
                    .height(100.percent)
            } else {
                Column {
                    Button("Add mDoc")
                        .onClick({ _ => this.onAddMdoc() })
                        .fontSize(18)
                        .width(80.percent)
                        .height(50.vp)
                        .margin(top: 40.vp)
                    Text("phase: ${this.phase}")
                        .fontSize(13)
                        .margin(top: 16.vp)
                    Text(this.result)
                        .fontSize(14)
                        .width(90.percent)
                        .margin(top: 16.vp)
                }
                .width(100.percent)
                .height(100.percent)
                .justifyContent(FlexAlign.Start)
                .padding(top: 80.vp)
            }
        }
        .width(100.percent)
        .height(100.percent)
    }

    private func head(s: String): String {
        if (s.size <= 60) {
            return s
        }
        return s[0..60]
    }
}
