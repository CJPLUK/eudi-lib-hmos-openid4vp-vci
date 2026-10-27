/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * dispatch_outcome.cj — VP dispatch result type.
 * Block 5 scope.
 *
 * Ported from iOS: Main/Services/DispatchOutcome.swift.
 * iOS enum with associated values → Cangjie sealed class hierarchy.
 */
package ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.service

// ---------------------------------------------------------------------------
// DispatchOutcome — mirrors iOS DispatchOutcome
// ---------------------------------------------------------------------------

public abstract sealed class DispatchOutcome {
    public static func accepted(redirectUri!: Option<String>): AcceptedOutcome {
        AcceptedOutcome(redirectUri)
    }
    public static func rejected(reason!: String): RejectedOutcome {
        RejectedOutcome(reason)
    }
}

public class AcceptedOutcome <: DispatchOutcome {
    // Optional redirect URI returned by verifier
    public let redirectUri: Option<String>
    public init(redirectUri: Option<String>) {
        this.redirectUri = redirectUri
    }
}

public class RejectedOutcome <: DispatchOutcome {
    public let reason: String
    public init(reason: String) { this.reason = reason }
}
