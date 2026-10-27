/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * vp_spec.cj — OpenID4VP specification constants.
 * Ported from iOS: OpenId4VPSpec, Constants (VP side).
 */
package ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.entity.types

// ---------------------------------------------------------------------------
// OpenId4VPSpec — mirrors iOS OpenId4VPSpec
// ---------------------------------------------------------------------------

public class OpenId4VPSpec {
    public static let CLIENT_ID_SCHEME_SEPARATOR: Rune = ':'
    public static let CLIENT_ID_SCHEME_DID_WITH_SEPARATOR: String = "did:"
    public static let CLIENT_ID_SCHEME_PRE_REGISTERED: String = "pre-registered"
    public static let CLIENT_ID_SCHEME_REDIRECT_URI: String = "redirect_uri"
    public static let CLIENT_ID_SCHEME_HTTPS: String = "https"
    public static let CLIENT_ID_SCHEME_OPENID_FEDERATION: String = "openid_federation"
    public static let CLIENT_ID_SCHEME_DID: String = "decentralized_identifier"
    public static let CLIENT_ID_SCHEME_X509_SAN_DNS: String = "x509_san_dns"
    public static let CLIENT_ID_SCHEME_X509_HASH: String = "x509_hash"
    public static let CLIENT_ID_SCHEME_VERIFIER_ATTESTATION: String = "verifier_attestation"

    public static let AUTHORIZATION_REQUEST_OBJECT_TYPE: String = "oauth-authz-req+jwt"

    public static let TRANSACTION_DATA_TYPE: String = "type"
    public static let TRANSACTION_DATA_CREDENTIAL_IDS: String = "credential_ids"
    public static let TRANSACTION_DATA_HASH_ALGORITHMS: String = "transaction_data_hashes_alg"

    public static let FORMAT_MSO_MDOC: String = "mso_mdoc"
    public static let FORMAT_MSO_MDOC_ZK: String = "mso_mdoc_zk"
    public static let FORMAT_SD_JWT_VC: String = "dc+sd-jwt"
    public static let FORMAT_W3C_SIGNED_JWT: String = "jwt_vc_json"

    public static let DCQL_CREDENTIALS: String = "credentials"
    public static let DCQL_CREDENTIAL_SETS: String = "credential_sets"
    public static let DCQL_ID: String = "id"
    public static let DCQL_FORMAT: String = "format"
    public static let DCQL_META: String = "meta"
    public static let DCQL_CLAIMS: String = "claims"
    public static let DCQL_CLAIM_SETS: String = "claim_sets"
    public static let DCQL_OPTIONS: String = "options"
    public static let DCQL_REQUIRED: String = "required"
    public static let DCQL_PATH: String = "path"
    public static let DCQL_VALUES: String = "values"
    public static let DCQL_SD_JWT_VC_VCT_VALUES: String = "vct_values"
    public static let DCQL_MSO_MDOC_DOCTYPE_VALUE: String = "doctype_value"
    public static let DCQL_MSO_MDOC_NAMESPACE: String = "namespace"
    public static let DCQL_MSO_MDOC_CLAIM_NAME: String = "claim_name"
    public static let DCQL_MULTIPLE: String = "multiple"
    public static let DCQL_TRUSTED_AUTHORITIES: String = "trusted_authorities"
    public static let DCQL_REQUIRE_CRYPTOGRAPHIC_HB: String = "require_cryptographic_holder_binding"
    public static let DCQL_MSO_MDOC_INTENT_TO_RETAIN: String = "intent_to_retain"
    public static let DCQL_TRUSTED_AUTHORITY_TYPE: String = "type"
    public static let DCQL_TRUSTED_AUTHORITY_VALUES: String = "values"
    public static let DCQL_TRUSTED_AUTHORITY_TYPE_AKI: String = "aki"
    public static let DCQL_TRUSTED_AUTHORITY_TYPE_ETSI_TL: String = "etsi_tl"
    public static let DCQL_TRUSTED_AUTHORITY_TYPE_OPENID_FEDERATION: String = "openid_federation"
}

// ---------------------------------------------------------------------------
// VPConstants — mirrors iOS Constants (VP-relevant keys)
// ---------------------------------------------------------------------------

public class VPConstants {
    public static let WALLET_NONCE_FORM_PARAM: String = "wallet_nonce"
    public static let WALLET_METADATA_FORM_PARAM: String = "wallet_metadata"
    public static let CLIENT_ID: String = "client_id"
    public static let NONCE: String = "nonce"
    public static let SCOPE: String = "scope"
    public static let STATE: String = "state"
    public static let HTTPS: String = "https"
    public static let CLIENT_ID_SCHEME: String = "client_id_scheme"
    public static let DCQL_QUERY: String = "dcql_query"
    public static let VERIFIER_INFO: String = "verifier_info"
    public static let CLIENT_METADATA: String = "client_metadata"
    public static let TRANSACTION_DATA: String = "transaction_data"
    public static let RESPONSE_URI: String = "response_uri"
    public static let PRESENTATION_SUBMISSION_KEY: String = "presentation_submission"
    public static let SCOPE_SEPARATOR: String = " "
}
