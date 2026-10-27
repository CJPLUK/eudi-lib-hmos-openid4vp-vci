# eudi_lib_openid4vp_vci

Cangjie (HarmonyOS) port of the two OpenID protocol libraries the EUDI Wallet needs,
merged into one cjpm module:

- **OpenID4VCI** (credential issuance) — modelled on
  [eudi-lib-ios-openid4vci-swift](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-openid4vci-swift)
- **OpenID4VP / SIOPv2** (credential presentation) — modelled on
  [eudi-lib-ios-siop-openid4vp-swift](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-siop-openid4vp-swift)

Cangjie 包名 `ohos_app_cangjie_eudi_cjopenid4vp_vci`(模块目录 `eudi_cjopenid4vp_vci`)。
bundleName `eu.europa.ec.eudi.openid4vp.vci`。源码:`openid4vci/`(VCI,36 文件)+ `openid4vp/`(VP,20 文件)。

> 逐函数对照 iOS 两库迁移;密码学/JOSE/x509/SD-JWT 一律复用已交付库,不重造。被 wallet-kit 消费。

---

## 能力

### VCI(签发)
- **入口 resolver**:`openid-credential-offer://` URI 解析(passByValue / fetchByReference)+ 自动抓取
  `/.well-known/openid-credential-issuer` 与 `/.well-known/oauth-authorization-server` metadata
  (`CredentialOfferRequestResolver` / `CredentialIssuerMetadataResolver` /
  `AuthorizationServerMetadataResolver` / `MetadataFetcher`,含 signed-metadata 策略)
- **授权**:PAR + auth-code flow、pre-authorized_code flow(tx_code 校验)、refresh token
- **PKCE**(S256)、**DPoP**(含 ath,真 ES256 签名)
- **Nonce endpoint**(c_nonce)
- **Credential request**:proof JWT(JwtKey,真 ES256)、multi-proof(batch)
- **Credential response**:JWE 解密(ECDH-ES + A256GCM)、deferred、notify
- **Credential 格式配置**:mso_mdoc / SD-JWT VC / W3C(JWT、JSON-LD)
- **Client attestation PoP JWT**(真 ES256 JWS,拒绝对称算法)
- **Credential reuse policy**(model + validator)、**Key Attestation JWT**(model)
- **DEFLATE**(`util/deflate.cj`,基于 stdx.compress.zlib)用于 credential response/request 压缩协商

### VP(展示)
- **请求解析**:request_uri(GET)、JWT-by-value、JWT-by-reference;client_id_scheme 全 7 变体 → Client
- **DCQL**:CredentialQuery / ClaimsQuery(claimSets)/ CredentialSetQuery / ClaimPath(3 类 element)/
  TrustedAuthority(3 类)+ uniqueness 校验
- **ResolvedRequestData** 构建、**TransactionData**(base64url JSON 往返)、**VerifierInfo**
- **响应**:vp_token / id_token / presentation_submission、Consensus → AuthorizationResponse
- **响应加密**(direct_post.jwt / JARM):真 JWE,复用 jose `EcdhEsEncrypter`
- **Dispatch**:direct_post / direct_post.jwt / query / fragment;ErrorDispatcher;DispatchOutcome

---

## 复用(非自造密码学/JOSE/x509)

| 能力 | 复用库 |
|---|---|
| JWE ECDH-ES 加/解密 | `ohos_app_cangjie_eudi_cjjose`(EcdhEsEncrypter / EcdhEsDecrypter / EcPublicKey) |
| JWS ES256(DPoP / proof / attestation PoP / response) | `eudi_cjjose.JoseJws.signEs256` |
| Base64Url / Rng / Digest(PKCE) / Jws | `eudi_lib_core_crypto` |
| JSON / HTTP / DEFLATE | `stdx.encoding.json` / `stdx.net.http` / `stdx.compress.zlib` |
| x509 / SD-JWT VC | `eudi_cjx509` / `eudi_cjsdjwt`(配置层声明;解包由消费方做) |

cjpm.toml `[dependencies]`:`eudi_lib_core_crypto` / `ohos_app_cangjie_eudi_cjjose` /
`ohos_app_cangjie_eudi_cjx509` / `ohos_app_cangjie_eudi_cjsdjwt`(均 path dep,置于同级 `third_party/`);
stdx 走 `entry/libs/stdx` path-option。

---

## 降级 / 已知限制(行为正确,fail-fast,已对照 iOS)

| 降级项 | 处置 | iOS 对应 | 评定 |
|---|---|---|---|
| BindingKey **x509 / DID** proof 生成 | throw `CryptographicBindingMethodNotSupported`(诚实失败) | SecKey/CMS、DID resolve | 合理:EUDI 主流程用 JwtKey(JWK) |
| **RSA-OAEP** JWE | 仅 ECDH-ES + A256GCM;RSA 系列不支持 | JOSESwift RSA | 合理:EUDI 规范用 ECDH-ES |
| VP **JWT-secured request 签名验证** | 结构 parse,未做 JWS 验签 | JOSEController verify | 已知降级,后续补 |
| VP **x509 cert chain 验证 / DID resolution** | 未实现 | X509 trust / DID lookup | 已知降级 |
| **PresentationDefinition / InputDescriptor** | 不实现(仅 DCQL) | iOS 本身已废弃,仅留 DCQL | 与 iOS 同步,正确 |
| iOS `async/await` + Actor | 全部同步 + class | Swift Concurrency | 平台合理重塑 |
| Swift `Codable` 自动编解码 | 手写 `stdx.encoding.json` parse | Codable | 平台合理重塑 |

> 上述均为 Reviewer 能力级审计判定的"合理省略/平台重塑"。Reviewer 原判"不可交付"的两项阻断缺口
> **GAP-01(VCI 入口 resolver)** 与 **GAP-02(DEFLATE)** 已在返修轮实现(见上"能力"),不再是缺口。

---

## 新建(Cangjie 新增,iOS 无直接对应)

- `network/http_client.cj` / `http_types.cj` — 独立 HTTP 层(iOS 用 URLSession 内联)
- `util/deflate.cj` — DEFLATE 解压封装(基于 stdx.compress.zlib)
- 各子包锚文件(`*.cj` 占位 package 根,满足 S-003 根包需可编译源)
- DPoP nonce 重试以递归替代 iOS 的 Task retry

---

## 测试

`entry` 内含 **48 个 `@Test` 类**(OpenHarmonyTestRunner),覆盖 VCI(27)+ VP(21)全部公开能力接口:
PKCE/DPoP、credential offer 与 metadata resolver、grants、token 参数、proof JWT、credential 格式、
client attestation PoP(含对称算法拒绝)、DEFLATE 往返、DCQL/ClaimPath、ResponseMode 各变体、
TransactionData 往返、vp_token form params、ResponseEncryptor JWE、dispatch outcome 等。
模拟器 `aa test`(bundle `eu.europa.ec.eudi.openid4vp.vci`)**全过,ResultCode: 0**。

## 依赖消费(external_repo_module)

clone 本仓到 `third_party/eudi_lib_openid4vp_vci`,把 `eudi_lib_core_crypto` / `eudi_lib_jose` /
`eudi_lib_x509` / `eudi_lib_sdjwt` 置于同级 `third_party/`;消费方 `cjpm.toml [dependencies]` 加
`ohos_app_cangjie_eudi_cjopenid4vp_vci = { path = "../third_party/eudi_lib_openid4vp_vci/eudi_cjopenid4vp_vci" }`。
