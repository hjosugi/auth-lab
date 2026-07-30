# 参考サイト・仕様一覧

auth-lab を作るのに実際に参照した一次情報と、学習に使える良サイト。
「まず一次情報（RFC/仕様）、詰まったら解説サイト」の順で当たるのがおすすめ。

## 一次仕様 (RFC / W3C / OASIS)

### OAuth / OIDC
- [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749) — OAuth 2.0 本体
- [RFC 6819](https://datatracker.ietf.org/doc/html/rfc6819) — OAuth 2.0 脅威モデル
- [RFC 9700](https://datatracker.ietf.org/doc/html/rfc9700) — **OAuth Security BCP**（「結局どうすべきか」の決定版）
- [draft-ietf-oauth-v2-1](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1) — OAuth 2.1
- [RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636) — PKCE
- [RFC 8628](https://datatracker.ietf.org/doc/html/rfc8628) — デバイスフロー
- [RFC 7662](https://datatracker.ietf.org/doc/html/rfc7662) / [RFC 7009](https://datatracker.ietf.org/doc/html/rfc7009) — introspection / revocation
- [RFC 8414](https://datatracker.ietf.org/doc/html/rfc8414) — AS メタデータ
- [RFC 8707](https://datatracker.ietf.org/doc/html/rfc8707) — Resource Indicators
- [RFC 9068](https://datatracker.ietf.org/doc/html/rfc9068) — JWT アクセストークン (`at+jwt`)
- [RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449) — **DPoP**
- [RFC 8705](https://datatracker.ietf.org/doc/html/rfc8705) — mTLS クライアント認証 & 証明書束縛トークン
- [RFC 9126](https://www.rfc-editor.org/rfc/rfc9126) — PAR（Pushed Authorization Requests）
- [RFC 9101](https://www.rfc-editor.org/rfc/rfc9101) — JAR（JWT-Secured Authorization Request）
- [RFC 9396](https://www.rfc-editor.org/rfc/rfc9396) — RAR（Rich Authorization Requests）
- [JARM Final](https://openid.net/specs/oauth-v2-jarm-final.html) — 署名付き認可response
- [CIBA Core 1.0 Final](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0-final.html) — backchannel認証
- [FAPI 2.0 Security Profile Final](https://openid.net/specs/fapi-security-profile-2_0.html) — confidential client、PAR、sender constraint
- [FAPI 2.0 Message Signing Final](https://openid.net/specs/fapi-message-signing-2_0.html) — JAR/JARM/signed introspection
- [RFC 9701](https://www.rfc-editor.org/rfc/rfc9701) — JWT Token Introspection Response
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html) — OIDC
- [OpenID Connect Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html)

### JOSE
- [RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515) JWS / [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519) JWT
- [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517) JWK / [RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518) JWA
- [RFC 7638](https://datatracker.ietf.org/doc/html/rfc7638) JWK Thumbprint
- [RFC 8725](https://datatracker.ietf.org/doc/html/rfc8725) — **JWT BCP**（alg=none 等の対策）

### MFA / パスワードレス
- [RFC 4226](https://datatracker.ietf.org/doc/html/rfc4226) HOTP / [RFC 6238](https://datatracker.ietf.org/doc/html/rfc6238) TOTP（テストベクタ付き）
- [W3C WebAuthn Level 2](https://www.w3.org/TR/webauthn-2/)
- [FIDO2 CTAP 2.1](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html)
- [passkeys.dev](https://passkeys.dev/) — 実装者向けのまとめ

### 暗号
- [RFC 8017](https://datatracker.ietf.org/doc/html/rfc8017) — PKCS#1 (RSA)
- [RFC 6979](https://datatracker.ietf.org/doc/html/rfc6979) — 決定的 ECDSA nonce
- [FIPS 186-4](https://csrc.nist.gov/publications/detail/fips/186/4/final) — DSA/ECDSA, P-256
- [FIPS 197](https://csrc.nist.gov/publications/detail/fips/197/final) — AES
- [RFC 7914](https://datatracker.ietf.org/doc/html/rfc7914) — scrypt
- [RFC 8018](https://datatracker.ietf.org/doc/html/rfc8018) — PBKDF2
- [RFC 8949](https://datatracker.ietf.org/doc/html/rfc8949) — CBOR

### エンタープライズ
- [SAML 2.0 Core](https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf) / [W3C XML-DSig](https://www.w3.org/TR/xmldsig-core/)
- [W3C Exclusive XML Canonicalization 1.0](https://www.w3.org/TR/xml-exc-c14n/) / [相互運用レポート](https://www.w3.org/Signature/2002/02/01-exc-c14n-interop.html)
- [RFC 4120](https://datatracker.ietf.org/doc/html/rfc4120) — Kerberos v5 / [RFC 3962](https://datatracker.ietf.org/doc/html/rfc3962) — AES enctypes
- [RFC 4511](https://datatracker.ietf.org/doc/html/rfc4511) LDAP / [RFC 4515](https://datatracker.ietf.org/doc/html/rfc4515) フィルタ
- [RFC 7643](https://datatracker.ietf.org/doc/html/rfc7643) / [RFC 7644](https://datatracker.ietf.org/doc/html/rfc7644) — SCIM 2.0

### 認可
- [Google Zanzibar 論文](https://research.google/pubs/pub48190/) — ReBAC の原典
- [X.509 / RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280)

## 学習に使える良サイト

### 総合・体系
- [oauth.net](https://oauth.net/2/) — Aaron Parecki による OAuth の定番ハブ
- [oauth.com](https://www.oauth.com/) — 無料書籍「OAuth 2.0 Simplified」
- [OpenID: How Connect Works](https://openid.net/developers/how-connect-works/)
- [Auth0 Docs](https://auth0.com/docs) / [Okta Developer](https://developer.okta.com/) — 実装視点の解説が丁寧

### インタラクティブ / ツール
- [jwt.io](https://jwt.io/) — JWT デバッガ（このラボの JWT タブはその自己完結版）
- [webauthn.io](https://webauthn.io/) / [webauthn.guide](https://webauthn.guide/) — passkey を実際に試せる
- [PortSwigger Web Security Academy](https://portswigger.net/web-security) — OAuth/JWT/SAML の**無料ハンズオンラボ**（最推し）

### セキュリティ / 攻撃
- [OWASP API Security Top 10 (2023)](https://owasp.org/API-Security/editions/2023/en/0x11-t10/) — BOLA/BFLA
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/) — 認証・セッション・パスワード保存・JWT
- [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/) — 検証基準
- [HackTricks](https://book.hacktricks.xyz/) — Kerberos/AD 攻撃の実務リファレンス（Kerberoasting, golden ticket, DCSync）
- [The Hacker Recipes](https://www.thehacker.recipes/) — AD 攻撃を体系的に

### 深掘り読み物
- 「On Breaking SAML: Be Whoever You Want to Be」(Somorovsky et al., USENIX 2012) — XSW の原典
- 「Hardening Persona」/ 各種 JWT アルゴリズム混同の解説記事
- [latacora: A Child's Garden of Inter-Service Authentication Schemes](https://latacora.micro.blog/2018/06/12/a-childs-garden.html)
- [latacora: How (not) to sign a JSON object](https://latacora.micro.blog/2019/07/24/how-not-to.html)

## 日本語で読める良記事
- [IPA / 各種認証ガイドライン](https://www.ipa.go.jp/security/)
- [OpenID Foundation Japan の翻訳仕様](https://www.openid.or.jp/)
- 各社技術ブログ（OAuth/OIDC/passkey 導入記）は「一次仕様で裏を取る」前提で読むと良い
