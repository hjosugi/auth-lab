# auth-lab ↔ Spring Security 対応表

Spring Security を使うと「動くけど中身が見えない」。auth-lab で仕組みを理解したうえで、
「それは Spring のどのクラスか」を対応づけておくと、実務にそのまま接続できる。

この表は「auth-lab のこの概念 = Spring Security のこのクラス/インターフェース」の索引。

## 認証全般

| auth-lab | Spring Security | 役割 |
|----------|-----------------|------|
| `PasswordHasher` | `PasswordEncoder` (`BCryptPasswordEncoder`, `Argon2PasswordEncoder`, `DelegatingPasswordEncoder`) | パスワードのハッシュ/検証 |
| `PasswordHasher.needs_rehash` | `PasswordEncoder.upgradeEncoding` | コスト更新の必要判定 |
| `PasswordHasher.fake_verify` | (自前実装が必要) | ユーザ列挙対策の定数時間比較 |
| ログインフロー | `AuthenticationManager` / `ProviderManager` | 認証の入口 |
| 資格情報の検証 | `AuthenticationProvider` (`DaoAuthenticationProvider`) | 実際の検証ロジック |
| ユーザ取得 | `UserDetailsService` / `UserDetails` | ユーザ情報のロード |
| 認証済み主体 | `Authentication` / `SecurityContextHolder` | スレッドローカルの認証情報 |

## MFA / パスワードレス

| auth-lab | Spring Security | 備考 |
|----------|-----------------|------|
| `authlab.mfa` (TOTP/HOTP) | 標準では非搭載（`spring-security-web` に自前 filter、または Spring Authorization Server + 拡張） | TOTP は自作か外部ライブラリ |
| `authlab.webauthn` | `spring-security-webauthn`(6.4+) / `WebAuthnAuthenticationFilter` | Passkey サポートは 6.4 で正式化 |
| `RecoveryCodes` | (自前実装) | バックアップコード |

## JWT / JOSE / リソースサーバ

| auth-lab | Spring Security | 役割 |
|----------|-----------------|------|
| `authlab.jose.JWS/JWT` | Nimbus JOSE + JWT (`spring-security-oauth2-jose`) | JWT の署名/検証 |
| `JWTValidator` | `JwtDecoder` + `OAuth2TokenValidator` (`JwtTimestampValidator`, `JwtIssuerValidator`, `JwtClaimValidator`) | クレーム検証 |
| `allowed_algorithms` 必須 | `NimbusJwtDecoder` の `jwsAlgorithms` | alg 固定 |
| `JWKSet` / `by_kid` | `JWKSource` / `RemoteJWKSet` | 鍵解決・ローテーション |
| `ResourceServer` | `oauth2ResourceServer(jwt())` / `BearerTokenAuthenticationFilter` | Bearer トークン検証 |
| `require_scope` | `@PreAuthorize("hasAuthority('SCOPE_...')")` / `JwtAuthenticationConverter` | scope→権限 |
| `require_ownership` (BOLA対策) | `@PreAuthorize` / `@PostAuthorize` + ドメイン判定 | **これは自前が必須。scope では不可** |
| introspection | `oauth2ResourceServer(opaqueToken())` / `OpaqueTokenIntrospector` | 不透明トークン |

## OAuth / OIDC クライアント・認可サーバ

| auth-lab | Spring | 役割 |
|----------|--------|------|
| `OAuthClient` (RP) | `spring-security-oauth2-client` / `OAuth2LoginAuthenticationFilter` | ログインするクライアント |
| PKCE 生成/検証 | `OAuth2AuthorizationRequestCustomizers.withPkce()` | PKCE |
| `state` 検証 | `HttpSessionOAuth2AuthorizationRequestRepository` | CSRF/state |
| `nonce`/`at_hash` | `OidcIdTokenValidator` | ID トークン検証 |
| `AuthorizationServer` | **Spring Authorization Server** (`spring-security-oauth2-authorization-server`) | 認可サーバ本体 |
| クライアント登録 | `RegisteredClient` / `RegisteredClientRepository` | クライアント設定 |
| リフレッシュ・ローテーション | `OAuth2RefreshTokenGenerator` + 設定 | リフレッシュ |
| device flow | Spring Authorization Server 1.3+ | デバイスフロー |
| DPoP | Spring Authorization Server 1.3+ / `DPoP` サポート | 送信者制約 |

## 認可モデル

| auth-lab | Spring | 役割 |
|----------|--------|------|
| `RBAC` | `hasRole` / `hasAuthority` / `RoleHierarchy` | ロール階層 |
| `ABAC` | `@PreAuthorize` + SpEL / `AuthorizationManager` | 属性ベース |
| `ReBAC` | 標準非搭載（SpiceDB / OpenFGA / Cerbos と連携） | 関係ベース |
| deny-overrides | `AuthorizationManagers.allOf` / カスタム | 合成規則 |

## エンタープライズ連携

| auth-lab | Spring | 役割 |
|----------|--------|------|
| `authlab.saml` | `spring-security-saml2-service-provider` (`Saml2WebSsoAuthenticationFilter`) | SAML SP |
| `authlab.kerberos` | `spring-security-kerberos`（別プロジェクト） | Kerberos/SPNEGO |
| `authlab.directory.ldap` | `spring-security-ldap` / `LdapAuthenticationProvider` | LDAP 認証 |
| `authlab.directory.scim` | 標準非搭載（外部 IdP / スクラッチ） | プロビジョニング |
| `authlab.mtls` | `x509()` / `X509AuthenticationFilter` + TLS 設定 | クライアント証明書 |

## 覚えておくと強い対応

1. **`ResourceServer` の 8 ステップ**（署名→typ→iss→aud→exp→送信者制約→scope→所有権）は、
   Spring では「`JwtDecoder` + `OAuth2TokenValidator` の連鎖」＋「`@PreAuthorize` でのドメイン判定」に分かれる。
   最後の所有権判定を Spring が自動でやってくれないことを理解しているのが実務での差。

2. **BOLA/IDOR** は Spring でも `SCOPE_` の権限チェックだけでは防げない。
   `@PostAuthorize("returnObject.owner == authentication.name")` のような**明示的な所有者チェック**が要る。

3. **alg 固定**は `NimbusJwtDecoder.withPublicKey(...).signatureAlgorithm(RS256)` のように必ず指定する。
   auth-lab が「許可リスト必須・デフォルトなし」にしているのと同じ理由。
