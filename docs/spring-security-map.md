# Spring Securityへの対応表

このラボで中身を追った後、本番実装ではSpring Securityの検証済み機能へ置き換えます。
独自JWT validatorや独自OAuth Authorization Serverを本番に持ち込まないことが原則です。

[Java 21 / Spring Security companion](https://github.com/hjosugi/auth-lab/tree/main/spring-companion)では、
この表のissuer、audience、token type、scope、object ownershipを実際の
`SecurityFilterChain`、validator、method security、回帰テストへ写経しています。

| ラボ概念 | Spring Security / 関連製品 | 本番で明示する設定 |
|---|---|---|
| Password hash | `PasswordEncoder`, `DelegatingPasswordEncoder` | algorithm ID、cost、upgrade方針 |
| Login/session | `SecurityFilterChain`, `SessionManagementConfigurer` | fixation protection、cookie、CSRF |
| TOTP/MFA | Authentication provider + IdP/MFA product | assurance level、recovery、rate limit |
| JWT resource server | `oauth2ResourceServer().jwt()` | issuer-uri、audience validator、clock skew |
| Opaque token | `oauth2ResourceServer().opaqueToken()` | introspection auth、cache、fail closed |
| OAuth client/OIDC login | `oauth2Login()`, `OAuth2AuthorizedClientManager` | state/nonce/PKCE、redirect registration |
| Authorization Server | Spring Authorization Server | consent、client auth、token lifecycle、keys |
| Method auth | `@EnableMethodSecurity`, `@PreAuthorize` | object ownershipを引数から評価 |
| RBAC | `GrantedAuthority`, role hierarchy | role prefix、階層、default deny |
| ABAC | AuthorizationManager / SpEL / policy service | attribute source、deny precedence、audit |
| ReBAC | external relationship service | consistency、cycle/depth、list objects |
| SAML SP | `saml2Login()` | relying-party metadata、credentials、clock skew |
| LDAP | `ldapAuthentication()`, Spring LDAP | TLS、bind account、safe filter、pool |
| mTLS | servlet container + X.509 auth | trust store、SAN mapping、revocation |
| CSRF | `CsrfConfigurer` | browser cookie authでは原則有効 |
| CORS | `CorsConfigurationSource` | allowed origin/method/headerを最小化 |
| Security headers | `headers()` | CSP、HSTS、frame policy |

## JWT Resource Serverの思考順序

1. `issuer-uri`で信頼するissuerを固定する。
2. JWKS取得先をissuer metadataに結びつける。
3. algorithmを許可リスト化する。
4. API固有のaudience validatorを追加する。
5. scope/authority変換を明示する。
6. method/object level authorizationを別途行う。
7. key rotation、metadata outage、clock skew時の挙動をテストする。

## ありがちな誤解

- `authenticated()`はobject ownershipを保証しない。
- `hasRole("ADMIN")`だけではtenant境界を保証しない。
- JWTがdecodeできることとsignatureがvalidであることは別。
- signatureがvalidであることとissuer/audience/timeがvalidであることも別。
- CORSは認証・認可ではなく、ブラウザのcross-origin read制御。
- CSRFを無効化してよいのは「JWTだから」ではなく、credential送信方法と
  ブラウザ挙動を分析した結果で決める。
