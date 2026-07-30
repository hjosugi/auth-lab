# Spring Security companion

`auth-lab` で読める形にした検証順序を、Java 21 / Spring Boot 4.1 /
Spring Security 7.1 の構成へ対応付ける companion application です。
Python ラボの置き換えではなく、本番向けライブラリへ移るときの写経先です。

## 実行と検証

Java 21 と Maven 3.6.3 以上を使います。

```bash
mvn --file spring-companion/pom.xml verify
mvn --file spring-companion/pom.xml spring-boot:run
```

起動そのものは外部通信を行いません。既定値は loopback の fixture issuer を指し、
秘密値は意図的に無効な `change-me` です。実際の OIDC login または opaque token
introspection を試す場合だけ、次の環境変数をローカルの検証用 IdP に合わせます。
実 credential をこのリポジトリへ保存しないでください。

| 環境変数 | 信頼境界 |
|---|---|
| `AUTHLAB_ISSUER` | JWT、ID Token、opaque tokenで一致必須のissuer |
| `AUTHLAB_AUDIENCE` | resource serverが受理するaudience |
| `AUTHLAB_JWK_SET_URI` | JWT access token用の固定JWKS endpoint |
| `AUTHLAB_INTROSPECTION_URI` | opaque tokenの検証先 |
| `AUTHLAB_INTROSPECTION_CLIENT_ID`, `AUTHLAB_INTROSPECTION_CLIENT_SECRET` | introspection client認証 |
| `AUTHLAB_AUTHORIZATION_URI`, `AUTHLAB_TOKEN_URI`, `AUTHLAB_OIDC_JWK_SET_URI`, `AUTHLAB_USERINFO_URI` | OIDC client endpoint |
| `AUTHLAB_OIDC_CLIENT_ID`, `AUTHLAB_OIDC_CLIENT_SECRET` | OIDC client登録 |
| `AUTHLAB_ALLOWED_ORIGIN` | browser APIを読める唯一のorigin |
| `SESSION_COOKIE_SECURE` | HTTPSでは`true`。loopback HTTPの手動試験時だけ`false` |

## 検証の対応

| auth-labの検証項目 | companionの実装 |
|---|---|
| algorithm allowlist | JWT access tokenとOIDC ID Tokenを`RS256`へ固定 |
| issuer | `JwtIssuerValidator`。opaque tokenもintrospection結果の`iss`を比較 |
| audience | `JwtAudienceValidator`。ID Tokenはclient ID、opaque tokenは`aud`を比較 |
| token type | JWTは`typ=at+jwt`、opaque tokenは`token_type=access_token`を必須化 |
| expiry | `JwtTimestampValidator`で`exp`必須、clock skewは60秒 |
| scope | `@PreAuthorize`で`SCOPE_documents.read/write`を要求 |
| object ownership | `DocumentOwnership`でsubjectとdocument ownerを比較 |
| rotation / outage | ローカルJWKS serverを使う`JwkRotationAndOutageTest` |

`/api/jwt/**` と `/api/opaque/**` は別の `SecurityFilterChain` ですが、
同じ `DocumentService` のmethod securityへ到達します。したがってtoken形式を
変えてもscopeとobject ownershipの境界は迂回できません。

## Threat model

### OIDC browser session

OIDC login後の`JSESSIONID`はブラウザが自動送信するcredentialです。攻撃者のorigin
から状態変更リクエストを送られるCSRFを想定し、browser chainではCSRFを有効のまま
保ちます。認証成功時はsession IDを変更し、cookieは`HttpOnly`、`Secure`、
`SameSite=Lax`にします。`Secure`を無効化するのはloopback HTTPの手動学習時だけです。

### Stateless bearer APIs

API credentialはcookieではなく`Authorization: Bearer` headerで明示送信し、
server sessionを作りません。この前提に限定してAPI chainのCSRFを無効化します。
将来cookie認証を追加する場合はこの判断を再利用せず、CSRFを有効化します。

CORSは認証・認可ではありません。許可origin、method、headerを最小化し、
credential付きcross-origin requestを禁止します。非ブラウザclientや同一originの
攻撃をCORSで防げるとは扱いません。

### Issuer metadata、鍵rotation、障害

resource serverとOIDC clientはendpointを明示するため、起動時のissuer metadata
取得へ依存しません。その代わりissuer比較を独立したvalidatorで必須化し、取得先と
信頼するissuerを別々に固定します。JWT decoderは既知の鍵をcacheできるため、
JWKS一時障害中も既知`kid`は検証できます。未知`kid`はfail closedにし、endpoint
復旧後の新しい`kid`だけをrotationとして受理します。

Opaque tokenは毎回introspectionするため、失効を直ちに反映できますが、
authorization server障害時はfail closedになります。availabilityのためのcacheを
追加するなら、失効遅延とTTLを別途設計・テストする必要があります。

## Pythonラボとの分離

Python側にはJava依存を追加していません。従来どおり次だけで、Spring companionを
buildせずに標準ライブラリのラボをすべて検証できます。

```bash
python scripts/verify.py
```

このcompanionも構成例とローカル回帰のための教材です。fixture設定のまま公開したり、
レビューなしで本番の認証境界へ転用したりしないでください。
