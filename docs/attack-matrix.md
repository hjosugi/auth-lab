# 攻撃・設計ミス・防御の対応表

この表は防御観点のチェックリストです。`attacks/run_regressions.py`は外部へ通信せず、
危険な入力がローカル実装で拒否されることを確認します。

| 失敗パターン | 壊れる信頼 | 必須防御 | ラボ |
|---|---|---|---|
| Passwordの平文/高速hash | DB漏えい後の総当たり耐性 | salt + memory-hard KDF + work factor | `passwords.py` |
| Username存在で早期return | アカウント存在の秘匿 | dummy hash、同じ応答 | `PasswordStore` |
| OTP再利用 | freshness | counter記録、短い窓、rate limit | `TotpVerifier` |
| JWT `alg=none` | 署名方式 | verifier側でalg固定 | attack regression |
| HS/RS algorithm confusion | 鍵の型 | algとkey typeを固定 | `jose.py` |
| `jku`/`jwk`注入 | key trust | allowlisted JWKS、embedded key拒否 | attack regression |
| iss/aud未検証 | 発行者・用途 | exact issuer/audience | `verify_jwt` |
| redirect URI前方一致 | code配送先 | exact match | attack regression |
| stateなし | browser request binding | 予測不能state、一回性 | attack regression |
| PKCEなし/`plain` | code所持者 | S256必須 | `oauth.py` |
| code replay | 一回性 | used状態、短寿命、family revoke | Drill 4 |
| refresh token再利用 | session継続権 | rotation + reuse detection | Drill 5 |
| ID TokenをAPIで受理 | token用途 | type/audience分離 | docs/tests |
| SAML wrapping | 検証対象XML | 署名したAssertionだけ読む | attack regression |
| SAML replay | Assertion一回性 | ID cache、NotOnOrAfter | `saml.py` |
| Kerberos replay | authenticator freshness | timestamp + nonce cache | `kerberos.py` |
| WebAuthn phishing origin | RP binding | origin + rpIdHash検証 | attack regression |
| cloned authenticator | credential integrity | signCount異常を検知 | `webauthn.py` |
| Bearer token窃取 | token所持 | TLS、短寿命、mTLS/DPoP | Drill 13 |
| DPoP replay/substitution | request/key binding | htm/htu/iat/jti/ath/nonce/jkt | `dpop.py` |
| LDAP injection | query構造 | filter escape、安全API | `directory.py` |
| SCIM lost update | lifecycle整合性 | ETag/If-Match | `SCIMService` |
| IDOR/BOLA | object authorization | objectごとにsubject/action評価 | authorization tests |
| roleだけをUIで隠す | server-side enforcement | API側でdefault deny | `authorization.py` |
| HMAC request replay | HTTP request freshness | timestamp + nonce cache | `http_auth.py` |

## 検証順序

1. 入力サイズ、形式、許可アルゴリズムを絞る。
2. 信頼するkey/issuer/metadataをローカル設定から選ぶ。
3. 暗号学的完全性を検証する。
4. issuer、audience、client、redirect、origin、RP IDを束縛する。
5. expiry、not-before、iat、clock skewを検証する。
6. state、nonce、jti、code、ticket IDの一回性を検証する。
7. subjectに対するobject-level authorizationを評価する。
8. 失敗理由はログへ残し、外部応答は情報を出しすぎない。

