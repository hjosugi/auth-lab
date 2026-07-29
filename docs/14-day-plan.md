# 14日で認証・認可を身体に入れる計画

毎日60〜90分を想定します。読むだけではなく、必ず「値を一つ変えて失敗させる」
ところまで行います。

| Day | テーマ | 実行 | 手で壊す | 説明できるゴール |
|---:|---|---|---|---|
| 1 | Password KDF | Drill 1 | salt/work factor/password | 暗号化とhashの違い |
| 2 | HOTP/TOTP | Drill 2 | counter/time/window | なぜreplay cacheが要るか |
| 3 | JWS/JWT/JWKS | Drill 3 | alg/kid/iss/aud/exp | 署名検証だけで足りない理由 |
| 4 | OAuth code + PKCE | Drill 4 | state/verifier/redirect | 各束縛の攻撃者モデル |
| 5 | Refresh rotation | Drill 5 | 古いrefresh token再利用 | family revokeの意味 |
| 6 | Client Credentials | Drill 6 | client secret/scope | user delegationとの違い |
| 7 | Device Grant | Drill 7 | polling interval/user code | TV/CLIのUXとphishing |
| 8 | Introspection/Revoke | Drill 8 | active/expiry/revoke | opaqueとJWTのtradeoff |
| 9 | RBAC/ABAC/ReBAC | Drill 9 | role/attribute/tuple | IDORをどこで止めるか |
| 10 | SAML | Drill 10 | audience/ACS/assertion count | XML署名wrappingの本質 |
| 11 | Kerberos | Drill 11 | realm/service/time/replay | TGTとservice ticket |
| 12 | WebAuthn | Drill 12 | challenge/origin/rpIdHash | phishing耐性の出所 |
| 13 | mTLS/DPoP | Drill 13 | x5t/jkt/htm/htu/ath | bearerとPoPの差 |
| 14 | LDAP/SCIM/HMAC | Drill 14 | filter/ETag/nonce | identity lifecycle全体 |

## 毎日の型

```text
10分: シーケンス図を書き直す
20分: 対応モジュールを一行ずつ追う
20分: 正常系を実行し、中間値を表示する
20分: bindingを一つ壊し、拒否理由を予想する
10分: 「資産・攻撃者・信頼境界・防御」を声に出す
```

## 最終試験

次を資料なしで説明できれば合格です。

- OAuthとOIDCの違い、ID TokenとAccess Tokenの読み手
- PKCE、state、nonce、audienceがそれぞれ何を束縛するか
- JWT署名が正しくても拒否すべき5つの例
- SAMLとOIDCのtrust bootstrapとreplay対策
- Kerberosでパスワードがserviceへ渡らない仕組み
- WebAuthnがshared secretを使わずphishingへ強い理由
- RBAC/ABAC/ReBACの使い分けとIDOR対策
- mTLS/DPoPがBearer token theftをどう狭めるか
- LDAP/SCIMで退職者のアクセスを確実に止める流れ

