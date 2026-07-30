# auth-lab ドキュメント

認証・認可プロトコルを**ゼロから実装して**理解するためのラボ。解説本文は日本語、
コード内コメントとインタビュー用スクリプトは英語で統一している。

## ブラウザで試す

[**GitHub Pages の playground**](https://hjosugi.github.io/auth-lab/) —
JWT デコード、TOTP 生成、PKCE、パスワードハッシュ、ReBAC チェックなどを
**ブラウザ内で本物の暗号処理**（Web Crypto API）で動かせる。ローカルでも
`docs/index.html` を開けば動く。

## ドキュメント一覧

### プロトコル解説（日本語）
- [01 - 土台: パスワード・MFA・セッション](01_foundations.md)
- [02 - JOSE / OAuth 2.0 + Security BCP / OIDC](02_jose_oauth_oidc.md)
- [03 - SAML 2.0](03_saml.md)
- [04 - Kerberos](04_kerberos.md)
- [05 - WebAuthn / passkeys](05_webauthn.md)
- [06 - mTLS と DPoP（送信者制約）](06_mtls_dpop.md)
- [07 - LDAP と SCIM](07_ldap_scim.md)
- [08 - 認可モデル: RBAC / ABAC / ReBAC](08_authz.md)

### 図で見る
- [図集（全プロトコルのシーケンス図・構造図）](diagrams.md) — OAuth/OIDC/SAML/Kerberos/WebAuthn/DPoP/mTLS のフロー図

### リファレンス
- [09 - 攻撃対応表（CWE / OWASP マッピング）](09_attack_matrix.md)
- [10 - Spring Security 対応表](10_spring_security_map.md)
- [11 - 14日ドリル計画](11_14day_plan.md)
- [12 - 面接用スクリプト（英語）](12_interview_english.md)
- [13 - 参考サイト・仕様一覧](13_references.md)

## リポジトリ構成

```
authlab/          実装本体（Python 標準ライブラリのみ、pip install 不要）
  util/           base64url, 定数時間比較, クロック
  crypto/         RSA, ECDSA(P-256/384/521), Ed25519, AES, CBOR, X.509 CA
  passwords/      scrypt/PBKDF2/Argon2id パスワードハッシュ
  mfa/            HOTP/TOTP, リカバリコード
  jose/           JWS/JWT/JWKS
  oauth/          認可サーバ, リソースサーバ, クライアント, DPoP
  saml/           SAML SP/IdP, XML-DSig
  kerberos/       KDC, クライアント, サービス
  webauthn/       認証器, リライングパーティ, COSE
  mtls/           相互TLS（本物のTLSハンドシェイク）
  directory/      LDAP, SCIM
  authz/          RBAC, ABAC, ReBAC
  server.py       curl で叩ける HTTP デモサーバ
drills/           13本の自己検証ドリル（run_all.py で一括）
attacks/          攻撃カタログ（素朴実装が破れる→authlabは防ぐ）
tests/            unittest（RFC 8032/6979/9106 ベクタ含む）
docs/             このドキュメント + playground
```

## 動かし方

```bash
# 依存なし。Python 3.11+ 標準ライブラリのみ
python drills/run_all.py                    # 全プロトコルが緑になるのを見る
python -m unittest discover -s tests        # 全unittest
PYTHONPATH=. python attacks/catalog.py      # 攻撃カタログ
python -m authlab.server                    # OAuth/OIDC サーバを起動 (:8080)
```

## 設計方針

- **Spring Security を使わない**。使うと「動くけど中身が見えない」。
  トークンに触れる全ての行を読める状態にするため、あえて全部スクラッチ。
- **検証可能**。RFC 4226/6238 の公式テストベクタ、FIPS-197、RFC 8949 に一致。
  RFC 8032/6979/9106 の署名・KDFベクタ、W3C exc-c14n の re-enveloping 例にも一致する。
  X.509 は `openssl verify`、SAML 署名は任意の `xmlsec1` 双方向チェックを通り、
  mTLS は本物の TLS ハンドシェイクで動く。
- **依存なしを維持**。Argon2id は読み解くための低コスト純Python経路を持つ。
  本番コストを使う場合だけ `argon2-cffi` を任意で利用し、未導入でもラボ全体は動く。
- **攻撃を実演する**。「防げる」と書くだけでなく、素朴な実装で破ってから authlab で防ぐ。
