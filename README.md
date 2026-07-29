# auth-lab 🔐

認証・認可プロトコルを**ゼロから実装して**「からだにたたきこむ」ためのラボ。
Python 標準ライブラリのみ（`pip install` 不要）。

> **なぜスクラッチか**: Spring Security などを使うと「動くけど中身が見えない」。
> トークンに触れる全ての行を読める状態にするため、あえて全部自前で書いた。
> 各ファイルは一気に読み切れる長さで、なぜその検証が要るかをコメントに書いてある。

## ▶ ブラウザで試す

**[playground（GitHub Pages）](https://hjosugi.github.io/auth-lab/)** — JWT デコード、
ライブ TOTP 生成、PKCE、パスワードハッシュ、ReBAC チェック、alg=none 攻撃などを、
**ブラウザ内で本物の暗号処理**（Web Crypto API）で動かせる。インストール不要。

> GitHub Pages の有効化: リポジトリの **Settings → Pages → Source: `main` ブランチ /
> `docs` フォルダ** を選ぶだけ。数分で `https://hjosugi.github.io/auth-lab/` が公開される。
> ローカルなら `docs/index.html` を直接開いても動く。

## 実装したもの

| 領域 | 実装 | 検証 |
|------|------|------|
| **RSA** | 鍵生成・PKCS#1 v1.5 署名/検証（純Python） | openssl で相互検証 |
| **ECDSA** | P-256, RFC 6979 決定的nonce, low-S | — |
| **AES** | 128/192/256, CBC, encrypt-then-MAC | FIPS-197 KAT |
| **X.509** | v3 証明書を発行する CA | `openssl verify` 通過 |
| **パスワード** | scrypt/PBKDF2, ソルト, パラメータ埋込, 列挙対策 | 列挙タイミング差なし |
| **TOTP/HOTP** | RFC 4226/6238 をゼロから | RFC 公式ベクタ一致 |
| **JWS/JWT/JWKS** | HS/RS 256/384/512, 全クレーム検証, alg固定 | 改ざん・混同を全拒否 |
| **OAuth 2.1** | code+PKCE / refresh(ローテ+再利用検知) / client_credentials / device | curl で動作 |
| **OIDC** | ID トークン, nonce, at_hash, amr, discovery | — |
| **DPoP** | RFC 9449 送信者制約 | 盗難トークン無効化 |
| **mTLS** | RFC 8705 証明書束縛（**本物のTLSハンドシェイク**） | ssl モジュールが検証 |
| **SAML 2.0** | SP/IdP, XML-DSig | XSW 攻撃を拒否 |
| **Kerberos** | KDC/AS/TGS, 4大AD攻撃を実演 | — |
| **WebAuthn** | 認証器 + RP, COSE, クローン検知 | フィッシング耐性を実演 |
| **LDAP** | search-then-bind, インジェクション/匿名bind対策 | — |
| **SCIM 2.0** | プロビジョニング全ライフサイクル | — |
| **RBAC/ABAC/ReBAC** | ロール階層 / deny-overrides / Zanzibar | ネストグループ解決 |

## 使い方

```bash
git clone https://github.com/hjosugi/auth-lab
cd auth-lab                                  # Python 3.11+ のみ。依存なし

python drills/run_all.py                     # 13本のドリルが全部緑になるのを見る
python -m unittest discover -s tests         # 108 テスト（RFCベクタ含む）
PYTHONPATH=. python attacks/catalog.py       # 攻撃カタログ（素朴実装→authlab）
python -m authlab.server                     # OAuth/OIDC サーバ起動 (:8080)
```

curl で OAuth を叩く例:

```bash
python -m authlab.server &
curl -s localhost:8080/.well-known/openid-configuration | python3 -m json.tool
curl -s -u service:service-secret \
  -d grant_type=client_credentials -d scope=orders:read \
  localhost:8080/token
```

## 構成

```
authlab/     実装本体（util, crypto, passwords, mfa, jose, oauth, saml,
             kerberos, webauthn, mtls, directory, authz, server.py）
drills/      13本の自己検証ドリル（run_all.py で一括実行）
attacks/     攻撃カタログ（catalog.py）
tests/       108 テスト
docs/        日本語解説 + ブラウザ playground(index.html)
```

## ドキュメント

- [docs/00_index.md](docs/00_index.md) — 目次
- プロトコル解説（日本語）: [土台](docs/01_foundations.md) / [JOSE·OAuth·OIDC](docs/02_jose_oauth_oidc.md) /
  [SAML](docs/03_saml.md) / [Kerberos](docs/04_kerberos.md) / [WebAuthn](docs/05_webauthn.md) /
  [mTLS·DPoP](docs/06_mtls_dpop.md) / [LDAP·SCIM](docs/07_ldap_scim.md) / [認可モデル](docs/08_authz.md)
- [攻撃対応表（CWE/OWASP）](docs/09_attack_matrix.md)
- [Spring Security 対応表](docs/10_spring_security_map.md)
- [14日ドリル計画](docs/11_14day_plan.md)
- [面接用スクリプト（英語）](docs/12_interview_english.md)
- [参考サイト・仕様一覧](docs/13_references.md)

## 設計上の正直な注記

これは**学習用ラボであり、本番の認証スタックではない**。純Python の RSA/AES/ECDSA は
定数時間ではなく（サイドチャネルに脆弱）、SAML は exc-c14n でなく C14N 2.0 を使うため
本番 IdP とは相互運用しない。目的は「本番で使うこと」ではなく「全バイトを読めること」。
本番では実績ある実装（各言語の標準暗号ライブラリ、Spring Authorization Server, Keycloak 等）を使う。

## ライセンス

MIT
