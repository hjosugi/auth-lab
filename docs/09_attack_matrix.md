# 攻撃対応表 (Attack Matrix)

この表は、auth-lab が防御している各攻撃を **CWE** と **OWASP** にマッピングしたもの。
面接や設計レビューで「なぜこのチェックが要るのか」を一言で説明できるようにするためのカンペ。

各行の「防御コード」は実装の該当箇所。`attacks/catalog.py` で実際に
「素朴な実装なら破れる → authlab は防ぐ」を実行して確認できる。

| # | 攻撃 | 分類 | CWE | OWASP | 防御方法 | 防御コード |
|---|------|------|-----|-------|----------|-----------|
| 1 | `alg=none` | JWT 偽造 | CWE-347 | API2:2023 | アルゴリズム許可リスト必須（デフォルトなし） | `jose/jws.py` |
| 2 | RS256→HS256 confusion | JWT 偽造 | CWE-347 | API2:2023 | 鍵に型を持たせ、公開鍵をHMAC秘密鍵に流用不可 | `jose/jws.py` |
| 3 | `jwk`/`jku`/`x5u` ヘッダ注入 | 鍵すり替え | CWE-347 | API2:2023 | トークンが自分の検証鍵を指定するのを拒否 | `jose/jws.py` |
| 4 | `state` 欠如 → ログインCSRF | CSRF | CWE-352 | A01:2021 | `state` 必須・セッションに紐付け検証 | `oauth/client.py` |
| 5 | `redirect_uri` 前方一致 | オープンリダイレクト/コード窃取 | CWE-601 | A01:2021 | 完全一致のみ（prefix/startswith 禁止） | `oauth/authorization_server.py` |
| 6 | 認可コード再利用 | コード窃取 | CWE-294 | API2:2023 | 単回使用 + 検知時にトークン一括失効 | `oauth/authorization_server.py` |
| 7 | PKCE ダウングレード/省略 | コード横取り | CWE-330 | API2:2023 | public client は PKCE 必須、S256 のみ | `oauth/authorization_server.py`, `oauth/pkce.py` |
| 8 | リフレッシュトークン再利用 | トークン窃取 | CWE-613 | API2:2023 | ローテーション + family 単位の再利用検知 | `oauth/authorization_server.py` |
| 9 | ID トークンを API に使う | トークン混同 | CWE-287 | API2:2023 | `typ=at+jwt` と `aud` の両方を検証 | `oauth/resource_server.py` |
| 10 | BOLA / IDOR | オブジェクト認可欠陥 | CWE-639 | **API1:2023** | scope とは別にオブジェクト所有者を検証 | `oauth/resource_server.py` |
| 11 | Bearer トークン窃取・再利用 | トークン窃取 | CWE-522 | API2:2023 | DPoP / mTLS による送信者制約 | `oauth/dpop.py`, `mtls/tls.py` |
| 12 | LDAP インジェクション | インジェクション | CWE-90 | A03:2021 | フィルタエスケープ + 構文パーサ | `directory/ldap.py` |
| 13 | LDAP 匿名バインド | 認証バイパス | CWE-287 | A07:2021 | 空パスワードのバインドを拒否 | `directory/ldap.py` |
| 14 | タイミングによるユーザ列挙 | 情報漏洩 | CWE-208 | A07:2021 | 定数時間 `fake_verify` | `passwords/hasher.py` |
| 15 | XML 署名ラッピング (XSW) / 正規化方式の差し替え | SAML 偽造 | CWE-347 | A07:2021 | 「署名された要素」を返し、exc-c14n・transform・参照IDを固定 | `saml/signature.py`, `saml/c14n.py` |
| 16 | Kerberoasting | 資格情報窃取 | CWE-916 | — | サービスは長いランダムパスワード / gMSA | `kerberos/kdc.py` (実演) |
| 17 | AS-REP roasting | 資格情報窃取 | CWE-916 | — | 事前認証(preauth)を無効化しない | `kerberos/kdc.py` (実演) |
| 18 | ゴールデンチケット | 権限昇格 | CWE-284 | — | krbtgt鍵の保護と定期ローテーション | `kerberos/kdc.py` (実演) |
| 19 | Pass-the-ticket | 資格情報再利用 | CWE-294 | — | 短命チケット + ホスト隔離 + 監視 | `kerberos/client.py` (実演) |
| 20 | パディングオラクル | 暗号 | CWE-696 | — | encrypt-then-MAC + 一様なエラー | `crypto/aes.py` |
| 21 | WebAuthn オリジン偽装 | フィッシング | CWE-290 | A07:2021 | origin と rpIdHash の完全一致検証 | `webauthn/relying_party.py` |
| 22 | WebAuthn 署名カウンタ退行 | クローン検知 | CWE-294 | — | signCount の単調増加を検証 | `webauthn/relying_party.py` |
| 23 | JOSE の曲線/署名形式混同 | JWT 偽造・相互運用不全 | CWE-347 | API2:2023 | ES256/384/512 と曲線を固定し、JWS は固定長 R‖S のみ受理 | `jose/jws.py`, `crypto/ec.py` |
| 24 | Ed25519 小位数鍵 / COSE 型混同 | 署名偽造 | CWE-347 | API2:2023 | 公開鍵の素数位数部分群を検証し、`kty`/`alg`/`crv` を完全一致 | `crypto/ed25519.py`, `webauthn/cose.py` |
| 25 | PAR front-channel parameter 注入 | 認可request改ざん | CWE-345 | API2:2023 | client認証済みPAR全体を短命・単回の`request_uri`へ束縛 | `oauth/par.py` |
| 26 | JAR 改ざん・replay | 認可request偽造 | CWE-347 | API2:2023 | client署名、`iss/client_id`、`aud`、期限、単回`jti`を検証 | `oauth/jar.py` |
| 27 | JARM response差し替え / AS mix-up | 認可response偽造 | CWE-345 | API2:2023 | AS署名、`iss`、`aud`、`exp`、`state`、単回`jti`を検証 | `oauth/jarm.py` |
| 28 | RARの金額・対象・action差し替え | 過剰な認可 | CWE-863 | API1:2023 | type/schemaを検証し、承認objectをcode/tokenへ継承 | `oauth/rar.py`, `oauth/authorization_server.py` |
| 29 | CIBA `auth_req_id`取り違え / 過剰poll | 認証フロー混同 | CWE-294 | A07:2021 | client・期限・承認へ束縛し、intervalと単回使用を強制 | `oauth/ciba.py` |
| 30 | FAPI Bearer / public-client downgrade | token再利用 | CWE-287 | API2:2023 | confidential client、PAR、S256、短命code、mTLS/DPoPを一体で強制 | `oauth/fapi2_security.py` |
| 31 | signed introspectionをaccess tokenとして使用 | JWT型混同 | CWE-843 | API2:2023 | 専用`typ`と`token_introspection` claim、`iss`/`aud`を検証 | `oauth/fapi2_message_signing.py` |
| 32 | cross-tenant relationによる境界越え | 認可欠陥 | CWE-863 | API1:2023 | relation grantより先にsubject/resourceのtenant一致を必須化 | `authz/policy_comparison.py` |
| 33 | owner/adminによるexplicit deny迂回 | 認可欠陥 | CWE-863 | API5:2023 | deny-overrides / forbid-overrides-permitを全モデルで固定 | `authz/policy_comparison.py` |
| 34 | relationship graphの循環・過深度 | DoS / 認可不整合 | CWE-674 | API4:2023 | path-local cycle検知と設定可能なdepth上限 | `authz/rebac.py`, `authz/policy_comparison.py` |
| 35 | decision logへの識別子・policy input漏洩 | 情報漏洩 | CWE-532 | API8:2023 | HMAC仮名化、field allowlist、期限付きretention | `authz/policy_comparison.py` |
| 36 | malformed token/XML/filterによるparser crash・resource exhaustion | DoS | CWE-400 | API4:2023 | 入力/時間上限、trust-boundary error正規化、固定seed property fuzz | `tests/property_fuzz.py`, `directory/scim.py` |

## 使い方

```bash
PYTHONPATH=. python attacks/catalog.py    # 1〜11, 14 を実演
python drills/09_saml.py                   # 15 (XSW) を実演
python drills/10_kerberos.py               # 16〜19 を実演
python drills/13_ldap_scim.py              # 12, 13 を実演
python drills/11_webauthn.py               # 21, 22 を実演
python -m unittest tests.test_saml_signature # 15 の正規化・方式差し替えnegative test
python drills/14_advanced_oauth.py          # 25〜31 のbindingを実演
python -m unittest tests.test_oauth_advanced # 25〜31 の正常系・negative test
python drills/08_authz_models.py            # 32〜35 の5モデル比較
python -m unittest tests.test_policy_comparison # 32〜35 のparity/negative test
PYTHONPATH=. python attacks/run_regressions.py  # 32, 33 を含む拒否回帰
python scripts/run_property_fuzz.py             # 6〜9, 15, 36 の順序・parser生成回帰
```

## 一番大事な一行

**認証が通ったこと（valid token）と、その操作が許可されていること（authorized）は別物。**
scope は「注文を読める」であって「誰の注文を読めるか」ではない。この隙間が BOLA (API1:2023)、
つまり OWASP API セキュリティの第1位。トークン検証だけでは絶対に塞げない。
