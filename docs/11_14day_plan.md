# 14日ドリル計画

「認証認可がよわい」を「からだにたたきこむ」ための2週間。各日 30〜60分。
毎日、対応するドリルを**手で打って実行**し、`docs/` の該当解説を読み、最後に
「この攻撃はなぜ防げるか」を声に出して説明する（面接練習を兼ねる）。

原則:
- 読むだけにしない。必ず `python drills/NN_*.py` を実行して緑を見る。
- 各プロトコルで「一番やりがちなミス」を1つ言えるようにする。
- 週末に `python -m unittest discover -s tests` と `python drills/run_all.py` で総復習。

---

## 第1週: 土台とトークン

### Day 1 — パスワード
- ドリル: `drills/01_passwords.py`
- 読む: playground の Passwords タブ、`authlab/passwords/hasher.py`
- 言えるように: なぜ salt が要る / なぜ遅くする / なぜ scrypt(memory-hard) が GPU に効く / `fake_verify` は何を防ぐか
- チェック: PHC 形式 `$scrypt$...` を空で読める

### Day 2 — MFA (TOTP/HOTP)
- ドリル: `drills/02_mfa_totp.py`、playground の TOTP タブでライブ生成
- 読む: `authlab/mfa/totp.py`
- 言えるように: TOTP = HOTP + 時計 / リプレイ対策(last_step) / なぜ TOTP はフィッシングされるか
- チェック: RFC 6238 ベクタ (t=59 → 94287082) を再現

### Day 3 — JWT/JOSE の構造
- ドリル: `drills/03_jwt.py`、playground の JWT タブでデコード
- 読む: `authlab/jose/jws.py`, `jwt.py`
- 言えるように: 署名対象は「受信したテキスト」/ 3セグメントの意味
- チェック: jwt を手でデコードできる

### Day 4 — JWT の3大偽造
- 再: `drills/03_jwt.py`、playground で alg=none ボタン
- 言えるように: alg=none / RS256→HS256 confusion / jwk ヘッダ注入 の3つを、防御理由つきで
- チェック: 「なぜ許可リストを必須にすると3つとも塞げるか」

### Day 5 — OAuth 認可コード + PKCE
- ドリル: `drills/04_authcode_pkce.py`、playground の OAuth タブでフロー、PKCE タブで生成
- 読む: `authlab/oauth/authorization_server.py`, `client.py`, `pkce.py`
- 言えるように: PKCE が何を守るか / state との違い / redirect_uri 完全一致の理由
- チェック: フロー11ステップを図なしで説明

### Day 6 — リフレッシュ / device / client_credentials
- ドリル: `drills/05_refresh_rotation.py`, `drills/06_device_and_cc.py`
- 言えるように: ローテーション再利用検知の挙動 / なぜ family ごと失効 / implicit と ROPC がなぜ廃止
- チェック: リフレッシュで scope は狭められるが広げられない、を再現

### Day 7 — 週末総復習 + リソースサーバ
- 実行: `python drills/run_all.py`
- 読む: `authlab/oauth/resource_server.py` の8ステップ
- 言えるように: 「valid token ≠ authorized」/ ID トークンを API に投げると何が起きるか / BOLA
- チェック: `attacks/catalog.py` を実行して全 DEFENDED を確認

---

## 第2週: エンタープライズと高度なトークン

### Day 8 — DPoP と送信者制約
- ドリル: `drills/07_dpop.py`
- 読む: `authlab/oauth/dpop.py`
- 言えるように: Bearer の弱点 / cnf.jkt / なぜ DPoP の jwk ヘッダは「正しい」のか（JWS との対比）
- チェック: 盗んだトークンが Bearer でも別鍵でも使えないことを再現

### Day 9 — 認可モデル (RBAC/ABAC/ReBAC)
- ドリル: `drills/08_authz_models.py`、playground の RBAC/ABAC/ReBAC タブ
- 読む: `authlab/authz/`
- 言えるように: RBAC が言えない「their own」/ deny-overrides + default-deny / Zanzibar のタプル
- チェック: ネストグループ経由の check() を説明

### Day 10 — SAML
- ドリル: `drills/09_saml.py`
- 読む: `authlab/saml/`、`docs/03_saml.md`（あれば）
- 言えるように: OIDC との対応表 / XML 署名ラッピング (XSW) と防御 / SP が検証すべき9項目
- チェック: 「署名を検証したのに乗っ取られる」XSW の仕組み

### Day 11 — Kerberos
- ドリル: `drills/10_kerberos.py`
- 読む: `authlab/kerberos/`
- 言えるように: TGT/サービスチケット/セッションキー / なぜ KDC を毎回呼ばないか / 4大AD攻撃
- チェック: Kerberoasting がなぜオフラインで検知されないか

### Day 12 — WebAuthn / passkeys
- ドリル: `drills/11_webauthn.py`、playground の TOTP タブの比較表
- 読む: `authlab/webauthn/`
- 言えるように: なぜフィッシング耐性があるか（origin 束縛）/ 署名カウンタ / syncable passkey
- チェック: 「なぜ passkey はサーバに秘密がないか」

### Day 13 — mTLS + LDAP + SCIM
- ドリル: `drills/12_mtls.py`, `drills/13_ldap_scim.py`
- 読む: `authlab/mtls/`, `authlab/directory/`
- 言えるように: mTLS と RFC8705 束縛 / LDAP インジェクション + 匿名バインド / SCIM の deactivate≠delete
- チェック: mTLS が本物の TLS ハンドシェイクで動くのを確認

### Day 14 — 総仕上げ
- 実行: `python -m unittest discover -s tests`（全unittest成功）+ `python drills/run_all.py`
- 読む: `docs/09_attack_matrix.md` を上から音読
- 仕上げ: `docs/12_interview_english.md` を英語で通しで説明（録音して聞く）
- チェック: 攻撃対応表22項目を、防御理由つきで空で言える

---

## 到達目標

14日後に、以下を**紙もコードも見ずに**言える状態:

1. 認証と認可の違いと、それぞれの代表的な失敗
2. JWT の3大偽造と、許可リスト1つで全部塞げる理由
3. 認可コード + PKCE のフローと、各ステップが守るもの
4. 「valid token ≠ authorized」と BOLA が OWASP API #1 である理由
5. SAML XSW / Kerberos 4大攻撃 / WebAuthn のフィッシング耐性
6. DPoP・mTLS の送信者制約が Bearer の何を直すか
