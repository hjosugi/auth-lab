# 02 - JOSE / OAuth 2.0 + Security BCP / OIDC

> 実装: `authlab/jose/`, `authlab/oauth/`, `authlab/oidc/` / ドリル: `drills/03_jwt.py`〜`drills/07_dpop.py`
> 図: [JWT構造](diagrams.md#jwt-の構造) / [認可コード+PKCE](diagrams.md#oauth-20-security-bcp-認可コード--pkce) / [リフレッシュ再利用検知](diagrams.md#リフレッシュトークン-ローテーション--再利用検知) / [ID vs アクセストークン](diagrams.md#oidc-id-トークン-vs-アクセストークン) / [DPoP](diagrams.md#dpop-送信者制約-rfc-9449) / [リソースサーバ8ステップ](diagrams.md#リソースサーバの8ステップ)

## JOSE (JWS / JWT / JWK)

コンパクト JWS は3つの base64url をドットで繋いだもの:

```
BASE64URL(header) . BASE64URL(payload) . BASE64URL(signature)
\_______________署名対象_______________/
```

**署名対象は先頭2セグメントのテキスト（ドット込み）**。検証側は受信したバイト列を
そのまま検証しなければならず、パースし直した JSON を再シリアライズしてはいけない。
再シリアライズはキー順や空白を失い、相互運用を壊す（最悪、別バイト列が1つの署名で
検証を通る）。

### JWT の3大偽造と防御

1. **alg=none**: RFC 7515 は空署名の「無署名 JWS」を定義する。トークンの `alg` を
   読んで分岐する検証器は、alg=none の偽造を受理してしまう。
   → **防御: 呼び出し側が許可アルゴリズムを明示。ヘッダの alg は「許可集合と照合」する
   だけで、検証方法の選択には使わない。** `none` は許可集合に入れられない。

2. **アルゴリズム混同 (RS256→HS256)**: 検証器がヘッダの alg で HMAC を選び、RSA 公開鍵を
   HMAC 秘密鍵として渡すと、公開鍵（＝公開情報）を持つ誰もがトークンを作れる。
   → **防御: 期待アルゴリズムは設定から。鍵は型付きで、RSA 鍵を HMAC に流用不可。**

3. **jwk / jku / x5u ヘッダ**: トークンが自分の鍵を運ぶ/指す。従う検証器は攻撃者が
   自分の偽造を検証する鍵を供給できてしまう。
   → **防御: これらのヘッダを拒否し、鍵は設定済み JWKS から `kid` でのみ解決。**

> 対比: DPoP では inline `jwk` は**正しい**。DPoP の proof は「信頼される対象」ではなく、
> 「この proof を作った者が、AS が署名したトークンの cnf.jkt に一致する鍵を持つ」ことだけを
> 示す。トークン自身の jwk を信じるのはバイパスだが、検証済みトークンの thumbprint に対して
> proof の jwk を照合するのは設計そのもの。

### 署名アルゴリズム表

実装: [`authlab/jose/jws.py`](https://github.com/hjosugi/auth-lab/blob/main/authlab/jose/jws.py) の `ALGORITHMS`。

| alg | 種別 | 鍵型 (JWK `kty`) | 曲線 / 鍵 | ハッシュ | 署名長 | 備考 |
|-----|------|------------------|-----------|----------|--------|------|
| HS256/384/512 | HMAC | `oct` | 共有秘密 | SHA-256/384/512 | 32/48/64B | 検証者＝発行者になれる。マルチテナントでは使わない |
| RS256/384/512 | RSASSA-PKCS1-v1_5 | `RSA` | 2048bit 以上 | SHA-256/384/512 | 鍵長と同じ (256B) | 最も普及。署名が大きい |
| ES256 | ECDSA | `EC` | **P-256** | SHA-256 | 64B (R‖S 各32B) | passkey/WebAuthn の既定 |
| ES384 | ECDSA | `EC` | **P-384** | SHA-384 | 96B (各48B) | |
| ES512 | ECDSA | `EC` | **P-521** | SHA-512 | 132B (各66B) | **名前はハッシュ由来。P-512 という曲線は存在しない** |
| EdDSA | Ed25519 | `OKP` | Ed25519 | SHA-512 (内部) | 64B | RFC 8037。曲線は `crv` 側にあるので alg は1つだけ |

**ES\* で必ず踏む落とし穴 — 署名エンコーディングが2種類ある。**
JOSE は固定長の生 `R‖S`（RFC 7518 §3.4）、X.509 と WebAuthn は可変長の
DER `SEQUENCE{INTEGER r, INTEGER s}`。DER は r/s の最上位ビットが立つと
`0x00` が前置されるので長さが署名ごとに変わる。passkey バックエンドの
「署名が検証できない」の大半はこの変換漏れ。変換は
[`signature_to_raw` / `signature_to_der`](https://github.com/hjosugi/auth-lab/blob/main/authlab/crypto/ec.py) にある。

**曲線は alg に固定されている。** `ES384` ヘッダに P-256 鍵、は仕様違反であり、
本実装は `Algorithm._require_curve` で拒否する。JWKS 側でも `crv` と座標長の
一致を検証する（P-521 と称して48バイト座標、は破損か曲線混同のどちらか）。

**なぜ EdDSA が増えているか。** ECDSA の危険な部分は署名ごとのノンス `k` で、
再利用すると秘密鍵が落ちる（PS3 の署名鍵、Android RNG バグ時代の Bitcoin ウォレット）。
EdDSA はノンスを `SHA-512(prefix ‖ message)` として導出するので、署名経路に RNG が
存在しない。さらにメッセージを**公開鍵ごと**ハッシュするため、署名を別の鍵に
付け替える duplicate-signature key substitution も塞がっている。
本実装は [`authlab/crypto/ed25519.py`](https://github.com/hjosugi/auth-lab/blob/main/authlab/crypto/ed25519.py)（RFC 8032 準拠、
テストベクタ一致）。32バイトなら何でも公開鍵として受けるのではなく、canonical な曲線点か、
素数位数の署名部分群に属するかも検証する。恒等点のような小位数鍵を許すと、検証式から
メッセージと公開鍵の束縛が消えるためである。

> 注意: ECDSA へ RFC 6979 の決定的ノンスを後付けしたのが `crypto/ec.py` の
> `_rfc6979_k`。EdDSA は最初からそう設計されている、という差。

### クレーム検証（署名は簡単な方の半分）

- `iss`: どの AS が発行したか。無いと信頼する任意の IdP のトークンが全サービスで通る。
- `aud`: このトークンは**誰のためか**。これを飛ばすのが最頻ミス。ID トークンが API で
  リプレイされたり、サービスA向けのトークンがサービスB で通る。「含むか」を検証する
  （aud は文字列or配列）。
- `exp`/`nbf`/`iat`: 有効期間。leeway は 60 秒程度。
- `jti`: 一度きりトークンの使用済みマーク。
- OIDC `nonce`: ID トークンをフローを開始したブラウザセッションに束縛。

### JWKS と鍵ローテーション

無停止ローテーションは「新旧の鍵を両方公開 → 新 kid で署名開始 → 全トークン失効後に
旧鍵を削除」。RS は unknown kid で1回だけ再取得（レート制限付き、さもないと
ランダム kid で IdP を叩く DoS になる）。`authlab/jose/jwks.py`。

## OAuth 2.0 + Security BCP

### 実装したグラント

| グラント | 用途 | 判定 |
|----------|------|------|
| authorization_code + PKCE | Web/SPA/モバイル | ユーザがいる全てのデフォルト |
| client_credentials | サービス間 | 機械（ユーザ無し）に正しい |
| device_code | TV/CLI | 入力制約デバイスに正しい |
| refresh_token | 再ログイン無しの更新 | ローテーション+再利用検知付き |

### 廃止対象のグラント（Security BCP / OAuth 2.1 draft）

- **implicit** (`response_type=token`): アクセストークンを URL フラグメントで返す →
  ブラウザ履歴・referer・ページ上の全スクリプトに漏れる。→ code+PKCE に置換。
- **ROPC (password)**: クライアントがユーザの生パスワードを扱う → OAuth の意味がなく、
  MFA も連携も不可能。→ code/device フローに置換。

### 認可コード + PKCE の要点

1. `redirect_uri` は**完全一致**。prefix/startswith/「同じホスト」は不可。
   prefix 一致は `…/cb.attacker.net` や `…/cb/../open-redirect` を生む。
2. `state` 必須。無いとリダイレクトエンドポイントに CSRF 防御がない（ログイン CSRF）。
3. コードは単回使用。再提示は失効イベントとして扱い、そのコードが生んだトークンを
   一括失効（RFC 6749 §4.1.2）。
4. public client は PKCE 必須。受理側が省略を許すと攻撃者が省略してダウングレードできる。

### リフレッシュのローテーションと再利用検知

毎回新トークンを返し旧を無効化。1ログインの子孫は同じ family_id を共有。ローテーション済み
トークンの再提示＝漏洩なので family ごと失効（正規ユーザも攻撃者も落ちる＝正しい対応）。
scope は狭められるが広げられない（漏れた read トークンが admin に昇格しないため）。

### リソースサーバの8ステップ（`authlab/oauth/resource_server.py`）

ここが最も自作されるゆえに最も抜ける。順に:

1. 署名（JWKS から kid で、alg 固定）
2. `typ` が `at+jwt`（ID トークンをここで弾く）
3. `iss` が信頼する AS
4. `aud` が**自分を含む**
5. `exp`/`nbf`/`iat`
6. 送信者制約（`cnf` があれば DPoP/mTLS を検証。cnf 付きトークンを素の Bearer で
   出したら拒否＝ダウングレード攻撃）
7. このエンドポイントに必要な scope
8. **このユーザがこの特定オブジェクトを触ってよいか**（所有権）

8 が BOLA/IDOR。**scope は認可ではない**。`orders:read` は「注文を読める」であって
「誰の注文か」ではない。トークン検証では絶対に塞げない。

## OIDC

- ID トークンの `aud` は**クライアント**（API ではない）。だから ID トークンを API に
  資格情報として送ってはいけないし、正しい RS は拒否する。
- `at_hash` で ID トークンをアクセストークンに束縛。`amr` で認証手段（pwd/otp/mfa）を伝達
  → RP は「IdP が MFA したはず」ではなく amr を検証する。
- discovery (`/.well-known/openid-configuration`) と JWKS で自動連携。
