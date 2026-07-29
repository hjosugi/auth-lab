# 06 - mTLS と DPoP（送信者制約トークン）

> 実装: `authlab/mtls/`, `authlab/oauth/dpop.py` / ドリル: `drills/12_mtls.py`, `drills/07_dpop.py`
> 図: [mTLS ハンドシェイク](diagrams.md#mtls-ハンドシェイク) / [DPoP 送信者制約](diagrams.md#dpop-送信者制約-rfc-9449)

Bearer トークンは「持つ者が使える」。ログ・referer・侵害プロキシから盗めば、期限まで
その人になれる。この問題を、トークンを鍵に束縛して解く2つの方法。

## mTLS（相互 TLS, RFC 8705）

通常の TLS はサーバだけを認証する。mTLS はクライアント認証を**ハンドシェイクの中に**移す:
サーバがクライアント証明書を要求し、信頼する CA で検証する。

このラボで唯一**本物のソケット**で動く。自作 CA が発行した証明書を Python の `ssl` モジュールが
実際に検証する（`authlab/mtls/tls.py`, `authlab/crypto/x509.py`）。`openssl verify` も通る。

### 効く場所
- サービスメッシュ（Istio/Linkerd）: 各ワークロードが短命証明書を持ち、サービス間に
  パスワードが無い
- 高価値 API（銀行/FAPI）: Bearer では不十分
- OAuth トークンの証明書束縛（`cnf.x5t#S256` = DER 証明書の SHA-256）

### コスト（だから普及しない）
- 証明書ライフサイクル（発行・ローテ・失効）が重い → メッシュは数時間寿命で自動化
- 失効は PKI 共通の未解決問題（CRL は肥大・陳腐化、OCSP は soft-fail）→ 短命寿命で対処
- 終端が厄介: LB で TLS 終端すると、検証済み証明書をヘッダでアプリに渡す必要があり、
  LB がクライアント供給ヘッダを剥がさないとヘッダ偽装される

## DPoP (RFC 9449)

ソフトウェアで送信者制約する方法。

1. クライアントが鍵ペアを生成（P-256。ブラウザでは IndexedDB の非抽出 CryptoKey）。
2. 毎リクエスト（トークンエンドポイント**と**リソースサーバ）で `DPoP` ヘッダに、その鍵で
   署名した短い JWT を送る。proof の JOSE ヘッダに**公開鍵を inline `jwk`** で、payload に
   `htm`(HTTPメソッド), `htu`(URL), `iat`, `jti` を入れる。
3. AS はその公開鍵の RFC 7638 thumbprint をアクセストークンに `cnf: {"jkt": "..."}` として入れる。
4. RS が検証: proof 署名・htm/htu が今のリクエストと一致・iat が新しい・jti が未使用・
   thumbprint(proof.jwk) == token.cnf.jkt。さらに `ath`（アクセストークンのハッシュ）で
   proof を1トークンに束縛。

盗まれたアクセストークンは秘密鍵なしでは無価値。

### JWS との対比（重要）

`authlab.jose.jws` は `jwk` ヘッダを**拒否**する。DPoP では inline 鍵が**正しく必須**。
理由: proof は信頼される対象ではない。jwk は「この proof を作った者が、token の cnf.jkt に
一致する鍵を持つ」ことだけを示す。権限を運ぶのは AS が署名したトークン。
**トークン自身の jwk を信じる = バイパス。検証済みトークンの thumbprint に対して proof の
jwk を照合する = 設計そのもの。**

### DPoP が塞がないこと
- 完全侵害デバイス（鍵も奪われる）
- nonce なしだと proof を事前計算可能 → `DPoP-Nonce` ヘッダと `use_dpop_nonce` エラーで
  サーバが鮮度を強制（ラボは両方実装）

## RS 側の「ダウングレード拒否」

`cnf` 付きトークンを素の `Bearer` スキームで出したら**拒否**する。これが攻撃の本体。
`authlab/oauth/resource_server.py` はこれを明示的に弾く。

## 一言で

**Bearer の弱点は「持てば使える」。DPoP は鍵の所有証明を毎回要求し、mTLS は TLS 層で
クライアント証明書を要求する。どちらもトークンを鍵に束縛し、盗んだだけでは使えなくする。**
