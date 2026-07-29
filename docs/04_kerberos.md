# 04 - Kerberos

> 実装: `authlab/kerberos/` / ドリル: `drills/10_kerberos.py`

このラボで最も古いプロトコル（MIT, 1980年代）で、地球上の全 Active Directory ドメインを
今も動かしている。信頼モデルが OAuth と正反対なのが学ぶ価値: 全て対称鍵、公開鍵なし、
KDC がレルムの全秘密を知る。

## 登場人物

- **principal**: 名前付き ID。`alice@LAB.LOCAL`, `HTTP/web.lab.local@LAB.LOCAL`
- **KDC**: Key Distribution Center。全 principal の長期鍵を持つ。論理的に2つ:
  - AS (Authentication Service): TGT を発行
  - TGS (Ticket Granting Service): サービスチケットを発行
- **TGT**: Ticket Granting Ticket。「ログイン済み」トークン。krbtgt の鍵で暗号化。
- **チケット**: サービスチケット。**対象サービスの鍵**で暗号化。
- **セッションキー**: KDC がチケットごとに生成し両者に渡す対称鍵。
- **authenticator**: セッションキーで暗号化したタイムスタンプ。今その鍵を持つことの証明
  （鮮度・リプレイ対策）。

## メッセージフロー

```
AS-REQ   client → KDC   「alice です、TGT ください」
                        + PA-ENC-TIMESTAMP（パスワード由来鍵で暗号化したタイムスタンプ）
AS-REP   KDC → client   TGT（krbtgt鍵で暗号化）+ セッションキー（alice鍵で暗号化）

TGS-REQ  client → KDC   TGT + authenticator + 「HTTP/web が欲しい」
TGS-REP  KDC → client   サービスチケット（HTTP/web鍵で暗号化）+ 新セッションキー

AP-REQ   client → svc   サービスチケット + authenticator
AP-REP   svc → client   （任意）復号できたことの証明＝相互認証
```

**核心の洞察**: チケットはサービス自身の長期鍵で暗号化されるので、サービスは KDC を
呼ばずに復号できる。だから DC が数万台をさばける。

**危険の洞察**: krbtgt 鍵を持つ者は誰にでも・任意のグループで TGT を作れ、全サービスが
それを信じ、何もログに残らない。これがゴールデンチケット。

## 4大 AD 攻撃（ドリルで実演）

### Kerberoasting
任意の認証ユーザが任意の SPN のサービスチケットを要求でき、それはサービスアカウントの
パスワード由来鍵で暗号化されている。持ち帰ってオフラインで総当たり。**失敗ログインも
ロックアウトもネットワークトラフィックも無い**。対策はファイアウォールではなく、
長いランダムパスワードか gMSA。

### AS-REP roasting
ユーザが事前認証 (preauth) 無効なら、誰でもそのユーザ向けの暗号化ブロブを要求でき、
オフラインで割れる。対策: preauth を無効にしない。

### ゴールデンチケット
krbtgt 鍵を持てば、任意ユーザ・任意グループの TGT をオフラインで偽造。デフォルト
10年寿命が検知シグナル（本物の TGT は約10時間）。対策: krbtgt の保護と定期ローテーション。

### Pass-the-ticket
侵害ホストの LSASS をダンプしてチケットとセッションキーを奪い、自分のマシンから
チケット期限まで再生。パスワード不要。対策: 短命チケット・ホスト隔離・監視。

## 一言で

**チケットはサービスの鍵で暗号化されるから KDC を毎回呼ばずに済む（＝スケールする）。
逆に言えば krbtgt 鍵1つが全レルムの信頼の根。** AD 侵害対応で「krbtgt を2回リセット」が
定番なのはこのため。

> 相違: 本物は ASN.1 DER over UDP/TCP 88、enctype は aes256-cts-hmac-sha384-192。ラボは
> Python オブジェクトを渡し、AES-CBC + HMAC-SHA256 (encrypt-then-MAC) を `aes256-lab` と
> 呼ぶ。string_to_key は PBKDF2/4096 回で、これは本物の AES enctype と同じ回数＝2024年には
> 少なすぎる。Kerberoasting が成立する理由をそのまま見せるためあえて本物の値。
