# 05 - WebAuthn / passkeys

> 実装: `authlab/webauthn/` / ドリル: `drills/11_webauthn.py`
> 図: [WebAuthn 登録](diagrams.md#webauthn-登録) / [WebAuthn 認証](diagrams.md#webauthn-認証)

パスキーの正体。サイトごとに鍵ペアを作り、秘密鍵は認証器から出ず、署名はオリジンに
束縛される。この1点が「パスキーはフィッシング耐性がある」の全て。

## なぜ他の要素に勝つか

| 要素 | フィッシング可能? | サーバに秘密? |
|------|------------------|--------------|
| パスワード | 可 | 可（ハッシュ） |
| TOTP | 可（リアルタイムproxyが窓内で中継） | 可（共有秘密） |
| Push | 可（プロンプト疲労） | — |
| パスキー | **不可**（署名がオリジンに束縛） | **不可**（公開鍵のみ） |

ユーザは evil.example にコードを打ち込ませられても、認証器は evil.example 用の署名を
作らない。ブラウザが本物のオリジンを渡し、RP ID が一致しないから。

## 認証器 (authenticator)

YubiKey / Touch ID / Windows Hello がやること。秘密鍵を持ち、「登録されたオリジンにしか
署名しない」だけが貢献。`authlab/webauthn/authenticator.py` は仮想認証器。

### authenticatorData（署名される正確なバイト列）

```
32  rpIdHash        SHA-256(RP ID)
 1  flags           bit0 UP(user present) / bit2 UV(user verified)
                    bit3 BE(backup eligible) / bit4 BS(backup state)
                    bit6 AT(attested cred data あり)
 4  signCount       単調増加カウンタ
..  attestedCredentialData（登録時のみ: AAGUID, credId, COSE公開鍵）
```

認証時の署名対象は `authenticatorData || SHA-256(clientDataJSON)`。チャレンジは
clientDataJSON にのみ入り、そのハッシュ経由で署名に含まれる。だから RP は
「clientDataJSON のチャレンジを検証」**かつ**「そのハッシュが署名対象と一致」の両方が要る。

## RP (リライングパーティ) の検証項目

- **origin** が許可リストと完全一致（endswith も正規表現も不可。これがフィッシング防御の本体）
- **rpIdHash** が自分の RP ID の SHA-256
- **UP**（人が物理的に操作した）/ MFA を謳うなら **UV**（PIN/生体）必須
- **チャレンジ**が単回・サーバ生成・一致
- **署名**が保存した公開鍵で検証できる
- **signCount** の単調増加（退行＝クローンかリプレイ）
- **clientData.type** が `webauthn.get`（登録レスポンスをログインに流用させない）

## COSE 鍵

WebAuthn は公開鍵を JWK ではなく COSE (CBOR) で運ぶ。整数ラベル（1=kty, 3=alg, -1=crv,
-2=x, -3=y）。認証器は RAM が KB 単位のチップだから。`authlab/webauthn/cose.py`。

## 署名カウンタとクローン検知

ハードウェア認証器は署名ごとにカウンタを増やす。サーバが増えていないカウンタを見たら、
クローン（鍵抽出）か古いレスポンスのリプレイ。ただし**同期パスキー**（iCloud/Google）は
複数デバイスで同じ鍵なので 0 のまま。0 を「クローン」とすると全 iPhone ユーザが締め出される
ので、条件付き（登録時に非0だった場合のみ）にする。

## パスキーが解決しないこと

- アカウント復旧（最弱リンクになる。多くは結局「メールでリンク」＝1ホップ先のパスワード）
- デバイス紛失（同期パスキーでない限り。同期パスキーはクラウドアカウントの強さ止まり）
- 完全に侵害されたクライアント（マルウェアが正規のタイミングで正規のアサーションを要求可）

## 一言で

**サイトごとの秘密鍵は認証器から出ず、署名はオリジンに束縛される。だからサーバに盗む
秘密がなく（公開鍵のみ）、別ドメインでは署名が無価値。フィッシングする対象そのものが無い。**
