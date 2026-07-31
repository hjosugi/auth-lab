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

## ブラウザ標準 API で動かす

[GitHub Pages の WebAuthn native タブ](https://hjosugi.github.io/auth-lab/) は
`navigator.credentials.create()` / `get()` を直接呼ぶ。ローカルでは secure context の
`localhost` を使う。

```bash
python -m http.server -d docs 8000
# http://localhost:8000/ を開き、WebAuthn native タブへ
```

登録後は `allowCredentials` に credential ID を指定する認証と、ID を空にする
discoverable login（ユーザー名なし認証）を比較できる。ブラウザから返る
`clientDataJSON`、`attestationObject`、`authenticatorData` を教材 RP が解析し、
challenge/origin/RP ID hash/UP/UV/署名を検証する。origin と RP ID の不一致を意図的に
拒否するボタンもある。

CI の `tests/browser/webauthn-e2e.mjs` は Chrome DevTools Protocol の仮想認証器で、
非 discoverable 登録、resident credential、UV、discoverable login、BE/BS flags、
origin/RP ID mismatch を本物のブラウザ API に通す。外部サイトや実 credential は使わない。

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

| alg | 名前 | kty | crv | 鍵の形 | アサーション署名 |
|-----|------|-----|-----|--------|------------------|
| `-7` | ES256 | 2 (EC2) | 1 (P-256) | x, y 各32B | **DER** `SEQUENCE{r,s}`（可変長） |
| `-8` | EdDSA | 1 (OKP) | 6 (Ed25519) | x のみ32B（点は圧縮済み） | **生 64B**（RFC 8032） |

**署名フォーマットが alg ごとに違う。** すべての署名を DER パーサに通す RP は、
最初の Ed25519 認証器が現れた瞬間に落ちる。本実装は保存済み鍵の型で分岐する
（[`verify_credential_signature`](https://github.com/hjosugi/auth-lab/blob/main/authlab/webauthn/relying_party.py)）。
**アルゴリズムは検証対象のメッセージからではなく、登録時に保存した鍵から決める** —
JWS の `alg` と同じ教訓。

`crv=4` は X25519（鍵共有専用で署名できない）。「どちらも 25519」で通すのは
型混同なので拒否する。`pubKeyCredParams` で `-8` を広告しておきながら
`-7` しか検証できない実装は、登録は成功してログインだけ失敗する。本実装の登録オプションは
実際に検証できる `-7`, `-8` の両方だけを、この順で広告する。

## 署名カウンタとクローン検知

ハードウェア認証器は署名ごとにカウンタを増やす。サーバが増えていないカウンタを見たら、
クローン（鍵抽出）か古いレスポンスのリプレイ。ただし**同期パスキー**（iCloud/Google）は
複数デバイスで同じ鍵なので 0 のまま。0 を「クローン」とすると全 iPhone ユーザが締め出される
ので、条件付き（登録時に非0だった場合のみ）にする。

## Attestation・同期・本番との境界

- consumer passkey の既定は `attestation: "none"`。端末 provenance を必要とする管理用途で
  `direct` を選ぶ場合は、attestation trust store・メタデータ更新・プライバシー方針が別途必要。
- BE は backup eligible、BS は現在 backup 済みという信号。同期 credential を許すかは
  recovery とリスク方針に合わせる。
- 同期 passkey では sign counter が 0 のまま、または端末間で単調増加しない場合がある。
  counter 退行はリスク信号として扱い、それだけでアカウントを停止しない。
- playground は公開鍵をページのメモリだけに保存する。本番 RP は challenge の短期保存と
  一回限り消費、credential/userHandle の永続化、監査、recovery、複数 credential 管理が必要。

## パスキーが解決しないこと

- アカウント復旧（最弱リンクになる。多くは結局「メールでリンク」＝1ホップ先のパスワード）
- デバイス紛失（同期パスキーでない限り。同期パスキーはクラウドアカウントの強さ止まり）
- 完全に侵害されたクライアント（マルウェアが正規のタイミングで正規のアサーションを要求可）

## 一言で

**サイトごとの秘密鍵は認証器から出ず、署名はオリジンに束縛される。だからサーバに盗む
秘密がなく（公開鍵のみ）、別ドメインでは署名が無価値。フィッシングする対象そのものが無い。**
