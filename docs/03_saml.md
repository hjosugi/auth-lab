# 03 - SAML 2.0

> 実装: `authlab/saml/` / ドリル: `drills/09_saml.py`
> 図: [SAML Web SSO](diagrams.md#saml-web-sso) / [XML署名ラッピング(XSW)](diagrams.md#xml-署名ラッピング-xsw)

SAML はエンタープライズ SSO が15年間動いてきた基盤で、今も大企業の多くで現役。
OAuth より古く、JSON でなく XML で、アサーション全体をブラウザ経由で運ぶ。形は OIDC と同じ。

## OIDC との対応

| SAML | OIDC |
|------|------|
| Service Provider (SP) | Relying Party / client |
| Identity Provider (IdP) | OpenID Provider |
| AuthnRequest | /authorize リクエスト |
| Assertion | ID トークン |
| `<Audience>` | aud |
| `<Issuer>` | iss |
| NameID | sub |
| RelayState | state |
| `<AttributeStatement>` | claims / userinfo |
| AuthnContextClassRef | acr |
| `<Conditions NotOnOrAfter>` | exp |

**SAML が劣る点**: アサーションが POST body でブラウザを通る（大きく、ページ上から見える）／
署名が XML-DSig（JWS より遥かに間違えやすい）／リフレッシュ相当が無い。

**SAML が優れる点**: 2005 年から SLO（シングルログアウト）と豊富な属性文がある／
バックチャネルなしで動く（SP が IdP を一切呼ばない）。

## XML-DSig がなぜ難しいか

JWS はバイト列に署名する。XML-DSig は**木**に署名する。木は直列化の仕方が複数ある
（属性順・名前空間 prefix・空白・自己終了タグ）。だから正規化 (c14n) を先に行う。

このラボは SAML で一般的な
[Exclusive XML Canonicalization 1.0](https://www.w3.org/TR/xml-exc-c14n/)
（exc-c14n）を `authlab/saml/c14n.py` に標準ライブラリだけで実装する。
ElementTree は wire 上の prefix を失うため、正規化だけは prefix と名前空間軸を保持する
DOM で行う。実装している要点は次のとおり。

- 要素名または属性名が**可視に利用する**名前空間だけを、その場所で出力する。
- 署名対象を別の envelope へ移しても、未使用の祖先名前空間や `xml:lang` を取り込まない。
- QName が属性値にだけ現れる場合は可視と見なされないため、
  `InclusiveNamespaces PrefixList`（既定名前空間は `#default`）で明示する。
- 名前空間と属性を仕様順に並べ、空要素を開始・終了タグへ展開し、文字を正規 escape する。
- 宣言した `CanonicalizationMethod` と `Transform` が exc-c14n でなければ検証を拒否する。

`tests/test_saml_signature.py` は W3C 勧告 2.2 の re-enveloping 例、可視名前空間、
`PrefixList`、属性順、DTD 拒否、アルゴリズム差し替えを固定ベクタとして確認する。
さらに `xmlsec1` がある環境では、独立実装との双方向署名を実行できる。

```bash
python scripts/verify_saml_xmlsec.py
```

これは教材の相互運用チェックであり、本番の SAML SP でスクラッチ XML 署名実装を使う
推奨ではない。本番は schema-aware な保守済みライブラリ、信頼済み metadata、
証明書 rollover、厳格な XML parser 制限まで一体で運用する。

エンベロープ署名の構造:

```
<Assertion ID="_abc">
  <Signature>
    <SignedInfo>
      <Reference URI="#_abc">          ← Assertion を指す
        <DigestValue>base64(sha256(c14n(署名対象からSignatureを除いた木)))</DigestValue>
      </Reference>
    </SignedInfo>
    <SignatureValue>base64(rsa(sha256(c14n(SignedInfo))))</SignatureValue>
  </Signature>
  ...claims...
</Assertion>
```

ハッシュが2つ、署名が1つ。署名は SignedInfo を覆い、SignedInfo は参照要素の digest を含む。
この間接参照こそが XML Signature Wrapping (XSW) の温床。

## XML Signature Wrapping (XSW)

攻撃者は元の署名済みアサーションを文書のどこかに残す（digest はそのまま合う）。そして
アプリが実際に読む**2つ目の署名なしアサーション**を追加する。あらゆる主要 SAML ライブラリが
一度は出荷したバグ（Somorovsky et al., USENIX 2012「On Breaking SAML」）。

**防御**（`authlab/saml/signature.py`）: `verify_signature` は**署名された要素を返す**。
呼び出し側はその返り値を使わなければならず、文書を再検索してはいけない。API が
`verify(doc) -> bool` の後に `doc.find('Assertion')` ならバグる。`verify(doc) -> signed_element`
なら構造的にバグれない。加えて、署名は文書に1つだけ（2つ目は拒否）、Reference URI が
ID で一意に解決すること、アルゴリズム固定も強制する。
正規化方式と transform 列も固定し、宣言と実処理の差、外部 URI、DTD/entity も拒否する。

## SP が検証すべき9項目（1つでも飛ばすとバイパス）

1. 署名 → **署名された要素だけを使う**
2. 署名対象が Assertion であること
3. Issuer が設定した IdP
4. Status が Success
5. Destination / Recipient が**自分の ACS URL**（他 SP 向けアサーションのリプレイ防止）
6. InResponseTo が**自分が開始したリクエスト**（CSRF チェック。IdP-initiated の
   unsolicited は InResponseTo が無い＝未認証なので原則拒否）
7. Conditions の NotBefore / NotOnOrAfter（小さな leeway）
8. AudienceRestriction が自分の entity id を含む
9. アサーション ID が未使用（リプレイ）

## 一言で

**署名を検証しただけでは足りない。「署名された要素」を掴んで離さず、宛先・監査・
InResponseTo・有効期間・audience・リプレイを全部見る。** XSW は「署名は正しいのに
乗っ取られる」攻撃であり、API 設計で構造的に潰すのが正解。

> 実装上の正直な相違: 本物の SAML は排他的正規化 (exc-c14n) を使う。標準ライブラリは
> C14N 2.0 のみ提供するのでそれを使い、CanonicalizationMethod に明示している。署名は
> 自己完結して構造的には本物と同一だが、本番 IdP との相互運用には exc-c14n の自作が要る。
