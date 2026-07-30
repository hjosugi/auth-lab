# Issues 一覧

このリポジトリに登録した GitHub Issues のまとめ。学習ロードマップと、正直な制限事項
（今後の拡張バックログ）の2種類。

## 学習ロードマップ（トラッカー）

`docs/11_14day_plan.md`（14日計画）をチェックリスト化したもの。毎日ドリルを実行して
チェックを付けていく。

| # | タイトル | 内容 |
|---|----------|------|
| [#2](https://github.com/hjosugi/auth-lab/issues/2) | Week 1 トラッカー: 土台とトークン (Day 1–7) | パスワード / MFA / JWT / OAuth code+PKCE / refresh・device / リソースサーバ8ステップ |
| [#3](https://github.com/hjosugi/auth-lab/issues/3) | Week 2 トラッカー: エンタープライズと高度なトークン (Day 8–14) | DPoP / 認可モデル / SAML / Kerberos / WebAuthn / mTLS・LDAP・SCIM / 総仕上げ |

## 拡張バックログ（今後の実装候補）

「学習用ラボ」として意図的に簡略化した箇所や、次に実装すると学びが深い項目。

| # | タイトル | ラベル | 概要 |
|---|----------|--------|------|
| [#4](https://github.com/hjosugi/auth-lab/issues/4) | CI: GitHub Actions で verify.py を実行 | enhancement, good first issue | push/PR で全unittest+13ドリル+攻撃回帰を自動実行 |
| [#5](https://github.com/hjosugi/auth-lab/issues/5) | SAML: exc-c14n を実装して本番 IdP と相互運用 | enhancement | 排他的正規化を実装し実 IdP と繋げる |
| [#7](https://github.com/hjosugi/auth-lab/issues/7) | Playground を Pyodide で実 Python 実行に | enhancement | ブラウザで authlab 本体を動かす REPL タブ |
| [#11](https://github.com/hjosugi/auth-lab/issues/11) | EdDSA(Ed25519) と ES256 の JOSE/WebAuthn 対応 | enhancement | ES256 を JWS に接続、Ed25519 を RFC 8032 で追加 |
| [#15](https://github.com/hjosugi/auth-lab/issues/15) | パスワード: Argon2id 対応と定数時間注記 | enhancement | Argon2id を PHC 形式で追加 |

## 攻撃対応（実装済み・issue ではなく検証項目）

以下は既に実装・検証済みで、`docs/09_attack_matrix.md` に CWE/OWASP マッピング付きで
一覧化している。`python attacks/run_regressions.py` で回帰チェックできる。

alg=none / アルゴリズム混同 / jwk ヘッダ注入 / ログインCSRF / redirect_uri 前方一致 /
認可コード再利用 / PKCE ダウングレード / リフレッシュ再利用 / IDトークン誤用 / BOLA /
Bearer 窃取 / LDAP インジェクション / 匿名バインド / ユーザ列挙 / XML署名ラッピング /
Kerberoasting / AS-REP roasting / ゴールデンチケット / Pass-the-ticket / パディングオラクル /
WebAuthn オリジン偽装 / 署名カウンタ退行

## 運用メモ

- issue の追加・更新は GitHub 上で行い、この表を随時同期する。
- 学習トラッカー（#2, #3）はチェックが全部埋まったらクローズする。
- 拡張 issue は着手時に自分をアサインし、PR で `Closes #N` を付ける。
