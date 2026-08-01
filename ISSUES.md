# Issues 一覧

GitHub Issues の索引。**未着手のものだけが open** で、実装済みのものは closed です。
受け入れ条件つきの詳細は [docs/issue-backlog.md](docs/issue-backlog.md)（サイト上でも
読めます）にあります。このファイルはその上位の索引です。

## Open — 学習トラッカー

`docs/11_14day_plan.md`（14日計画）をチェックリスト化したもの。毎日ドリルを実行して
チェックを付けていきます。

| # | タイトル | 内容 |
|---|----------|------|
| [#2](https://github.com/hjosugi/auth-lab/issues/2) | Week 1: 土台とトークン (Day 1–7) | パスワード / MFA / JWT / OAuth code+PKCE / refresh・device / リソースサーバ8ステップ |
| [#3](https://github.com/hjosugi/auth-lab/issues/3) | Week 2: エンタープライズと高度なトークン (Day 8–14) | DPoP / 認可モデル / SAML / Kerberos / WebAuthn / mTLS・LDAP・SCIM / 総仕上げ |

> このチェックは**学習者本人が手で実行して説明できたときだけ**付けます。CI やエージェントの
> 自動実行は完了を意味しません。

## Closed — すべて実装済み

当初「今後の拡張候補」として立てた項目は、すべて実装・検証まで完了しています。
このリポジトリに「未実装の宿題」は残っていません。

| # | 内容 | 実装 |
|---|------|------|
| [#4](https://github.com/hjosugi/auth-lab/issues/4) | CI で全検証を自動実行、バッジ追加 | `.github/workflows/ci.yml` |
| [#5](https://github.com/hjosugi/auth-lab/issues/5) | SAML 排他的正規化 (exc-c14n) と実 IdP 相互運用 | `authlab/saml/` |
| [#6](https://github.com/hjosugi/auth-lab/issues/6) | Keycloak / OpenLDAP / MIT Kerberos とのローカル相互運用 | `interop/`, `scripts/run_interop.py` |
| [#7](https://github.com/hjosugi/auth-lab/issues/7) | Pyodide でブラウザ内の実 Python 実行 | `docs/assets/pyodide-lab.js` |
| [#8](https://github.com/hjosugi/auth-lab/issues/8) | PAR / JAR / JARM / RAR / CIBA / FAPI 2.0 | `authlab/oauth/` |
| [#9](https://github.com/hjosugi/auth-lab/issues/9) | ブラウザ標準 API による passkey E2E | `tests/browser/webauthn-e2e.mjs` |
| [#10](https://github.com/hjosugi/auth-lab/issues/10) | Cedar / Rego を含む5認可モデルの比較 | `authlab/authz/` |
| [#11](https://github.com/hjosugi/auth-lab/issues/11) | Ed25519 (RFC 8032) と ES256/384/512 の JOSE・COSE 対応 | `authlab/crypto/ed25519.py` |
| [#12](https://github.com/hjosugi/auth-lab/issues/12) | property / fuzz / プロトコル状態機械の適合検証 | `scripts/run_property_fuzz.py` |
| [#13](https://github.com/hjosugi/auth-lab/issues/13) | Java 21 / Spring Security 版の写経 | `spring-companion/` |
| [#14](https://github.com/hjosugi/auth-lab/issues/14) | 日英2言語の対話型シーケンス | `docs/assets/sequences.js` |
| [#15](https://github.com/hjosugi/auth-lab/issues/15) | Argon2id 対応と定数時間に関する注記 | `authlab/passwords/` |

## 攻撃対応（issue ではなく常時の検証項目）

`docs/09_attack_matrix.md` に CWE / OWASP マッピング付きで一覧化しています。

```bash
python attacks/catalog.py           # 素朴実装が破れる → authlab が防ぐ
python attacks/run_regressions.py   # 全防御をアサーションで回帰チェック
```

alg=none / アルゴリズム混同 / jwk ヘッダ注入 / ログイン CSRF / redirect_uri 前方一致 /
認可コード再利用 / PKCE ダウングレード / リフレッシュ再利用 / ID トークン誤用 / BOLA /
Bearer 窃取 / LDAP インジェクション / 匿名バインド / ユーザ列挙 / XML 署名ラッピング /
Kerberoasting / AS-REP roasting / ゴールデンチケット / pass-the-ticket / パディングオラクル /
WebAuthn オリジン偽装 / 署名カウンタ退行 / PAR・JAR・JARM・RAR・CIBA・FAPI のパラメータ注入と型混同

## 運用メモ

- issue の追加・更新は GitHub 上で行い、この索引を同期する。
- 学習トラッカー（#2, #3）は学習者がチェックを埋め終えたらクローズする。
- 新しい拡張を始めるときは、受け入れ条件を [docs/issue-backlog.md](docs/issue-backlog.md)
  に書いてから issue を立て、PR に `Closes #N` を付ける。
