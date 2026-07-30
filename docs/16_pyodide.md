# 16 - Pyodide browser Python REPL

## 何を確認するか

[GitHub Pages の Python REPL](https://hjosugi.github.io/auth-lab/#t-pyodide) は、
JavaScript で同じ処理を書き直すデモではない。Pages build が `authlab/**/*.py` だけを
決定的 ZIP にし、version 固定の
[Pyodide stable runtime](https://pyodide.org/en/stable/usage/downloading-and-deploying.html)
へ展開する。preset は実際の `JWT.issue()` と `JWTValidator.validate()` を呼び、
正常 token を受理したあと、payload だけを差し替えた token を署名不正として拒否する。

既存ページの初期表示では Pyodide を取得しない。Python REPL タブを選んだときだけ
Web Worker が runtime と source bundle を遅延ロードする。Python が長く動いても UI thread と
分離され、必要なら「worker をリセット」で停止できる。

## ローカル実行

```bash
python scripts/build_pyodide_bundle.py
python -m http.server -d docs 8000
# http://localhost:8000/#t-pyodide
```

生成される `docs/assets/authlab-pyodide.zip` は build artifact で、Git には含めない。
GitHub Pages workflow も同じ script で毎回 main の source から生成する。

## Password KDF の差

WebAssembly build では OpenSSL 依存の `hashlib.scrypt` が利用できない場合がある。
起動時に小さい fixture を実行して確認し、利用不可なら `Pbkdf2Params` の
純 Python PBKDF2-HMAC-SHA256 fallback を検証して status に表示する。fallback は同じ入力で
CPython の `hashlib.pbkdf2_hmac` と同じ出力になることを unit test で固定している。

これは「PBKDF2 が scrypt と同等」という意味ではない。PBKDF2 は memory-hard ではないため、
本番の password policy は Argon2id/scrypt と適切な native implementation を使う。

## 実行しない領域

- `socket`、`ssl`、`authlab.mtls`、X.509 socket flow は browser import guard で止める。
  実 TLS handshake は `python drills/12_mtls.py` をローカルで実行する。
- 入力した source は browser 内で CPU とメモリを消費する。fixture 以外の secret を
  貼り付けず、browser sandbox を本番の認証・認可境界として扱わない。
- 教材の純 Python 暗号は、side-channel 耐性や適合認証を持つ本番用実装ではない。

## 検証

`tests/browser/pyodide-e2e.mjs` は実 Chrome/Brave で、初期表示が軽いこと、keyboard tab
navigation、Pyodide 3.14 の起動、実 authlab JWT の正常/改ざん拒否、socket guard、
mobile overflow、touch target を確認する。desktop/mobile screenshot は CI artifact
`browser-gui-evidence` に保存する。
