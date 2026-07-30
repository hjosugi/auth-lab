# 07 - LDAP と SCIM

> 実装: `authlab/directory/` / ドリル: `drills/13_ldap_scim.py`

LDAP は「認証の裏側」、SCIM は「アカウントの配布と失効」。どちらも地味だが、
ここでの失敗が「退職者がアクセスを持ち続ける」に直結する。

## LDAP

AD / OpenLDAP の裏にあるプロトコル。多くは認証フォームのバックエンドとして出会う。
DN はリーフ先頭で読む: `uid=alice,ou=people,dc=lab,dc=local`。

認証は BIND 操作で、2種類ある:

- **simple bind**: DN とパスワードを送り、サーバが照合。パスワードが平文で流れるので、
  TLS なしの simple bind はネットワーク上の平文資格情報。歴史的にデフォルト。
- **SASL bind**: 適切なメカニズム交渉（EXTERNAL=クライアント証明書, GSSAPI=Kerberos,
  SCRAM=チャレンジ応答）。こちらを使うべき。

### 2つの罠

**1. LDAP インジェクション**。定番の認証フィルタ:
```
(&(uid=<input>)(userPassword=<input>))
```
username に `*)(uid=*))(|(uid=*` を入れると全員にマッチ。`admin)(&)` で短絡も可能。
対策は RFC 4515 のフィルタエスケープ（`authlab/directory/ldap.py` の `escape_filter`）と、
そもそも**ユーザ入力からフィルタを組まない**こと: サービスアカウントで bind → ユーザを
パラメータで検索 → 見つかった DN で bind（search-then-bind）。

**2. 匿名バインドの罠**。LDAPv3 は「有効な DN + **空パスワード**」を**匿名バインド**と定義し、
これは**成功する**。だから「ユーザの DN とパスワードで bind して、成功したら認証成功」という
素朴なロジックは、パスワード欄を空にした誰でも通す。CVE 級で今も出荷されている。
auth-lab は空パスワードの bind を明示的に拒否する。

### auth-lab の正しい認証

```python
directory.authenticate(username, password, base_dn=...)
```
= search-then-bind + 空パスワード拒否 + フィルタエスケープ + 構文パーサ。パーサがあるので
インジェクションは「新しい句」ではなく「構文エラー」になる。

## SCIM 2.0 (RFC 7643/7644)

**認証**ではなく**プロビジョニング**（作成・更新・無効化）を跨システムで行う仕組み。
入社時に IdP（Okta/Entra/Google）が全 SaaS に「ユーザ作成」を push し、退職時に「無効化」を
push する。「deprovisioning」の配管であり、間違えると退職者がアクセスを保持する。

```
POST   /Users            作成
GET    /Users/{id}       取得
GET    /Users?filter=... 検索
PUT    /Users/{id}       全置換
PATCH  /Users/{id}       部分更新（active=false など）
DELETE /Users/{id}       削除
```

### SCIM 固有のセキュリティ課題

- **無効化 ≠ 削除**。IdP は `active:false` を PATCH で送る。アプリが DELETE だけを
  「アクセス剥奪」と扱い、IdP が PATCH しか送らないと、アカウントが残る。
  → **`active` を全リクエスト（最低でもトークン更新時）で確認する**。auth-lab の
  `is_active()` がそれ。SCIM はフラグを立てるだけで、切るのはアプリの責任。
- SCIM エンドポイントは超高価値。1つの bearer トークンでテナント全 ID を作成・改変できる。
  漏れたら「テナント全体のアカウント作成プリミティブ」。テナントスコープで厳重に。
- **externalId** が IdP のキー、`id` が自分のキー。email や username で突合すると、改名や
  email 再利用で2人のアクセスが混ざる。
- フィルタ（RFC 7644 §3.4.2）はクエリ言語。バックエンドに注入すれば LDAP と同じ問題
  （auth-lab はパースして値として扱う）。
- 空、括弧不整合、dangling operator、未知operatorはすべて`SCIMError invalidFilter`へ
  正規化する。`scripts/run_property_fuzz.py`が有界な生成入力で、内部の`IndexError`等を
  trust boundaryの外へ漏らさないことを回帰する。

## 一言で

**LDAP は「空パスワード＝匿名バインドが成功する」罠と「入力からフィルタを組む」罠を
search-then-bind で塞ぐ。SCIM は「無効化は delete でなく active:false で来る、そして
アプリが active を毎回見ないと退職者が残る」。**
