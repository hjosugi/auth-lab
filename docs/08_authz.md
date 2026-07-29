# 08 - 認可モデル: RBAC / ABAC / ReBAC

> 実装: `authlab/authz/` / ドリル: `drills/08_authz_models.py`

認証は「あなたは誰か」、認可は「あなたは〜してよいか」。別々の失敗をし、たいてい別々の人が
書く。だからバグは2つ目に住む。表現力の弱い順に3モデル。

## RBAC (Role-Based Access Control)

権限がロールに付き、ロールがユーザに付く。「編集者は記事を公開できる」。
監査しやすく（「請求書を削除できる全員を出せ」）、コンプラ説明が楽。

要点:
- **階層**: `admin` ⊃ `editor` ⊃ `viewer`。継承がないと権限リストのコピペが増えてズレる。
  継承があるならサイクル検知が要る（さもないと解決が無限ループ）。auth-lab は DFS で検知。
- **命名**: `resource:action` はスケールする。フラットな `can_edit_invoice` はしない。
  ワイルドカード（`invoice:*`, `*:read`）は便利だが過剰付与が紛れるので、`explain()` で可視化。

**RBAC が言えないこと**: 「their own（自分の）」。`orders:read` はオブジェクトの**クラス**に
関する言明で、特定の1つに関しては何も言わない。要件に「自分の」「their」が出た瞬間、
ABAC か ReBAC が必要。飛ばすと BOLA を出荷する。

## ABAC (Attribute-Based Access Control)

subject / resource / action / environment の属性でルールを評価する小さなポリシエンジン。

**合成アルゴリズムがルール自体より重要**。auth-lab は **deny-overrides + default-deny**
（XACML の deny-overrides、AWS IAM と同じ）:

- **default-deny**: ポリシの無いリソースは閉じている。default-allow は全ての隙間で fail-open し、
  隙間は誰かが見つけるまで見えない。
- **deny-overrides**: 狙った例外（「契約社員は給与を読めない」）を、どこかの広い許可が
  覆せない。allow-overrides では信頼できる禁止が書けない。

コスト: 「なぜ拒否されたか」が難しくなる → 全 decision に発火したポリシ一覧を持たせる。

条件コンビネータ（`all_of`, `attr_equals`, `time_between`, `subject_matches_resource_owner` …）は
小さく合成可能でテスト可能に。中でも `subject_matches_resource_owner` が RBAC の言えない
「自分の」を表現する1個。

## ReBAC (Relationship-Based, Google Zanzibar 方式)

Google Drive / GitHub / Notion が実際に必要とするモデル。2019年の Zanzibar 論文が原典で、
OpenFGA / SpiceDB / Ory Keto / Auth0 FGA は全てその子孫。

全ては**関係タプル**:
```
object#relation@user       document:budget#viewer@user:alice
                           document:budget#editor@group:finance#member  ← userset
                           document:budget#parent@folder:2024
```
`user` 側が具体的な主体でも、別の**userset**（「group:finance の member 全員」）でもよい。
この間接参照1つで、グループ・ネストグループ・チームのチームが全部タダで出る。

各 relation には **userset rewrite** がある:
- `this` — 直接タプルされた者
- `computed_userset(r)` — この object の relation r の全員（「editor は viewer でもある」）
- `tuple_to_userset(t, r)` — relation t で別 object へ辿り、そこの relation r を取る
  （「親フォルダの viewer はここの viewer」＝階層継承）

アプリが実際に要るクエリ:
```
check(object, relation, user)     alice はこの doc を見られる?    ← ホットパス
expand(object, relation)          この doc を見られるのは誰?      ← 共有UI
list_objects(user, relation)      alice が見られるのは?          ← 一覧ページ
```
3つ目が肝。権限をアプリコードで計算すると「このユーザが見えるもの」を答えるのに全件ロード
してフィルタするしかなく、毎ページ O(全ドキュメント)。だから専用システムが要る。

サイクル対策: ネストグループは循環しうる（A⊃B⊃A）。無限再帰する check は自作 DoS なので
深さ上限を持つ（auth-lab は MAX_DEPTH）。

省略した本物の要素: zookie（古い ACL キャッシュでの "new enemy" を防ぐ整合性トークン）、
Leopard の反転インデックス、分散。評価セマンティクスは同じ。

## 実務での組み合わせ

現実は「粗い判定は RBAC、条件は ABAC、共有・階層があるものは ReBAC」。競合ではなく合成。

## 一言で

**RBAC は「編集者は記事を公開できる」。ABAC は「営業時間内に、社内ネットから、10万円未満の
経費を、MFA 済みマネージャが承認できる」。ReBAC は「この文書の親フォルダの編集者グループの
メンバーなら見られる」。要件に『自分の』が出たら RBAC では不可＝そこが BOLA の入口。**
