# 08 - 認可モデル: RBAC / ABAC / ReBAC / Cedar / Rego

> 実装: `authlab/authz/` / ドリル: `drills/08_authz_models.py`
> 図: [RBAC/ABAC/ReBAC](diagrams.md#認可モデル-rbacabacrebac) / [リソースサーバ8ステップ(BOLA)](diagrams.md#リソースサーバの8ステップ)

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

## 同じ行列を5モデルで判定する

`authlab/authz/policy_comparison.py` は、同じ subject / resource / action を5つのアダプタへ渡す。
比較対象は次の4つの境界を全部含む。

- tenant が違えば、グループ関係があっても拒否
- owner と tenant admin は read / write を許可
- `platform` のメンバーは、ネストされた親グループ `eng` を経由して read だけ許可
- `locked` の明示的 deny は owner や admin の allow より強い

```python
from authlab.authz import AccessRequest, PolicyComparison, canonical_dataset

lab = PolicyComparison(canonical_dataset())
decisions = lab.decide_all(AccessRequest("alice", "read", "budget"))
assert {decision.allowed for decision in decisions.values()} == {True}
```

| モデル | この行列をどう表すか | ネイティブでない部分 |
|---|---|---|
| RBAC | resource ごとの `owner:*` / `reader:*` role を事前生成 | tenant と explicit deny はアプリ側 guard。「自分の」を role に materialize すると更新コストが出る |
| ABAC | subject/resource 属性、deny-overrides、default-deny | ネストグループの到達集合を subject 属性へ事前計算 |
| ReBAC | owner、reader group、nested group を relation tuple で辿る | tenant と explicit deny は union-only のタプル評価外に guard を置く |
| Cedar | entity hierarchy、`permit`、`forbid` | このリポジトリは Cedar runtime を埋め込まず、同じ意味の標準ライブラリアダプタを実行 |
| Rego | structured input/data、`graph.reachable`、`default allow := false` | このリポジトリは OPA runtime を埋め込まず、同じ意味の標準ライブラリアダプタを実行 |

「同じ答えになる」は「同じモデル」という意味ではない。RBAC は関係を role に展開し、ABAC は
group closure を属性に展開する。ReBAC / Cedar は関係を辿り、Rego は data graph の到達集合を
作る。テストは答えの parity と、各モデルがその答えを出した理由の両方を確認する。

### Cedar と Rego の合成規則

Cedar の標準アルゴリズムは default-deny かつ forbid-overrides-permit。1つでも満たされた
`forbid` があれば、満たされた `permit` があっても Deny になる。`CEDAR_POLICY` では
cross-tenant と locked を `forbid` にした。

Rego の例は `default allow := false` で fail closed にし、`allow if { permit; not deny }` で
deny を優先する。Rego のルール自体を再帰させるのではなく、nested group は
`graph.reachable(data.group_parents, input.subject.direct_groups)` で解決する。実際の Cedar / OPA
への相互運用は依存なしのコアとは分離すべきであり、このラボのクラス名に
「本物の runtime を実行した」という意味はない。

## check と list-objects のコスト・整合性

`check(subject, action, resource)` が速くても、一覧画面の
`list_objects(subject, action)` が速いとは限らない。ラボの
`list_objects_all()` は全モデルで意図的に candidate 数、経過 `ns`、戦略、整合性モデルを返す。
経過時間は環境依存なのでテストで順位を決めず、候補数と結果集合を検証する。

| モデル | check の主なコスト | このラボの list-objects | 本番で必要になるもの |
|---|---|---|---|
| RBAC | effective role と permission の照合 | materialized role + 全resource走査 | role/resource の反転索引、materialization 更新 |
| ABAC | 適用policy数と属性取得 | resourceごとのpolicy再評価 | resource索引、policyで安全に絞れる条件の抽出 |
| ReBAC | relation graph の探索 | tuple候補 + graph check | 反転索引、キャッシュ、Zanzibar型の整合性token |
| Cedar | relevant policy/entity の評価 | resourceごとのpolicy再評価 | entity slice、索引、更新snapshotの設計 |
| Rego | rule とdata graph の評価 | resourceごとのrule再評価 | partial evaluation、索引可能なdata、bundle revision |

ラボの結果は1つの不変なメモリsnapshotなので互いに整合する。しかし分散環境では、アクセスを
外した直後に古い一覧結果が返る **new enemy problem** がある。check と list-objects が同じ
revisionを読んだことを証明する token（Zanzibar の zookie、policy bundle revision など）が
なければ、単に「テストが同じ集合だった」だけで強い整合性を主張してはいけない。

## relationship のサイクルと深さ

`A contains B contains A` はデータとして作れてしまう。`ReBAC.check()` と `expand()` は現在の
探索pathを保持し、再訪を cycle として止める。さらに `max_depth`（既定25）で、非循環でも
極端に深い graph を止める。比較用 `PolicyDataset.resolve_group()` も
`cycle_detected` / `depth_limited` を返す。

重要なのは global な `seen` ではなく **path-local** な集合を使うこと。別branchで同じ
usersetに到達する正当な経路まで「既に見た」と捨てると、false deny になる。

## decision log のプライバシー

認可ログは incident response に必要だが、policy input を丸ごと記録すると、メール、IP、
resource名、tenant、token、医療・人事属性まで集めた二次データベースになる。
`PrivacyPreservingDecisionLog` は次だけを保持する。

- HMAC-SHA-256 で domain separation した subject / resource / request / policy の参照値
- allow/deny、action、固定された reason code、model
- `low` / `medium` / `high` の粗い risk bucket
- `occurred_at` と `expires_at`。期限後は `purge()` で削除

任意context、raw policy input、メール、IP、tokenは保存しない。HMAC鍵はログと別管理し、
定期ローテーション、保存時暗号化、最小権限、監査、用途に合った短いretentionを組み合わせる。
仮名化は匿名化ではない。同じ鍵なら同じ主体を相関できるため、ログ自体を機密データとして扱う。

## 実務での組み合わせ

現実は「粗い判定は RBAC、条件は ABAC、共有・階層があるものは ReBAC」。競合ではなく合成。

## 一言で

**RBAC は「編集者は記事を公開できる」。ABAC は「営業時間内に、社内ネットから、10万円未満の
経費を、MFA 済みマネージャが承認できる」。ReBAC は関係graph、Cedar は typed entity と
permit/forbid、Rego はdataに対する宣言的ruleで同じ問いを表す。要件に『自分の』が出たら
素のRBACでは不可。そこがBOLAの入口。**
