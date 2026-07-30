# 15 - Property / fuzz / protocol-state conformance

例を1件ずつ書く通常のunit testに加え、「入力や操作順をseedから生成しても安全性が
崩れない」というpropertyを毎回検証する。外部fuzzerや実サービスは使わず、
Python標準ライブラリだけでローカル完結する。

## 実行

```bash
python scripts/run_property_fuzz.py

# CIの失敗を同じseedで再現
python scripts/run_property_fuzz.py \
  --seed 0xA17A2026 \
  --cases 128 \
  --max-size 256 \
  --max-steps 24 \
  --deadline-seconds 30
```

既定の出力先は`.tmp/property-fuzz/`。

- `seed.txt`: campaign全体のseed
- `summary.json`: propertyごとの派生seed、実行件数、上限、Python version
- `counterexamples.json`: 失敗した入力、失敗理由、delta-minimize後の最小入力

成功時のcounterexampleは空配列になる。失敗時もrunnerは先にseedを書き、
最小化した入力を残してからnon-zeroで終了する。CIは`if: always()`でこの3ファイルを
artifactとして保存するため、test failureでuploadがskipされない。

## 5つのproperty

| Property | 生成するもの | 常に成立すべき条件 |
|---|---|---|
| malformed compact token | segment数、空segment、base64url/JSON破損 | JOSE errorとして拒否し、内部例外を漏らさない |
| malformed / unsigned XML | truncate、nest不整合、duplicate attribute、DTD/entity | XML signature errorとして拒否し、DTD/entityを解決しない |
| malformed SCIM filter | 空白、括弧不整合、dangling operator、未知operator | `SCIMError invalidFilter`として拒否し、`IndexError`等を漏らさない |
| OAuth client state | begin前callback、別session、state不一致、callback再利用 | pending session/stateへ束縛し、成功callbackは一度だけ消費する |
| OAuth token state | code/refreshの発行前利用、rotation、任意順replay | 各credentialは一度だけ成功し、再利用時はfamilyをfail closedにする |

OAuthのoperation列そのものを生成するため、単に固定した「2回呼ぶ」テストではなく、
無関係な失敗や新しいrotationを挟んだ順序でもreplay防止を確認できる。

## Boundとminimize

既定値はpropertyごとに128 cases、入力256 bytes、状態遷移24 steps、campaign全体30秒。
CLIにも上限（5000 cases / 4096 bytes / 100 steps / 120秒）があり、巨大入力や
無制限探索をCIへ持ち込めない。各caseにも0.5秒のbudgetを置く。

失敗時は入力の連続chunkを取り除き、同じpropertyがまだ失敗する間だけ縮める。
このdelta debuggingは文字列にもoperation列にも同じように適用される。元入力と
最小入力を両方保存するので、原因調査で情報を失わない。

## 安全境界

生成値は最大長が決まったローカルfixtureだけで、network endpoint、実credential、
外部tenantを一切使わない。このrunnerが示すのは「この有界campaignでpropertyが
成立した」ことであり、全入力空間の数学的証明や本番fuzzerの代替ではない。
