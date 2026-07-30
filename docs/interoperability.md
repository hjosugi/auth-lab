# 実製品 interoperability profile

auth-lab の教材実装で可視化した検証項目を、実際の Keycloak、OpenLDAP、MIT
Kerberos が送受信する wire flow へ対応付ける任意プロファイルです。Python
ランタイムの依存なしという原則は変えず、Docker はこの統合検査を実行するときだけ使います。

> [!CAUTION]
> これは **localhost 専用の学習 fixture** です。外部システム、実アカウント、実credential
> を対象にしません。`fixture-only-*` 以外のcredentialを設定しないでください。

## 1コマンドで検査する

Docker Engine と Docker Compose が利用できる環境で、リポジトリのrootから実行します。

```bash
python scripts/run_interop.py --start
```

runner はcontainer imageをbuild/startし、readyになるまで待ち、4 protocolの正常系と
異常系を実行してからvolumeごと停止します。成功時の標準出力は次のようなstatusだけです。

```text
[interop] OIDC     valid credentials  PASS
[interop] OIDC     wrong client secret REJECTED
[interop] SAML     valid credentials  PASS
[interop] SAML     wrong password     REJECTED
[interop] LDAP     valid bind/search  PASS
[interop] LDAP     wrong password     REJECTED
[interop] Kerberos valid AS/TGS       PASS
[interop] Kerberos wrong password     REJECTED
[interop] profile  complete           PASS
```

途中でcontainerを観察する場合だけ `--keep` を追加し、終了時に明示的に片付けます。

```bash
python scripts/run_interop.py --start --keep
docker compose -f interop/compose.yaml down --volumes --remove-orphans
```

## 実装と検証bindingの対応

| Protocol | 実製品 | 実際に行うflow | auth-labへ対応する検証 | 負例 |
|---|---|---|---|---|
| OIDC | Keycloak 26.7.0 | discovery → token endpoint → JWKS | `JWTValidator` がRS256署名、`iss`、`aud`、`exp`、`iat`、subjectを検証 | 誤ったclient secretを4xxで拒否 |
| SAML 2.0 | Keycloak 26.7.0 | SAML client → IdP login → HTTP-POST Response | Response、Assertion、XML Signature、NameIDを同じresponseで確認 | 誤ったpasswordではassertionを発行しない |
| LDAP | OpenLDAP / Debian bookworm | simple bind → subtree search | bind DN、search base、返された`uid=learner`を対応付ける | 誤ったpasswordをInvalid credentialsで拒否 |
| Kerberos v5 | MIT Kerberos / Debian bookworm | `kinit` AS exchange → `kvno` TGS exchange | client principal、realm、TGT、対象service principalを対応付ける | 誤ったpasswordをpreauthentication failureで拒否 |

OIDCのfixtureは、token endpointとJWT/JWKSの相互運用を小さく再現するために
KeycloakのDirect Access Grantを有効化しています。これは学習fixtureのみに限定し、
本番browser loginの推奨方式にはしません。本番のユーザloginではAuthorization Code +
PKCEを使います。

## 外部へ出ない構成

`interop/compose.yaml` は製品だけでなく検査runnerも `internal: true` のDocker networkへ
入れます。hostへ公開するportはありません。runner imageにだけLDAP/Kerberos clientを
入れ、Python sourceはread-only、redacted evidence directoryだけをwrite可能でmountします。

| Service | Internal endpoint | Container networkでの役割 |
|---|---|---|
| runner | product DNSだけを利用 | protocol client / verifier |
| Keycloak | `keycloak:8080` | OIDC issuer / SAML IdP |
| OpenLDAP | `openldap:1389` | directory server |
| MIT Kerberos | `kerberos:88` (TCP/UDP) | KDC |

realm、directory、KDCは起動ごとに固定fixtureから再構築され、runnerの終了時にvolumeと
一緒に破棄されます。Keycloakのadmin accountもfixtureのimport/startにしか使いません。
image取得はcontainer起動前にDocker Engineが行い、起動後のfixture networkには外向きの
default routeを与えません。

## redacted trace

検査結果は `.tmp/interop/trace.jsonl` にJSON Linesとして残ります。保存するのは
protocol、scenario、`PASS` / `REJECTED`、検証済みbindingだけです。

```json
{"details":{"audience":"authlab-oidc","signature_verified":true,"subject_bound":true},"protocol":"OIDC","scenario":"valid credentials","status":"PASS"}
{"details":{"result":"invalid credentials"},"protocol":"LDAP","scenario":"wrong password","status":"REJECTED"}
```

次の値はkey名と実値の両方でmaskします。

- passwordとclient/admin/master secret
- access token、ID token、Authorization header
- SAML Response / Assertion
- compact JWTに見える3 segmentの値

runner自身もtokenやassertionを標準出力へ出しません。失敗時のmessageとdiagnostic
artifactにも同じmaskを適用し、container statusと末尾logだけを
`.tmp/interop/diagnostics.txt` に保存します。

## GitHub Actionsでの実製品検証

`.github/workflows/interop.yml` はPRと`main`で同じrunnerを実行し、redacted traceと
sanitized container statusをartifactとして保存します。通常の `scripts/verify.py` は
Dockerを要求しないため、依存なしの高速gateと実製品gateを分離できます。

ローカルにDocker daemonがない場合でもunit/static gateは実行できます。

```bash
python -m unittest tests.test_interop
docker compose -f interop/compose.yaml config --quiet  # daemon不要
```

実製品との成功を主張できるのは、`interop.yml` のDocker jobが成功したcommitだけです。
unit testやCompose構文検査の成功を、実製品flowの成功とは扱いません。

## sourceを追う

- runnerとredaction: [`scripts/run_interop.py`](../scripts/run_interop.py)
- local topology: [`interop/compose.yaml`](../interop/compose.yaml)
- Keycloak realm: [`interop/keycloak/auth-lab-interop-realm.json`](../interop/keycloak/auth-lab-interop-realm.json)
- OpenLDAP fixture: [`interop/openldap/`](../interop/openldap/)
- MIT Kerberos fixture: [`interop/kerberos/`](../interop/kerberos/)
- isolated protocol client: [`interop/runner/`](../interop/runner/)
- unit/negative checks: [`tests/test_interop.py`](../tests/test_interop.py)

製品側の起動方法は
[Keycloak container guide](https://www.keycloak.org/server/containers) と
[realm import/export guide](https://www.keycloak.org/server/importExport) に対応させています。
