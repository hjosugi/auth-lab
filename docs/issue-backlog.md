# GitHub Issue backlog

このファイルは、現在完成している教材の「未実装」を明確にし、GitHub Issuesと
同じ受け入れ条件を保持します。基礎ラボの完成条件ではなく、実製品との相互運用を
深める次段階です。

## Live Issue index

2026-07-29時点のGitHub Issuesを、学習トラッカーと実装backlogに分けて記録します。
詳細と最新状態は各Issueを正とします。

| Issue | 状態 | 種別 | 内容 |
|---:|---|---|---|
| [#2](https://github.com/hjosugi/auth-lab/issues/2) | Open | 学習 | Week 1: 土台とトークン（Day 1–7） |
| [#3](https://github.com/hjosugi/auth-lab/issues/3) | Open | 学習 | Week 2: エンタープライズと高度なトークン（Day 8–14） |
| [#4](https://github.com/hjosugi/auth-lab/issues/4) | Closed | CI | Actionsで全検証を実行、badgeを追加 |
| [#5](https://github.com/hjosugi/auth-lab/issues/5) | Closed | SAML | exc-c14nと実IdP相互運用 |
| [#6](https://github.com/hjosugi/auth-lab/issues/6) | Open | Interop | OAuth/LDAP/Kerberos/SAML container lab |
| [#7](https://github.com/hjosugi/auth-lab/issues/7) | Open | Pages | Pyodideで実Pythonモジュールを実行 |
| [#8](https://github.com/hjosugi/auth-lab/issues/8) | Closed | OAuth | PAR/JAR/JARM/RAR/CIBA/FAPI 2.0 |
| [#9](https://github.com/hjosugi/auth-lab/issues/9) | Open | WebAuthn | 実ブラウザpasskey E2E |
| [#10](https://github.com/hjosugi/auth-lab/issues/10) | Closed | Authz | Cedar/Rego/RBAC/ABAC/ReBAC比較 |
| [#11](https://github.com/hjosugi/auth-lab/issues/11) | Closed | Crypto | Ed25519とES256のJOSE/WebAuthn対応 |
| [#12](https://github.com/hjosugi/auth-lab/issues/12) | Open | Testing | property/fuzz/conformance test |
| [#13](https://github.com/hjosugi/auth-lab/issues/13) | Open | Spring | Java 21 Spring Security companion |
| [#14](https://github.com/hjosugi/auth-lab/issues/14) | Closed | Pages | 二言語interactive sequence |
| [#15](https://github.com/hjosugi/auth-lab/issues/15) | Closed | Password | Argon2idと定数時間注記 |

## 1. Containerized interoperability lab

**Goal:** KeycloakまたはSpring Authorization Server、OpenLDAP、MIT Kerberos、
SAML IdPを起動し、教材実装の概念を実製品のwire flowへ対応付ける。

**Acceptance criteria:**

- Docker Composeは明示的なローカル専用networkで起動する。
- OAuth/OIDC、LDAP、Kerberos、SAMLを最低1フローずつ実行する。
- fixture secretだけを使い、実credentialを要求しない。
- traceからsecret/tokenをredactする。
- `docs/interoperability.md`にラボ実装との対応表を載せる。

## 2. Advanced OAuth and FAPI profiles

**Goal:** PAR、JAR、JARM、RAR、CIBAとFAPI 2.0を追加する。

**Acceptance criteria:**

- 各profileの脅威モデルと追加bindingを図示する。
- successとnegative testを各1件以上追加する。
- Security ProfileとMessage Signingの適用範囲を分離する。
- OAuth 2.1 draft/statusを固定規格として誤記しない。

## 3. Browser-native passkey end-to-end lab

**Goal:** 実ブラウザのWebAuthn APIとvirtual authenticatorで登録・認証を試す。

**Acceptance criteria:**

- localhostまたはHTTPSで動く。
- resident credential、user verification、discoverable loginを比較する。
- origin/RP ID不一致をnegative testにする。
- attestation、sync、backup eligibilityの説明を追加する。

## 4. Policy engines: Cedar, Rego, and relationship authorization

**Goal:** 同じaccess matrixをRBAC、ABAC、ReBAC、Cedar/Regoで表現・比較する。

**Acceptance criteria:**

- tenant境界、owner、group nesting、explicit denyを含む。
- decision parity testを追加する。
- list-objectsとcheckの性能・整合性tradeoffを記録する。
- policy decision logのprivacy要件を示す。

## 5. Property, fuzz, and conformance testing

**Goal:** parserと状態遷移へproperty test/fuzzingを追加する。

**Acceptance criteria:**

- malformed compact token/XML/SCIM filterでprocessがcrashしない。
- replayは任意の並びでも二度目を拒否する。
- OAuth state machineの不正遷移を自動生成する。
- seedと最小化したcounterexampleをCI artifactに保存する。

## 6. Java 21 Spring Security companion application

**Goal:** 本ラボの検証項目を本番向けSpring Security構成へ写経する。

**Acceptance criteria:**

- OIDC login、JWT/opaque resource server、method securityを含む。
- issuer/audience/type/scope/object ownershipをテストする。
- CSRF/CORS/session cookie判断を脅威モデルで説明する。
- `docs/spring-security-map.md`から相互リンクする。

## 7. Interactive sequence animations and bilingual narration

**Goal:** Pagesのflow図を操作可能にし、日本語/英語で同じ概念を説明する。

**実装:** [GitHub PagesのFlows × 4](https://hjosugi.github.io/auth-lab/) と
`docs/assets/sequences.js`。21 messageすべてにasset、trust boundary、bindingの共通concept IDと
日英narrationを持ち、`tests/browser/sequence-player.test.js`でcontrolsとaccessibilityを検証する。

**Acceptance criteria:**

- OAuth、SAML、Kerberos、WebAuthnの4フローをstep実行できる。
- 各stepでasset、trust boundary、bindingを表示する。
- keyboard操作、reduced motion、contrastを検証する。
- narrationは日本語/英語で意味が一致する。
