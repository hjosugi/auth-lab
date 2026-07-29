# 図集（プロトコル・フロー図）

全プロトコルのシーケンス図・構造図。GitHub 上でそのまま描画される（Mermaid）。
ブラウザ Playground の「Diagrams」タブでも見られる。

- [全体像](#全体像)
- [JWT の構造](#jwt-の構造)
- [OAuth 2.0 Security BCP: 認可コード + PKCE](#oauth-20-security-bcp-認可コード--pkce)
- [リフレッシュトークン ローテーション + 再利用検知](#リフレッシュトークン-ローテーション--再利用検知)
- [OIDC: ID トークン vs アクセストークン](#oidc-id-トークン-vs-アクセストークン)
- [デバイスフロー](#デバイスフロー-rfc-8628)
- [DPoP 送信者制約](#dpop-送信者制約-rfc-9449)
- [mTLS ハンドシェイク](#mtls-ハンドシェイク)
- [SAML Web SSO](#saml-web-sso)
- [XML 署名ラッピング (XSW)](#xml-署名ラッピング-xsw)
- [Kerberos AS/TGS/AP](#kerberos-astgsap)
- [WebAuthn 登録](#webauthn-登録)
- [WebAuthn 認証](#webauthn-認証)
- [リソースサーバの8ステップ](#リソースサーバの8ステップ)
- [認可モデル RBAC/ABAC/ReBAC](#認可モデル-rbacabacrebac)

---

## 全体像

認証は「誰か」、認可は「何をしてよいか」。OAuth は委譲認可、OIDC がその上に認証を足す。

```mermaid
flowchart TD
    U["人・端末"] --> A["Authentication<br/>本人確認"]
    A --> C["Credential / Session / Token"]
    C --> Z["Authorization<br/>操作してよいか"]
    Z --> R["Protected Resource"]
    I["IdP / Authorization Server"] --> C
    D["LDAP / SCIM / HR"] --> I
    P["RBAC / ABAC / ReBAC"] --> Z
```

---

## JWT の構造

3つの base64url をドットで繋ぐ。署名対象は先頭2セグメントのテキスト。

```mermaid
flowchart LR
    H["header<br/>{alg, typ, kid}"] -->|base64url| HS["eyJhbG..."]
    P["payload<br/>{iss, sub, aud,<br/>exp, nbf, iat, jti}"] -->|base64url| PS["eyJzdWI..."]
    HS --> SI["signing input =<br/>header . payload"]
    PS --> SI
    SI -->|sign with key| SG["signature"]
    SG -->|base64url| SGS["4s0h2p..."]
    HS --> T["JWT = header.payload.signature"]
    PS --> T
    SGS --> T
```

検証時: 受信した `header.payload` のテキストをそのまま検証する（再シリアライズ禁止）。

---

## OAuth 2.0 Security BCP: 認可コード + PKCE

一番の山場。verifier はクライアントに留まり、challenge（そのSHA-256）だけがブラウザを通る。

```mermaid
sequenceDiagram
    autonumber
    participant U as User
    participant C as Client (SPA)
    participant B as Browser
    participant AS as Authorization Server
    participant API as Resource Server

    U->>C: ログイン
    Note over C: state, nonce, code_verifier を生成<br/>challenge = SHA-256(verifier)
    C->>B: /authorize?client_id&redirect_uri<br/>&state&code_challenge=...&S256
    B->>AS: 認可リクエスト（challengeのみ）
    AS->>U: ログイン画面（PW + MFA）
    U->>AS: 資格情報
    Note over AS: client_id / redirect_uri を検証（完全一致）<br/>code を challenge に束縛
    AS->>B: 302 redirect_uri?code=...&state=...
    B->>C: callback（code, state）
    Note over C: 保存した state と一致を確認（CSRF防御）
    C->>AS: POST /token（back channel）<br/>code + code_verifier
    Note over AS: redirect_uri再確認 / SHA-256(verifier)==challenge<br/>code を used に
    AS->>C: access_token + refresh_token + id_token
    Note over C: id_token を完全検証<br/>署名/iss/aud=client/nonce
    C->>API: Authorization: Bearer access_token
    Note over API: 署名/typ/iss/aud/exp/scope/所有権
    API->>C: 200 データ
```

---

## リフレッシュトークン ローテーション + 再利用検知

漏洩したトークンの再提示を検知し、family ごと失効する。

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant AS as Authorization Server
    Note over AS: 1ログインの子孫は同じ family_id

    C->>AS: refresh_token=R1
    AS->>C: R2（R1 は used に）
    C->>AS: refresh_token=R2
    AS->>C: R3（R2 は used に）
    Note over C,AS: --- ここで R1 が漏洩し攻撃者が使う ---
    C-->>AS: refresh_token=R1（rotated済みの再提示）
    Note over AS: 再利用検知！<br/>family 全体を失効
    AS-->>C: invalid_grant（family revoked）
    Note over C,AS: 正規ユーザも攻撃者も失効<br/>＝漏洩への正しい対応
```

---

## OIDC: ID トークン vs アクセストークン

`aud` が別。ID トークンを API に投げると RS が typ/aud で拒否する。

```mermaid
flowchart TB
    subgraph ID["ID トークン (OIDC)"]
        direction TB
        ID1["aud = client_id"]
        ID2["用途: 誰がログインしたか"]
        ID3["消費者: クライアント"]
        ID4["typ: JWT"]
    end
    subgraph AT["アクセストークン (OAuth)"]
        direction TB
        AT1["aud = API"]
        AT2["用途: このAPIを呼べるか"]
        AT3["消費者: リソースサーバ"]
        AT4["typ: at+jwt"]
    end
    X["ID トークンを API に送る"] -->|RS が拒否| REJ["typ=JWT≠at+jwt<br/>aud=client≠API"]
```

---

## デバイスフロー (RFC 8628)

TV/CLI 用。別デバイス（スマホ）で承認する。

```mermaid
sequenceDiagram
    autonumber
    participant TV as Device (TV/CLI)
    participant AS as Authorization Server
    participant Ph as User's Phone

    TV->>AS: POST /device_authorization
    AS->>TV: device_code, user_code, verification_uri, interval
    TV->>TV: 画面に user_code を表示
    loop interval ごとにポーリング
        TV->>AS: POST /token（device_code）
        AS-->>TV: authorization_pending / slow_down
    end
    Ph->>AS: verification_uri で user_code を入力し承認
    TV->>AS: POST /token（device_code）
    AS->>TV: access_token (+ refresh, id_token)
    Note over AS: device_code は単回使用
```

---

## DPoP 送信者制約 (RFC 9449)

トークンを鍵に束縛。盗んだトークンは秘密鍵なしでは無価値。

```mermaid
sequenceDiagram
    autonumber
    participant C as Client (holds P-256 key)
    participant AS as Authorization Server
    participant API as Resource Server

    Note over C: 鍵ペア生成。proof = ES256 署名<br/>{htm, htu, iat, jti, jwk(公開鍵)}
    C->>AS: POST /token + DPoP: proof
    Note over AS: proof検証。thumbprint(jwk)=jkt を算出
    AS->>C: access_token（cnf.jkt = 鍵thumbprint）, token_type=DPoP
    C->>API: DPoP access_token + DPoP: proof(+ath)
    Note over API: proof署名/htm/htu/iat/jti未使用<br/>thumbprint(proof.jwk)==token.cnf.jkt
    API->>C: 200
    Note over C,API: --- 攻撃者がトークンを盗む ---
    C-->>API: Bearer access_token（proof無し）
    API-->>C: 401（cnf付きをBearerで出した＝拒否）
```

---

## mTLS ハンドシェイク

クライアント認証を TLS ハンドシェイクの中に移す。CERT_REQUIRED。

```mermaid
sequenceDiagram
    autonumber
    participant C as Client (+client cert)
    participant S as Server (CERT_REQUIRED)
    participant CA as 信頼するCA

    C->>S: ClientHello
    S->>C: ServerHello + Server証明書 + CertificateRequest
    Note over C: Server証明書を CA と SAN で検証
    C->>S: Client証明書 + CertificateVerify（秘密鍵で署名）
    Note over S: Client証明書を CA で検証<br/>失敗ならハンドシェイクで切断
    S->>C: Finished（相互認証完了）
    Note over S: x5t#S256 = SHA-256(DER cert)<br/>→ RFC 8705 でトークンに束縛
```

---

## SAML Web SSO

OIDC と同じ形。SP が9項目を検証する。

```mermaid
sequenceDiagram
    autonumber
    participant U as User
    participant SP as Service Provider
    participant B as Browser
    participant IdP as Identity Provider

    U->>SP: 保護リソースへアクセス
    SP->>B: AuthnRequest（RelayState付き）
    B->>IdP: リダイレクト
    IdP->>U: ログイン
    U->>IdP: 資格情報
    Note over IdP: Assertion に XML-DSig 署名
    IdP->>B: 署名付き Response（POST）
    B->>SP: ACS へ Response
    Note over SP: 9項目検証:<br/>署名/署名対象=Assertion/Issuer/Status<br/>Recipient=自ACS/InResponseTo/Conditions<br/>Audience/replay
    SP->>U: セッション確立
```

---

## XML 署名ラッピング (XSW)

「署名された要素を返す」API で構造的に防ぐ。

```mermaid
flowchart TB
    subgraph Attack["攻撃者が細工した文書"]
        F["偽 Assertion（署名なし）<br/>NameID=admin"]
        O["元 Assertion（署名あり・digest一致）<br/>NameID=alice"]
    end
    V{"検証方法は?"}
    Attack --> V
    V -->|"verify(doc)→bool の後に<br/>doc.find('Assertion')"| BUG["偽Assertionを読む<br/>❌ 乗っ取り成立"]
    V -->|"verify(doc)→署名された要素 を返す"| SAFE["元Assertionだけ使う<br/>✅ 2つ目のAssertionは拒否"]
```

---

## Kerberos AS/TGS/AP

パスワードは kinit の一度だけ。以後はチケット。

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant AS as KDC (AS)
    participant TGS as KDC (TGS)
    participant Svc as Service (HTTP/web)

    Note over C: kinit（パスワードは一度だけ）
    C->>AS: AS-REQ + PA-ENC-TIMESTAMP
    AS->>C: TGT（krbtgt鍵で暗号化）+ セッションキー
    C->>TGS: TGS-REQ（TGT + authenticator + SPN）
    TGS->>C: サービスチケット（Svc鍵で暗号化）+ 新セッションキー
    C->>Svc: AP-REQ（サービスチケット + authenticator）
    Note over Svc: 自分の鍵で復号＝KDCが発行した証明<br/>authenticator で鮮度・リプレイ確認
    Svc->>C: AP-REP（相互認証）
```

golden ticket は krbtgt 鍵で TGT を偽造、Kerberoasting はサービスチケットをオフラインで割る。

---

## WebAuthn 登録

認証器が鍵ペアを作り、RP は**公開鍵だけ**を保存する。

```mermaid
sequenceDiagram
    autonumber
    participant U as User
    participant A as Authenticator
    participant B as Browser
    participant RP as Relying Party

    RP->>B: challenge + rp.id + pubKeyParams(ES256)
    B->>A: navigator.credentials.create
    Note over A: 鍵ペア生成（秘密鍵は出ない）<br/>authenticatorData(rpIdHash, flags, signCount)<br/>+ COSE公開鍵 + attestation
    A->>B: attestationObject + clientDataJSON
    B->>RP: 登録レスポンス
    Note over RP: origin一致/rpIdHash/UP,UV/challenge<br/>公開鍵を保存（秘密は保存しない）
    RP->>U: 登録完了
```

---

## WebAuthn 認証

署名がオリジンに束縛される＝フィッシング耐性。

```mermaid
sequenceDiagram
    autonumber
    participant U as User
    participant A as Authenticator
    participant B as Browser
    participant RP as Relying Party

    RP->>B: challenge + rpId + allowCredentials
    B->>A: navigator.credentials.get（origin付き）
    Note over A: rp_id に鍵が無ければ署名しない<br/>＝偽サイトには何も返らない
    A->>B: signature over<br/>authenticatorData ‖ SHA-256(clientDataJSON)
    B->>RP: アサーション
    Note over RP: origin完全一致/rpIdHash/UP,UV<br/>公開鍵で署名検証/signCount単調増加
    RP->>U: ログイン成功
```

---

## リソースサーバの8ステップ

「valid token ≠ authorized」。8がBOLA。

```mermaid
flowchart TD
    T["Bearer / DPoP トークン"] --> S1["1. 署名（JWKSのkid, alg固定）"]
    S1 --> S2["2. typ = at+jwt（IDトークンを弾く）"]
    S2 --> S3["3. iss = 信頼するAS"]
    S3 --> S4["4. aud が自分を含む"]
    S4 --> S5["5. exp / nbf / iat"]
    S5 --> S6["6. 送信者制約（cnf: DPoP/mTLS）"]
    S6 --> S7["7. scope（このエンドポイント）"]
    S7 --> S8["8. 所有権（このユーザのこのオブジェクトか）"]
    S8 --> OK["データを返す"]
    S8 -.-> BOLA["scope だけでは不十分<br/>❌ BOLA / IDOR<br/>OWASP API #1"]
```

---

## 認可モデル RBAC/ABAC/ReBAC

表現力の弱い順。要件に「自分の」が出たら RBAC では不可。

```mermaid
flowchart TB
    subgraph RBAC["RBAC — ロール"]
        R1["user → role → permission"]
        R2["admin ⊃ editor ⊃ viewer"]
        R3["「their own」は言えない"]
    end
    subgraph ABAC["ABAC — 属性 + ポリシー"]
        A1["subject / resource / action / env"]
        A2["deny-overrides + default-deny"]
        A3["subject.sub == resource.owner"]
    end
    subgraph ReBAC["ReBAC — 関係グラフ (Zanzibar)"]
        Z1["object#relation@user"]
        Z2["computed / tuple_to_userset"]
        Z3["ネストグループ・フォルダ継承"]
    end
    RBAC -->|条件が要る| ABAC
    ABAC -->|共有・階層が要る| ReBAC
```

ReBAC の check の例（alice がフォルダ継承経由で文書を閲覧）:

```mermaid
flowchart LR
    A["user:alice"] -->|member| G["group:eng"]
    G -->|viewer| F["folder:2024"]
    F -->|parent| D["document:budget"]
    D -.->|"tuple_to_userset(parent, viewer)"| RESULT["check(document:budget, viewer, alice) = true"]
```
