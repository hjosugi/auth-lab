/* Bilingual, keyboard-operable protocol sequence player.
 *
 * The data and controller are usable from both a browser and Node's built-in
 * test runner.  No DOM emulator or third-party dependency is required.
 */
(function exposeSequencePlayer(globalScope) {
  "use strict";

  const text = (ja, en) => Object.freeze({ ja, en });
  const fact = (id, ja, en) => Object.freeze({ id, ...text(ja, en) });
  const step = (from, to, message, narration, asset, boundary, binding) =>
    Object.freeze({ from, to, message, narration, asset, boundary, binding });

  const SEQUENCES = Object.freeze({
    oauth: Object.freeze({
      name: text("OAuth 2.0 認可コード + PKCE", "OAuth 2.0 Authorization Code + PKCE"),
      steps: Object.freeze([
        step(
          "User", "Client",
          text("ログイン開始", "Start sign-in"),
          text("ユーザがクライアントに委譲認可を開始させる。", "The user asks the client to start delegated authorization."),
          fact("browser-session", "ブラウザセッション", "browser session"),
          fact("user-client", "ユーザとクライアントの操作境界", "user-to-client interaction boundary"),
          fact("intent", "ユーザ操作がtransactionを開始", "user intent starts this transaction"),
        ),
        step(
          "Client", "Authorization Server",
          text("認可request + S256 challenge", "Authorization request + S256 challenge"),
          text("client_id、完全一致redirect URI、state、nonce、PKCE challengeを送る。verifierは送らない。", "Send client_id, the exact redirect URI, state, nonce, and the PKCE challenge. The verifier does not travel."),
          fact("authorization-request", "認可request", "authorization request"),
          fact("front-channel", "ブラウザを通るfront channel", "browser-mediated front channel"),
          fact("state-pkce-challenge", "stateはtransactionへ、challengeは後のcode交換へ束縛", "state binds the browser transaction; the challenge binds the later code exchange"),
        ),
        step(
          "Authorization Server", "User",
          text("認証 + 同意", "Authentication + consent"),
          text("認可サーバだけがユーザを認証し、clientとscopeへの同意を確認する。", "Only the authorization server authenticates the user and confirms consent for the client and scopes."),
          fact("credential-consent", "credentialと同意", "credential and consent"),
          fact("as-user", "認可サーバとユーザの認証境界", "authorization-server-to-user authentication boundary"),
          fact("authenticated-session", "認証済みsessionとclient/scopeを結合", "the authenticated session is joined to the client and scopes"),
        ),
        step(
          "Authorization Server", "Client",
          text("code + state", "Code + state"),
          text("短命・単回のcodeをredirect URIへ返す。clientは保存済みstateと完全一致を確認する。", "Return a short-lived, single-use code to the redirect URI. The client compares state exactly with its stored value."),
          fact("authorization-code", "認可code", "authorization code"),
          fact("front-channel-return", "信頼しないブラウザ経由の戻り", "return through the untrusted browser"),
          fact("code-client-redirect", "codeをclient、redirect URI、challenge、subjectへ束縛", "the code is bound to the client, redirect URI, challenge, and subject"),
        ),
        step(
          "Client", "Authorization Server",
          text("code + verifier", "Code + verifier"),
          text("back channelでcodeと秘密のverifierを送り、S256が保存済みchallengeと一致することを証明する。", "Send the code and secret verifier over the back channel, proving that S256 matches the stored challenge."),
          fact("pkce-verifier", "PKCE verifier", "PKCE verifier"),
          fact("token-endpoint", "clientからtoken endpointへのback channel", "client-to-token-endpoint back channel"),
          fact("pkce", "verifier所持を認可requestのchallengeへ束縛", "proof of verifier possession is bound to the authorization-request challenge"),
        ),
        step(
          "Authorization Server", "Client / API",
          text("ID token / access token / refresh token", "ID token / access token / refresh token"),
          text("ID tokenはclient audience、access tokenはAPI audience。clientとAPIは用途、issuer、audience、期限を別々に検証する。", "The ID token targets the client; the access token targets the API. Each validates purpose, issuer, audience, and expiry independently."),
          fact("tokens", "用途の異なるtoken", "purpose-specific tokens"),
          fact("issuer-consumers", "issuerからclient/APIへのtrust boundary", "issuer-to-client/API trust boundary"),
          fact("signature-audience", "署名、issuer、audience、token typeで受信者へ束縛", "signature, issuer, audience, and token type bind each token to its consumer"),
        ),
      ]),
    }),
    saml: Object.freeze({
      name: text("SAML 2.0 Web SSO", "SAML 2.0 Web SSO"),
      steps: Object.freeze([
        step(
          "User / Browser", "Service Provider",
          text("保護resourceへアクセス", "Request a protected resource"),
          text("SPはlocal sessionがないことを確認し、一回性request IDとRelayStateを作る。", "The SP finds no local session and creates a one-time request ID and RelayState."),
          fact("sp-session", "SP sessionと元のURL", "SP session and original URL"),
          fact("browser-sp", "ブラウザとSPの境界", "browser-to-SP boundary"),
          fact("relay-state", "RelayStateを元のSP transactionへ束縛", "RelayState binds the return to the original SP transaction"),
        ),
        step(
          "Service Provider", "Identity Provider",
          text("AuthnRequest", "AuthnRequest"),
          text("SP entity ID、IdP宛先、ACS、request IDを含むAuthnRequestをbrowserで運ぶ。", "Carry an AuthnRequest containing the SP entity ID, IdP destination, ACS, and request ID through the browser."),
          fact("authn-request", "AuthnRequest", "AuthnRequest"),
          fact("federation-front-channel", "SPからIdPへのfront channel", "SP-to-IdP front channel"),
          fact("metadata-destination", "entity ID、destination、metadataで相手を束縛", "entity ID, destination, and metadata bind the federation peers"),
        ),
        step(
          "Identity Provider", "User",
          text("IdP認証", "IdP authentication"),
          text("IdPがユーザを認証する。credentialはSPへ渡らない。", "The IdP authenticates the user. The credential is never sent to the SP."),
          fact("idp-credential", "IdP credential", "IdP credential"),
          fact("idp-user", "IdPとユーザの認証境界", "IdP-to-user authentication boundary"),
          fact("idp-session", "認証結果をIdP sessionへ束縛", "the authentication result is bound to the IdP session"),
        ),
        step(
          "Identity Provider", "Service Provider",
          text("署名付きResponse / Assertion", "Signed Response / Assertion"),
          text("browserは運搬者にすぎない。SPは署名されたAssertion、issuer、audience、recipient、InResponseTo、時刻を検証する。", "The browser is only a carrier. The SP validates the signed Assertion, issuer, audience, recipient, InResponseTo, and time conditions."),
          fact("saml-assertion", "署名付きSAML Assertion", "signed SAML Assertion"),
          fact("browser-post", "信頼しないbrowser POSTを跨ぐ", "crosses an untrusted browser POST"),
          fact("xml-signature-conditions", "XML署名とconditionsをSP requestへ束縛", "the XML signature and conditions bind the assertion to the SP request"),
        ),
        step(
          "Service Provider", "User / Browser",
          text("SP sessionを発行", "Issue the SP session"),
          text("Assertion IDをreplay cacheへ記録してから、SP自身のsession cookieを発行する。", "After recording the Assertion ID in the replay cache, the SP issues its own session cookie."),
          fact("sp-cookie", "SP session cookie", "SP session cookie"),
          fact("sp-local-session", "federation assertionからlocal sessionへの境界", "federation-assertion-to-local-session boundary"),
          fact("assertion-replay-session", "単回Assertionを新しいSP sessionへ束縛", "the one-time assertion is bound to the new SP session"),
        ),
      ]),
    }),
    kerberos: Object.freeze({
      name: text("Kerberos AS / TGS / AP", "Kerberos AS / TGS / AP"),
      steps: Object.freeze([
        step(
          "Client", "Authentication Server",
          text("AS-REQ + pre-auth", "AS-REQ + pre-auth"),
          text("clientはpassword由来keyの所持をfresh timestampで証明する。password自体は送らない。", "The client proves possession of the password-derived key with a fresh timestamp. The password itself is not sent."),
          fact("long-term-user-key", "userの長期key", "user long-term key"),
          fact("client-as", "clientとASのrealm境界", "client-to-AS realm boundary"),
          fact("preauth", "暗号化timestampをuser principalへ束縛", "the encrypted timestamp is bound to the user principal"),
        ),
        step(
          "Authentication Server", "Client",
          text("TGT + client/TGS session key", "TGT + client/TGS session key"),
          text("TGTはkrbtgt keyで保護され、client部分はuser keyで保護される。", "The TGT is protected with the krbtgt key; the client part is protected with the user key."),
          fact("tgt-session-key", "TGTとsession key", "TGT and session key"),
          fact("as-client", "ASからclientへのkey配布境界", "AS-to-client key-distribution boundary"),
          fact("ticket-principal", "TGTをclient principal、realm、期限へ束縛", "the TGT is bound to the client principal, realm, and lifetime"),
        ),
        step(
          "Client", "Ticket Granting Server",
          text("TGS-REQ + authenticator", "TGS-REQ + authenticator"),
          text("TGTとfresh authenticatorを提示し、対象service principalのticketを要求する。", "Present the TGT and a fresh authenticator to request a ticket for the target service principal."),
          fact("tgt-authenticator", "TGTとauthenticator", "TGT and authenticator"),
          fact("client-tgs", "clientとTGSの境界", "client-to-TGS boundary"),
          fact("authenticator-session-key", "authenticatorをTGT session keyと時刻へ束縛", "the authenticator is bound to the TGT session key and time"),
        ),
        step(
          "Ticket Granting Server", "Client",
          text("service ticket", "Service ticket"),
          text("serviceだけが開けるticketとclient/service session keyを返す。", "Return a ticket only the service can open and a client/service session key."),
          fact("service-ticket", "service ticket", "service ticket"),
          fact("tgs-client", "TGSからclientへのticket発行境界", "TGS-to-client ticket-issuance boundary"),
          fact("service-principal", "ticketをservice principal、client、期限へ束縛", "the ticket is bound to the service principal, client, and lifetime"),
        ),
        step(
          "Client", "Service",
          text("AP-REQ + mutual proof", "AP-REQ + mutual proof"),
          text("serviceはticket宛先、期限、authenticator、replay cacheを検証し、必要なら相互認証responseを返す。", "The service validates ticket destination, lifetime, authenticator, and replay cache, then returns mutual-authentication proof when required."),
          fact("ap-request", "ticketとAP authenticator", "ticket and AP authenticator"),
          fact("client-service", "clientとserviceの最終境界", "final client-to-service boundary"),
          fact("mutual-session-key", "双方を同じsession keyとfreshnessへ束縛", "both parties are bound to the same session key and freshness"),
        ),
      ]),
    }),
    webauthn: Object.freeze({
      name: text("WebAuthn 認証", "WebAuthn authentication"),
      steps: Object.freeze([
        step(
          "User / Browser", "Relying Party",
          text("ログイン開始", "Start authentication"),
          text("ユーザがRPのoriginでpasskey認証を開始する。", "The user starts passkey authentication at the RP origin."),
          fact("rp-session", "RP login session", "RP login session"),
          fact("browser-rp", "browserとRPの境界", "browser-to-RP boundary"),
          fact("user-intent", "ユーザ操作を現在のRP sessionへ束縛", "user intent is bound to the current RP session"),
        ),
        step(
          "Relying Party", "Browser",
          text("challenge + RP ID", "Challenge + RP ID"),
          text("RPは高entropy・単回のchallengeと許可credential、RP IDを返す。", "The RP returns a high-entropy, single-use challenge, allowed credentials, and RP ID."),
          fact("webauthn-challenge", "WebAuthn challenge", "WebAuthn challenge"),
          fact("rp-browser", "RPからbrowserへのceremony境界", "RP-to-browser ceremony boundary"),
          fact("challenge-session", "challengeをRP sessionとceremonyへ束縛", "the challenge is bound to the RP session and ceremony"),
        ),
        step(
          "Browser", "Authenticator",
          text("origin-bound request", "Origin-bound request"),
          text("browserが現在のoriginとRP contextをauthenticatorへ渡すため、偽siteは別RPの鍵を使えない。", "The browser supplies the current origin and RP context, so a phishing site cannot use another RP's key."),
          fact("rp-context", "originとRP ID", "origin and RP ID"),
          fact("browser-authenticator", "browser platformとauthenticatorの境界", "browser-platform-to-authenticator boundary"),
          fact("rp-id-key", "credential private keyをRP IDへ束縛", "the credential private key is bound to the RP ID"),
        ),
        step(
          "Authenticator", "Browser",
          text("署名付きassertion", "Signed assertion"),
          text("user presence / verification後、authenticatorDataとclientDataHashへcredential秘密鍵で署名する。", "After user presence or verification, sign authenticatorData and clientDataHash with the credential private key."),
          fact("credential-signature", "credential署名とflags", "credential signature and flags"),
          fact("authenticator-browser", "authenticatorからbrowserへの境界", "authenticator-to-browser boundary"),
          fact("signature-challenge-origin", "署名をchallenge、origin、RP ID、flagsへ束縛", "the signature is bound to challenge, origin, RP ID, and flags"),
        ),
        step(
          "Browser", "Relying Party",
          text("clientData + assertion", "clientData + assertion"),
          text("RPはchallenge、origin、rpIdHash、UP/UV flags、署名、counterを検証してchallengeを消費する。", "The RP validates challenge, origin, rpIdHash, UP/UV flags, signature, and counter, then consumes the challenge."),
          fact("assertion", "WebAuthn assertion", "WebAuthn assertion"),
          fact("browser-rp-return", "信頼しないbrowser transportを跨ぐ", "crosses the untrusted browser transport"),
          fact("verification-checklist", "全checkを保存済みcredentialとsessionへ束縛", "every check is bound to the stored credential and session"),
        ),
      ]),
    }),
  });

  const UI_TEXT = Object.freeze({
    ja: Object.freeze({
      asset: "守るasset",
      boundary: "越えるtrust boundary",
      binding: "検証するbinding",
      previous: "前へ",
      next: "次へ",
      reset: "最初へ",
      step: "ステップ",
    }),
    en: Object.freeze({
      asset: "Asset at risk",
      boundary: "Trust boundary crossed",
      binding: "Binding to verify",
      previous: "Previous",
      next: "Next",
      reset: "First step",
      step: "Step",
    }),
  });

  const CONTRAST_PALETTES = Object.freeze({
    dark: Object.freeze({
      background: "#161b22",
      asset: "#56d364",
      boundary: "#e3b341",
      binding: "#79c0ff",
    }),
    light: Object.freeze({
      background: "#f6f8fa",
      asset: "#116329",
      boundary: "#7d4e00",
      binding: "#0550ae",
    }),
  });

  function createSequenceState(flow = "oauth", locale = "ja") {
    if (!SEQUENCES[flow]) throw new RangeError(`unknown flow: ${flow}`);
    if (!UI_TEXT[locale]) throw new RangeError(`unknown locale: ${locale}`);
    return { flow, locale, index: 0 };
  }

  function currentView(state) {
    const flow = SEQUENCES[state.flow];
    const current = flow.steps[state.index];
    const ui = UI_TEXT[state.locale];
    return {
      flowName: flow.name[state.locale],
      step: current,
      message: current.message[state.locale],
      narration: current.narration[state.locale],
      asset: current.asset[state.locale],
      boundary: current.boundary[state.locale],
      binding: current.binding[state.locale],
      progress: `${ui.step} ${state.index + 1} / ${flow.steps.length}`,
      atStart: state.index === 0,
      atEnd: state.index === flow.steps.length - 1,
      ui,
    };
  }

  function installSequencePlayer(root) {
    const byId = (id) => root.getElementById(id);
    const elements = {
      shell: byId("sequence-shell"),
      card: byId("sequence-card"),
      flow: byId("sequence-flow"),
      locale: byId("sequence-language"),
      from: byId("sequence-from"),
      to: byId("sequence-to"),
      message: byId("sequence-message"),
      narration: byId("sequence-narration"),
      asset: byId("sequence-asset"),
      boundary: byId("sequence-boundary"),
      binding: byId("sequence-binding"),
      assetLabel: byId("sequence-asset-label"),
      boundaryLabel: byId("sequence-boundary-label"),
      bindingLabel: byId("sequence-binding-label"),
      progress: byId("sequence-progress"),
      previous: byId("sequence-previous"),
      next: byId("sequence-next"),
      reset: byId("sequence-reset"),
    };
    if (Object.values(elements).some((element) => !element)) {
      throw new Error("sequence player markup is incomplete");
    }

    const state = createSequenceState(elements.flow.value, elements.locale.value);

    function render() {
      const view = currentView(state);
      const current = view.step;
      elements.shell.lang = state.locale;
      elements.from.textContent = current.from;
      elements.to.textContent = current.to;
      elements.message.textContent = view.message;
      elements.narration.textContent = view.narration;
      elements.asset.textContent = view.asset;
      elements.boundary.textContent = view.boundary;
      elements.binding.textContent = view.binding;
      elements.assetLabel.textContent = view.ui.asset;
      elements.boundaryLabel.textContent = view.ui.boundary;
      elements.bindingLabel.textContent = view.ui.binding;
      elements.progress.textContent = view.progress;
      elements.previous.textContent = `← ${view.ui.previous}`;
      elements.next.textContent = `${view.ui.next} →`;
      elements.reset.textContent = view.ui.reset;
      elements.previous.disabled = view.atStart;
      elements.next.disabled = view.atEnd;
      const reduceMotion = (
        typeof globalScope.matchMedia === "function"
        && globalScope.matchMedia("(prefers-reduced-motion: reduce)").matches
      );
      if (!reduceMotion && typeof elements.card.animate === "function") {
        elements.card.animate(
          [
            { opacity: 0, transform: "translateY(4px)" },
            { opacity: 1, transform: "translateY(0)" },
          ],
          { duration: 180, easing: "ease-out" },
        );
      }
      return view;
    }

    function move(delta) {
      const last = SEQUENCES[state.flow].steps.length - 1;
      state.index = Math.max(0, Math.min(last, state.index + delta));
      return render();
    }

    elements.flow.addEventListener("change", () => {
      if (!SEQUENCES[elements.flow.value]) return;
      state.flow = elements.flow.value;
      state.index = 0;
      render();
    });
    elements.locale.addEventListener("change", () => {
      if (!UI_TEXT[elements.locale.value]) return;
      state.locale = elements.locale.value;
      render();
    });
    elements.previous.addEventListener("click", () => move(-1));
    elements.next.addEventListener("click", () => move(1));
    elements.reset.addEventListener("click", () => {
      state.index = 0;
      render();
    });
    elements.shell.addEventListener("keydown", (event) => {
      const actions = {
        ArrowLeft: () => move(-1),
        ArrowRight: () => move(1),
        Home: () => {
          state.index = 0;
          render();
        },
        End: () => {
          state.index = SEQUENCES[state.flow].steps.length - 1;
          render();
        },
      };
      const action = actions[event.key];
      if (!action || event.altKey || event.ctrlKey || event.metaKey) return;
      event.preventDefault();
      action();
    });

    render();
    return {
      getState: () => ({ ...state }),
      move,
      render,
    };
  }

  const api = Object.freeze({
    CONTRAST_PALETTES,
    SEQUENCES,
    UI_TEXT,
    createSequenceState,
    currentView,
    installSequencePlayer,
  });

  if (typeof module !== "undefined" && module.exports) module.exports = api;
  globalScope.AuthLabSequences = api;

  if (typeof document !== "undefined") {
    document.addEventListener("DOMContentLoaded", () => {
      if (document.getElementById("sequence-shell")) installSequencePlayer(document);
    });
  }
})(typeof globalThis !== "undefined" ? globalThis : this);
