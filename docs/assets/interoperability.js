"use strict";

(function exposeInterop(root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  if (root) root.AuthLabInterop = api;
})(typeof globalThis !== "undefined" ? globalThis : this, function buildInterop() {
  const PROTOCOLS = Object.freeze({
    oidc: Object.freeze({
      label: "OpenID Connect",
      product: "Keycloak 26.7.0",
      wire: Object.freeze([
        "discovery documentを取得",
        "fixture userでtoken endpointへ認証",
        "公開JWKSを取得",
        "authlab JWTValidatorで署名・issuer・audience・時刻・subjectを検証",
      ]),
      bindings: "RS256 signature · iss · aud=authlab-oidc · exp/iat · preferred_username",
      negative: "誤ったclient secretを4xxで拒否",
      source: "authlab/jose/jwt.py ↔ Keycloak OIDC endpoint",
    }),
    saml: Object.freeze({
      label: "SAML 2.0",
      product: "Keycloak 26.7.0",
      wire: Object.freeze([
        "SP client endpointからAuthnRequest transactionを開始",
        "fixture IdP login formをPOST",
        "HTTP-POST bindingのSAMLResponseを受信",
        "Response・Assertion・Signature・NameIDの束縛を検査",
      ]),
      bindings: "signed Response/Assertion · NameID=learner · POST binding · one-time condition",
      negative: "誤ったpasswordを拒否しassertionを発行しない",
      source: "authlab/saml/ ↔ Keycloak SAML endpoint",
    }),
    ldap: Object.freeze({
      label: "LDAP",
      product: "OpenLDAP (Debian bookworm)",
      wire: Object.freeze([
        "fixture directoryへsimple bind",
        "dc=auth-lab,dc=localをbaseに検索",
        "uid=learner entryを取得",
        "bind DNと検索結果の同一identityを検査",
      ]),
      bindings: "bind DN · search base · uid=learner",
      negative: "誤ったpasswordをInvalid credentialsで拒否",
      source: "authlab/directory/ldap.py ↔ OpenLDAP ldapsearch",
    }),
    kerberos: Object.freeze({
      label: "Kerberos v5",
      product: "MIT Kerberos (Debian bookworm)",
      wire: Object.freeze([
        "learner principalでAS exchange",
        "TGTをcredential cacheへ保存",
        "HTTP service principalへTGS exchange",
        "service ticketの宛先principalを検査",
      ]),
      bindings: "client principal · realm · TGT · HTTP service principal",
      negative: "誤ったpasswordをpreauthentication failureで拒否",
      source: "authlab/kerberos/ ↔ MIT krb5 kinit/kvno",
    }),
  });

  function protocolView(protocol) {
    const selected = PROTOCOLS[protocol];
    if (!selected) throw new RangeError(`unknown interoperability protocol: ${protocol}`);
    return selected;
  }

  function installInteropExplorer(document) {
    const select = document.getElementById("interop-protocol");
    if (!select) return null;
    const product = document.getElementById("interop-product");
    const wire = document.getElementById("interop-wire");
    const bindings = document.getElementById("interop-bindings");
    const negative = document.getElementById("interop-negative");
    const source = document.getElementById("interop-source");

    function render() {
      const view = protocolView(select.value);
      product.textContent = view.product;
      wire.replaceChildren(...view.wire.map((step, index) => {
        const item = document.createElement("li");
        item.textContent = `${index + 1}. ${step}`;
        return item;
      }));
      bindings.textContent = view.bindings;
      negative.textContent = view.negative;
      source.textContent = view.source;
      return view;
    }

    select.addEventListener("change", render);
    render();
    return { render, selected: () => select.value };
  }

  if (typeof document !== "undefined") {
    document.addEventListener("DOMContentLoaded", () => installInteropExplorer(document));
  }

  return Object.freeze({ PROTOCOLS, protocolView, installInteropExplorer });
});
