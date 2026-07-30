#!/usr/bin/env node

import assert from "node:assert/strict";

import {
  createBrowserSession,
  evaluate,
  navigate,
  waitForExpression,
} from "./support/browser-harness.mjs";

async function main() {
  const session = await createBrowserSession("auth-lab-webauthn-");
  try {
    await session.devtools.command("WebAuthn.enable", {}, session.sessionId);
    const { authenticatorId } = await session.devtools.command(
      "WebAuthn.addVirtualAuthenticator",
      {
        options: {
          protocol: "ctap2",
          ctap2Version: "ctap2_1",
          transport: "internal",
          hasResidentKey: true,
          hasUserVerification: true,
          hasLargeBlob: true,
          automaticPresenceSimulation: true,
          isUserVerified: true,
          defaultBackupEligibility: true,
          defaultBackupState: true,
        },
      },
      session.sessionId,
    );
    await navigate(session);
    await waitForExpression(session, "window.AuthLabPasskeys?.lab", {
      message: "Native WebAuthn lab did not initialize",
    });

    const nonresident = await evaluate(
      session,
      "AuthLabPasskeys.lab.register({residentKey:'discouraged',userVerification:'preferred'})",
    );
    assert.equal(nonresident.resident, false);
    assert.equal(nonresident.backupEligible, true);
    assert.equal(nonresident.backupState, true);
    const allowed = await evaluate(
      session,
      "AuthLabPasskeys.lab.authenticate({userVerification:'preferred'})",
    );
    assert.equal(allowed.verified, true);
    assert.equal(allowed.discoverable, false);

    const resident = await evaluate(
      session,
      "AuthLabPasskeys.lab.register({residentKey:'required',userVerification:'required'})",
    );
    assert.equal(resident.resident, true);
    assert.equal(resident.userVerified, true);
    const stored = await session.devtools.command(
      "WebAuthn.getCredentials",
      { authenticatorId },
      session.sessionId,
    );
    assert.ok(stored.credentials.some((credential) => credential.isResidentCredential === true));
    assert.ok(stored.credentials.some((credential) => credential.isResidentCredential === false));

    const discoverable = await evaluate(
      session,
      "AuthLabPasskeys.lab.authenticate({discoverable:true,userVerification:'required'})",
    );
    assert.equal(discoverable.verified, true);
    assert.equal(discoverable.discoverable, true);
    assert.ok(discoverable.userHandle);

    await session.devtools.command("WebAuthn.setUserVerified", {
      authenticatorId,
      isUserVerified: false,
    }, session.sessionId);
    const uvRejection = await evaluate(session, `(async () => {
      try {
        await AuthLabPasskeys.lab.authenticate({discoverable:true,userVerification:'required'});
        return {rejected:false};
      } catch (error) {
        return {rejected:true,name:error.name,message:error.message};
      }
    })()`);
    assert.equal(uvRejection.rejected, true);
    await session.devtools.command("WebAuthn.setUserVerified", {
      authenticatorId,
      isUserVerified: true,
    }, session.sessionId);

    const originRejection = await evaluate(
      session,
      "AuthLabPasskeys.lab.probeOriginMismatch()",
    );
    assert.equal(originRejection.rejected, true);
    assert.match(originRejection.message, /Origin binding failed/u);
    const rpIdRejection = await evaluate(
      session,
      "AuthLabPasskeys.lab.probeRpIdMismatch()",
    );
    assert.equal(rpIdRejection.rejected, true);
    assert.match(rpIdRejection.name, /SecurityError|NotAllowedError/u);

    console.log(JSON.stringify({
      browser: session.executable,
      origin: session.origin,
      ceremonies: ["registration", "allowCredentials", "discoverable"],
      negativeTests: ["user verification", "origin", "RP ID"],
      virtualCredentials: stored.credentials.length,
    }));
  } finally {
    await session.close();
  }
}

await main();
