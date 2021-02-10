import {
  Actor,
  AnonymousIdentity,
  blobFromHex,
  blobFromUint8Array,
  makeLog,
  Principal,
  SignIdentity,
} from "@dfinity/agent";
import {
  authenticator,
  Ed25519KeyIdentity,
  IdentitiesIterable,
} from "@dfinity/authentication";
// @ts-expect-error because this can't be resolved without configuring the resolver to point to `dfx build` output
import whoamiContract from "ic:canisters/whoami";
import { Render } from "./render";
import * as assert from "assert";

/**
 * Main process for ic-whoami.
 * This process runs on an Internet Computer canister web page running @dfinity/bootstrap.
 * It should help the user authenticate using ic-id, then show the end-user the publicKey
 * or principal of their Authenticated Session.
 * @param this Window
 * @param options options
 * @param options.render - call to render something where the end-user can see it.
 */
export default async function WhoamiProcess(
  this: Pick<typeof globalThis, "document">,
  options: {
    render: Render;
  }
): Promise<void> {
  const { render } = options;
  await Promise.all([
    authenticate.call(this),
    handleEachIdentity.call(this, {
      events: this.document,
      render,
    }),
  ]);
}

/**
 * Use @dfinity/authentication Authenticator + session to set-up authn state.
 * * on load, read a session from storage, or else create a new one
 *   * the session MUST have an ed25519 keyPair
 * * if the session doesn't have an authenticationResponse
 *   * if the current URL looks like an Authentication Response, use that.
 *   * else request one from the ic-id Identity Provider via
 *     `authenticator.sendAuthenticationRequest` (which will redirect away)
 * * pass the session to `authenticator.useSession`
 * @param this Window
 */
async function authenticate(this: Pick<typeof globalThis, "document">) {
  const log = makeLog("authenticate");

  // "on load, read a session from storage, or else create a new one."
  let secretSession = readOrCreateSession();
  const secretSessionPublicKeyHex = toHex(
    SessionSignIdentity(secretSession).getPublicKey().toDer()
  );
  log("debug", "initial session is", secretSession, {
    secretSessionPublicKeyHex,
  });

  // "if the session doesn't have an authenticationResponse"
  if (!secretSession.authenticationResponse) {
    // "if the current URL looks like an Authentication Response, use that."
    if (/access_token=/.test(location.search)) {
      writeSession({
        ...secretSession,
        authenticationResponse: location.href,
      });
      secretSession = readOrCreateSession();
    } else {
      // "else request one from the ic-id Identity Provider"
      /*
      We don't have an AuthenticationResponse, but that's required for an authenticated Session.
      We need to request an AuthenticationResponse.
      We do that by sending an AuthenticationRequest to an IdentityProvider,
      which should respond with a resulting AuthenticationResponse
      (after ensuring end-user consent to signatures).
      AuthenticaticationRequests are sent by redirecting the user-agent to the IdentityProvider.
      The IdentityProvider will send an AuthenticationResponse by redirecting the user-agent
      back to your redirect_uri (defaults to this page).
      When your page handles the authenticationResponse, it can provide it to
      `authenticator.useSession({ authenticationResponse, identity })`
      */
      if (confirm("log in?")) {
        authenticator.sendAuthenticationRequest({
          // redirectUri: /* default */ new URL(location.href),
          scope: [
            {
              type: "CanisterScope",
              principal: Actor.canisterIdOf(whoamiContract),
            },
          ],
          session: AuthenticatorSession(secretSession),
        });
      } else {
        log(
          "warn",
          "user has no authenticated session, yet declined to log in."
        );
      }
    }
    // now we have an authenticationResponse
    assert.ok(secretSession.authenticationResponse);
  }
  // We either have a new candidate session, or one from storage.
  // Either way, we want to use it.
  const useSessionCommand = AuthenticatorSession(secretSession);
  authenticator.useSession(useSessionCommand);
}

/**
 * Listen for changes to the authenticated Identity.
 * For each identity:
 * * log the new identity principalHex
 * * call testWhoamiContract to test the new identity
 * @param this Window
 * @param options options
 * @param options.events - where to dispatch/listenFor DOM events
 * @param options.render - call to render something where the end-user can see it.
 */
async function handleEachIdentity(
  this: Pick<typeof globalThis, "document">,
  options: {
    events: Pick<EventTarget, "addEventListener" | "dispatchEvent">;
    render: Render;
  }
) {
  const log = makeLog("handleEachIdentity");
  const { events, render } = options;
  const identityGenerator = IdentitiesIterable(events);
  for await (const identity of identityGenerator) {
    const principalHex =
      identity.type === "AnonymousIdentity"
        ? new AnonymousIdentity().getPrincipal().toHex()
        : Principal.selfAuthenticating(blobFromHex(identity.publicKey)).toHex();
    log("debug", "identity", {
      ...identity,
      principalHex,
    });
    await testWhoamiContract.call(this, { render });
  }
}

interface Session {
  authenticationResponse: undefined | string;
  identity: {
    type: "Ed25519KeyIdentity";
    secretKey: {
      hex: string;
    };
  };
}

function readSession(): Readonly<Session> | undefined {
  const log = makeLog("readSession");
  const stored = localStorage.getItem("ic-whoami-session");
  if (!stored) {
    return;
  }
  const parsed = (() => {
    try {
      return JSON.parse(stored) as unknown;
    } catch (error) {
      log("warn", "error parsing stored localStorage", { error });
    }
  })();
  if (!parsed) {
    return;
  }
  return parsed as Session;
}

function writeSession(session: Session) {
  const stringified = JSON.stringify(session, null, 2);
  localStorage.setItem("ic-whoami-session", stringified);
}

function readOrCreateSession(): Readonly<Session> {
  const log = makeLog("readOrCreateSession");
  const session1 = readSession();
  log("debug", "read session", session1);
  if (session1) {
    return session1;
  }
  const session2 = createSession();
  writeSession(session2);
  return session2;
}

function createSession(): Readonly<Session> {
  const seed = crypto.getRandomValues(new Uint8Array(32));
  const keyPair = Ed25519KeyIdentity.generate(seed).getKeyPair();
  return {
    authenticationResponse: undefined,
    identity: {
      type: "Ed25519KeyIdentity",
      secretKey: {
        hex: toHex(keyPair.secretKey),
      },
    },
  };
}

function toHex(input: Uint8Array): string {
  return Array.from(input)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function hexToBytes(hex: string) {
  return Uint8Array.from(
    (hex.match(/.{2}/gi) || []).map((s) => parseInt(s, 16))
  );
}

function SessionSignIdentity(session: Session): SignIdentity {
  const id = Ed25519KeyIdentity.fromSecretKey(
    hexToBytes(session.identity.secretKey.hex)
  );
  return id;
}

function AuthenticatorSession(session: Session) {
  const log = makeLog("AuthenticatorSession");
  const sessionIdentity = SessionSignIdentity(session);
  return {
    authenticationResponse: session.authenticationResponse,
    identity: {
      publicKey: sessionIdentity.getPublicKey(),
      sign: async (challenge: ArrayBuffer) => {
        challenge = new Uint8Array(challenge);
        log("debug", "sign", {
          challenge: String.fromCharCode(...new Uint8Array(challenge)),
        });
        const signature: Uint8Array = new Uint8Array(
          await sessionIdentity.sign(
            blobFromUint8Array(new Uint8Array(challenge))
          )
        );
        log("debug", "signature", toHex(signature));
        return signature;
      },
    },
  };
}

/**
 * Ask the ic canister `whoami()` and log the response.
 * @param this Window
 * @param options options
 * @param options.render - call to render something where the end-user can see it.
 */
async function testWhoamiContract(
  this: Pick<typeof globalThis, "document">,
  options: {
    render: Render;
  }
) {
  const log = makeLog("whoamiContract");
  log("debug", "invoking whoamiContract.whoami()", whoamiContract);
  const { render } = options;
  render(LoadingElement.call(this));
  const whoamiResponse = await whoamiContract.whoami();
  if (typeof (whoamiResponse as Principal).toHex === "function") {
    const hex = whoamiResponse.toHex();
    log(
      "info",
      "The whoami() contract method says your publicKey|der|hex is ",
      hex
    );
    log("info", {
      principal: whoamiResponse,
    });
    render(this.document.createTextNode(hex));
  } else {
    console.warn("unexpected whoamiResponse", whoamiResponse);
  }
}

function LoadingElement(this: Pick<typeof globalThis, "document">) {
  const loading = this.document.createElement("marquee");
  loading.innerHTML = "Loading&hellip;";
  loading.direction = "right";
  loading.behavior = "alternate";
  return loading;
}
