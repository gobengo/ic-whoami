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

/**
 * Use an Authenticator to control authentication on the page.
 * See below for usage.
 * tl;dr use sendAuthenticationRequest, receiveAuthenticationResponse
 */
type Authenticator = typeof authenticator;

/**
 * Coordinates an end-user authenticating and then seeing their publicKey/principal.
 * sends/receives messages via DOM Events.
 * @param window
 */
export default async function WhoamiActor(
  this: Pick<typeof globalThis, "document">,
  options: {
    render: Render;
  }
) {
  const { render } = options;
  await Promise.all([
    authenticate.call(this, { render }),
    handleEachIdentity.call(this, {
      events: this.document,
      render,
    }),
  ]);
}

/** Ask the ic canister `whoami()` and log the response */
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

/**
 * Coordinate determining who the end-user is by sending an AuthenticationRequest to the @dfinity/identity-provider.
 * The end-user will be redirected away to authenticate, then sent back, and this will run a second time.
 * If the URL looks like an AuthenticationResponse, call authenticator.receiveAuthenticationResponse();
 */
async function authenticate(
  this: Pick<typeof globalThis, "document">,
  options: { render: Render }
) {
  const { document } = this;
  const log = makeLog("authenticate");
  log("debug", "init");
  // This contains a secretKey.
  let secretSession = readOrCreateSession();
  log("debug", "session is", secretSession, {
    secretSessionPublicKeyHex: toHex(
      SessionSignIdentity(secretSession).getPublicKey().toDer()
    ),
  });

  // if we have no authenticationResponse, we might need to set it
  if (!secretSession.authenticationResponse) {
    log("debug", "no session.authenticationResponse");
    // might this URL be an authenticationResponse?
    if (!/access_token=/.test(location.search)) {
      // no authenticationResponse... User needs to log in.
      if (confirm("log in?")) {
        authenticator.sendAuthenticationRequest({
          scope: [
            {
              type: "CanisterScope",
              principal: Actor.canisterIdOf(whoamiContract),
            },
          ],
          session: AuthenticatorSession(secretSession),
        });
      }
    } else {
      // use this url as authenticationResponse
      writeSession({
        ...secretSession,
        authenticationResponse: location.href,
      });
      secretSession = readOrCreateSession();
    }
  }
  const useSessionCommand = AuthenticatorSession(secretSession);
  log("debug", "useSessionCommand", useSessionCommand);
  authenticator.useSession(useSessionCommand);
}

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
    await new Promise((resolve) => setTimeout(resolve, 10));
    await testWhoamiContract.call(this, { render });
  }
}

function LoadingElement(this: Pick<typeof globalThis, "document">) {
  const loading = this.document.createElement("marquee");
  loading.innerHTML = "Loading&hellip;";
  loading.direction = "right";
  loading.behavior = "alternate";
  return loading;
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
