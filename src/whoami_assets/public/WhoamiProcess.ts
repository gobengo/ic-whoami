import {
  Actor,
  AnonymousIdentity,
  HttpAgent,
  Principal,
  SignIdentity,
} from "@dfinity/agent";
import {
  Authenticator,
  DelegationChain,
  DelegationIdentity,
  Ed25519KeyIdentity,
  response,
} from "@dfinity/authentication";
import whoamiInterfaceFactory from "./whoami.did";
import { Render } from "./render";
import * as assert from "assert";
import * as canisterIds from "./canisters";
import { makeLog } from "./log";

export type PublicIdentity = SignIdentity|AnonymousIdentity

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
    authenticate.call(this, {
      onIdentity: async (id) => {
        console.log('authenticate onIdentity ', { id })
        const agent = createSessionAgent(id);
        console.log('calling testWhoamiContract', { agent })
        await testWhoamiContract.call(this, {
          agent,
          render,
        })
      }
    }),
    // handleEachIdentity.call(this, {
    //   events: this.document,
    //   render,
    // }),
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
 * @param options options
 * @param options.onIdentity - called with each identity
 */
async function authenticate(this: Pick<typeof globalThis, "document">, options: {
  onIdentity(identity: PublicIdentity): void
}) {
  const log = makeLog("authenticate");
  const authenticator = new Authenticator({
    identityProvider: {
      url: new URL('https://auth.ic0.app/authorize')
    },
  });
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
    if (/access_token=/.test(location.href)) {
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
        const assetCanisterId = parseCanisterPrincipalText(new URL(location.href));
        console.debug('parsed assetCanisterId from location.href', { assetCanisterId })
        assert.ok(assetCanisterId)
        const authnRequestCanisters = [
          assetCanisterId,
          canisterIds.whoami,
        ];
        authenticator.sendAuthenticationRequest({
          // redirectUri: /* default */ new URL(location.href),
          scope: [
            ...authnRequestCanisters.map(canisterIdText => ({
              type: "CanisterScope" as const,
              principal: Principal.fromText(canisterIdText),
            })),
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
    console.debug('assert.ok secretSession.authenticationResponse', { secretSession })
    assert.ok(secretSession.authenticationResponse);
  }
  // We either have a new candidate session, or one from storage.
  // Either way, we want to use it.
  const publicSession = AuthenticatorSession(secretSession);
  authenticator.useSession(publicSession);

  const icAgentIdentity = createSessionIdentity(secretSession)
  options.onIdentity(icAgentIdentity)
}

/**
 * Create an IC HttpAgent to act on behalf of the session
 * @param identity - identity to use to sign icp requests 
 */
function createSessionAgent(identity: PublicIdentity) {
  const agentOptions = {
    host: HttpAgentHost(new URL(location.href)),
    identity,
  };
  console.debug('creating HttpAgent', agentOptions)
  const agent = new HttpAgent(agentOptions);
  return agent;
}

/**
 * @param url - URL of current page
 * @returns - options.host value for @dfinity/agent HttpAgent
 */
function HttpAgentHost(url: URL): string {
  const href = url.toString();
  if (href.match(/https?:\/\/(.+)\.ic0\.app/i)) {
    return 'https://gw.dfinity.network'
  }
  return '';
}

/**
 * Given a session, return a SignIdentity
 * @param secretSession - session
 * @returns SignIdentity corresponding to info in session
 */
function createSessionIdentity(secretSession: Readonly<Session>): PublicIdentity {
  console.debug('createSessionIdentity', { secretSession })
  const { authenticationResponse } = secretSession;
  if ( ! authenticationResponse) {
    return new AnonymousIdentity();
  }
  const hash = new URL(authenticationResponse).hash?.slice(1);
  console.log('hash', hash)
  const icidResponse = response.fromQueryString(new URLSearchParams(hash))
  const parsedBearerToken = response.parseBearerToken(icidResponse.accessToken);
  const delegationIdentity = DelegationIdentity.fromDelegation(
    SessionSignIdentity(secretSession),
    DelegationChain.fromJSON(JSON.stringify(parsedBearerToken)),
  );
  return delegationIdentity;
}

// /**
//  * Listen for changes to the authenticated Identity.
//  * For each identity:
//  * * log the new identity principalHex
//  * * call testWhoamiContract to test the new identity
//  * @param this Window
//  * @param options options
//  * @param options.events - where to dispatch/listenFor DOM events
//  * @param options.render - call to render something where the end-user can see it.
//  */
// async function handleEachIdentity(
//   this: Pick<typeof globalThis, "document">,
//   options: {
//     events: Pick<EventTarget, "addEventListener" | "dispatchEvent">;
//     render: Render;
//   }
// ) {
//   const log = makeLog("handleEachIdentity");
//   const { events } = options;
//   const identityGenerator = IdentitiesIterable(events);
//   for await (const identity of identityGenerator) {
//     const principalHex =
//       identity.type === "AnonymousIdentity"
//         ? new AnonymousIdentity().getPrincipal().toHex()
//         : Principal.selfAuthenticating(blobFromHex(identity.publicKey)).toHex();
//     log("debug", "identity", {
//       ...identity,
//       principalHex,
//     });
//     // await testWhoamiContract.call(this, { render });
//   }
// }


interface Session {
  authenticationResponse: undefined | string;
  identity: {
    type: "Ed25519KeyIdentity";
    secretKey: {
      hex: string;
    };
  };
}

/**
 * Read a Session from persistent Storage.
 * If there isn't one stored, return undefined.
 */
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

/**
 * Write a Session to persistent Storage.
 * @param session - session to store
 */
function writeSession(session: Session) {
  const stringified = JSON.stringify(session, null, 2);
  localStorage.setItem("ic-whoami-session", stringified);
}

/**
 * Return a Session, somehow.
 * If one is stored, return it.
 * Otherwise, create a brand new one, save it, and return it.
 */
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

/**
 * Create a brand new Session.
 * New sessions have an identity, but they aren't yet authenticated.
 * i.e. they have an ed25519 keyPair created right here,
 * but the `.authenticationResponse` property is undefined.
 * AuthenticationResponse can be requested via @dfinity/authentication
 * `authenticator.sendAuthenticationRequest`
 */
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

/**
 * Encode the input as a hexidecimal number string.
 * @param input - thing to hex-encode
 */
function toHex(input: Uint8Array): string {
  return Array.from(input)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Decode a hex string to bytes
 * @param hex - hexidecimal number string to decode
 */
function hexToBytes(hex: string) {
  return Uint8Array.from(
    (hex.match(/.{2}/gi) || []).map((s) => parseInt(s, 16))
  );
}

/**
 * Given a Session, return a corresponding @dfinity/authentication SignIdentity.
 * The only supported SignIdentity is Ed25519KeyIdentity (so far)
 * @param session - ic-whoami Session to use as inputs to SignIdentity construction
 */
function SessionSignIdentity(session: Session): SignIdentity {
  const id = Ed25519KeyIdentity.fromSecretKey(
    hexToBytes(session.identity.secretKey.hex)
  );
  return id;
}

/**
 * Session wrapped so it can be passed to @dfinity/authentication Authenticator methods
 * @param session - ic-whoami Session
 */
function AuthenticatorSession(session: Session) {
  // const log = makeLog("AuthenticatorSession");
  const sessionIdentity = SessionSignIdentity(session);
  return {
    authenticationResponse: session.authenticationResponse,
    identity: sessionIdentity,
  };
}

/**
 * Ask the ic canister `whoami()` and log the response.
 * @param this Window
 * @param options options
 * @param options.agent - internet computer agent to use to request whoami canister
 * @param options.render - call to render something where the end-user can see it.
 */
async function testWhoamiContract(
  this: Pick<typeof globalThis, "document">,
  options: {
    agent: HttpAgent;
    render: Render;
  }
) {
  const log = makeLog("whoamiContract");
  const whoamiContract = Actor.createActor(
    whoamiInterfaceFactory,
    {
      agent: options.agent,
      canisterId: canisterIds.whoami,
    }
  )
  log("debug", "invoking whoamiContract.whoami()", whoamiContract);
  const { render } = options;
  render(LoadingElement.call(this));
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const whoamiResponse = await (whoamiContract as any).whoami();
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
 * A silly element that's like a loading spinner, but it's a <marquee />
 * @param this Window
 */
function LoadingElement(this: Pick<typeof globalThis, "document">) {
  const loading = this.document.createElement("marquee");
  loading.innerHTML = "Loading&hellip;";
  loading.direction = "right";
  loading.behavior = "alternate";
  return loading;
}

/**
 * Given a URL, return a canister id that serves it, if any.
 * @param url - url to parse
 */
function parseCanisterPrincipalText(url: URL): undefined|string {
  const href = url.toString();
  const hostnameMatch = href.match(/https?:\/\/(.+)\.ic0\.app/i)
  if (hostnameMatch) {
    return hostnameMatch[1]
  }
  const canisterIdQueryMatch = href.match(/canisterId=([\w-]+)/)
  if (canisterIdQueryMatch) {
    return canisterIdQueryMatch[1];
  }
  return;
}
