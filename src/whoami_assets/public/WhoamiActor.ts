import { Actor, Principal } from "@dfinity/agent";
import { authenticator } from "@dfinity/authentication";
// @ts-expect-error 'ic:canisters' is not resolvable without dfx output knowledge
import whoamiActor from "ic:canisters/whoami";
import { StoredSession } from "./session";
import { makeLog } from "./log";

/**
 * Use an Authenticator to control authentication on the page.
 * See below for usage.
 * tl;dr use sendAuthenticationRequest, receiveAuthenticationResponse
 */
type Authenticator = typeof authenticator;

/**
 * Coordinates an end-user authenticating and then seeing who they are (whoami).
 * @param window
 */
export default async function WhoamiActor(
  this: Pick<typeof globalThis, "document">,
  {
    render,
  }: {
    render(el: Element): void;
  }
) {
  const log = makeLog("WhoamiActor");
  log("debug", "booting");
  await Promise.all([
    // testWhoamiContract({ render }),
    greetUser(),
    authenticate.call(this, { render }),
    BootstrapIdentityChangedEventProcessor({ render }),
  ]);
}

async function BootstrapIdentityChangedEventProcessor({ render }: { render(el: Node): void }) {
  const log = makeLog('BootstrapIdentityChangedEventProcessor');
  log('debug', 'init')
  const BootstrapIdentityChangedEventName = 'https://internetcomputer.org/ns/authentication/BootstrapIdentityChangedEvent' as const;
  document.addEventListener(BootstrapIdentityChangedEventName, handleEvent)
  async function handleEvent(event: Event|CustomEvent) {
    log('debug', 'handling BootstrapIdentityChangedEvent', event)
    await testWhoamiContract({ render })
  }
}

/** First thing a user sees is a hello and some orientation. */
async function greetUser() {
  if (
    ["", "0", "false"].includes(
      new URL(location.href).searchParams.get("greet") || ""
    )
  ) {
    // url has ?greet=false. skip
    return;
  }
  alert(
    "welcome. We will now authenticate you using an Internet Computer Identity Provider. You will be redirected away, but then right back. See you soon, whoever you are!"
  );
}

/** Ask the ic canister `whoami()` and log the response */
async function testWhoamiContract({ render }: { render(el: Node): void }) {
  const log = makeLog("whoamiContract");
  // @ts-ignore
  const { default: whoamiContract } = await import("ic:canisters/whoami");
  log("debug", "invoking whoamiContract.whoami()", whoamiContract);
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
    render(document.createTextNode(hex));
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
  {
    render,
  }: {
    render(el: Element): void;
  }
) {
  const log = makeLog('WhoAmiActor authenticate')
  const storage = new StoredSession({
    storage: {
      localStorage,
      key: "ic-whoami-session",
    },
  });
  if (/access_token=/.test(location.search)) {
    const authenticationResponse = location.href;
    log('debug', 'setting storage.session.authenticationResponse = location.href', authenticationResponse)
    storage.authenticationResponse = authenticationResponse
  }
  const useSessionCommand = {...storage.session};
  log('debug', 'calling useSession with', useSessionCommand)
  authenticator.useSession(storage.session)
  if ( ! storage.session.authenticationResponse) {
    if (confirm('login?')) {
      authenticator.sendAuthenticationRequest({
        session: storage.session,
        scope: [],
      })
    }
  }
}

function LoadingElement({ createElement }: Pick<Document, "createElement">) {
  const loading = createElement("marquee");
  loading.innerHTML = "Loading&hellip;";
  loading.direction = "right";
  return loading;
}
