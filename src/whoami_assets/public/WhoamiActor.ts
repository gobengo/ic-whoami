import { Principal } from "@dfinity/agent";
import { authenticator } from "@dfinity/authentication";

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
export default async function WhoamiActor(this: Pick<typeof globalThis, 'document'>, { render }: {
    render(el: Element): void;
}) {
    await Promise.all([
        testWhoamiContract({ render }),
        greetUser(),
        authenticate.call(this, { render }),
    ])
}

/** First thing a user sees is a hello and some orientation. */
async function greetUser() {
    if (['','0', 'false'].includes(new URL(location.href).searchParams.get('greet') || '')) {
        // url has ?greet=false. skip
        return;
    }
    alert('welcome. We will now authenticate you using an Internet Computer Identity Provider. You will be redirected away, but then right back. See you soon, whoever you are!')
}

/** Ask the ic canister `whoami()` and log the response */
async function testWhoamiContract({render}:{
    render(el: Node): void;
}) {
    const log = makeLog('whoamiContract')
    // @ts-ignore
    const { default: whoamiContract } = await import('ic:canisters/whoami')
    log('debug', 'invoking whoamiContract.whoami()', whoamiContract)
    const whoamiResponse = await whoamiContract.whoami();
    if (typeof (whoamiResponse as Principal).toHex === 'function') {
        const hex = whoamiResponse.toHex();
        log('info', 'The whoami() contract method says your publicKey|der|hex is ', hex)
        log('info', {
            principal: whoamiResponse,
        })
        render(document.createTextNode(hex))
    } else {
        console.warn('unexpected whoamiResponse', whoamiResponse)
    }
}

/**
 * Coordinate determining who the end-user is by sending an AuthenticationRequest to the @dfinity/identity-provider.
 * The end-user will be redirected away to authenticate, then sent back, and this will run a second time.
 * If the URL looks like an AuthenticationResponse, call authenticator.receiveAuthenticationResponse();
 */
async function authenticate(this: Pick<typeof globalThis, 'document'>, {render}:{
    render(el: Element): void;
}) {
    const { document } = this;
    const log = makeLog('authenticate');
    log('debug', 'init');
    const isAuthenticationRedirect = (new URL(this.document.location.href)).searchParams.has('access_token');
    if ( ! isAuthenticationRedirect) {
        log('debug', 'initiating sendAuthenticationRequest')
        if (confirm('Do you want to Authenticate?')) {
            setImmediate(() => authenticator.sendAuthenticationRequest({scope:[]}))
        }
        return;
    } else {
        render(LoadingElement({
            createElement: document.createElement.bind(document)
        }));

        alert('Thanks for authenticating. This web page will now receive the AuthenticationResponse.')

        // defer this just to let others set up first.
        const url = new URL(document.location.href);
        setImmediate(receiveUrl.bind(this, url));
        /*
        for await (const identity of authenticator.identities {
            log('info', 'new @dfinity/authentication identity', identity);
        }
        */
    }
    return;

    function receiveUrl (url: URL) {
        const typeofReceiveAuthenticationResponse = typeof authenticator.receiveAuthenticationResponse;
        switch (typeof authenticator.receiveAuthenticationResponse) {
            case "function":
                log('debug', 'doing receive', { url });
                authenticator.receiveAuthenticationResponse(url);
                break;
            default:
                log('warn', 'authenticator.receiveAuthenticationResponse is not a function!', { typeofReceiveAuthenticationResponse })
        }
    }
}


function makeLog(loggerName: string) {
    return (level: 'debug'|'info'|'error'|'warn', ...loggables: any[]) => {
        let message = [`[${loggerName}]`, ...loggables]
        if (typeof console[level] === 'function') {
            console[level](...message)
        } else {
            console.log(`[${level}]`, ...message)
        }
    }
}

function LoadingElement({ createElement }: Pick<Document, 'createElement'>) {
    const loading = createElement('marquee');
    loading.innerHTML = 'Loading&hellip;'
    loading.direction = 'right';
    return loading;
}
