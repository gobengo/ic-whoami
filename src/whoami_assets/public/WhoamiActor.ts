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
export default async function WhoamiActor(window: Window) {
    await Promise.all([
        testWhoamiContract(),
        greetUser(),
        authenticate(),
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
async function testWhoamiContract() {
    const log = makeLog('whoamiContract')
    // log('info', {whoamiContract})
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
    } else {
        console.warn('unexpected whoamiResponse', whoamiResponse)
    }
}

/**
 * Coordinate determining who the end-user is by sending an AuthenticationRequest to the @dfinity/identity-provider.
 * The end-user will be redirected away to authenticate, then sent back, and this will run a second time.
 * If the URL looks like an AuthenticationResponse, call authenticator.receiveAuthenticationResponse();
 */
async function authenticate() {
    const log = makeLog('authenticate');
    log('debug', 'init');
    const url = new URL(document.location.href);
    const isAuthenticationRedirect = url.searchParams.has('access_token');
    if ( ! isAuthenticationRedirect) {
        log('debug', 'initiating sendAuthenticationRequest')
        if (confirm('Do you want to Authenticate?')) {
            authenticator.sendAuthenticationRequest({scope:[]})
        }
        return;
    } else {
        if (isFutureAuthenticator(authenticator)) {
            alert('Thanks for authenticating. This web page will now receive the AuthenticationResponse.')
            log('debug', 'initiating receiveAuthenticationResponse')
            const receive = () => isFutureAuthenticator(authenticator) && authenticator.receiveAuthenticationResponse();
            setImmediate(receive);
            alert('@todo add more code to show the logged in state.')
            /*
            for await (const identity of authenticator.identities {
                log('info', 'new @dfinity/authentication identity', identity);
            }
            */
        } else {
            log('warn', '@dfinity/authentication authenticator does NOT support receiveAuthenticationResponse. You must be using an old version.')
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

interface FutureAuthenticator extends Authenticator {
    receiveAuthenticationResponse(): void;
}

function isFutureAuthenticator(authenticator: Authenticator): authenticator is FutureAuthenticator {
    if (typeof (authenticator as FutureAuthenticator)?.receiveAuthenticationResponse !== 'function') return false;
    return true;
}
