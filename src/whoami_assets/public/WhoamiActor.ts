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
        greetUser(),
        authenticate(),
    ])
}

/** First thing a user sees is a hello and some orientation. */
async function greetUser() {
    alert('welcome. We will now authenticate you using an Internet Computer Identity Provider. You will be redirected away, but then right back. See you soon, whoever you are!')
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
        authenticator.sendAuthenticationRequest({scope:[]})
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
        let message = [loggerName, ...loggables]
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
