import { blobFromUint8Array } from "@dfinity/agent";
import { Authenticator, Ed25519KeyIdentity, Ed25519PublicKey } from "@dfinity/authentication";

import tweetnacl, { sign } from "tweetnacl";
import { makeLog } from "./log";
type SignFunction = (challenge: ArrayBuffer) => Promise<ArrayBuffer>;
type AuthenticationResponse = string;
type UseSessionCommand = Parameters<Authenticator["useSession"]>[0];

interface PublicSessionIdentity {
    publicKey: {
        toDer(): Uint8Array
    }
    sign: SignFunction;
}

type UnauthenticatedPublicSession = {
    authenticationResponse: undefined;
    identity: PublicSessionIdentity;
}
type AuthenticatedPublicSession = {
    authenticationResponse: AuthenticationResponse;
    identity: PublicSessionIdentity;
}

type LocalStorageKey = {
  localStorage: typeof globalThis.localStorage;
  key: string;
};

type JsonSession = {
  authenticationResponse?: string;
  identity: {
    type: "ed25519";
    secretKey: {
      hex: string;
    };
  };
};



class SessionNotFound extends Error {
  public name = "SessionNotFound" as const;
  constructor(message?: string) {
    super(message); // 'Error' breaks prototype chain here
    Object.setPrototypeOf(this, new.target.prototype); // restore prototype chain
  }
}

export class StoredSession {
  private log = makeLog("StoredSession");
  private storage: LocalStorageKey;
  constructor(parameters: { storage: LocalStorageKey }) {
    this.storage = parameters.storage;
    try {
      const existingSession = this.jsonSession;
    } catch (error) {
      switch (error?.name) {
        case "SessionNotFound": {
          const newSession = this.createSession();
          this.jsonSession = newSession;
          break;
        }
        default:
          throw error;
      }
    }
  }
  public set authenticationResponse(response: string) {
      this.jsonSession = {
          ...this.jsonSession,
          authenticationResponse: response,
      }
  }
  public get session(): Readonly<UnauthenticatedPublicSession|AuthenticatedPublicSession> {
    const authenticationResponse = this.jsonSession.authenticationResponse;
    const identity = this.createSignIdentity(this.jsonSession.identity);
    return { authenticationResponse, identity }
  }
  public hasAuthenticationResponse() {
      return Boolean(this.jsonSession.authenticationResponse);
  }
  private createSignIdentity(
    input: JsonSession["identity"]
  ): PublicSessionIdentity {
    const secretKey = HexEncoder().decode(input.secretKey.hex);
    const keyPair = tweetnacl.sign.keyPair.fromSecretKey(secretKey);
    const sessionIdentity = Ed25519KeyIdentity.fromSecretKey(secretKey);
    const sign = async (challenge: ArrayBuffer) => {
      // if ( ! confirm(`sign\npublicKey=${HexEncoder().encode(keyPair.publicKey)}\nchallenge=${challenge}`)) {
      //   throw new Error('user declined to sign challenge')
      // }
      this.log('debug', 'sign', { challenge })
      const signature = await sessionIdentity.sign(challenge);
      this.log('debug', 'signed -> signature', {
        challenge: HexEncoder().encode(new Uint8Array(challenge)),
        signature: HexEncoder().encode(signature),
      })
      return signature;
      // return tweetnacl.sign.detached(new Uint8Array(challenge), secretKey);
    }
    const publicKey = sessionIdentity.getPublicKey();
    return {
      sign,
      publicKey: {
        toDer: () => {
          const der = publicKey.toDer();
          this.log('debug', 'session signIdentity toDer called', {
            hex: HexEncoder().encode(der),
          })
          return der;
        }
      }
    };
  }
  private get jsonSession(): Readonly<JsonSession> {
    const { key, localStorage } = this.storage;
    const stored = localStorage.getItem(key);
    if (stored) {
      const parsed = JSON.parse(localStorage.getItem(key) || "{}");
      const authenticationResponse = parsed?.authenticationResponse;
      const secretKeyHex = parsed?.identity?.secretKey?.hex;
      if (typeof secretKeyHex === "string") {
        return {
          authenticationResponse,
          identity: {
            type: "ed25519",
            secretKey: { hex: secretKeyHex },
          },
        };
      } else {
        this.log(
          "warn",
          "StoredSession had stored value, but failed to parse."
        );
      }
    }
    throw new SessionNotFound("no session in storage");
  }
  private set jsonSession(input: Readonly<JsonSession>) {
    const { key, localStorage } = this.storage;
    const stringified = JSON.stringify(input);
    this.log("debug", "about to setItem", { key, stringified });
    localStorage.setItem(key, stringified);
    this.log("debug", "finished setItem", key);
  }
  protected createSession = (): JsonSession => {
    const sessionIdentity = Ed25519KeyIdentity.generate(tweetnacl.randomBytes(32))
    const keyPair = sessionIdentity.getKeyPair();
    // const keyPair = tweetnacl.sign.keyPair.fromSeed(tweetnacl.randomBytes(32));
    const session: JsonSession = {
      authenticationResponse: undefined,
      identity: {
        type: "ed25519",
        secretKey: {
          hex: HexEncoder().encode(keyPair.secretKey),
        },
      },
    };
    return session;
  };
}

function HexEncoder() {
  return Object.freeze({ encode, decode });
  function encode(bytes: Uint8Array): string {
    return Array.from(bytes)
      .map((b) => b.toString(16).padEnd(2, "0"))
      .join("");
  }
  function decode(hex: string): Uint8Array {
    return Uint8Array.from(
      (hex.match(/.{2}/gi) || []).map((octet) => parseInt(octet, 16))
    );
  }
}
