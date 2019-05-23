/* tslint:disable:no-console */

import * as cryptojs from 'crypto-js';
import {nul, bool, num, str, literal, opt, arr, tuple, obj, union, TsType, validatingParse} from 'ts-json-validator';
import {PromiseSequentialContext} from '@/promise-sequential-context';
import * as utils from '@/utils';
import {UserTalk, Talk} from '@/Talk';
import {jwkThumbprintByEncoding} from 'jwk-thumbprint';

const rsaOtherPrimesInfoFormat = obj({
  d: opt(str),
  r: opt(str),
  t: opt(str),
});

const jsonWebKeyFormat = obj({
  alg: opt(str),
  crv: opt(str),
  d: opt(str),
  dp: opt(str),
  dq: opt(str),
  e: opt(str),
  ext: opt(bool),
  k: opt(str),
  key_ops: opt(arr(str)),
  kty: opt(str),
  n: opt(str),
  oth: opt(arr(rsaOtherPrimesInfoFormat)),
  p: opt(str),
  q: opt(str),
  qi: opt(str),
  use: opt(str),
  x: opt(str),
  y: opt(str),
});

const keyExchangeParcelFormat = obj({
  kind: literal('key_exchange' as const),
  content: obj({
    // Public key for session ID generation
    sessionIdPublicJwk: jsonWebKeyFormat,
    // Public key for encryption
    encryptPublicJwk: jsonWebKeyFormat,
  }),
});
type KeyExchangeParcel = TsType<typeof keyExchangeParcelFormat>;


const sessionIdSignatureParcelFormat = obj({
  kind: literal('session_id_signature' as const),
  content: str,
});
type SessionIdSignatureParcel = TsType<typeof sessionIdSignatureParcelFormat>;


const talkParcelFormat = obj({
  kind: literal('talk' as const),
  content: str,
});
type TalkParcel = TsType<typeof talkParcelFormat>;


const parcelFormat = union(keyExchangeParcelFormat, sessionIdSignatureParcelFormat, talkParcelFormat);
type Parcel = TsType<typeof parcelFormat>;



function getPath(toId: string, fromId: string): string {
  return cryptojs.SHA256(`${toId}-to-${fromId}`).toString();
}

// Generate session ID
async function generateSessionId(sessionIdPublicJwk: JsonWebKey, sessionIdPrivateKey: CryptoKey): Promise<string> {
  // Convert JWK To CryptoKey
  const sessionIdPublicKey: CryptoKey = await crypto.subtle.importKey(
    'jwk',
    sessionIdPublicJwk,
    {name: 'ECDH', namedCurve: 'P-256'},
    true,
    [],
  );
  // Create secret key for session ID generation
  const sessionIdKey: CryptoKey = await crypto.subtle.deriveKey(
    { name: 'ECDH', public: sessionIdPublicKey },
    sessionIdPrivateKey,
    {name: 'AES-GCM', length: 128},
    true,
    ['encrypt', 'decrypt'],
  );
  // Convert the secret key to JWK
  // NOTE: 'kty' should be 'oct'  logically
  const sessionIdJwk: JsonWebKey & {kty: 'oct'} = await window.crypto.subtle.exportKey(
    'jwk',
    sessionIdKey,
  ) as (JsonWebKey & {kty: 'oct'});
  // Get JWK thumbprint by hex
  return jwkThumbprintByEncoding(sessionIdJwk, 'SHA-256', 'hex');
}


interface Parameters {
  serverUrl: string;
  connectId: string;
  peerConnectId: string;
  enableSignature: boolean;
  privateSignPem: string;
  peerPublicSignPem: string;

  // TODO: Use type-safe EventEmitter instead of onXxx
  onSessionId: (sessionId: string) => void;
  onEncryptKeyPair: (encryptKeyPair: CryptoKeyPair) => void;
  onPeerEncryptPublicCryptoKey: (peerEncryptPublicCryptoKey: CryptoKey) => void;
  onEstablished: () => void;
  onTalk: (talk: Talk) => void;
}

export class PipingChatter {
  // Initialization vector size
  private readonly aesGcmIvLength: number = 12;

  // Key pair to create session ID
  private sessionIdKeyPairPromise: PromiseLike<CryptoKeyPair> = window.crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256'},
    true,
    ['deriveKey', 'deriveBits'],
  );
  // Session ID
  private sessionId: string = '';

  // Key pair for encryption
  private encryptKeyPairPromise: PromiseLike<CryptoKeyPair>;

  // Peer's public key for encryption
  private peerEncryptPublicCryptoKey?: CryptoKey;

  // Context to receive talks sequentially
  private recieveSeqCtx = new PromiseSequentialContext();
  // Context to send talks sequentially
  private sendSeqCtx    = new PromiseSequentialContext();

  // Algorithm for signature
  private signAlg = { name: 'RSASSA-PKCS1-v1_5', hash: { name: 'SHA-256' } };

  // Whether your public key sent or not
  private hasPublicKeySent: boolean = false;
  // Whether peer's public key received or not
  private hasPeerPublicKeyReceived: boolean = false;
  // Whether peer is verified by public key authentication
  private peerVerified: boolean = false;

  // Whether emitting "establish"
  private hasBeenEmitEstablished: boolean = false;


  constructor(readonly params: Parameters) {
    this.encryptKeyPairPromise = window.crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256'},
      true,
      ['deriveKey', 'deriveBits'],
    );
    this.encryptKeyPairPromise.then((encryptKeyPair) => {
      this.params.onEncryptKeyPair(encryptKeyPair);
    });
  }

  public connectToPeer(): void {
    // Send my public key
    this.sendPublicKey();

    // Get-loop of peer's message
    this.receiveParcelLoop();
  }

  public sendTalk(message: string): void {
    const userTalk: UserTalk = {
      kind: 'user',
      time: new Date(),
      talkerId: this.params.connectId,
      content: message,
      arrived: false,
    };
    // Push my talk
    this.params.onTalk(userTalk);
    const myTalk: string = message;

    (async () => {
      const url = `${this.params.serverUrl}/${getPath(this.params.connectId, this.params.peerConnectId)}`;
      if (this.peerEncryptPublicCryptoKey === undefined) {
        this.echoSystemTalk('Peer\'s public key is not received yet.');
      } else {
        const parcel: Parcel = {
          kind: 'talk',
          content: myTalk,
        };
        // Encrypt parcel
        const body = await this.encryptParcel(parcel, this.peerEncryptPublicCryptoKey);
        await this.sendSeqCtx.run(async () => {
          const res = await fetch(url, {
            method: 'POST',
            body,
          });
          if (res.body === null) {
            this.echoSystemTalk('Unexpected error: send-body is null.');
          } else {
            // Wait for body being complete
            await res.body.pipeTo(new WritableStream({}));
            // Set arrived as true
            // NOTE: destructive operation: mutation
            userTalk.arrived = true;
          }
        });
      }
    })();
  }

  /**
   * Encrypt parcel attached IV on head
   * @param parcel
   * @param peerEncryptPublicCryptoKey
   */
  private async encryptParcel(parcel: Parcel, peerEncryptPublicCryptoKey: CryptoKey): Promise<Uint8Array> {
    // Create an initialization vector
    const iv = crypto.getRandomValues(new Uint8Array(this.aesGcmIvLength));
    // Get secret key
    const secretKey = await this.getSecretKey(peerEncryptPublicCryptoKey);
    // Encrypt parcel
    const encryptedParcel = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv, tagLength: 128 },
      secretKey,
      // (from: https://stackoverflow.com/a/41180394/2885946)
      new TextEncoder().encode(JSON.stringify(parcel)),
    );
    // Join IV and encrypted parcel
    return utils.mergeUint8Array(iv, new Uint8Array(encryptedParcel));
  }

  private echoSystemTalk(message: string): void {
    this.params.onTalk({
      kind: 'system',
      time: new Date(),
      content: message,
    });
  }

  private async sendPublicKey() {
    this.echoSystemTalk(`Sending your public key to "${this.params.peerConnectId}"...`);

    // Get public JWK for session ID generation
    const sessionIdPublicJwk: JsonWebKey = await crypto.subtle.exportKey(
      'jwk',
      (await this.sessionIdKeyPairPromise).publicKey,
    );

    // Get public JWK for encryption
    const encryptPublicJwk: JsonWebKey = await crypto.subtle.exportKey(
      'jwk',
      (await this.encryptKeyPairPromise).publicKey,
    );

    const url = `${this.params.serverUrl}/${getPath(this.params.connectId, this.params.peerConnectId)}`;

    const parcel: KeyExchangeParcel = {
      kind: 'key_exchange',
      content: {
        sessionIdPublicJwk,
        encryptPublicJwk,
      },
    };
    console.log('parcel:', JSON.stringify(parcel));
    const res = await this.sendSeqCtx.run(() =>
      fetch(url, {
        method: 'POST',
        headers: {
          // TODO: This should be "application/json".
          //       however, POST application/json triggers preflight request
          //       and Piping Server doesn't support preflight request.
          'content-type': 'text/plain',
        },
        body: JSON.stringify(parcel),
      }),
    );

    this.echoSystemTalk('Your public key sent.');
    this.hasPublicKeySent = true;
    this.establishProcessIfNeed();
    console.log('res:', res);
  }

  private get isEstablished(): boolean {
    return (
      this.hasPublicKeySent &&
      this.hasPeerPublicKeyReceived &&
      (!this.params.enableSignature || this.peerVerified)
    );
  }

  // Print established message if established
  private establishProcessIfNeed(): void {
    if (!this.hasBeenEmitEstablished && this.isEstablished) {
      this.hasBeenEmitEstablished = true;
      this.echoSystemTalk(`Connection established with "${this.params.peerConnectId}"!`);
      this.params.onEstablished();
    }
  }

  private async receiveParcelLoop() {
    const url = `${this.params.serverUrl}/${getPath(this.params.peerConnectId, this.params.connectId)}`;
    while (true) {
      try {
        console.log(`Getting ${url}...`);
        const res = await this.recieveSeqCtx.run(() =>
          fetch(url, {
            method: 'GET',
          }),
        );

        if (res.body === null) {
          console.log('ERROR: Body not found');
          return;
        }

        // Get parcel
        const parcel: Parcel | undefined = await (async () => {
          // If content type is JSON
          // TODO: This should be "application/json".
          //       however, POST application/json triggers preflight request
          //       and Piping Server doesn't support preflight request.
          if (res.headers.get('content-type') === 'text/plain') {
            return validatingParse(
              parcelFormat,
              await res.text(),
            );
          } else {
            if ( this.peerEncryptPublicCryptoKey === undefined ) {
              console.error('Error: this.peerPublicCryptoKey is undefined');
              return undefined;
            }
            // Get body
            const body: Uint8Array = await utils.getBodyBytesFromResponse(res);
            // Split body into IV and encrypted parcel
            const iv = body.slice(0, this.aesGcmIvLength);
            const encryptedParcel = body.slice(this.aesGcmIvLength);
            console.log('body:', body);
            // Get secret key
            const secretKey = await this.getSecretKey(this.peerEncryptPublicCryptoKey);
            // Decrypt body text
            const decryptedParcel: ArrayBuffer = await crypto.subtle.decrypt(
              { name: 'AES-GCM', iv, tagLength: 128 },
              secretKey,
              encryptedParcel,
            );
            // Parse and validate
            return validatingParse(
              parcelFormat,
              // (from: https://stackoverflow.com/a/41180394/2885946)
              new TextDecoder().decode(decryptedParcel),
            );
          }
        })();

        if (parcel === undefined) {
          console.error(`Parse error: ${await res.json()}`);
          return;
        }

        switch (parcel.kind) {
          case 'key_exchange':
            // Set peer's public JWK
            const peerPublicJwk: JsonWebKey = parcel.content.encryptPublicJwk;
            console.log('Peer\'s public JWK:', peerPublicJwk);

            // Assign session ID
            this.sessionId = await generateSessionId(
              parcel.content.sessionIdPublicJwk,
              (await this.sessionIdKeyPairPromise).privateKey,
            );
            this.params.onSessionId(this.sessionId);
            console.log('Session ID:', this.sessionId);

            // Assign peer's public JWK by import
            this.peerEncryptPublicCryptoKey = await crypto.subtle.importKey(
              'jwk',
              peerPublicJwk,
              {name: 'ECDH', namedCurve: 'P-256'},
              true,
              [],
            );
            this.params.onPeerEncryptPublicCryptoKey(this.peerEncryptPublicCryptoKey);

            this.echoSystemTalk('Peer\'s public key received.');
            this.hasPeerPublicKeyReceived = true;

            // If signature is enabled
            if (this.params.enableSignature) {
              // Get private key by PEM
              const { privateKey } = await utils.privRsaPemToPubPrivKeys(this.signAlg, this.params.privateSignPem);
              // Sign session ID
              // NOTE: Peer has the same session ID
              // tslint:disable-next-line:no-shadowed-variable
              const signatureBuff: ArrayBuffer = await window.crypto.subtle.sign(
                this.signAlg,
                privateKey,
                utils.stringToArrayBuffer(this.sessionId),
              );
              // Get signature by using base64 encode
              // tslint:disable-next-line:no-shadowed-variable
              const signature = btoa(utils.arrayBufferToString(signatureBuff));
              console.log('send signature:', signature);

              // tslint:disable-next-line:no-shadowed-variable
              const parcel: SessionIdSignatureParcel = {
                kind: 'session_id_signature',
                content: signature,
              };
              // Encrypt parcel
              const body = await this.encryptParcel(parcel, this.peerEncryptPublicCryptoKey);
              // NOTE: Should not use await not to prevent receive loop
              this.sendSeqCtx.run(async () => {
                // tslint:disable-next-line:no-shadowed-variable
                const url = `${this.params.serverUrl}/${getPath(this.params.connectId, this.params.peerConnectId)}`;
                // Send signature
                // tslint:disable-next-line:no-shadowed-variable
                const res = await fetch(url, {
                  method: 'POST',
                  body,
                });
                if (res.body === null) {
                  this.echoSystemTalk('Unexpected error: send-body is null.');
                } else {
                  // Wait for body being complete
                  await res.body.pipeTo(new WritableStream({}));
                }
              });
            }

            this.establishProcessIfNeed();
            break;
          case 'session_id_signature':
            if (this.sessionId === '') {
              console.error('Unexpected Error: session is empty');
              break;
            }
            // Get based64 encoded signature
            // tslint:disable-next-line:no-shadowed-variable
            const signature: string = parcel.content;
            console.log('receive signature:', signature);
            // Decode base64
            // tslint:disable-next-line:no-shadowed-variable
            const signatureBuff: ArrayBuffer = utils.stringToArrayBuffer(atob(signature));
            // Get peer's public key
            const peerPublicKey = await utils.pubRsaPemToPubKey(this.signAlg, this.params.peerPublicSignPem);
            // Verify
            this.peerVerified = await window.crypto.subtle.verify(
              this.signAlg,
              peerPublicKey,
              signatureBuff,
              utils.stringToArrayBuffer(this.sessionId),
            );
            console.log('verified:', this.peerVerified);

            if (this.peerVerified) {
              this.echoSystemTalk('Peer was verified!');
            } else {
              this.echoSystemTalk('Error: Peer was not verified.');
              this.echoSystemTalk('Error: Connection was not established.');
              break;
            }
            this.establishProcessIfNeed();
            break;
          case 'talk':
            const userTalk: UserTalk = {
              kind: 'user',
              time: new Date(),
              talkerId: this.params.peerConnectId,
              content: parcel.content,
              arrived: true,
            };

            console.log('userTalk:', userTalk);
            this.params.onTalk(userTalk);
            break;
        }
      } catch (err) {
        console.error('Error:', err);
      }
    }
  }

  private async getSecretKey(peerPublicCryptoKey: CryptoKey): Promise<CryptoKey> {
    return crypto.subtle.deriveKey(
      { name: 'ECDH', public: peerPublicCryptoKey },
      (await this.encryptKeyPairPromise).privateKey,
      {name: 'AES-GCM', length: 128},
      false,
      ['encrypt', 'decrypt'],
    );
  }
}
