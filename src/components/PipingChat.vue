<template xmlns:v-slot="http://www.w3.org/1999/XSL/Transform">
  <div>
    <v-layout>
      <v-flex xs12 offset-sm2 sm8 offset-md3 md6>
        <v-card style="padding: 1em;">
          <v-text-field label="Server URL"
                        v-model="serverUrl" />
          <v-text-field label="Your ID"
                        v-model="talkerId" />
          <v-text-field label="Peer ID"
                        v-model="peerId"
                        placeholder="e.g. bma" />
          <v-switch label="Public key authentication"
                    v-model="enableSignature" />

          <div v-if="enableSignature">
            <v-textarea label="Your public RSA PEM"
                        v-model="publicSignPem"
                        readonly
                        outline
                        prepend-icon="person" />
            <v-switch label="Show your private PEM"
                      color="secondary"
                      v-model="showsPrivateSignPem"/>
            <v-textarea label="Your private RSA PEM"
                        v-model="privateSignPem"
                        v-if="showsPrivateSignPem"
                        outline
                        prepend-icon="lock" />

            <v-text-field label="Key bits"
                          type="number"
                          v-model="nKeyBits" />
            <!-- Generate PEM button -->
            <v-btn color="secondary"
                   v-on:click="assignPrivatePem()">
              <v-icon>autorenew</v-icon>
              Generate PEMs
            </v-btn>
            <!-- Save PEM button -->
            <v-btn color="secondary"
                   v-on:click="savePrivateKey()">
              <v-icon>save</v-icon>
              Save PEMs
            </v-btn>
            <!-- Erase PEM button -->
            <v-btn color="secondary"
                   v-on:click="erasePrivateKey()">
              <v-icon>delete</v-icon>
              Erase PEMs
            </v-btn>

            <v-textarea label="Peer's public RSA PEM"
                        v-model="peerPublicSignPem"
                        outline
                        prepend-icon="person"
                        style="padding-top: 3em;"/>
          </div>

          <v-btn color="success"
                 v-on:click="connectToPeer()"
                 block>
            Connect
          </v-btn>
        </v-card>

        <v-expansion-panel>
          <v-expansion-panel-content>
            <template v-slot:header>
              <v-icon>person</v-icon>
              <div>Connection details</div>
            </template>
            <v-card style="padding: 1em;">
              <v-text-field label="Session ID"
                            v-bind:value="sessionId"
                            placeholder=" "
                            readonly />
              <v-textarea label="Your public JWK for encryption"
                          v-model="publicEncryptJwkString"
                          readonly
                          prepend-icon="public"
                          outline />
              <v-switch label="Show private JWK for encryption"
                        color="secondary"
                        v-model="showsPrivateEncryptJwk"/>
              <v-textarea label="Your private JWK for encryption"
                          v-model="privateEncryptJwkString"
                          v-if="showsPrivateEncryptJwk"
                          readonly
                          prepend-icon="vpn_key"
                          outline />

              <h4></h4>
              <v-textarea label="Peer's public JWK for encryption"
                          v-model="peerPublicEncryptJwkString"
                          readonly
                          prepend-icon="public"
                          placeholder=" "
                          outline />
            </v-card>
          </v-expansion-panel-content>
        </v-expansion-panel>
      </v-flex>
    </v-layout>

    <div style="margin: 1em;">
      <!-- Talk input -->
      <v-layout>
        <v-flex offset-md1 md10 offset-lg2 lg8>
          <v-container fluid>
            <v-layout column>
              <v-flex>
                <!-- NOTE: hide-details is for deleting bottom space -->
                <v-textarea label="Your talk"
                            v-model="talk"
                            v-bind:disabled="!isEstablished"
                            outline
                            hide-details />
              </v-flex>
              <v-flex offset-xs9 xs3 offset-lg11 lg1>
                <v-btn v-on:click="sendTalk()"
                       v-bind:disabled="!isEstablished"
                       color="secondary"
                       block >
                  <v-icon>send</v-icon>
                  Send
                </v-btn>
              </v-flex>

            </v-layout>
          </v-container>
        </v-flex>
      </v-layout>


      <!-- History of talks-->
      <div>
        <div v-for="talk in talks" :class='{"me": talk.talkerId === talkerId}'>
        <span v-if="talk.kind === 'user'">
          <div v-if="talk.talkerId !== talkerId">
            <b>{{ talk.talkerId }}</b>
            <time-ago :refresh="60" :datetime="talk.time" class="time"></time-ago><br>
          </div>
          <span v-if="talk.talkerId === talkerId">
            {{ talk.arrived ? "✓" : "" }}
            <time-ago :refresh="60" :datetime="talk.time" class="time"></time-ago>
          </span>
        「{{ talk.content }}」
        </span>
          <span v-if="talk.kind === 'system'">
          <b>System</b> <time-ago :refresh="60" :datetime="talk.time" class="time"></time-ago>:
          {{ talk.content }}
        </span>
        </div>
      </div>
    </div>
  </div>
</template>

<script lang="ts">
/* tslint:disable:no-console */
import {Component, Vue} from 'vue-property-decorator';
import TimeAgo from 'vue2-timeago';
import * as jsencrypt from 'jsencrypt';
import * as cryptojs from 'crypto-js';
import {PromiseSequentialContext} from '@/promise-sequential-context';
import {AsyncComputed} from '@/AsyncComputed';
import * as utils from '@/utils';
import { jwk2pem } from 'pem-jwk';
import {nul, bool, num, str, literal, opt, arr, tuple, obj, union, TsType, validatingParse} from 'ts-json-validator';


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

interface UserTalk {
  kind: 'user';
  time: Date;
  talkerId: string;
  content: string;
  arrived: boolean;
}

interface SystemTalk {
  kind: 'system';
  time: Date;
  content: string;
}

type Talk = UserTalk | SystemTalk;

/**
 * Get random ID
 * @param len
 */
function getRandomId(len: number): string {
  // NOTE: some similar shaped alphabets are not used
  const alphas  = [
    'a', 'b', 'c', 'd', 'e', 'f', 'h', 'i', 'j', 'k', 'm', 'n', 'p', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
  ];
  const chars   = [...alphas];

  const randomArr = window.crypto.getRandomValues(new Uint32Array(len));
  return Array.from(randomArr).map((n) => chars[n % chars.length]).join('');
}


function getPath(toId: string, fromId: string): string {
  return cryptojs.SHA256(`${toId}-to-${fromId}`).toString();
}

// (NOTE: The reason not to use JSON.stringify() is that I'm not sure the order of items is always same.)
// TODO: Remove it and Use JWK thumbprint instead
function getPoorJwkFingerprint(jwk: JsonWebKey): string {
  // JSON string sorted by keys
  // (from: https://stackoverflow.com/a/16168003/2885946)
  return JSON.stringify(jwk, Object.keys(jwk));
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
  const sessionIdJwk: JsonWebKey = await window.crypto.subtle.exportKey(
    'jwk',
    sessionIdKey,
  );
  const sessionIdPoorFingerprint = getPoorJwkFingerprint(sessionIdJwk);
  // Return session ID
  return cryptojs.SHA256(sessionIdPoorFingerprint).toString();
}


/**
 * Get JSON string from Crypto key
 * @param key
 */
async function getJwkString(key: CryptoKey): Promise<string> {
  const jwk = await window.crypto.subtle.exportKey('jwk', key);
  return JSON.stringify(jwk, null, '  ');
}

const StorageKeys = {
  PRIVATE_SIGNATURE_PEM: 'LOCAL_STORAGE_KEY/PRIVATE_SIGNATURE_PEM',
};

@Component({
  components: {
    TimeAgo,
  },
})
export default class PipingChat extends Vue {

  // My public key
  get publicSignPem(): string {
    if (this.privateSignPem === '') {
      return '';
    } else {
      try {
        // Compute public key by the private key
        const crypt = new jsencrypt.JSEncrypt();
        crypt.setPrivateKey(this.privateSignPem);
        return crypt.getPublicKey();
      } catch (err) {
        console.error(err);
        return 'INVALID PRIVATE KEY';
      }
    }
  }

  get isEstablished(): boolean {
    return this.hasPublicKeySent && this.hasPeerPublicKeyReceived && (!this.enableSignature || this.peerVerified);
  }
  // TODO: Hard code
  public serverUrl: string = 'https://ppng.ml';
  public peerId: string = '';

  public talkerId = getRandomId(3);
  public talks: Talk[] = [];

  public talk: string = '';

  public nKeyBits = 4096;

  // Key pair to create session ID
  public sessionIdKeyPairPromise: PromiseLike<CryptoKeyPair> = window.crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256'},
    true,
    ['deriveKey', 'deriveBits'],
  );

  // Session ID
  public sessionId: string = '';
  // Whether peer is verified by public key authentication
  public peerVerified: boolean = false;

  // Key pair for encryption
  public encryptKeyPairPromise: PromiseLike<CryptoKeyPair> = window.crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256'},
    true,
    ['deriveKey', 'deriveBits'],
  );

  // Peer's public key for encryption
  public peerEncryptPublicCryptoKey?: CryptoKey;

  // Initialization vector size
  public readonly aesGcmIvLength: number = 12;

  // Whether using signature to verify peer
  public enableSignature = false;
  // Private PEM only for signature
  public privateSignPem = '';
  // Peer's public PEM for signature
  public peerPublicSignPem = '';
  // Whether showing private PEM for signature or not
  public showsPrivateSignPem: boolean = false;
  // Whether showing private JWK for encryption or not
  public showsPrivateEncryptJwk: boolean = false;

  // Algorithm for signature
  public signAlg = { name: 'RSASSA-PKCS1-v1_5', hash: { name: 'SHA-256' } };

  // Whether your public key sent or not
  private hasPublicKeySent: boolean = false;
  // Whether peer's public key received or not
  private hasPeerPublicKeyReceived: boolean = false;

  // Context to receive talks sequentially
  private recieveSeqCtx = new PromiseSequentialContext();
  // Context to send talks sequentially
  private sendSeqCtx    = new PromiseSequentialContext();


  // Public JWK string for encryption
  @AsyncComputed()
  public async publicEncryptJwkString(): Promise<string> {
    return getJwkString((await this.encryptKeyPairPromise).publicKey);
  }

  // Private JWK string for encryption
  @AsyncComputed()
  public async privateEncryptJwkString(): Promise<string> {
    return getJwkString((await this.encryptKeyPairPromise).privateKey);
  }

  // Peer's public JWK string for encryption
  @AsyncComputed()
  public async peerPublicEncryptJwkString(): Promise<string> {
    const self = this;
    return new Promise((resolve) => {
      // Watch peerPublicCryptoKey
      (async function loop() {
        if (self.peerEncryptPublicCryptoKey === undefined) {
          setTimeout(loop, 1000);
        } else {
          resolve(getJwkString(self.peerEncryptPublicCryptoKey));
        }
      })();
    });
  }

  public mounted() {
    const privatePem: string | null = localStorage.getItem(StorageKeys.PRIVATE_SIGNATURE_PEM);
    // If private key is found
    if (privatePem !== null) {
      this.privateSignPem = privatePem;
      this.echoSystemTalk('🔑 Your private PEM loaded!');
    }
  }

  // Print established message if established
  public echoEstablishMessageIfNeed(): void {
    if (this.isEstablished) {
      this.echoSystemTalk(`Connection established with "${this.peerId}"!`);
    }
  }

  public connectToPeer(): void {
    // Send my public key
    this.sendPublicKey();

    // Get-loop of peer's message
    this.receiveParcelLoop();
  }

  public async sendPublicKey() {
    this.echoSystemTalk(`Sending your public key to "${this.peerId}"...`);

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

    const url = `${this.serverUrl}/${getPath(this.talkerId, this.peerId)}`;

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
    this.echoEstablishMessageIfNeed();
    console.log('res:', res);
  }

  public async receiveParcelLoop() {
    const url = `${this.serverUrl}/${getPath(this.peerId, this.talkerId)}`;
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
            console.log('Session ID:', this.sessionId);

            // Assign peer's public JWK by import
            this.peerEncryptPublicCryptoKey = await crypto.subtle.importKey(
              'jwk',
              peerPublicJwk,
              {name: 'ECDH', namedCurve: 'P-256'},
              true,
              [],
            );

            this.echoSystemTalk('Peer\'s public key received.');
            this.hasPeerPublicKeyReceived = true;

            // If signature is enabled
            if (this.enableSignature) {
              // Get private key by PEM
              const { privateKey } = await utils.privRsaPemToPubPrivKeys(this.signAlg, this.privateSignPem);
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
                const url = `${this.serverUrl}/${getPath(this.talkerId, this.peerId)}`;
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

            this.echoEstablishMessageIfNeed();
            break;
          case 'session_id_signature':
            if (this.sessionId === undefined) {
              console.error('Unexpected Error: session is not defined');
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
            const peerPublicKey = await utils.pubRsaPemToPubKey(this.signAlg, this.peerPublicSignPem);
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
            this.echoEstablishMessageIfNeed();
            break;
          case 'talk':
            const userTalk: UserTalk = {
              kind: 'user',
              time: new Date(),
              talkerId: this.peerId,
              content: parcel.content,
              arrived: true,
            };

            console.log('userTalk:', userTalk);

            // NOTE: I'm not sure this usage is correct to update asynchronously,
            //       but without this, it sometimes weren't updated.
            this.$nextTick(() => {
              // Push peer's message
              this.talks.unshift(userTalk);
            });
            break;
        }
      } catch (err) {
        console.error('Error:', err);
      }
    }
  }

  public sendTalk(): void {
    const userTalk: UserTalk = {
      kind: 'user',
      time: new Date(),
      talkerId: this.talkerId,
      content: this.talk,
      arrived: false,
    };
    // Push my talk
    this.talks.unshift(userTalk);
    const myTalk: string = this.talk;
    this.talk = '';

    (async () => {
      const url = `${this.serverUrl}/${getPath(this.talkerId, this.peerId)}`;
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
    this.talks.unshift({
      kind: 'system',
      time: new Date(),
      content: message,
    });
  }

  // Assign a private key asynchronously
  private async assignPrivatePem(): Promise<void> {
    // Echo generating message
    this.echoSystemTalk(`${this.nKeyBits}-bit key generating...`);

    // Record start
    const startTime = new Date();
    // Generating message loop
    const timerId = setInterval(() => {
      const pastSec: number = (new Date().getTime() - startTime.getTime()) / 1000;
      this.echoSystemTalk(`${this.nKeyBits}-bit key generating... (${pastSec} sec passed)`);
    }, 4000);

    // Generate RSA private PEM
    const rsaPrivateKey: CryptoKeyPair = await window.crypto.subtle.generateKey(
      { ...this.signAlg, modulusLength: this.nKeyBits,  publicExponent: new Uint8Array([0x01, 0x00, 0x01]) },
      true,
      ['sign', 'verify'],
    );
    // Clear the timer
    clearInterval(timerId);

    // Export to JWK
    const rsaPrivateJwk: JsonWebKey = await window.crypto.subtle.exportKey('jwk', rsaPrivateKey.privateKey);
    if (rsaPrivateJwk.kty !== undefined && rsaPrivateJwk.n !== undefined && rsaPrivateJwk.e !== undefined) {
      const jwk = {
        ...rsaPrivateJwk,
        kty: rsaPrivateJwk.kty,
        n: rsaPrivateJwk.n,
        e: rsaPrivateJwk.e,
      };
      // Assign private pem
      this.privateSignPem = jwk2pem(jwk);
      // Echo generated message
      this.echoSystemTalk(`🔑 ${this.nKeyBits}-bit PEM generated!`);
    } else {
      // Echo generated message
      this.echoSystemTalk(`Error: ${this.nKeyBits}-bit PEM not generated`);
    }
  }

  private savePrivateKey(): void {
    // If private is not invalid
    if (this.privateSignPem !== '') {
      // Save private key in local storage
      localStorage.setItem(StorageKeys.PRIVATE_SIGNATURE_PEM, this.privateSignPem);
      this.echoSystemTalk('Your private PEM saved.');
    }
  }

  private erasePrivateKey(): void {
    // If private key in storage not found
    if (localStorage.getItem(StorageKeys.PRIVATE_SIGNATURE_PEM) === null) {
      this.echoSystemTalk('Private PEM is not saved yet.');
    } else {
      localStorage.removeItem(StorageKeys.PRIVATE_SIGNATURE_PEM);
      this.echoSystemTalk('Your private PEM erased from local storage.');
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
</script>

<!-- Add "scoped" attribute to limit CSS to this component only -->
<style scoped>
.me{
  text-align: right;
}
.time{
  font-size: 0.6em;
  color: #aaa;
}
</style>
