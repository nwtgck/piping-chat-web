<template>
  <div>
    <p>
      Server: <input type="text" v-model="serverUrl"><br>
      Your ID: <input type="text" v-model="talkerId"><br>
      Peer ID: <input type="text" v-model="peerId" placeholder="e.g. bma"><br>
      <button v-on:click="connectToPeer()">Connect</button><br>
      <input type="checkbox" v-model="enableSignature"> Enable connect with signature<br>
      <details>
        <summary>Advanced</summary>
        <h3>For signature</h3>
        <h4>Your public RSA PEM</h4>
        <textarea v-model="publicSignPem" cols="80" rows="10" disabled></textarea><br>
        <details>
          <summary>Your private RSA PEM</summary>
          <textarea v-model="privateSignPem" cols="80" rows="10"></textarea><br>
          Key bits: <input type="number" v-model="nKeyBits">
          <button v-on:click="assignPrivatePem()">Generate private keys only for signature</button><br>
          <button v-on:click="savePrivateKey()">Save private key</button>
          <button v-on:click="erasePrivateKey()">Erase private key from storage</button>
        </details>
        <h4>Peer's public RSA PEM</h4>
        <textarea cols="80" rows="8" v-model="peerPublicSignPem"></textarea>

        <details>
          <summary>For encryption</summary>
          <h4>Your public JWK</h4>
          <textarea cols="80" rows="8" v-model="publicEncryptJwkString" disabled></textarea>
          <details>
            <summary>Your private JWK</summary>
            <textarea cols="80" rows="8" v-model="privateEncryptJwkString" disabled></textarea>
          </details>
          <h4>Peer's public JWK</h4>
          <textarea cols="80" rows="8" v-model="peerPublicEncryptJwkString" disabled></textarea>
        </details>
      </details>
    </p>
    <hr>
    <p>
      <input type="text" v-model="talk" placeholder="Your talk">
      <button v-on:click="sendTalk()">Send</button>
    </p>
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


interface EcdhPublicJwkParcel {
  kind: 'ecdh_public_jwk';
  content: {
    jwk: JsonWebKey,
    signature?: string,
  };
}

interface TalkParcel {
  kind: 'talk';
  content: string;
}

type Parcel = EcdhPublicJwkParcel | TalkParcel;

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

/**
 * Parse JSON to Parcel
 * @param json
 */
function parseJsonToParcel(json: any): Parcel | undefined {
  if (json.content === undefined) {
    return undefined;
  }
  switch (json.kind) {
    case 'ecdh_public_jwk':
    case 'talk':
      return {
        kind: json.kind,
        content: json.content,
      };
    default:
      return undefined;
  }
}


// (NOTE: The reason not to use JSON.stringify() is that I'm not sure the order of items is always same.)
// TODO: Remove it and Use JWK thumbprint instead
function getSignDataFromJwk(jwk: JsonWebKey): string {
  // JSON string sorted by keys
  // (from: https://stackoverflow.com/a/16168003/2885946)
  return JSON.stringify(jwk, Object.keys(jwk));
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
    return this.hasPublicKeySent && this.hasPeerPublicKeyReceived;
  }
  // TODO: Hard code
  public serverUrl: string = 'https://ppng.ml';
  public peerId: string = '';

  public talkerId = getRandomId(3);
  public talks: Talk[] = [];

  public talk: string = '';

  public nKeyBits = 4096;

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
  public enableSignature = true; // TODO: false
  // Private PEM only for signature
  public privateSignPem = '';
  // Peer's public PEM for signature
  public peerPublicSignPem = '';

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

    // Get public JWK for encryption
    const publicJwk: JsonWebKey = await crypto.subtle.exportKey(
      'jwk',
      (await this.encryptKeyPairPromise).publicKey,
    );

    const url = `${this.serverUrl}/${getPath(this.talkerId, this.peerId)}`;

    // Signature of public encryption JWK
    const signature: string | undefined = await (async () => {
      if (this.enableSignature) {
        // Get private key by PEM
        const { privateKey } = await utils.privRsaPemToPubPrivKeys(this.signAlg, this.privateSignPem);
        // Sign
        const signatureBuff: ArrayBuffer = await window.crypto.subtle.sign(
          this.signAlg,
          privateKey,
          utils.stringToArrayBuffer(getSignDataFromJwk(publicJwk)),
        );
        // Base64 encode
        return btoa(utils.arrayBufferToString(signatureBuff));
      } else {
        return undefined;
      }
    })();

    const parcel: EcdhPublicJwkParcel = {
      kind: 'ecdh_public_jwk',
      content: {
        jwk: publicJwk,
        signature,
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

        // Response JSON
        const resJson: any = await (async () => {
          // If content type is JSON
          // TODO: This should be "application/json".
          //       however, POST application/json triggers preflight request
          //       and Piping Server doesn't support preflight request.
          if (res.headers.get('content-type') === 'text/plain') {
            return res.json();
          } else {
            if ( this.peerEncryptPublicCryptoKey === undefined ) {
              console.error('Error: this.peerPublicCryptoKey is undefined');
              return {};
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
            // Parse the text to JSON
            return JSON.parse(
              // TODO: any
              // String.fromCharCode.apply(null, new Uint8Array(decryptedParcel) as any)
              // (from: https://stackoverflow.com/a/41180394/2885946)
              new TextDecoder().decode(decryptedParcel),
            );
          }
        })();

        // Parse parcel
        const parcel: Parcel | undefined = parseJsonToParcel(resJson);

        if (parcel === undefined) {
          console.error(`Parse error: ${await res.json()}`);
          return;
        }

        switch (parcel.kind) {
          case 'ecdh_public_jwk':
            // Set peer's public JWK
            const peerPublicJwk: JsonWebKey = parcel.content.jwk;
            console.log('Peer\'s public JWK:', peerPublicJwk);

            // If signature connection is enable
            if (this.enableSignature) {
              const signature =  parcel.content.signature;
              // If no signature
              if (signature === undefined) {
                this.echoSystemTalk('Error: establishment failed because peer has no signature');
                break;
              }

              // Decode base64
              const signatureBuff: ArrayBuffer = utils.stringToArrayBuffer(atob(signature));

              // Get peer's public key
              const peerPublicKey = await utils.pubRsaPemToPubKey(this.signAlg, this.peerPublicSignPem);

              // Peer's JWK
              const signData: ArrayBuffer = utils.stringToArrayBuffer(getSignDataFromJwk(peerPublicJwk));

              const verified = await window.crypto.subtle.verify(
                this.signAlg,
                peerPublicKey,
                signatureBuff,
                signData,
              );

              console.log('verified:', verified);

              if (verified) {
                this.echoSystemTalk('Peer was verified!');
              } else {
                this.echoSystemTalk('Error: Peer was not verified.');
                this.echoSystemTalk('Error: Connection was not established.');
                break;
              }
            }

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
        // Create an initialization vector
        const iv = crypto.getRandomValues(new Uint8Array(this.aesGcmIvLength));
        // Get secret key
        const secretKey = await this.getSecretKey(this.peerEncryptPublicCryptoKey);
        // Encrypt parcel
        const encryptedParcel: ArrayBuffer = await crypto.subtle.encrypt(
          { name: 'AES-GCM', iv, tagLength: 128 },
          secretKey,
          // (from: https://stackoverflow.com/a/41180394/2885946)
          new TextEncoder().encode(JSON.stringify(parcel)),
        );
        await this.sendSeqCtx.run(async () => {
          const res = await fetch(url, {
            method: 'POST',
            body: utils.mergeUint8Array(iv, new Uint8Array(encryptedParcel)),
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
