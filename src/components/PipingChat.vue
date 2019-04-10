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
        <details>
          <summary>Your private RSA PEM</summary>
          <textarea v-model="privateSignPem" cols="80" rows="10"></textarea>
        </details>
        <h4>Peer's public RSA PEM</h4>
        <textarea cols="80" rows="8" v-model="peerPublicSignPem"></textarea>

        <details>
          <summary>For encryption</summary>
          <h4>Your public JWK</h4>
          <textarea cols="80" rows="8" v-model="publicJwkString" disabled></textarea>
          <details>
            <summary>Your private JWK</summary>
            <textarea cols="80" rows="8" v-model="privateJwkString" disabled></textarea>
          </details>
          <!--        Key bits: <input type="number" v-model="nKeyBits">-->
          <!--        <button v-on:click="assignPrivateKey()">Regenerate keys</button><br>-->
          <!--        <button v-on:click="savePrivateKey()">Save private key</button>-->
          <!--        <button v-on:click="erasePrivateKey()">Erase private key from storage</button>-->
          <h4>Peer's public JWK</h4>
          <textarea cols="80" rows="8" v-model="peerPublicJwkString" disabled></textarea>
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
import {Component, Vue} from 'vue-property-decorator';
import TimeAgo from 'vue2-timeago'
import * as jsencrypt from 'jsencrypt';
import * as cryptojs from 'crypto-js';
import {PromiseSequentialContext} from "@/promise-sequential-context";
import {AsyncComputed} from "@/AsyncComputed";
import * as utils from '@/utils';


type EcdhPublicJwkParcel = {
  kind: "ecdh_public_jwk",
  content: {
    jwk: JsonWebKey,
    signature?: string
  }
};

type TalkParcel = {
  kind: "talk",
  content: string
};

type Parcel = EcdhPublicJwkParcel | TalkParcel;

type UserTalk = {
  kind: "user";
  time: Date,
  talkerId: String,
  content: String,
  arrived: boolean,
};

type SystemTalk = {
  kind: "system";
  time: Date,
  content: String
};

type Talk = UserTalk | SystemTalk;

/**
 * Get random ID
 * @param len
 */
function getRandomId(len: number): string {
  // NOTE: some similar shaped alphabets are not used
  const alphas  = ["a", "b", "c", "d", "e", "f", "h", "i", "j", "k", "m", "n", "p", "r", "s", "t", "u", "v", "w", "x", "y", "z"];
  const chars   = [...alphas];

  const randomArr = window.crypto.getRandomValues(new Uint32Array(len));
  return Array.from(randomArr).map(n => chars[n % chars.length]).join('');
}


function getPath(toId: string, fromId: string): string {
  return cryptojs.SHA256(`${toId}-to-${fromId}`).toString();
}

/**
 * Parse JSON to Parcel
 * @param json
 */
function parseJsonToParcel(json: any): Parcel | undefined {
  if(json.content === undefined) {
    return undefined;
  }
  switch (json.kind) {
    case "ecdh_public_jwk":
    case "talk":
      return {
        kind: json.kind,
        content: json.content
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

const StorageKeys = {
  PRIVATE_KEY: "PRIVATE_KEY_LOCAL_STORAGE_KEY"
};

@Component({
  components: {
    TimeAgo
  }
})
export default class PipingChat extends Vue {
  // TODO: Hard code
  serverUrl: string = "https://ppng.ml";
  peerId: string = "";

  talkerId = getRandomId(3);
  talks: Talk[] = [];

  talk: string = "";

  nKeyBits = 2048;

  // My private key
  // NOTE: public key can be computable by private key
  privateKey: string = "";

  // Peer's public key
  peerPublicKey: string = "";

  // My key pair
  keyPairPromise: PromiseLike<CryptoKeyPair> = window.crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256'},
    true,
    ['deriveKey', 'deriveBits']
  );

  // Peer's public key
  peerPublicCryptoKey?: CryptoKey;

  // Initialization vector size
  readonly aesGcmIvLength: number = 12;

  enableSignature = false;
  privateSignPem = "";
  peerPublicSignPem = "";

  // Algorithm for signature
  signAlg = { name: 'RSASSA-PKCS1-v1_5', hash: { name: "SHA-256" }};

  // My public key
  get publicKey(): string {
    if (this.privateKey === "") {
      return "";
    } else {
      try {
        // Compute public key by the private key
        const crypt = new jsencrypt.JSEncrypt();
        crypt.setPrivateKey(this.privateKey);
        return crypt.getPublicKey();
      } catch (err) {
        console.error(err);
        return "INVALID PRIVATE KEY";
      }
    }
  }

  // Whether your public key sent or not
  private hasPublicKeySent: boolean = false;
  // Whether peer's public key received or not
  private hasPeerPublicKeyReceived: boolean = false;

  private recieveSeqCtx = new PromiseSequentialContext();
  private sendSeqCtx    = new PromiseSequentialContext();

  @AsyncComputed()
  async publicJwkString(): Promise<string>{
    const jwk = await window.crypto.subtle.exportKey('jwk', (await this.keyPairPromise).publicKey);
    return JSON.stringify(jwk, null, "  ");
  }

  @AsyncComputed()
  async privateJwkString(): Promise<string>{
    const jwk = await window.crypto.subtle.exportKey('jwk', (await this.keyPairPromise).privateKey);
    return JSON.stringify(jwk, null, "  ");
  }

  @AsyncComputed()
  async peerPublicJwkString(): Promise<string> {
    const self = this;
    return new Promise(resolve => {
      // Watch peerPublicCryptoKey
      (async function loop(){
        if(self.peerPublicCryptoKey === undefined) {
          setTimeout(loop, 1000);
        } else {
          const jwk = await window.crypto.subtle.exportKey('jwk', self.peerPublicCryptoKey);
          resolve(JSON.stringify(jwk, null, "  "));
        }
      })();
    });
  }

  private echoSystemTalk(message: string): void {
    this.talks.unshift({
      kind: "system",
      time: new Date(),
      content: message
    });
  }

  // Assign a private key asynchronously
  private async assignPrivateKey(): Promise<void> {
    // TODO: do something
    return;

    // Echo generating message
    this.echoSystemTalk(`${this.nKeyBits}-bit key generating...`);

    // Record start
    const startTime = new Date();
    // Generating message loop
    const timerId = setInterval(()=>{
      const pastSec: number = (new Date().getTime() - startTime.getTime()) / 1000;
      this.echoSystemTalk(`${this.nKeyBits}-bit key generating... (${pastSec} sec passed)`);
    }, 4000);

    // Generate key
    const { privateKey } = await utils.RSA.generateKeys({
      default_key_size: this.nKeyBits
    });
    // Clear the time
    clearInterval(timerId);
    // Update private key
    this.privateKey = privateKey;

    // Echo generated message
    this.echoSystemTalk(`🔑 ${this.nKeyBits}-bit key generated!`);
  }

  mounted() {
    const privateKey: string | null = localStorage.getItem(StorageKeys.PRIVATE_KEY);
    // If private key is not found
    if(privateKey === null) {
      // Assign a private key asynchronously
      this.assignPrivateKey();
    } else {
      this.privateKey = privateKey;
      this.echoSystemTalk("🔑 Your private key loaded!");
    }
  }

  private savePrivateKey(): void {
    // If private is not invalid
    if(this.privateKey !== "") {
      // Save private key in local storage
      localStorage.setItem(StorageKeys.PRIVATE_KEY, this.privateKey);
      this.echoSystemTalk("Your private key saved.");
    }
  }

  private erasePrivateKey(): void {
    // If private key in storage not found
    if(localStorage.getItem(StorageKeys.PRIVATE_KEY) === null) {
      this.echoSystemTalk("Private key is not saved yet.");
    } else {
      localStorage.removeItem(StorageKeys.PRIVATE_KEY);
      this.echoSystemTalk("Your private key erased from local storage.");
    }
  }

  get isEstablished(): boolean {
    return this.hasPublicKeySent && this.hasPeerPublicKeyReceived;
  }

  // Print established message if established
  echoEstablishMessageIfNeed(): void {
    if(this.isEstablished) {
      this.echoSystemTalk(`Connection established with "${this.peerId}"!`);
    }
  }

  connectToPeer(): void {
    // Send my public key
    this.sendPublicKey();

    // Get-loop of peer's message
    this.receiveParcelLoop();
  }

  async sendPublicKey() {
    this.echoSystemTalk(`Sending your public key to "${this.peerId}"...`);

    // Get public JWK for encryption
    const publicJwk: JsonWebKey = await crypto.subtle.exportKey(
      'jwk',
      (await this.keyPairPromise).publicKey
    );

    const url = `${this.serverUrl}/${getPath(this.talkerId, this.peerId)}`;

    // Signature of public encryption JWK
    const signature: string | undefined = await (async ()=>{
      if (this.enableSignature) {
        // Get private key by PEM
        const { privateKey } = await utils.privRsaPemToPubPrivKeys(this.signAlg, this.privateSignPem);
        // Sign
        const signatureBuff: ArrayBuffer = await window.crypto.subtle.sign(
          this.signAlg,
          privateKey,
          utils.stringToArrayBuffer(getSignDataFromJwk(publicJwk))
        );
        // Base64 encode
        return btoa(utils.arrayBufferToString(signatureBuff));
      } else {
        return undefined;
      }
    })();

    const parcel: EcdhPublicJwkParcel = {
      kind: "ecdh_public_jwk",
      content: {
        jwk: publicJwk,
        signature: signature
      },
    };
    console.log('parcel:', JSON.stringify(parcel));
    const res = await this.sendSeqCtx.run(()=>
      fetch(url, {
        method: "POST",
        headers: {
          // TODO: This should be "application/json".
          //       however, POST application/json triggers preflight request
          //       and Piping Server doesn't support preflight request.
          "content-type": "text/plain"
        },
        body: JSON.stringify(parcel)
      })
    );

    this.echoSystemTalk("Your public key sent.");
    this.hasPublicKeySent = true;
    this.echoEstablishMessageIfNeed();
    console.log("res:", res);
  }

  async receiveParcelLoop() {
    const url = `${this.serverUrl}/${getPath(this.peerId, this.talkerId)}`;
    while(true) {
      try {
        console.log(`Getting ${url}...`);
        const res = await this.recieveSeqCtx.run(()=>
          fetch(url, {
            method: "GET"
          })
        );

        if(res.body === null) {
          console.log("ERROR: Body not found");
          return;
        }

        // Response JSON
        const resJson: any = await (async ()=>{
          // If content type is JSON
          // TODO: This should be "application/json".
          //       however, POST application/json triggers preflight request
          //       and Piping Server doesn't support preflight request.
          if(res.headers.get("content-type") === "text/plain") {
            return res.json();
          } else {
            if( this.peerPublicCryptoKey === undefined ) {
              console.error("Error: this.peerPublicCryptoKey is undefined");
              return {};
            }
            // Get body
            const body: Uint8Array = await utils.getBodyBytesFromResponse(res);
            // Split body into IV and encrypted parcel
            const iv = body.slice(0, this.aesGcmIvLength);
            const encryptedParcel = body.slice(this.aesGcmIvLength);
            console.log("body:", body);
            // Get secret key
            const secretKey = await this.getSecretKey(this.peerPublicCryptoKey);
            // Decrypt body text
            const decryptedParcel: ArrayBuffer = await crypto.subtle.decrypt(
              { name: 'AES-GCM', iv, tagLength: 128 },
              secretKey,
              encryptedParcel
            );
            // Parse the text to JSON
            return JSON.parse(
              // TODO: any
              // String.fromCharCode.apply(null, new Uint8Array(decryptedParcel) as any)
              // (from: https://stackoverflow.com/a/41180394/2885946)
              new TextDecoder().decode(decryptedParcel)
            );
          }
        })();

        // Parse parcel
        const parcel: Parcel | undefined = parseJsonToParcel(resJson);

        if(parcel === undefined) {
          console.error(`Parse error: ${await res.json()}`);
          return;
        }

        switch (parcel.kind) {
          case "ecdh_public_jwk":
            // Set peer's public JWK
            const peerPublicJwk: JsonWebKey = parcel.content.jwk;
            console.log("Peer's public JWK:", peerPublicJwk);

            // If signature connection is enable
            if (this.enableSignature) {
              const signature =  parcel.content.signature;
              // If no signature
              if (signature === undefined) {
                this.echoSystemTalk("Error: establishment failed because peer has no signature");
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
                signData
              );

              console.log('verified:', verified);

              if (verified) {
                this.echoSystemTalk("Peer was verified!");
              } else {
                this.echoSystemTalk("Error: Peer was not verified.");
                this.echoSystemTalk("Error: Connection was not established.");
                break;
              }
            }

            // Assign peer's public JWK by import
            this.peerPublicCryptoKey = await crypto.subtle.importKey(
              'jwk',
              peerPublicJwk,
              {name: 'ECDH', namedCurve: 'P-256'},
              true,
              []
            );

            this.echoSystemTalk("Peer's public key received.");
            this.hasPeerPublicKeyReceived = true;
            this.echoEstablishMessageIfNeed();
            break;
          case "talk":
            const userTalk: UserTalk = {
              kind: "user",
              time: new Date(),
              talkerId: this.peerId,
              content: parcel.content,
              arrived: true
            };

            console.log("userTalk:", userTalk);

            // NOTE: I'm not sure this usage is correct to update asynchronously,
            //       but without this, it sometimes weren't updated.
            this.$nextTick(()=>{
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

  sendTalk(): void {
    const userTalk: UserTalk = {
      kind: "user",
      time: new Date(),
      talkerId: this.talkerId,
      content: this.talk,
      arrived: false,
    };
    // Push my talk
    this.talks.unshift(userTalk);
    const myTalk: string = this.talk;
    this.talk = "";

    (async ()=>{
      const url = `${this.serverUrl}/${getPath(this.talkerId, this.peerId)}`;
      if(this.peerPublicCryptoKey === undefined) {
        this.echoSystemTalk("Peer's public key is not received yet.");
      } else {
        const parcel: Parcel = {
          kind: "talk",
          content: myTalk,
        };
        // Create an initialization vector
        const iv = crypto.getRandomValues(new Uint8Array(this.aesGcmIvLength));
        // Get secret key
        const secretKey = await this.getSecretKey(this.peerPublicCryptoKey);
        // Encrypt parcel
        const encryptedParcel: ArrayBuffer = await crypto.subtle.encrypt(
          { name: 'AES-GCM', iv, tagLength: 128 },
          secretKey,
          // (from: https://stackoverflow.com/a/41180394/2885946)
          new TextEncoder().encode(JSON.stringify(parcel))
        );
        await this.sendSeqCtx.run(async () => {
          const res = await fetch(url, {
            method: "POST",
            body: utils.mergeUint8Array(iv, new Uint8Array(encryptedParcel))
          });
          if (res.body === null) {
            this.echoSystemTalk("Unexpected error: send-body is null.");
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

  private async getSecretKey(peerPublicCryptoKey: CryptoKey): Promise<CryptoKey> {
    return crypto.subtle.deriveKey(
      { name: 'ECDH', public: peerPublicCryptoKey },
      (await this.keyPairPromise).privateKey,
      {'name': 'AES-GCM', length: 128},
      false,
      ['encrypt', 'decrypt']
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
