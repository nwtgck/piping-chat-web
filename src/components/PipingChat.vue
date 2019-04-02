<template>
  <div>
    <p>
      Server: <input type="text" v-model="serverUrl"><br>
      Your ID: <input type="text" v-model="talkerId"><br>
      Peer ID: <input type="text" v-model="peerId" placeholder="e.g. bma"><br>
      <button v-on:click="connectToPeer()">Connect</button><br>
      <details>
        <summary>Advanced</summary>
        <h3>Your public key</h3>
        <textarea cols="80" rows="8" v-model="publicKey" disabled></textarea>
        <details>
          <summary>Your private key (editable)</summary>
          <textarea cols="80" rows="8" v-model="privateKey"></textarea>
        </details>
        Key bits: <input type="number" v-model="nKeyBits">
        <button v-on:click="assignPrivateKey()">Regenerate keys</button>
        <h3>Peer's public key</h3>
        <textarea cols="80" rows="8" v-model="peerPublicKey"></textarea>
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
        <span v-if="talk.kind === 'user' && talk.talkerId !== talkerId">
          <b>{{ talk.talkerId }}</b>
          <time-ago :refresh="60" :datetime="talk.time" class="time"></time-ago><br>
        </span>
        <span v-if="talk.kind === 'user' && talk.talkerId === talkerId" class="time">
          <time-ago :refresh="60" :datetime="talk.time"></time-ago>
        </span>
        <span v-if="talk.kind === 'user'">
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
import { Component, Prop, Vue } from 'vue-property-decorator';
import TimeAgo from 'vue2-timeago'
import * as jsencrypt from 'jsencrypt';
import * as cryptojs from 'crypto-js';

type ParcelKind = "rsa_key" | "talk"

type Parcel = {
  kind: ParcelKind,
  content: string
};

type UserTalk = {
  kind: "user";
  time: Date,
  talkerId: String,
  content: String
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
    case "rsa_key":
    case "talk":
      return {
        kind: json.kind,
        content: json.content
      };
    default:
      return undefined;
  }
}

const RSA = {
  encrypt(publicKey: string, input: string): string {
    const crypt  = new jsencrypt.JSEncrypt();
    crypt.setPublicKey(publicKey);
    return crypt.encrypt(input);
  },
  decrypt(privateKey: string, encryptedText: string): string {
    const crypt  = new jsencrypt.JSEncrypt();
    crypt.setPublicKey(privateKey);
    return crypt.decrypt(encryptedText);
  },
  generateKeys(options: jsencrypt.Options): Promise<{publicKey: string, privateKey: string}> {
    const crypt  = new jsencrypt.JSEncrypt(options);
    return new Promise((resolve)=>{
      crypt.getKey(()=>{
        resolve({
          publicKey: crypt.getPublicKey(),
          privateKey: crypt.getPrivateKey(),
        })
      });
    });
  }
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

  private echoSystemTalk(message: string): void {
    this.talks.unshift({
      kind: "system",
      time: new Date(),
      content: message
    });
  }

  private async assignPrivateKey() {
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
    const { privateKey } = await RSA.generateKeys({
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
    this.assignPrivateKey();
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
    (async ()=>{
      this.echoSystemTalk(`Sending your public key to "${this.peerId}"...`);

      const url = `${this.serverUrl}/${getPath(this.talkerId, this.peerId)}`;
      const parcel: Parcel = {
        kind: "rsa_key",
        content: this.publicKey,
      };
      const res = await fetch(url, {
        method: "POST",
        body: JSON.stringify(parcel)
      });

      this.echoSystemTalk("Your public key sent.");
      this.hasPublicKeySent = true;
      this.echoEstablishMessageIfNeed();
      console.log("res:", res);
    })();

    // Get-loop of peer's message
    (async ()=>{
      const url = `${this.serverUrl}/${getPath(this.peerId, this.talkerId)}`;
      while(true) {
        try {
          console.log(`Getting ${url}...`);
          const res = await fetch(url, {
            method: "GET"
          });

          if(res.body === null) {
            console.log("ERROR: Body not found");
            return;
          }

          // Parse parcel
          const parcel: Parcel | undefined = parseJsonToParcel(
            await res.json()
          );

          if(parcel === undefined) {
            console.error(`Parse error: ${await res.json()}`);
            return;
          }

          switch (parcel.kind) {
            case "rsa_key":
              // Set peer's public key
              this.peerPublicKey = parcel.content;
              console.log("Peer's public key:", parcel.content);

              this.echoSystemTalk("Peer's public key received.");
              this.hasPeerPublicKeyReceived = true;
              this.echoEstablishMessageIfNeed();
              break;
            case "talk":
              // Decrypt talk
              const decryptedTalk: string = RSA.decrypt(
                this.privateKey,
                parcel.content
              );

              const userTalk: UserTalk = {
                kind: "user",
                time: new Date(),
                talkerId: this.peerId,
                content: decryptedTalk
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
    })();
  }

  sendTalk(): void {
    // Push my talk
    this.talks.unshift({
      kind: "user",
      time: new Date(),
      talkerId: this.talkerId,
      content: this.talk
    });
    const myTalk: string = this.talk;
    this.talk = "";

    (async ()=>{
      const url = `${this.serverUrl}/${getPath(this.talkerId, this.peerId)}`;
      if(this.peerPublicKey === undefined) {
        this.echoSystemTalk("Peer's public key is not received yet.");
      } else {
        // Encrypt talk
        const encryptedTalk: string = RSA.encrypt(
          this.peerPublicKey,
          myTalk
        );
        const parcel: Parcel = {
          kind: "talk",
          content: encryptedTalk,
        };
        const res = await fetch(url, {
          method: "POST",
          body: JSON.stringify(parcel)
        });
      }
    })();
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
