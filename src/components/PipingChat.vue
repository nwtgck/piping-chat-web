<template>
  <div>
    <p>
      Server: <input type="text" v-model="serverUrl">
      Peer ID: <input type="text" v-model="peerId" placeholder="e.g. bma">
      <button v-on:click="connectToPeer()">Connect</button>
    </p>
    <hr>
    <p>
      Your ID: <input type="text" v-model="talkerId">
      <input type="text" v-model="talk" placeholder="Your talk">
      <button v-on:click="sendTalk()">Send</button>
    </p>
    <!-- History of talks-->
    <div>
      <div v-for="talk in talks" :class='{"me": talk.talkerId === talkerId}'>
        <span v-if="talk.kind === 'user' && talk.talkerId !== talkerId">
          <b>{{ talk.talkerId }}</b>
          <span class="time">{{ dateFormat(talk.time )}}</span><br>
        </span>
        <span v-if="talk.kind === 'user' && talk.talkerId === talkerId" class="time">
          {{ dateFormat(talk.time) }}
        </span>
        <span v-if="talk.kind === 'user'">
        「{{ talk.content }}」
        </span>
        <span v-if="talk.kind === 'system'">
          System: {{ talk.content }}
        </span>
      </div>
    </div>
  </div>
</template>

<script lang="ts">
import { Component, Prop, Vue } from 'vue-property-decorator';
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
  const alphas  = ["a", "b", "c", "d", "e", "f", "h", "i", "j", "k", "m", "n", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z"];
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


@Component
export default class PipingChat extends Vue {
  // TODO: Hard code
  serverUrl: string = "https://ppng.ml";
  peerId: string = "";

  talkerId = getRandomId(3);
  talks: Talk[] = [];

  talk: string = "";

  // My crypt
  private crypt     = new jsencrypt.JSEncrypt();
  // Peer crypt
  private peerCrypt = new jsencrypt.JSEncrypt();

  // TODO: Implement properly
  dateFormat(date: Date): string {
    return date.toString();
  }

  connectToPeer(): void {

    this.talks.push({
      kind: "system",
      time: new Date(),
      content: "Connecting..."
    });

    // Send my public key
    (async ()=>{
      // Get my public key
      const publicKey: string = await new Promise(resolve => {
        this.crypt.getKey(()=>{
          resolve(this.crypt.getPublicKey())
        });
      });

      const url = `${this.serverUrl}/${getPath(this.talkerId, this.peerId)}`;
      const parcel: Parcel = {
        kind: "rsa_key",
        content: publicKey,
      };
      const res = await fetch(url, {
        method: "POST",
        body: JSON.stringify(parcel)
      });
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
              this.peerCrypt.setPublicKey(parcel.content);
              console.log("Peer's public key:", parcel.content);

              this.talks.push({
                kind: "system",
                time: new Date(),
                content: "Connection established!"
              });

              break;
            case "talk":
              // Decrypt talk
              const decryptedTalk: string = this.crypt.decrypt(parcel.content);

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
                this.talks.push(userTalk);
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
    this.talks.push({
      kind: "user",
      time: new Date(),
      talkerId: this.talkerId,
      content: this.talk
    });
    const myTalk: string = this.talk;
    this.talk = "";

    (async ()=>{
      const url = `${this.serverUrl}/${getPath(this.talkerId, this.peerId)}`;
      // Encrypt talk
      const encryptedTalk: string = this.peerCrypt.encrypt(myTalk);
      const parcel: Parcel = {
        kind: "talk",
        content: encryptedTalk,
      };
      const res = await fetch(url, {
        method: "POST",
        body: JSON.stringify(parcel)
      });
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
};
</style>
