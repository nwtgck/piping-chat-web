<template>
  <div>
    <p>
      Server: <input type="text" v-model="serverUrl">
      Peer ID: <input type="text" v-model="peerId" placeholder="e.g. bma">
      <button v-on:click="connectToPeer()">Connect</button>
    </p>
    <hr>
    <p>
      Your ID: <input type="text" v-bind:value="talkerId" disabled>
      <input type="text" placeholder="Your talk">
      <button>Send</button>
    </p>
    <!-- History of talks-->
    <div>
      <div v-for="talk in talks" :class='{"me": talk.talkerId === talkerId}'>
        <span v-if="talk.talkerId !== talkerId">
          <b>{{ talk.talkerId }}</b>
          <span class="time">{{ dateFormat(talk.time )}}</span><br>
        </span>
        <span v-if="talk.talkerId === talkerId" class="time">
          {{ dateFormat(talk.time) }}
        </span>
        「{{ talk.content }}」
      </div>
    </div>
  </div>
</template>

<script lang="ts">
import { Component, Prop, Vue } from 'vue-property-decorator';

type Talk = {
  time: Date,
  talkerId: String,
  content: String
};

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
  return `${toId}-to-${fromId}`;
}

@Component
export default class PipingChat extends Vue {
  // TODO: Hard code
  serverUrl: string = "https://ppng.ml";
  peerId: string = "";

  talkerId = getRandomId(3);
  // TODO: Hard code
  talks: Talk[] = [
    {
      time: new Date(),
      talkerId: "hoge_id2",
      content: "Hi!"
    },
    {
      time: new Date(),
      talkerId: this.talkerId,
      content: "Hello. How are you?"
    },
    {
      time: new Date(),
      talkerId: "hoge_id2",
      content: "Good."
    },
  ];

  // TODO: Implement properly
  dateFormat(date: Date): string {
    return date.toString();
  }

  connectToPeer(): void {
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

          const talk: Talk = {
            time: new Date(),
            talkerId: this.peerId,
            content: await res.text()
          };

          console.log("talk:", talk);

          // Push peer's message
          this.talks.push(talk);
        } catch (err) {
          console.error('Error:', err);
        }
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
};
</style>
