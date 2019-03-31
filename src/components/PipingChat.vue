<template>
  <div>
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

@Component
export default class PipingChat extends Vue {
  // TODO: Hard code
  talks: Talk[] = [
    {
      time: new Date(),
      talkerId: "hoge_id2",
      content: "Hi!"
    },
    {
      time: new Date(),
      talkerId: "hoge_id1",
      content: "Hello. How are you?"
    },
    {
      time: new Date(),
      talkerId: "hoge_id2",
      content: "Good."
    },
  ];

  talkerId = "hoge_id1";

  // TODO: Implement properly
  dateFormat(date: Date): string {
    return date.toString();
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
