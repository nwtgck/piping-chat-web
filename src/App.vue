<template>
  <div id="app">
    <h1>Piping Chat</h1>
    🛡 End-to-End Encryption Chat via <a href="https://github.com/nwtgck/piping-server">Piping Server</a>
    <PipingChat />
  </div>
</template>

<script lang="ts">
import { Component, Vue } from 'vue-property-decorator';
import PipingChat from './components/PipingChat.vue';

@Component({
  components: {
    PipingChat,
  },
})
export default class App extends Vue {}
</script>

<style>
#app {
  font-family: 'Avenir', Helvetica, Arial, sans-serif;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  /*text-align: center;*/
  color: #2c3e50;
  margin-top: 20px;
}
</style>
