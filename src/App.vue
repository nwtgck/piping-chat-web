<template>
  <div id="app">
    <Ribbon v-bind="ribbonOptions"></Ribbon>
    <h1>Piping Chat</h1>
    🛡 End-to-End Encryption Chat via <a href="https://github.com/nwtgck/piping-server">Piping Server</a>
    <PipingChat />
  </div>
</template>

<script lang="ts">
import { Component, Vue } from 'vue-property-decorator';
import ForkeMeOnGithub from 'fork-me-on-github-vue';
import PipingChat from './components/PipingChat.vue';

Vue.use(ForkeMeOnGithub);

@Component({
  components: {
    PipingChat,
    ForkeMeOnGithub
  },
})
export default class App extends Vue {
  ribbonOptions = {
    text: 'Open on GitHub',
    linkUrl: "https://github.com/nwtgck/piping-chat-web",
    fixed: true
  };
}
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
