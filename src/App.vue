<template>
  <v-app id="app">
    <Ribbon v-bind="ribbonOptions"></Ribbon>
    <h1 style="text-align: center">Piping Chat</h1>
    <p style="text-align: center">
      🛡 End-to-End Encryption Chat via <a href="https://github.com/nwtgck/piping-server">Piping Server</a>
    </p>
    <PipingChat />
  </v-app>
</template>

<script lang="ts">
import { Component, Vue } from 'vue-property-decorator';
import ForkeMeOnGithub from 'fork-me-on-github-vue';
import PipingChat from './components/PipingChat.vue';

Vue.use(ForkeMeOnGithub);

@Component({
  components: {
    PipingChat,
    ForkeMeOnGithub,
  },
})
export default class App extends Vue {
  public ribbonOptions = {
    text: 'Open on GitHub',
    linkUrl: 'https://github.com/nwtgck/piping-chat-web',
    fixed: true,
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
  padding-top: 20px;
}
</style>
