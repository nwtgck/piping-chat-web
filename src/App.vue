<template>
  <v-app id="app">
    <h1 style="text-align: center">Piping Chat</h1>
    <p style="text-align: center">
      🛡 End-to-End Encryption Chat via <a href="https://github.com/nwtgck/piping-server">Piping Server</a>&nbsp;
      <br>
      <a href="https://github.com/nwtgck/piping-chat-web">
        <v-icon>fab fa-github</v-icon> GitHub
      </a>
    </p>
    <PipingChat />
  </v-app>
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
  padding-top: 20px;
}

a {
  text-decoration: none;
}
</style>
