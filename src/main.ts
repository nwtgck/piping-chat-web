// (from: https://vuetifyjs.com/en/framework/icons#icons)
import 'material-design-icons-iconfont/dist/material-design-icons.css';
import Vue from 'vue';
import App from './App.vue';
import './registerServiceWorker';
import AsyncComputed from 'vue-async-computed';
import Vuetify from 'vuetify';
import 'vuetify/dist/vuetify.min.css';

Vue.config.productionTip = false;

Vue.use(AsyncComputed);
Vue.use(Vuetify);

new Vue({
  render: (h) => h(App),
}).$mount('#app');
