// (from: https://vuetifyjs.com/en/framework/icons#icons)
import 'material-design-icons-iconfont/dist/material-design-icons.css';

// (from: https://e-joint.jp/474/)
import '@fortawesome/fontawesome';
import '@fortawesome/fontawesome-free-solid';
// import '@fortawesome/fontawesome-free-regular';
import '@fortawesome/fontawesome-free-brands';

import Vue from 'vue';
import App from './App.vue';
import './registerServiceWorker';
import Vuetify from 'vuetify';
import 'vuetify/dist/vuetify.min.css';

Vue.config.productionTip = false;

Vue.use(Vuetify);

new Vue({
  render: (h) => h(App),
}).$mount('#app');
