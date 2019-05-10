import Vue from 'vue'
import App from './App.vue'
import './registerServiceWorker'
import AsyncComputed from 'vue-async-computed'

Vue.config.productionTip = false

Vue.use(AsyncComputed)

new Vue({
  render: h => h(App),
}).$mount('#app')
