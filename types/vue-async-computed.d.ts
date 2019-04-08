// (base: https://raw.githubusercontent.com/saraedum/vue-async-computed/5debb7dcd81f52183be55e05b866fc43278a9905/types/index.d.ts)

declare module 'vue-async-computed' {
  import Vue, { PluginFunction } from "vue";

  interface IAsyncComputedOptions {
    errorHandler?: (error: string[]) => void;
    useRawError?: boolean;
    default?: any;
  }
  
  export default class AsyncComputed {
    constructor(options?: IAsyncComputedOptions)
    static install: PluginFunction<never>;
    static version: string;
  }
  
  type AsyncComputedGetter<T> = () => (Promise<T> | T);
  export interface IAsyncComputedProperty<T> {
    default?: T | (() => T);
    get?: AsyncComputedGetter<T>;
    watch?: () => void;
    shouldUpdate?: () => boolean;
    lazy?: boolean;
  }
  
  interface IAsyncComputedProperties {
    [K: string]: AsyncComputedGetter<any> | IAsyncComputedProperty<any>;
  }
}

declare module "vue/types/options" {
  import Vue from "vue";
  import { IAsyncComputedProperties } from "vue-async-computed";

  export class InjectKey{}

  // tslint:disable-next-line:interface-name
  interface ComponentOptions<V extends Vue> {
    asyncComputed?: IAsyncComputedProperties;
  }
}

interface IASyncComputedState {
  state: "updating" | "success" | "error";
  updating: boolean;
  success: boolean;
  error: boolean;
  exception: Error | null;
  update: () => void;
}

declare module "vue/types/vue" {
  // tslint:disable-next-line:interface-name
  interface Vue {
    $asyncComputed: {[K: string]: IASyncComputedState };
  }
}
