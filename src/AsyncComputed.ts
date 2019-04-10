// (from: https://github.com/foxbenjaminfox/vue-async-computed/issues/25#issuecomment-459369072)

import { createDecorator, VueDecorator } from 'vue-class-component';
import { IAsyncComputedProperty } from 'vue-async-computed';

export function AsyncComputed<T>(
    computedOptions?: IAsyncComputedProperty<T>,
): VueDecorator {
    return createDecorator((_options, key) => {
        // TODO: Not use any casting
        const options: any = _options as any;
        options.asyncComputed = options.asyncComputed || {};
        const method = options.methods![key];
        options.asyncComputed![key] = <IAsyncComputedProperty<T>>{
            get: method,
            ...computedOptions,
        };
        delete options.methods![key];
    });
}
