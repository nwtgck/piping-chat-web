/**
 * Sequential context for promises which is like synchronize in Java
 *
 * In this context, previous promises run first
 */
export class PromiseSequentialContext {
  public prev: Promise<any> = Promise.resolve();
  public run<T>(asyncFunc: () => Promise<T>): Promise<T> {
    this.prev = this.prev.then(() => {
      return asyncFunc();
    }).catch(() => {
      return asyncFunc();
    });
    return this.prev;
  }
}
