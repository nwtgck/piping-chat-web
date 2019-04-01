// declare module 'jsencrypt';

export type Options = {
  default_key_size: number
};

export class JSEncrypt {
  constructor(options?: Options);
  getKey(callback: ()=>void): void;
  getPublicKey(): string;
  getPrivateKey(): string;
  encrypt(input: string): string;
  decrypt(crypted: string): string;
  setPublicKey(publicKey: string): void;
  setPrivateKey(privateKey: string): void;
}
