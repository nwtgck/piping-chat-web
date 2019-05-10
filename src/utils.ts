import { pem2jwk } from 'pem-jwk';
import * as jsencrypt from 'jsencrypt';


export async function pubRsaPemToPubKey(alg: RsaHashedImportParams, publicPem: string): Promise<CryptoKey> {
  // Get public and private JWKs
  const pubJwk: JsonWebKey  = pem2jwk(publicPem);
  return window.crypto.subtle.importKey(
    'jwk',
    pubJwk,
    alg,
    true,
    ['verify'],
  );
}

export async function privRsaPemToPubPrivKeys(
  alg: RsaHashedImportParams,
  privatePem: string,
): Promise<{ publicKey: CryptoKey, privateKey: CryptoKey }> {
  // Compute public key by the private key
  const crypt = new jsencrypt.JSEncrypt();
  crypt.setPrivateKey(privatePem);
  const publicPem = crypt.getPublicKey();

  // Get private JWK
  const privJwk: JsonWebKey = pem2jwk(privatePem);

  return {
    publicKey: await pubRsaPemToPubKey(alg, publicPem),
    privateKey: await window.crypto.subtle.importKey(
      'jwk',
      privJwk,
      alg,
      true,
      ['sign'],
    ),
  };
}


export function arrayBufferToString(arr: ArrayBuffer) {
  return String.fromCharCode(... new Uint8Array(arr));
}

// (from: https://gist.github.com/kawanet/352a2ed1d1656816b2bc)
export function stringToArrayBuffer(str: string): ArrayBuffer {
  const numbers: number[] = [].map.call(str, (c: string) => {
    return c.charCodeAt(0);
  }) as any; // TODO: Not use any
  return new Uint8Array(numbers).buffer;
}

export async function getBodyBytesFromResponse(res: Response): Promise<Uint8Array> {
  if (res.body === null) {
    return new Uint8Array();
  }
  const reader = res.body.getReader();
  const arrays = [];
  let totalLen = 0;
  while (true) {
    const {done, value} = await reader.read();
    if (done) { break; }
    totalLen += value.byteLength;
    arrays.push(value);
  }
  // (from: https://qiita.com/hbjpn/items/dc4fbb925987d284f491)
  const allArray = new Uint8Array(totalLen);
  let pos = 0;
  for (const arr of arrays) {
    allArray.set(arr, pos);
    pos += arr.byteLength;
  }
  return allArray;
}

export function mergeUint8Array(a: Uint8Array, b: Uint8Array): Uint8Array {
  const merged = new Uint8Array(a.byteLength + b.byteLength);
  merged.set(a, 0);
  merged.set(b, a.byteLength);
  return merged;
}

export const RSA = {
  encrypt(publicKey: string, input: string): string {
    const crypt  = new jsencrypt.JSEncrypt();
    crypt.setPublicKey(publicKey);
    return crypt.encrypt(input);
  },
  decrypt(privateKey: string, encryptedText: string): string {
    const crypt  = new jsencrypt.JSEncrypt();
    crypt.setPublicKey(privateKey);
    return crypt.decrypt(encryptedText);
  },
  generateKeys(options: jsencrypt.Options): Promise<{publicKey: string, privateKey: string}> {
    const crypt  = new jsencrypt.JSEncrypt(options);
    return new Promise((resolve) => {
      crypt.getKey(() => {
        resolve({
          publicKey: crypt.getPublicKey(),
          privateKey: crypt.getPrivateKey(),
        });
      });
    });
  },
};
