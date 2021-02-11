<template xmlns:v-slot="http://www.w3.org/1999/XSL/Transform">
  <div>
    <v-form v-model="isConnectable">
      <v-layout>
        <v-flex xs12 offset-sm2 sm8 offset-md3 md6>
          <v-card style="padding: 1em;">
            <v-text-field label="Server URL"
                          v-model="serverUrl"
                          :rules="[v => !!v || 'Server URL is required']"
                          required />
            <v-text-field label="Your ID"
                          v-model="talkerId"
                          :rules="[v => !!v || 'Your ID is required']"
                          required />
            <v-text-field label="Peer ID"
                          v-model="peerId"
                          placeholder="e.g. bma"
                          :rules="[v => !!v || 'Peer ID is required']"
                          required />
            <v-switch label="Public key authentication"
                      v-model="enableSignature" />

            <div v-if="enableSignature">
              <v-alert :value="true"
                       type="info"
                       outline
                       style="margin-bottom: 1em;"
              >
                NOTE: You can modify your public PEM by <b>private one</b>.
              </v-alert>
              <v-textarea label="Your public RSA PEM"
                          v-model="publicSignPem"
                          :rules="publicPrivateSignPemRules"
                          readonly
                          outline
                          prepend-icon="person" />
              <v-switch label="Show/Edit your private PEM"
                        color="secondary"
                        v-model="showsPrivateSignPem" />
              <v-textarea label="Your private RSA PEM"
                          v-model="privateSignPem"
                          :rules="publicPrivateSignPemRules"
                          v-if="showsPrivateSignPem"
                          outline
                          prepend-icon="lock" />

              <v-text-field label="Key bits"
                            type="number"
                            v-model="nKeyBits" />
              <!-- Generate PEM button -->
              <v-btn color="secondary"
                     v-on:click="assignPrivatePem()">
                <v-icon>autorenew</v-icon>
                Generate PEMs
              </v-btn>
              <!-- Save PEM button -->
              <v-btn color="secondary"
                     v-bind:disabled="!isSignPemSaveable"
                     v-on:click="savePrivateKey()">
                <v-icon>save</v-icon>
                Save PEMs
              </v-btn>
              <!-- Erase PEM button -->
              <v-btn color="secondary"
                     v-bind:disabled="!isSignPemErasable"
                     v-on:click="erasePrivateKey()">
                <v-icon>delete</v-icon>
                Erase PEMs
              </v-btn>

              <v-textarea label="Peer's public RSA PEM"
                          v-model="peerPublicSignPem"
                          outline
                          prepend-icon="person"
                          style="padding-top: 3em;"
                          :rules="[v => !!v || 'Peer\'s public RSA is required']"/>
            </div>

            <v-btn color="primary"
                   v-on:click="connectToPeer()"
                   v-bind:disabled="!isConnectable || isConnecting"
                   block >
              <v-icon>fas fa-plug</v-icon>&nbsp;
              Connect
            </v-btn>
          </v-card>

          <v-expansion-panel>
            <v-expansion-panel-content>
              <template v-slot:header>
                <v-icon>person</v-icon>
                <div>Connection details</div>
              </template>
              <v-card style="padding: 1em;">
                <v-text-field label="Session ID"
                              v-bind:value="sessionId"
                              placeholder=" "
                              readonly />
                <v-textarea label="Your public JWK for encryption"
                            v-model="publicEncryptJwkString"
                            readonly
                            prepend-icon="public"
                            outline />
                <v-switch label="Show private JWK for encryption"
                          color="secondary"
                          v-model="showsPrivateEncryptJwk"/>
                <v-textarea label="Your private JWK for encryption"
                            v-model="privateEncryptJwkString"
                            v-if="showsPrivateEncryptJwk"
                            readonly
                            prepend-icon="vpn_key"
                            outline />

                <h4></h4>
                <v-textarea label="Peer's public JWK for encryption"
                            v-model="peerPublicEncryptJwkString"
                            readonly
                            prepend-icon="public"
                            placeholder=" "
                            outline />
              </v-card>
            </v-expansion-panel-content>
          </v-expansion-panel>
        </v-flex>
      </v-layout>
    </v-form>

    <div style="margin: 1em;">
      <v-layout>
        <v-flex offset-md1 md10 offset-lg2 lg8>
          <!-- Talk input -->
          <v-container fluid v-if="isEstablished">
            <v-layout column>
              <v-flex>
                <!-- NOTE: hide-details is for deleting bottom space -->
                <v-textarea label="Your talk"
                            v-model="talk"
                            outline
                            hide-details />
              </v-flex>
              <v-flex offset-xs9 xs3 offset-lg11 lg1>
                <v-btn v-on:click="sendTalk()"
                       v-bind:disabled="talk === ''"
                       color="secondary"
                       block >
                  <v-icon>send</v-icon>
                  Send
                </v-btn>
              </v-flex>

            </v-layout>
          </v-container>

          <!-- History of talks-->
          <div v-for="talk in talks">
            <!-- User talk -->
            <span v-if="talk.kind === 'user'">
              <span v-if="talk.talkerId !== talkerId">
                {{ talk.talkerId }}
              </span>
              <div :class='{
                "me": talk.talkerId === talkerId,
                "peer": talk.talkerId !== talkerId,
                "talk": true
              }'>
                <pre>{{ talk.content }}</pre>
                <span style="color: #444">
                  <span v-if="talk.talkerId === talkerId">
                    {{ talk.arrived ? "✓" : "" }}
                  </span>
                  <time-ago :refresh="60"
                            :datetime="talk.time"
                            class="time" />
                </span>
              </div>
            </span>

            <!-- System talk -->
            <span v-if="talk.kind === 'system'" style="font-size: 1.5em;">
            <b>System</b> <time-ago :refresh="60" :datetime="talk.time" class="time"></time-ago>:
            {{ talk.content }}
          </span>
          </div>
        </v-flex>
      </v-layout>
    </div>
  </div>
</template>

<script lang="ts">
/* tslint:disable:no-console */
import {Component, Vue} from 'vue-property-decorator';
import TimeAgo from 'vue2-timeago';
import * as jsencrypt from 'jsencrypt';
import { jwk2pem } from 'pem-jwk';
import {PipingChatter} from '@/PipingChatter';
import {Talk} from '@/Talk';


/**
 * Get random ID
 * @param len
 */
function getRandomId(len: number): string {
  // NOTE: some similar shaped alphabets are not used
  const alphas  = [
    'a', 'b', 'c', 'd', 'e', 'f', 'h', 'i', 'j', 'k', 'm', 'n', 'p', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
  ];
  const chars   = [...alphas];

  const randomArr = window.crypto.getRandomValues(new Uint32Array(len));
  return Array.from(randomArr).map((n) => chars[n % chars.length]).join('');
}

/**
 * Get JSON string from Crypto key
 * @param key
 */
async function getJwkString(key: CryptoKey): Promise<string> {
  const jwk = await window.crypto.subtle.exportKey('jwk', key);
  return JSON.stringify(jwk, null, '  ');
}

/**
 * Get public PEM from private PEM
 * @param privatePem
 */
function getPublicPemFromPrivate(privatePem: string): string | undefined {
  if (privatePem === '') {
    return undefined;
  } else {
    try {
      // Compute public key by the private key
      const crypt = new jsencrypt.JSEncrypt();
      crypt.setPrivateKey(privatePem);
      return crypt.getPublicKey();
    } catch (err) {
      return undefined;
    }
  }
}

const StorageKeys = {
  PRIVATE_SIGNATURE_PEM: 'LOCAL_STORAGE_KEY/PRIVATE_SIGNATURE_PEM',
};

@Component({
  components: {
    TimeAgo,
  },
})
export default class PipingChat extends Vue {

  // My public key
  private get publicSignPem(): string {
    if (this.privateSignPem === '') {
      return '';
    } else {
      const publicSignPem: string | undefined = getPublicPemFromPrivate(this.privateSignPem);
      if (publicSignPem === undefined) {
        return 'INVALID PRIVATE KEY';
      } else {
        return publicSignPem;
      }
    }
  }

  private isEstablished: boolean = false;
  private isConnecting: boolean = false;

  // Whether connect form is valid or not
  private isConnectable: boolean = false;

  // TODO: Hard code
  private serverUrl: string = 'https://ppng.io';
  private peerId: string = '';

  private talkerId = getRandomId(3);
  private talks: Talk[] = [];

  private talk: string = '';

  private nKeyBits = 4096;

  private pipingChatter?: PipingChatter;

  // Session ID
  private sessionId: string = '';

  // Whether using signature to verify peer
  private enableSignature = false;
  // Private PEM only for signature
  private privateSignPem = '';
  // Peer's public PEM for signature
  private peerPublicSignPem = '';
  // Whether showing private PEM for signature or not
  private showsPrivateSignPem: boolean = false;
  // Whether showing private JWK for encryption or not
  private showsPrivateEncryptJwk: boolean = false;

  // Algorithm for signature
  private signAlg = { name: 'RSASSA-PKCS1-v1_5', hash: { name: 'SHA-256' } };

  // Whether sign PEM can be saved
  private get isSignPemSaveable(): boolean {
    return getPublicPemFromPrivate(this.privateSignPem) !== undefined;
  }

  // Whether sign PEM can be erased
  private isSignPemErasable: boolean = false;

  // NOTE: Should use getter if you use it as property, this.enableSignature is always false
  private get publicPrivateSignPemRules(): ReadonlyArray<(v: string) => string | true> {
    return [
      (v) => {
        if (this.enableSignature) {
          if (getPublicPemFromPrivate(this.privateSignPem) === undefined) {
            return 'Your private RSA PEM is not valid';
          } else {
            return true;
          }
        } else {
          return true;
        }
      },
    ];
  }

  // Public JWK string for encryption
  private publicEncryptJwkString: string = '';

  // Private JWK string for encryption
  private privateEncryptJwkString: string = '';

  // Peer's public JWK string for encryption
  private peerPublicEncryptJwkString: string = '';

  public mounted() {
    const privatePem: string | null = localStorage.getItem(StorageKeys.PRIVATE_SIGNATURE_PEM);
    // If private key is found
    if (privatePem !== null) {
      this.privateSignPem = privatePem;
      // Sign PEM is erasable
      this.isSignPemErasable = true;
      this.echoSystemTalk('🔑 Your private PEM loaded!');
    }
  }

  private connectToPeer(): void {
    // Generate chatting system
    this.pipingChatter = new PipingChatter({
      serverUrl: this.serverUrl,
      connectId: this.talkerId,
      peerConnectId: this.peerId,
      enableSignature: this.enableSignature,
      privateSignPem: this.privateSignPem,
      peerPublicSignPem: this.peerPublicSignPem,

      onSessionId: (sessionId: string) => {
        // NOTE: I'm not sure this usage is correct to update asynchronously,
        //       but without this, it sometimes weren't updated.
        Vue.nextTick(() => {
          this.sessionId = sessionId;
        });
      },
      onEstablished: () => {
        // NOTE: I'm not sure this usage is correct to update asynchronously,
        //       but without this, it sometimes weren't updated.
        Vue.nextTick(() => {
          this.isEstablished = true;
        });
      },
      onEncryptKeyPair: (encryptKeyPair: CryptoKeyPair) => {
        // NOTE: I'm not sure this usage is correct to update asynchronously,
        //       but without this, it sometimes weren't updated.
        Vue.nextTick(async () => {
          this.publicEncryptJwkString  = await getJwkString(encryptKeyPair.publicKey);
          this.privateEncryptJwkString = await getJwkString(encryptKeyPair.privateKey);
        });
      },
      onPeerEncryptPublicCryptoKey: (peerEncryptPublicCryptoKey: CryptoKey) => {
        // NOTE: I'm not sure this usage is correct to update asynchronously,
        //       but without this, it sometimes weren't updated.
        Vue.nextTick(async () => {
          this.peerPublicEncryptJwkString = await getJwkString(peerEncryptPublicCryptoKey);
        });
      },
      onTalk: (talk: Talk) => {
        // NOTE: I'm not sure this usage is correct to update asynchronously,
        //       but without this, it sometimes weren't updated.
        Vue.nextTick(() => {
          this.talks.unshift(talk);
        });
      },
    });

    // Connect to the peer
    this.pipingChatter.connectToPeer();
    this.isConnecting = true;
  }

  private sendTalk(): void {
    if (this.pipingChatter === undefined) {
      console.error('Unexpected error: piping chatter is not defined');
    } else {
      // Send a talk
      this.pipingChatter.sendTalk(this.talk);
      this.talk = '';
    }
  }

  private echoSystemTalk(message: string): void {
    this.talks.unshift({
      kind: 'system',
      time: new Date(),
      content: message,
    });
  }

  // Assign a private key asynchronously
  private async assignPrivatePem(): Promise<void> {
    // Echo generating message
    this.echoSystemTalk(`${this.nKeyBits}-bit key generating...`);

    // Record start
    const startTime = new Date();
    // Generating message loop
    const timerId = setInterval(() => {
      const pastSec: number = (new Date().getTime() - startTime.getTime()) / 1000;
      this.echoSystemTalk(`${this.nKeyBits}-bit key generating... (${pastSec} sec passed)`);
    }, 4000);

    // Generate RSA private PEM
    const rsaPrivateKey: CryptoKeyPair = await window.crypto.subtle.generateKey(
      { ...this.signAlg, modulusLength: this.nKeyBits,  publicExponent: new Uint8Array([0x01, 0x00, 0x01]) },
      true,
      ['sign', 'verify'],
    );
    // Clear the timer
    clearInterval(timerId);

    // Export to JWK
    const rsaPrivateJwk: JsonWebKey = await window.crypto.subtle.exportKey('jwk', rsaPrivateKey.privateKey);
    if (rsaPrivateJwk.kty !== undefined && rsaPrivateJwk.n !== undefined && rsaPrivateJwk.e !== undefined) {
      const jwk = {
        ...rsaPrivateJwk,
        kty: rsaPrivateJwk.kty,
        n: rsaPrivateJwk.n,
        e: rsaPrivateJwk.e,
      };
      // Assign private pem
      this.privateSignPem = jwk2pem(jwk);
      // Echo generated message
      this.echoSystemTalk(`🔑 ${this.nKeyBits}-bit PEM generated!`);
    } else {
      // Echo generated message
      this.echoSystemTalk(`Error: ${this.nKeyBits}-bit PEM not generated`);
    }
  }

  private savePrivateKey(): void {
    // If private is not invalid
    if (this.privateSignPem !== '') {
      // Save private key in local storage
      localStorage.setItem(StorageKeys.PRIVATE_SIGNATURE_PEM, this.privateSignPem);
      // Sign PEM is erasable
      this.isSignPemErasable = true;
      this.echoSystemTalk('Your private PEM saved.');
    }
  }

  private erasePrivateKey(): void {
    // If private key in storage not found
    if (localStorage.getItem(StorageKeys.PRIVATE_SIGNATURE_PEM) === null) {
      this.echoSystemTalk('Private PEM is not saved yet.');
    } else {
      localStorage.removeItem(StorageKeys.PRIVATE_SIGNATURE_PEM);
      // Sign PEM is not erasable
      this.isSignPemErasable = false;
      this.echoSystemTalk('Your private PEM erased from local storage.');
    }
  }
}
</script>

<!-- Add "scoped" attribute to limit CSS to this component only -->
<style scoped>
.time{
  font-size: 0.6em;
  color: #333;
}

.talk {
  width: 70%;
  font-size: 1.5em;
  padding: 0.5em;
  border-radius: 0.5em;
  margin-bottom: 1em;
}

.peer {
  background: #ccc;
}

.me {
  background: #4F91FD;
  /* (from: http://webfeelfree.com/css-align/) */
  margin-left: auto;
  color: white;
}
</style>
