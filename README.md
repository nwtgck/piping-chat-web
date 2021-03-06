# piping-chat
[![Netlify Status](https://api.netlify.com/api/v1/badges/907dbaac-d0c3-44dd-8578-e4ca6bfba2b9/deploy-status)](https://app.netlify.com/sites/piping-chat/deploys)  
 <a href="https://piping-chat.netlify.com"><img src="https://user-images.githubusercontent.com/9122190/28998409-c5bf7362-7a00-11e7-9b63-db56694522e7.png" alt="Launch now as Web App" height="48"></a>

End-to-End Encryption Chat via [Piping Server](https://github.com/nwtgck/piping-server)

![Piping Chat 0.4.1 without public key authentication](doc_assets/piping-chat-0.4.1-without-auth.gif)

## Application
Piping Chat: <https://piping-chat.netlify.com>

## Purpose & Features
The main purpose of Piping Chat allows users chat safely via Piping Server. It has the following features for the purpose.

* End-to-End Encryption by AES [GCM](https://en.wikipedia.org/wiki/Galois/Counter_Mode)
* [Forward Secrecy](https://en.wikipedia.org/wiki/Forward_secrecy) by [ECDH](https://en.wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellman)
* Public Key Authentication like SSH
* via [Piping Server](https://github.com/nwtgck/piping-server)
* Static hosting
* Progressive Web App (PWA)
* Accountless

## End-to-End Encryption + Public Key Authentication

Here is a demo to use Public Key Authentication. The public RSA PEM is used **only for authentication**, not for encryption. You can also use RSA PEM generated by `openssl` command.

![Piping Chat 0.4.1 with public key authentication](doc_assets/piping-chat-0.4.1-with-auth.gif)
