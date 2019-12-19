const GCM_OP_ENCRYPT = 1;
const GCM_OP_DECRYPT = 2;

var aesKey;

/* Polyfill IE 11 Crypto API */

var crypto = window.crypto || window.msCrypto;

/* Polyfill Textencoder */
if (typeof TextEncoder === "undefined") {
    TextEncoder=function TextEncoder(){};
    TextEncoder.prototype.encode = function encode(str) {
        "use strict";
        var Len = str.length, resPos = -1, resArr = new Uint8Array(Len * 3);
        for (var point=0, nextcode=0, i = 0; i !== Len; ) {
            point = str.charCodeAt(i), i += 1;
            if (point >= 0xD800 && point <= 0xDBFF) {
                if (i === Len) {
                    resArr[resPos += 1] = 0xef/*0b11101111*/; resArr[resPos += 1] = 0xbf/*0b10111111*/;
                    resArr[resPos += 1] = 0xbd/*0b10111101*/; break;
                }
                // https://mathiasbynens.be/notes/javascript-encoding#surrogate-formulae
                nextcode = str.charCodeAt(i);
                if (nextcode >= 0xDC00 && nextcode <= 0xDFFF) {
                    point = (point - 0xD800) * 0x400 + nextcode - 0xDC00 + 0x10000;
                    i += 1;
                    if (point > 0xffff) {
                        resArr[resPos += 1] = (0x1e/*0b11110*/<<3) | (point>>>18);
                        resArr[resPos += 1] = (0x2/*0b10*/<<6) | ((point>>>12)&0x3f/*0b00111111*/);
                        resArr[resPos += 1] = (0x2/*0b10*/<<6) | ((point>>>6)&0x3f/*0b00111111*/);
                        resArr[resPos += 1] = (0x2/*0b10*/<<6) | (point&0x3f/*0b00111111*/);
                        continue;
                    }
                } else {
                    resArr[resPos += 1] = 0xef/*0b11101111*/; resArr[resPos += 1] = 0xbf/*0b10111111*/;
                    resArr[resPos += 1] = 0xbd/*0b10111101*/; continue;
                }
            }
            if (point <= 0x007f) {
                resArr[resPos += 1] = (0x0/*0b0*/<<7) | point;
            } else if (point <= 0x07ff) {
                resArr[resPos += 1] = (0x6/*0b110*/<<5) | (point>>>6);
                resArr[resPos += 1] = (0x2/*0b10*/<<6)  | (point&0x3f/*0b00111111*/);
            } else {
                resArr[resPos += 1] = (0xe/*0b1110*/<<4) | (point>>>12);
                resArr[resPos += 1] = (0x2/*0b10*/<<6)    | ((point>>>6)&0x3f/*0b00111111*/);
                resArr[resPos += 1] = (0x2/*0b10*/<<6)    | (point&0x3f/*0b00111111*/);
            }
        }
        resArr = new Uint8Array(resArr.buffer.slice(0, resPos+1));
        return resArr;
    };
    TextEncoder.prototype.toString = function(){return "[object TextEncoder]"};
    if (Object.defineProperty) {
      Object.defineProperty(TextEncoder.prototype,"encoding",{get:function(){if(Object.getPrototypeOf
      (this)!==TextEncoder.prototype)throw TypeError("Illegal invocation");else return"utf-8"}});
    } else {
      TextEncoder.prototype.encoding = "utf-8";
    }
    if(typeof Symbol!=="undefined")TextEncoder.prototype[Symbol.toStringTag]="TextEncoder";
}

function textToArrayBuffer(pText) {
  return new TextEncoder().encode(pText);
}

function generateAesKey(pw, cb) {
  crypto.subtle.importKey(
    'raw', textToArrayBuffer(pw),
    {name: "PBKDF2"},
    false,
    ["deriveBits", "deriveKey"]
  ).then(function(masterkey) {

    crypto.subtle.deriveKey(
      {"name": "PBKDF2", "salt": new Uint8Array(16), "iterations": 1000, "hash": "SHA-256"},
      masterkey,
      {"name": "AES-GCM", "length": 256},
      true,
      ["encrypt", "decrypt"]
    ).then(function(key) {
      aesKey = key;
      if(cb != undefined)
        cb(key);
    }).catch(function(err) {
      console.error(err);
    })

  }).catch(function(err) {
    console.error(err);
  });
}


function doAesGcm(file, cb, action) {
  if(aesKey == undefined) {
    alert("No aes key generated");
    return;
  }

  let reader = new FileReader();

  reader.onload = function(e) {

    let iv = new Uint8Array(16);
    //var aes_func = GCM_OP_ENCRYPT ? crypto.subtle.encrypt : crypto.subtle.decrypt;
    let algo = {"name": "aes-gcm", "iv": iv};

    if(action == GCM_OP_ENCRYPT) {
      crypto.subtle.encrypt(algo, aesKey, e.target.result).then(cb);
    } else {
      crypto.subtle.decrypt(algo, aesKey, e.target.result).then(cb).catch(function(err) {
        alert("File corrupted!");
      })
    }
  }

  reader.readAsArrayBuffer(file);
}

function aesGcmEncrypt(file, cb) {
  doAesGcm(file, cb, GCM_OP_ENCRYPT);
}

function aesGcmDecrypt(file, cb) {
  doAesGcm(file, cb, GCM_OP_DECRYPT);
}

function fillUint8Array(arr) {
  for(i = 0; i < arr.length; i++)
    arr[i] = Math.floor(Math.random() * 100)

  return arr
}

function benchmarkApi() {
  let data, iv;
  let t0 = performance.now();

  data = new Uint8Array(1000 * 1000 * 10);
  iv = new Uint8Array(16);
  crypto.getRandomValues(iv);
  fillUint8Array(data);

  for(r = 1; r < 5; r++) {
    crypto.subtle.encrypt({"name": "aes-gcm", "iv": iv}, aesKey, data).then(function(d) {
    })
  }

  let t1 = performance.now();

  console.log("(API) Encryption took " + (t1-t0) + " ms");
  return t1-t0;
}

function benchmarkAsm() {
  let data, iv, key;
  let t0 = performance.now();

  // Dear reader, forgive me the copy & paste ;)
  key = new Uint8Array(16);
  data = new Uint8Array(1000 * 1000 * 10);
  iv = new Uint8Array(16);
  crypto.getRandomValues(iv);
  crypto.getRandomValues(key);
  fillUint8Array(data);

  for(r = 1; r < 5; r++) {
      asmCrypto.AES_GCM.encrypt(data, key, iv, undefined, 16);
  }

  let t1 = performance.now();

  console.log("(ASM) Encryption took " + (t1-t0) + " ms");
  return t1-t0;
}

function benchmarkOldAsm() {
  let data, iv, key;
  let t0 = performance.now();

  // Dear reader, forgive me the copy & paste ;)
  key = new Uint8Array(16);
  data = new Uint8Array(1000 * 1000 * 10);
  iv = new Uint8Array(16);
  crypto.getRandomValues(iv);
  crypto.getRandomValues(key);
  fillUint8Array(data);

  for(r = 1; r < 5; r++) {
    asmCrypto.AES_CBC.encrypt(data, key, iv, undefined, 16);
    asmCrypto.HMAC_SHA256.hex(data, key);
  }

  let t1 = performance.now();

  console.log("(ASM) Encryption took " + (t1-t0) + " ms");
  return t1-t0;
}

// debug:
//generateAesKey("123456", (k) => console.log(k));
