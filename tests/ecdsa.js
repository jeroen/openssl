//See: https://github.com/diafygi/webcrypto-examples

var ecdsa = window.crypto.subtle.generateKey({
    name: "ECDSA",
    namedCurve: "P-521",
}, true, ["sign", "verify"]);

ecdsa.then(function(key){
    //Private key
    var priv = window.crypto.subtle.exportKey("jwk", key.privateKey);
    priv.then(function(str){
        console.log(JSON.stringify(str));
    });

    //Pubkey
    var pub = window.crypto.subtle.exportKey("jwk", key.publicKey);
    pub.then(function(str){
        console.log(JSON.stringify(str));
    });

    //ECDSA
    var sig = window.crypto.subtle.sign({
        name: "ECDSA",
        hash: {name: "SHA-256"},
    }, key.privateKey, new Uint8Array("testje"));
    sig.then(function(signature){
        var base64String = btoa(String.fromCharCode.apply(null, new Uint8Array(signature)));
        console.log("sig: " + base64String);
    });
});

var ecdh = window.crypto.subtle.generateKey({
    name: "ECDH",
    namedCurve: "P-521",
}, true, ["deriveKey", "deriveBits"]);

ecdh.then(function(key){
    //Private key
    var priv = window.crypto.subtle.exportKey("jwk", key.privateKey);
    priv.then(function(str){
        console.log(JSON.stringify(str));
    });

    //Pubkey
    var pub = window.crypto.subtle.exportKey("jwk", key.publicKey);
    pub.then(function(str){
        console.log(JSON.stringify(str));
    });

    //DH
    window.crypto.subtle.deriveBits({
        name: "ECDH",
        namedCurve: "P-521",
        public: key.publicKey
    }, key.privateKey, 256).then(function(bits){
        var base64String = btoa(String.fromCharCode.apply(null, new Uint8Array(bits)));
        console.log("bits: " + base64String);
    });
});
