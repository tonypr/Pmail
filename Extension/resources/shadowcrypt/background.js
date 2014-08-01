// initialize keys for demo
chrome.storage.sync.get(function (o) {
    if (!("origin-https://mail.google.com" in o)) {
        var randInp = Array.prototype.slice.call(window.crypto.getRandomValues(new Uint32Array(4)));
        var key = sjcl.codec.hex.fromBits(sjcl.hash.sha256.hash(randInp));
        chrome.storage.sync.set({
            "key": key,
            "origin-https://mail.google.com": {
                "defaultFingerprint": "35edbab33e6939068818eab465968aa3eeee426bc37a571022f077da865a2c74",
                "keys": {
                    "35edbab33e6939068818eab465968aa3eeee426bc37a571022f077da865a2c74": {
                        "color": 6,
                        "name": "ShadowCrypt Users",
                        "note": "ShadowCrypt comes with this key. Anyone can get it.",
                        "passphrase": "wide open",
                        "secret": [
          1081330386,
          1897912442,
          1011823286,
          3617319768
        ]
                    }
                },

                "rules": [
                    {
                        urlPattern: "/mail/",
                        selector: "[id=gs_taif50]",
                        noShim: true
        },

                    {
                        urlPattern: "/mail/",
                        selector: "[name=to],[name=cc],[name=bcc],[name=subject], [name=subjectbox]",
                        noShim: true
        },

                    {
                        urlPattern: "/mail$",
                        selector: "[role=textbox]",
                        mode: "words"
        }
    ]
            }
        });
    }
});