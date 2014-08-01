var Setup = {
    "ParseAppId": "[REDACTED]",
    "ParseJavascriptKey": "[REDACTED]"
};

Parse.initialize(Setup.ParseAppId, Setup.ParseJavascriptKey);

/**
 * Applies the SHA256 hash on a message.
 * @param {string} message A string that represents the message to hash.
 * @return {string} The hashed form of the message.
 */
function sha256(message) {
    var bitArray = sjcl.hash.sha256.hash(message);
    var digest_sha256 = sjcl.codec.hex.fromBits(bitArray);
    return digest_sha256;
}

/**
 * Takes in a key and a message to process. Uses SHA256 to process the key/message pair.
 * @param {string} key utf8String used as the secret for the hmac.
 * @param {string} message The message to be processed.
 * @return {string} Hashed value of information.
 */
function hmac256(key, message) {
    var secret = sjcl.codec.utf8String.toBits(key);
    return Crypto.hmac(secret, message);
}

/**
 * Generates a token given a key and a keyword.
 * @param {string} key The user's secret key.
 * @param {string} keyword The keyword to query.
 * @return {string} returns The result of running hmac-sha256 on our key and sha256 of our keyword.
 */
function tokenize(key, w) {
    return hmac256(key, sha256(w));
}

/**
 * Calculates the xor value of two hex strings of equal length.
 * @param {string} left The left value in the xor operation.
 * @param {string} right The right value in the xor operation.
 * @returns {string} The output of the xor of our two hex strings.
 */
function xorHex(left, right) {
    if (left.length != right.length) {
        throw new Error("Invalid arguments for xorHex function. Received arguments of length " + left.length + " and " + right.length + ". Expected equal length inputs.");
    }
    var result = "",
        temp;
    for (i = 0; i < left.length; i++) {
        temp = parseInt(left.charAt(i), 16) ^ parseInt(right.charAt(i), 16);
        result += (temp).toString(16);
    }
    return result;
}

/**
 * Calculates the xor of an email identifier (16 chars) with our computed hash value (64 chars long).
 * @param {string} id The email identifier of a thread. It should be 16 characters long.
 * @param {string} hmacResult The result of calculating hmac256(token, count + "1") for a given integer value, count.
 * @return {string} Returns the xor of the inputs.
 */
function xorWithId(id, hmacResult) {
    // id is always 16 characters long, the head never changes
    var head = hmacResult.substring(0, 48);
    var tail = hmacResult.substring(48, 64);
    var newTail = xorHex(id, tail);
    return head + newTail;
}

/**
 * Calculates the xor of two hex strings (hash value and hmacDecoder).
 * @param {string} hval Hex string.
 * @param {string} hmacDecoder Hex string.
 * @return {string} Returns the xor of the two input hex strings.
 */
function xorForId(hval, hmacDecoder) {
    var length = hval.length;
    var length2 = hmacDecoder.length;
    var leftTail = hval.substring(length - 16, length);
    var rightTail = hmacDecoder.substring(length2 - 16, length2);
    return xorHex(leftTail, rightTail);
}

/** THREAD PROCESSING **/

/**
 * Remove duplicates from an array. From http://dreaminginjavascript.wordpress.com/2008/08/22/eliminating-duplicates/
 */
function eliminateDuplicates(arr) {
    var i,
        len = arr.length,
        out = [],
        obj = {};

    for (i = 0; i < len; i++) {
        obj["keyword-" + arr[i]] = 0;
    }
    for (i in obj) {
        var strLength = i.length;
        var originalKeyword = i.substring(8); // trim off first 8 chars "keyword-"
        out.push(originalKeyword);
    }
    return out;
}

/**
 * Extracts the unique keywords from a string.
 * @param {string} message The text from which we are extracting keywords.
 * @return {list} The list of unique words from our input.
 */
function getKeywords(message) {
    text = message.match(/(w+)/g);
    var allowedChars = /[^a-zA-Z']+/g;
    // Remove all irrelevant characters
    text = message.replace(allowedChars, " ").replace(/^\s+/, "").replace(/\s+$/, "");
    text = text.toLowerCase();
    wordList = text.split(/\s+/);
    wordList = eliminateDuplicates(wordList);
    return wordList;
}

/**
 * Produces an encoded key value pair (hkey, c1) in the javascript object format from the
 * secret key, the keyword, document id and the current count (how many times this keyword has shown up).
 * @param {string} key The key for the symmetric encryption used.
 * @param {string} w The keyword for this entry.
 * @param {string} id The document id for this entry.
 * @param {integer} cnt The count of this entry.
 * @return {object} Returns a javascript object containing the hash key and hash value (key/value pair for hash).
 */
function encodeEntry(key, w, id, cnt) {
    var token = tokenize(key, w);
    var hkey = hmac256(token, cnt + "0"); // Hash Key = HMAC(k, cnt || "0")
    id = id.toString(16); // rewrite in hex format
    var c1 = xorWithId(id, hmac256(token, cnt + "1")); // Hash Value = id ^ HMAC(k, cnt || "1")
    return {
        "hkey": hkey,
        "hval": c1
    };
}

/**
 * Decodes encrypted text using ShadowCrypt's fingerprint/key system.
 * @param {string} encryptedText The encrypted text to be decrypted.
 * @return {string} Returns the decrypted form of our input.
 */
function decodeText(encryptedText) {
    var messages = [];
    while (match = Codec.CODE_PATTERN.exec(encryptedText)) {
        var fingerprint = match[1];
        var cText = match[2];
        var tags = match[3];
        messages.push(Codec.decode(fingerprint, cText, tags));
    }
    return messages.join(" ");
}


/**
 * Extracts the plaintext from an encrypted thread.
 * @param {list} content A list of encrypted messages.
 * @param {object} threadIds Object that tracks processed threads.
 * @return {list} Returns the decrypted text from our encrypted thread.
 */
function extractNewEncodedMessages(content, threadIds) {
    var messages = [];

    content.forEach(function (encMessage, index, array) {
        var encryptedText = encMessage.message;
        var id = encMessage.id;
        if (!(id in threadIds)) {
            while (match = Codec.CODE_PATTERN.exec(encryptedText)) {
                var fingerprint = match[1];
                var cText = match[2];
                var tags = match[3];
                messages.push(Codec.decode(fingerprint, cText, tags));
            }
            threadIds[id] = true;
        }
    });
    return messages;
}

/**
 * Produces the encoded pairs from a thread.
 * @param {string} key The secret key for our search protocol.
 * @param {object} keywordDict Object that keeps track of keywords and how many times they appear in emails.
 * @param {string} id The email identifier of the current thread.
 * @param {list} Decrypted text from the current thread.
 * @return {list} Returns a list of encoded pairs to store in our online database.
 */
function produceEncodedPairList(key, keywordDict, id, messages) {
    var decryptedContent = messages.join(" ");
    var keywordList = getKeywords(decryptedContent);

    var encodedPairObject = Parse.Object.extend("HashPair");
    var encodedPairList = [];

    keywordList.forEach(function (keyword, index, array) {
        var safeKeyword = "keyword-" + keyword;
        // Update document count for keyword.
        if (safeKeyword in keywordDict) {
            keywordDict[safeKeyword] = keywordDict[safeKeyword] + 1;
        } else {
            keywordDict[safeKeyword] = 1;
        }
        var encodedPair = encodeEntry(key, keyword, id, keywordDict[safeKeyword]);

        var newEncodedObject = new encodedPairObject();
        newEncodedObject.set("HashKey", encodedPair.hkey);
        newEncodedObject.set("HashValue", encodedPair.hval);
        encodedPairList.push(newEncodedObject);
    });

    return encodedPairList;
}

/**
 * Stores the processed data (encoded pairs and messages which have been processed).
 * @param {list} encodedPairList The list of encoded pairs to store.
 * @param {object} keywordDict A dictionary that keeps track of how many email each keyword appears in.
 * @param {objcet} threadIds An object that keeps track of each processed thread.
 */
function saveData(encodedPairList, keywordDict, threadIds) {
    Parse.Object.saveAll(encodedPairList, {
        success: function (objs) {
            console.log("Success!");
        },
        error: function (error) {
            console.log("Failed!");
        }
    });
    // Update keyword dictionary in chrome's local storage.
    chrome.storage.sync.set({
        "keywordDict": keywordDict,
        "threadIds": threadIds
    });
}

/**
 * Extracts the keywords from a thread and produces hash pairs from them for our online database (used in the secure search procedure).
 * @param {string} key The key used to encrypt the hash information.
 * @param {object} thread An object containing the messages of a thread.
 * @param {object} keywordDict A dictionary of keywords which keeps track of the amount of emails a keyword has been in (used in secure search procedure).
 * @param {object} threadIds An object that keeps track of messages that have been processed (so that the same message is not processed twice).
 */
function processEmail(key, thread, keywordDict, threadIds) {
    var id = thread.id;
    var content = thread.messages;
    var messages = extractNewEncodedMessages(content, threadIds);

    if (messages.length != 0) {
        var encodedPairList = produceEncodedPairList(key, keywordDict, id, messages);
        saveData(encodedPairList, keywordDict, threadIds); // saves data to our online database and stores thread id information locally
    }
}

/**
 * Sends an authenticated request to a Google API (the Gmail API in our case). Uses chrome.identity and requires setup in the manifest file
 * as well as the Google Developers     Console. The request is attempted 3 times.
 * @param {string} method The method for the xhr request.
 * @param {string} url The url of the request.
 * @param {object} data The data to send along in the request.
 * @param {function} callback The handler for the response.
 */
function authenticatedXhr(method, url, data, callback) {

    var retry = 3;

    getTokenAndXhr();

    function getTokenAndXhr() {
        chrome.identity.getAuthToken({
                'interactive': true
            },
            function (access_token) {
                if (chrome.runtime.lastError) {
                    callback(chrome.runtime.lastError);
                    return;
                }
                var xhr = new XMLHttpRequest();

                xhr.open(method, url);
                xhr.setRequestHeader('Authorization',
                    'Bearer ' + access_token);
                if (method != "DELETE") {
                    xhr.setRequestHeader("Content-Type", "application/json");
                }
                xhr.onload = function () {
                    if (this.status === 401 && retry > 0) {
                        // This status may indicate that the cached
                        // access token was invalid. Retry once with
                        // a fresh token.
                        retry -= 1;
                        chrome.identity.removeCachedAuthToken({
                                'token': access_token
                            },
                            getTokenAndXhr);
                        return;
                    }
                    if (this.status === 500 && retry > 0) { // Check if add label went through, if not then retry
                        retry -= 1;
                        getTokenAndXhr();
                    }
                    if (method != "DELETE") {
                        callback(null, this.status, JSON.parse(this.responseText));
                    } else {
                        callback(null, this.status, this.responseText);
                    }

                }
                if (method != "DELETE") {
                    xhr.send(JSON.stringify(data));
                } else {
                    xhr.send();
                }
            });
    }
}

/**
 * A helper function to facilite making authenticated requests using javascript objects.
 * @param {object} request An authenticated request to send.
 */
function authenticatedXhrObj(request) {
    authenticatedXhr(request.method, request.url, request.data, request.callback);
}

/**
 * Sends a message to the content script running on the current active tab.
 * @param {object} data The data to send to the script.
 */
function sendMessage(data) {
    chrome.tabs.query({
        active: true,
        currentWindow: true
    }, function (tabs) {
        console.log("Found tab");
        console.timeEnd("apply search label");
        chrome.tabs.sendMessage(tabs[0].id, data, function (response) {});

    });
}

/** SEARCH OBJECT **/

/**
 * Initializes a new search object for a given keyword.
 * @param {string} keyword The keyword that for which there is a search request.
 * @return {object} Returns a new search object.
 */
var Search = function (key, keyword) {
    this.token = tokenize(key, keyword);
}

/**
 * This function creates the hash keys and hash value decouplers associated with the keyword in our search. It sends the
 * hash keys to our online database at Parse so that we may retrieve the hash values associated with the search.
 * Once the hash values are retrieved, we extract the email identifiers using the hash value decouplers associated with each
 * encoded pair.
 *
 * In detail:
 *
 * The database contains entries of the form (key, value) = (hashkey, emailId xor hashDecoupler)
 * We construct all of the hashkeys and hashDecouplers and extract the emailId by simply making an exclusive-or operation on the value
 * with the hashDecoupler.
 *
 * Note: We used the following property for exlcusive-or operations
 *                            (a xor b) xor b = a
 */
Search.prototype.databaseLookup = function () {
    var hashPairs = {};
    for (cnt = 1; cnt <= this.count; cnt++) {
        var hashKey = hmac256(this.token, cnt + "0");
        var hashValueDecoupler = hmac256(this.token, cnt + "1");
        hashPairs[hashKey] = hashValueDecoupler;
    }

    var HashPair = Parse.Object.extend("HashPair");
    var query = new Parse.Query(HashPair);
    var searchObj = this;

    query.containedIn("HashKey", Object.keys(hashPairs));

    query.find({
        success: function (results) {
            var ids = [];
            results.forEach(function (HashObj, index, array) {
                ids.push(xorForId(HashObj.get("HashValue"), hashPairs[HashObj.get("HashKey")]));
            });
            searchObj.ids = ids;
            searchObj.searchCount = ids.length;
            searchObj.markLabelsIfReady();
        }
    });
}

/**
 * Creates a new search label to apply to the threads from our search.
 */
Search.prototype.createSearchLabel = function () {
    var rand = Math.floor(Math.random() * 100 + 1);
    var name = "Search/" + rand;
    this.labelName = name;

    var searchObj = this;

    var hiddenLabelRequest = {
        method: "POST",
        url: "https://www.googleapis.com/gmail/v1/users/me/labels",
        data: {
            "labelListVisibility": "labelHide",
            "messageListVisibility": "hide",
            "name": name
        },
        callback: function (error, httpStatus, responseJSON) {
            if (httpStatus == 200) {
                var labelId = responseJSON.id;
                searchObj.labelId = labelId;
                searchObj.markLabelsIfReady();
            }
        }
    };

    authenticatedXhrObj(hiddenLabelRequest);
}

/**
 * Creates callback handlers to handle the response from adding a label to a thread.
 * @param {object} searchObj The object associated with the current search, used for updating the state of the current search.
 * @return {function} Returns a callback handler.
 */
function handleAddLabel(searchObj) {
    return function (error, httpStatus, responseText) {
        if (httpStatus === 200) {
            console.log("count = " + searchObj.searchCount);
            searchObj.updateCount();
        }
    }
}


/**
 * Determines if the search object has receied a label id and the ids of for the search result.
 * If it has, it continues the search process and marks each of the ids with the corresponding label.
 */
Search.prototype.markLabelsIfReady = function () {
    if (this.labelId && this.ids) {
        var requestObj = {
            method: "POST",
            data: {
                "addLabelIds": [this.labelId]
            },
            callback: handleAddLabel(this)
        };

        this.ids.forEach(function (threadId, index, array) {
            requestObj.url = "https://www.googleapis.com/gmail/v1/users/me/threads/" + threadId + "/modify";
            authenticatedXhrObj(requestObj);
        });
    }
}


/**
 * When a label is succesfully added to a thread, we update our count. If all threads have been labeled,
 * we tell the user's browser to redirect to the results page.
 * Messaging: sendMessage(data) - sends our message to our content script
 */
Search.prototype.updateCount = function () {
    if (this.searchCount == 1) {
        var data = {
            label: this.labelName
        };
        sendMessage(data);
    }
    this.searchCount -= 1;
}