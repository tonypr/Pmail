/* RECEIVEABLE COMMANDS FROM CONTENT SCRIPT */

var messageEnum = {
    "search": "Runs a search from a given keyword.",
    "thread": "Processes a thread.",
    "deleteLabels": "Deletes search labels."
}

/** Wait for and identify requests **/

chrome.extension.onMessage.addListener(function (message, sender, sendResponse) {
    if (message.action in messageEnum) {
        handleMessage(message);
        sendResponse("Proper message received.");
    } else {
        sendResponse("The message format was incorrect. Expected one of the following commands: " + Object.keys(messageEnum));
    }
});

/** Handle requests **/

/**
 * Handles a request from the content script
 * param {object} message The message received from the content script
 */
function handleMessage(message) {
    if (message.action == "search" && message.data.keyword) {
        var keyword = decodeText(message.data.keyword);
        runSearch(keyword);
    } else if (message.action == "thread") {
        var thread = message.data;
        runThread(thread);
    } else if (message.action == "deleteLabels") {
        runDeleteLabels();
    }
    console.log("Running process: " + message.action + "\nDescription: " + messageEnum[message.action]);
}

/** Run Requests **/

/**
 * Initializes a search request and runs the necessary commands.
 * @param {string} keyword The keyword for the search request.
 */
function runSearch(keyword) {
    chrome.storage.sync.get(["key", "keywordDict"], function (items) {
        var newSearch = new Search(items.key, keyword);
        if ("keywordDict" in items) {
            var keywordDictionary = items.keywordDict;
            var safeKeyword = "keyword-" + keyword;
            if (safeKeyword in keywordDictionary) {
                newSearch.count = keywordDictionary["keyword-" + keyword];
                newSearch.databaseLookup();
                newSearch.createSearchLabel();
            }
        } else {
            console.log("Error: No dictionary found. Cannot complete search.");
        }
    });
}

/**
 * Processes a thread: decrypts, extracts keywords and saves updates to local storage and the parse database.
 * @param {object} thread The current thread which we wish to process.
 */
function runThread(thread) {
    chrome.storage.sync.get(["keywordDict", "threadIds", "key"], function (items) {
        var keywordDictionary = {},
            threadIds = {};
        if (items.keywordDict && items.threadIds) {
            keywordDictionary = items.keywordDict;
            threadIds = items.threadIds;
            console.log("Found dictionary and threads");
        } else {
            console.log("Dictionary or threads not found");
        }
        processEmail(items.key, thread, keywordDictionary, threadIds);
    });
}

/**
* Deletes all labels that have been produced from previous searches.
*/
function runDeleteLabels() {
    function handleDelete(error, httpStatus, responseText) {
        if (httpStatus === 204) {
            console.log("Success in deletion!");
        } else {
            console.log("Failure in deletion!");
        }

    }

    function callback(error, httpStatus, responseJson) {
        var labels = responseJson.labels;
        labels.forEach(function (label, index, array) {
            if (label.name.indexOf("Search/") !== -1) {
                authenticatedXhr("DELETE", "https://www.googleapis.com/gmail/v1/users/me/labels/" + label.id, {}, handleDelete);
            }

        });
    }

    authenticatedXhr("GET", "https://www.googleapis.com/gmail/v1/users/me/labels", {}, callback);
}