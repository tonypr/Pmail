window.onload = function () {
    // inject gmailUtils into gmail page
    var url = "resources/gmailUtils.js";
    var newScript = document.createElement('script');
    var scriptURL = chrome.extension.getURL(url);
    newScript.src = scriptURL;
    document.getElementsByTagName('body')[0].appendChild(newScript);

    // listen to messages from the open gmail tab
    window.addEventListener("message", handleEvent, false);
}

chrome.extension.onMessage.addListener(function (msg, sender, sendResponse) {
    if (msg.label) {
        location.href = "#label/" + msg.label;
    };
});

/**
 * Handles messages received from the gmail page and forwards it to the background page.
 * @param {event} The event to be handled.
 */
function handleEvent(event) {
    // We only accept messages from ourselves
    if (event.source != window)
        return;

    if (event.data.type) {
        var request = {
            action: event.data.type,
            data: {}
        }
        var eventMessage;

        if (request.action == "search") {
            console.time('search');
            var input = event.data.search;
            request.data = {
                keyword: input
            };
            eventMessage = "Received search request " + input;
        } else if (request.action == "thread") {
            request.data = {
                id: event.data.id,
                messages: event.data.emailContent
            };
            eventMessage = "Captured thread from gmail page. #messages: " + request.data.messages.length + " for id: " + request.data.id;
        } else if (request.action == "deleteLabels") {
            eventMessage = "Unlabelling - script.js";
        } else {
            console.log("Incorrect message type:" + event.data.type);
            return;
        }
        console.log(eventMessage);
        chrome.extension.sendMessage(request, function (response) {
            console.log(response);
        });
    }
}