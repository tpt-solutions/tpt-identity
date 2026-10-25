// Scripts for the login page. The page's CSP allows scripts from this origin only, so each step is written here
// rather than inline.
(function () {
  "use strict";

  // base64url text to an ArrayBuffer, as WebAuthn expects for challenges and credential IDs.
  function fromBase64url(text) {
    var s = text.replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) {
      s += "=";
    }
    var binary = atob(s);
    var bytes = new Uint8Array(binary.length);
    for (var i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }

  // ArrayBuffer to base64url text, as the server expects.
  function toBase64url(buffer) {
    var bytes = new Uint8Array(buffer);
    var binary = "";
    for (var i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  // Passkey sign-in: run the WebAuthn ceremony, post the assertion, and follow the redirect the server returns.
  function passkey(button) {
    var status = document.getElementById("status");

    function say(text) {
      status.textContent = text;
    }

    button.addEventListener("click", async function () {
      if (!window.PublicKeyCredential) {
        say("This browser does not support passkeys. Use the email link instead.");
        return;
      }
      say("Waiting for your passkey...");
      try {
        var begin = await fetch("/api/v1/webauthn/login/begin", { method: "POST", credentials: "same-origin" });
        if (!begin.ok) {
          throw new Error("Passkey sign-in is not available right now.");
        }
        var options = await begin.json();
        var publicKey = options.publicKey;
        publicKey.challenge = fromBase64url(publicKey.challenge);
        if (publicKey.allowCredentials) {
          publicKey.allowCredentials.forEach(function (c) {
            c.id = fromBase64url(c.id);
          });
        }

        var credential = await navigator.credentials.get({ publicKey: publicKey });
        var body = {
          id: credential.id,
          rawId: toBase64url(credential.rawId),
          type: credential.type,
          response: {
            clientDataJSON: toBase64url(credential.response.clientDataJSON),
            authenticatorData: toBase64url(credential.response.authenticatorData),
            signature: toBase64url(credential.response.signature),
            userHandle: credential.response.userHandle ? toBase64url(credential.response.userHandle) : null
          }
        };

        var finish = await fetch("/login/passkey/finish?txn=" + encodeURIComponent(button.dataset.txn), {
          method: "POST",
          credentials: "same-origin",
          headers: { "Content-Type": "application/json", "X-CSRF-Token": button.dataset.csrf },
          body: JSON.stringify(body)
        });
        if (!finish.ok) {
          throw new Error((await finish.text()).trim() || "Sign-in failed.");
        }
        var result = await finish.json();
        if (result.redirect) {
          window.location.assign(result.redirect);
          return;
        }
        say(result.message || "Done.");
      } catch (err) {
        say(err && err.message ? err.message : "Passkey sign-in failed.");
      }
    });
  }

  // Consent: post the decision and follow the redirect. A plain form post would redirect to the relying party,
  // which the page's CSP form-action rule would block, so the post is made by script.
  function consent(form) {
    form.addEventListener("submit", async function (event) {
      event.preventDefault();
      var message = document.getElementById("message");
      try {
        var res = await fetch(form.action, {
          method: "POST",
          credentials: "same-origin",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams(new FormData(form, event.submitter))
        });
        var out = await res.json().catch(function () {
          return {};
        });
        if (!res.ok) {
          throw new Error(out.error || "The sign-in could not be completed.");
        }
        window.location.assign(out.redirect);
      } catch (err) {
        message.textContent = err.message || "The sign-in could not be completed.";
        message.hidden = false;
      }
    });
  }

  var button = document.getElementById("passkey");
  if (button) {
    passkey(button);
  }
  var form = document.querySelector("form[data-consent]");
  if (form) {
    consent(form);
  }
})();
