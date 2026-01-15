Java.perform(function () {
    var MainActivity = Java.use("com.christmas.lottery.MainActivity");
    var Toast = Java.use("android.widget.Toast");
    var Handler = Java.use("android.os.Handler");
    var Looper = Java.use("android.os.Looper");
    var RunnableInterface = Java.use("java.lang.Runnable");
    var JString = Java.use("java.lang.String");

    // ---- FLAG HOOK ----
    try {
        var makeText = Toast.makeText.overload(
            'android.content.Context',
            'java.lang.CharSequence',
            'int'
        );

        makeText.implementation = function (ctx, text, duration) {
            var msg = text ? text.toString() : "";
            if (msg.indexOf("HEX{") >= 0 || msg.indexOf("Flag:") >= 0) {
                send("[FLAG] " + msg);
            }
            return makeText.call(this, ctx, text, duration);
        };

        send("[*] Flag Toast hook active");
    } catch (e) {
        send("[-] Could not hook Toast: " + e);
    }

    // ---- Ticket generation logic ----
    function calculateChecksum(code) {
        var sum = 0;
        for (var i = 0; i < code.length; i++) {
            var c = code.charAt(i);
            var cp = c.charCodeAt(0);
            if (c >= '0' && c <= '9') {
                sum += (cp - 48);
            } else {
                sum += (cp - 65 + 1);
            }
        }
        return sum % 10;
    }

    function generateTicketCodeFromSeed(secretSeed) {
        secretSeed = Number(secretSeed) >>> 0;
        var letters = "ABCDEFGHJKLMNPQRSTUVWXYZ";
        var numbers = "0123456789";
        var code = "";

        for (var i = 0; i < 3; i++) {
            code += letters.charAt((secretSeed >>> (i * 3)) % letters.length);
        }
        code += "-";

        for (var j = 0; j < 4; j++) {
            code += numbers.charAt((secretSeed >>> (j * 4 + 9)) % numbers.length);
        }
        code += "-";

        for (var k = 0; k < 2; k++) {
            code += letters.charAt((secretSeed >>> (k * 5 + 25)) % letters.length);
        }

        var full = code.replace(/-/g, "");
        code += numbers.charAt(calculateChecksum(full));
        return code;
    }

    // ---- Once-per-seed tracking ----
    var seenSeeds = {};  // map of seedNumber -> true

    function schedulePoll() {
        Handler.$new(Looper.getMainLooper())
              .postDelayed(PollRunnable.$new(), 1200);
    }

    var PollRunnable = Java.registerClass({
        name: 'com.christmas.lottery.FridaPollRunnable',
        implements: [RunnableInterface],
        methods: {
            run: function () {
                try {
                    Java.choose("com.christmas.lottery.MainActivity", {
                        onMatch: function (inst) {
                            try {
                                // Convert to plain JS number
                                var rawSeed = inst.secretSeed.value;
                                var seed = Number(rawSeed);

                                if (!seed || seed === 0) {
                                    // Not initialized yet
                                    return;
                                }

                                if (seenSeeds[seed]) {
                                    // We've already handled this seed
                                    return;
                                }

                                // Mark this seed as handled
                                seenSeeds[seed] = true;

                                send("[+] New seed detected: " + seed);
                                var ticket = generateTicketCodeFromSeed(seed);
                                send("[+] Ticket for this seed: " + ticket);

                                // Call validateTicketCodeWithBackend(String)
                                try {
                                    if (inst.validateTicketCodeWithBackend) {
                                        try {
                                            var validateOver =
                                                inst.validateTicketCodeWithBackend
                                                    .overload('java.lang.String');
                                            validateOver.call(inst, JString.$new(ticket));
                                        } catch (eOver) {
                                            // Fallback: direct call, in case no overload object
                                            inst.validateTicketCodeWithBackend(JString.$new(ticket));
                                        }
                                        send("[*] Sent ticket to validateTicketCodeWithBackend()");
                                    } else {
                                        send("[-] validateTicketCodeWithBackend not found");
                                    }
                                } catch (callErr) {
                                    send("[-] Error calling validateTicketCodeWithBackend: " + callErr);
                                }

                            } catch (e) {
                                send("[-] Error processing MainActivity: " + e);
                            }
                        },
                        onComplete: function () {
                            schedulePoll();
                        }
                    });
                } catch (e) {
                    send("[-] PollRunnable exception: " + e);
                    schedulePoll();
                }
            }
        }
    });

    send("[*] Script running. Will auto-validate once per unique secretSeed.");
    schedulePoll();
});

