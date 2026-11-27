// The hero demo: type a search, narrow the list, copy, count down.
// With reduced motion the finished state is shown as-is.
(function () {
  "use strict";

  // Copy buttons for commands.
  document.querySelectorAll("button.copy").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var text = btn.getAttribute("data-text");
      if (!text || !navigator.clipboard) return;
      navigator.clipboard.writeText(text).then(function () {
        btn.textContent = "Copied";
        setTimeout(function () { btn.textContent = "Copy"; }, 1600);
      });
    });
  });

  var q = document.getElementById("q");
  var count = document.getElementById("count");
  var status = document.getElementById("status");
  var otp = document.getElementById("otp");
  var bar = document.getElementById("bar");
  var secs = document.getElementById("secs");
  var cursor = document.querySelector(".terminal .cursor");
  if (!q || !status) return;

  var still = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  if (still) return;

  var query = "jane corp";
  var counts = ["12/12", "9/12", "7/12", "4/12", "3/12", "3/12", "2/12", "2/12", "2/12", "2/12"];
  // A made-up code that changes every 30 s, just for the picture.
  var codes = ["482 913", "730 266", "915 048", "264 571"];
  var left = 19, codeIndex = 0;

  function pad(s, n) { while (s.length < n) s += " "; return s; }

  function tickOTP() {
    left -= 1;
    if (left <= 0) { left = 30; codeIndex = (codeIndex + 1) % codes.length; otp.textContent = codes[codeIndex]; }
    var filled = Math.round(left / 30 * 10);
    bar.firstChild.textContent = "━".repeat(filled);
    bar.lastChild.textContent = "─".repeat(10 - filled);
    secs.textContent = (left < 10 ? " " : "") + left + "s";
  }

  function countdown(n) {
    if (n <= 0) { status.classList.add("hidden"); return; }
    status.textContent = "✓ password copied (this Mac only) · clipboard clears in " + n + "s";
    setTimeout(function () { countdown(n - 1); }, 1000);
  }

  function run() {
    q.textContent = pad("", query.length);
    count.textContent = "12/12";
    status.classList.add("hidden");
    cursor.classList.add("blink");
    var i = 0;
    function type() {
      i += 1;
      q.textContent = pad(query.slice(0, i), query.length);
      count.textContent = counts[i] || "2/12";
      if (i < query.length) { setTimeout(type, 110 + Math.random() * 90); return; }
      setTimeout(function () { // press Enter
        cursor.classList.remove("blink");
        status.classList.remove("hidden");
        countdown(30);
      }, 700);
    }
    setTimeout(type, 900);
  }

  setInterval(tickOTP, 1000);
  run();
})();
