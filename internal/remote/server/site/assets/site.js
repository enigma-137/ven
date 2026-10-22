// Landing page niceties: rotating example command, copy button and
// peek-on-hover for the masked demo values. No tracking, no network.
(function () {
  var reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  var typed = document.querySelector(".typed");
  var cmd = document.querySelector(".cmd");
  if (typed && cmd) {
    var words = typed.getAttribute("data-words").split("|");
    var i = 0;
    var type = function (text, done) {
      var n = 0;
      typed.textContent = "";
      var step = function () {
        typed.textContent = text.slice(0, ++n);
        if (n < text.length) setTimeout(step, 45 + Math.random() * 50);
        else done();
      };
      step();
    };
    var next = function () {
      i = (i + 1) % words.length;
      cmd.setAttribute("data-copy", words[i]);
      type(words[i], function () { setTimeout(next, 2600); });
    };
    if (!reduced) setTimeout(next, 2600);

    var btn = cmd.querySelector(".copy");
    btn.addEventListener("click", function () {
      var text = cmd.getAttribute("data-copy");
      if (navigator.clipboard) navigator.clipboard.writeText(text);
      btn.classList.add("done");
      setTimeout(function () { btn.classList.remove("done"); }, 1200);
    });
  }

  document.querySelectorAll(".mask").forEach(function (el) {
    var hidden = el.textContent;
    el.parentElement.addEventListener("mouseenter", function () { el.textContent = el.getAttribute("data-real"); });
    el.parentElement.addEventListener("mouseleave", function () { el.textContent = hidden; });
  });
})();
