// Docs page: copy buttons, tabs, contents highlighting and the mobile menu.
// No tracking, no network.
(function () {
  var icon = '<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="8" y="8" width="12" height="12" rx="2.5" fill="none" stroke="currentColor" stroke-width="1.8"/><path d="M16 8V6.5A2.5 2.5 0 0 0 13.5 4h-7A2.5 2.5 0 0 0 4 6.5v7A2.5 2.5 0 0 0 6.5 16H8" fill="none" stroke="currentColor" stroke-width="1.8"/></svg>';

  document.querySelectorAll(".doc pre").forEach(function (pre) {
    var btn = document.createElement("button");
    btn.type = "button";
    btn.className = "copy";
    btn.setAttribute("aria-label", "Copy");
    btn.innerHTML = icon;
    btn.addEventListener("click", function () {
      // Drop trailing "# comments" so pasted commands run as-is.
      var text = pre.querySelector("code").textContent.split("\n").map(function (l) {
        return l.replace(/\s+#\s.*$/, "");
      }).join("\n").trim();
      if (navigator.clipboard) navigator.clipboard.writeText(text);
      btn.classList.add("done");
      setTimeout(function () { btn.classList.remove("done"); }, 1200);
    });
    pre.appendChild(btn);
  });

  document.querySelectorAll("[data-tabs]").forEach(function (box) {
    var buttons = box.querySelectorAll("[data-tab]");
    var select = function (name) {
      buttons.forEach(function (b) { b.setAttribute("aria-selected", String(b.getAttribute("data-tab") === name)); });
      box.querySelectorAll("[data-panel]").forEach(function (p) { p.hidden = p.getAttribute("data-panel") !== name; });
    };
    buttons.forEach(function (b) {
      b.addEventListener("click", function () { select(b.getAttribute("data-tab")); });
    });
    if (box.querySelector('[data-tab="win"]') && /Windows/.test(navigator.userAgent)) select("win");
  });

  var links = {};
  document.querySelectorAll(".toc a").forEach(function (a) { links[a.getAttribute("href").slice(1)] = a; });
  if ("IntersectionObserver" in window) {
    var current;
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) {
        if (!e.isIntersecting) return;
        if (current) current.classList.remove("on");
        current = links[e.target.id];
        if (current) current.classList.add("on");
      });
    }, { rootMargin: "-20% 0px -70% 0px" });
    document.querySelectorAll(".doc section[id]").forEach(function (s) { io.observe(s); });
  }

  // Links to a collapsed answer open it.
  var openTarget = function () {
    var el = location.hash && document.getElementById(location.hash.slice(1));
    if (el && el.tagName === "DETAILS") el.open = true;
  };
  window.addEventListener("hashchange", openTarget);
  openTarget();

  var menu = document.querySelector(".menu");
  var close = function () { document.documentElement.classList.remove("toc-open"); menu.setAttribute("aria-expanded", "false"); };
  menu.addEventListener("click", function () {
    var open = document.documentElement.classList.toggle("toc-open");
    menu.setAttribute("aria-expanded", String(open));
  });
  document.querySelectorAll(".toc a").forEach(function (a) { a.addEventListener("click", close); });
})();
