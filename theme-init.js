// apply saved theme before first paint to avoid a flash
try {
  const t = localStorage.getItem("theme");
  if (t === "light" || t === "dark")
    document.documentElement.dataset.theme = t;
} catch (e) {}
