const $ = (id) => document.getElementById(id);
const LABELS = {
  url_length:"URL length (characters)", host_length:"Domain length", path_length:"Path length",
  num_dots:"Number of dots", num_hyphens:"Number of hyphens", num_underscores:"Number of underscores",
  num_slashes:"Number of slashes", num_at_symbols:"Number of @ symbols", num_question_marks:"Number of ? marks",
  num_equal_signs:"Number of = signs", num_ampersands:"Number of & symbols", num_percent:"Number of % symbols",
  num_digits:"Number of digits", digit_ratio:"Share of characters that are digits", num_subdomains:"Number of subdomains",
  has_ip_address:"Uses an IP address", uses_https:"Uses HTTPS", is_shortened:"Link shortener",
  has_suspicious_keyword:"Suspicious keyword present", has_port:"Custom port in URL", double_slash_in_path:"Double slash in path",
  brand_like_subdomain:"Many subdomains (3+)", url_entropy:"URL randomness score", hostname_entropy:"Domain randomness score",
  has_www_prefix:"Starts with www", path_depth:"Path depth (folders)", tld_length:"Domain ending length"
};
const YES_NO = new Set(["has_ip_address","uses_https","is_shortened","has_suspicious_keyword","has_port","double_slash_in_path","brand_like_subdomain","has_www_prefix"]);

document.querySelectorAll(".chip").forEach((c) => c.addEventListener("click", () => {
  $("url-input").value = c.dataset.url; scan();
}));
$("scan-form").addEventListener("submit", (e) => { e.preventDefault(); scan(); });
$("toggle-details").addEventListener("click", () => {
  const t = $("details"); t.classList.toggle("hidden");
  $("toggle-label").textContent = t.classList.contains("hidden") ? "Show" : "Hide";
});

async function scan() {
  const url = $("url-input").value.trim();
  $("error").classList.add("hidden"); $("result").classList.add("hidden");
  if (!url) return showError("Please type or paste a link first.");
  $("scan-btn").disabled = true; $("scan-btn").textContent = "Checking...";
  try {
    const res = await fetch("/api/predict", {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({url})});
    const data = await res.json();
    if (!res.ok || !data.ok) return showError(data.error || "Something went wrong.");
    render(data);
  } catch (e) { showError("Could not reach the server. Is it running?"); }
  finally { $("scan-btn").disabled = false; $("scan-btn").textContent = "Check link"; }
}
function showError(m){ $("error").textContent = m; $("error").classList.remove("hidden"); }

function render(d) {
  const bad = d.label === "phishing";
  $("verdict").className = "verdict " + (bad ? "bad" : "good");
  $("verdict-title").textContent = bad ? "Likely phishing" : "Looks legitimate";
  $("verdict-text").textContent = bad ? "Do not enter passwords or personal details on this website." : "No strong phishing signs were found in this link.";
  $("verdict-url").textContent = d.url;
  $("confidence").textContent = Math.round(d.confidence) + "%";
  $("risk").textContent = d.risk_level; $("risk").className = "stat-value " + d.risk_level;
  const ul = $("reasons"); ul.innerHTML = "";
  d.reasons.forEach((r) => { const li = document.createElement("li"); li.textContent = r; ul.appendChild(li); });
  $("reasons-card").classList.toggle("hidden", d.reasons.length === 0);
  const tb = $("details").querySelector("tbody"); tb.innerHTML = "";
  Object.entries(d.features).forEach(([k, v]) => {
    const tr = document.createElement("tr");
    const a = document.createElement("td"); a.textContent = LABELS[k] || k;
    const b = document.createElement("td"); b.textContent = YES_NO.has(k) ? (v ? "Yes" : "No") : String(Math.round(v * 100) / 100);
    tr.append(a, b); tb.appendChild(tr);
  });
  $("result").classList.remove("hidden");
}
