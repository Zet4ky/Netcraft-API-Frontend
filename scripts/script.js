function encodeUrlForNetcraft(url) {
  try {
    const parsed = new URL(url);
    let path = parsed.pathname;

    if (path.endsWith("/")) {
      path = path.slice(0, -1);
    }

    if (path.startsWith("/")) {
      path = path.slice(1);
    }

    const encodedPath = path.split("/").join("?x=");
    const base64Url = btoa(
      `${parsed.origin}${encodedPath ? "?x=" + encodedPath : ""}`,
    )
      .replace(/=/g, "")
      .replace(/\+/g, "-")
      .replace(/\//g, "_");

    return base64Url;
  } catch (err) {
    console.error("Invalid URL:", url);
    return btoa(url).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
  }
}

function extractDomain(url) {
  try {
    const parsedUrl = new URL(url);
    return parsedUrl.hostname;
  } catch (error) {
    console.error("Invalid URL:", error);
    return null;
  }
}

async function resolveDomain(domain) {
  try {
    const response = await fetch(
      `https://cloudflare-dns.com/dns-query?name=${domain}&type=A`,
      {
        method: "GET",
        headers: {
          Accept: "application/dns-json",
        },
      },
    );

    const respJson = await response.json();
    return respJson.Answer?.[0]?.data ?? null;
  } catch (error) {
    console.error("DNS resolution failed:", error);
    return null;
  }
}

function isValidIP(ip) {
  const ipRegex =
    /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  return ipRegex.test(ip);
}

function defangUrl(url) {
  let defangedUrl = url.replace(/^https?:/, "hxxp:");
  defangedUrl = defangedUrl.replace(/\./g, "[.]");
  return defangedUrl;
}

function getCIDRPrefix(startIP, endIP) {
  const ipToBinary = (ip) =>
    ip
      .split(".")
      .map((octet) => parseInt(octet).toString(2).padStart(8, "0"))
      .join("");

  const binStart = ipToBinary(startIP);
  const binEnd = ipToBinary(endIP);
  let prefixLength = 0;

  for (let i = 0; i < 32; i++) {
    if (binStart[i] !== binEnd[i]) break;
    prefixLength++;
  }

  return `${startIP}/${prefixLength}`;
}

function getFlagEmoji(countryCode) {
  if (!countryCode || countryCode.length !== 2) return "🌐";
  const code = countryCode.toUpperCase();
  return [...code]
    .map((char) => String.fromCodePoint(char.charCodeAt(0) + 127397))
    .join("");
}

const getCountryLabel = (code) => {
  if (!code) return "🌐 World (UN)";

  const name = new Intl.DisplayNames(["en-GB"], { type: "region" }).of(code);
  return `${getFlagEmoji(code)} ${name} (${code})`;
};

document
  .getElementById("scanForm")
  .addEventListener("submit", async function (e) {
    e.preventDefault();

    const url = document.getElementById("url-input").value.trim();
    const resultsTable = document.getElementById("results-table");
    const loadingMessage = document.getElementById("loading-message");
    const errorMessage = document.getElementById("error-message");
    const resultsTableBody = resultsTable.querySelector("tbody");

    resultsTableBody.innerHTML = "";
    errorMessage.style.display = "none";
    resultsTable.style.display = "none";
    loadingMessage.style.display = "block";

    let ipaddress = await resolveDomain(extractDomain(url));

    let data = null;
    try {
      let ipValidationCount = 0;

      while (!isValidIP(ipaddress)) {
        ipaddress = await resolveDomain(ipaddress);
        if (ipValidationCount > 3) {
          break;
        }
        ipValidationCount++;
      }
      // -----  Cambio de proxy lexoday
      const endpoint = `https://api.codetabs.com/v1/proxy?quest=https://mirror.toolbar.netcraft.com/check_url/v4/${encodeUrlForNetcraft(url)}/dodns/info`;
      const res = await fetch(endpoint);

      if (res.status === 204) {
        errorMessage.textContent = "No information available.";
        errorMessage.style.display = "block";
        loadingMessage.style.display = "none";
        return;
      }

      if (!res.ok) {
        throw new Error(`Error: ${res.status}`);
      }
      // respon
      const text = await res.text();
      if (!text || text.trim() === "") {
        throw new Error("Empty response from server");
      }
      try {
        data = JSON.parse(text);
      } catch {
        throw new Error("Invalid or unknown URL — no data returned");
      }
      let matchCount = 0;
      let matchedTypes = [];

      if (Array.isArray(data.patterns)) {
        data.patterns.forEach((patternObj) => {
          try {
            let pattern = atob(patternObj.pattern);
            let flags = "";

            if (pattern.startsWith("(?i)")) {
              pattern = pattern.slice(4);
              flags += "i";
            }

            const regex = new RegExp(pattern, flags);

            console.log(regex);
            console.log(url);

            if (regex.test(url)) {
              matchCount++;
              matchedTypes.push(
                patternObj.n_type || patternObj.type || "unknown",
              );
            }
          } catch (regexError) {
            console.warn("Invalid regex skipped:", patternObj.pattern);
          }
        });
      }

      let netblock = getCIDRPrefix(
        data.netblock?.first_ip || "0.0.0.0",
        data.netblock?.last_ip || "0.0.0.0",
      );
      // cambio estructural code
      const rows = [
        [
          "Site",
          `<a href="https://sitereport.netcraft.com/?url=${url}" target="_blank" rel="noopener noreferrer">${defangUrl(url)}</a>`,
        ],
        ["Hosting", data.hoster ?? "undefined"],
        ["Country", getCountryLabel(data.country) ?? "undefined"],
        ["Risk", data.risk !== undefined ? `${data.risk}/10` : "undefined"],
        ["First Seen", data.firstseen ?? "undefined"],
        [
          "Netblock",
          `<a href="https://bgp.he.net/net/${netblock}" target="_blank" rel="noopener noreferrer">${netblock}</a>${data.netblock?.name ? ` (${data.netblock.name})` : ""}`,
        ],
        [
          "IP",
          `<a href="https://www.virustotal.com/gui/ip-address/${ipaddress}" target="_blank" rel="noopener noreferrer">${ipaddress}</a>`,
        ],
        [
          "Pattern Matches",
          `${matchCount} (${matchedTypes.join(", ") || "none"})`,
        ],
        [
          "Total Patterns",
          Array.isArray(data.patterns) ? data.patterns.length : "0",
        ],
      ];

      const toRow = ([label, value]) =>
        `<tr><td>${label}</td><td>${value}</td></tr>`;

      resultsTableBody.innerHTML = rows.map(toRow).join("\n");

      resultsTable.style.display = "table";
    } catch (err) {
      errorMessage.textContent = `Error querying: ${err.message} ${data?.message ? " - " + data.message : ""}`;
      errorMessage.style.display = "block";
    } finally {
      document.getElementById("url-input").value = "";
      loadingMessage.style.display = "none";
    }
  });
