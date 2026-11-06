// YouTube Home -> Subscriptions request rewrite (Surge, binary-body-mode)
// Rewrites the Home feed browse request (browseId FEwhat_to_watch) to FEsubscriptions,
// so the app loads the subscriptions feed in one request instead of Home first.
(() => {
  const FROM = "FEwhat_to_watch";
  const TO = "FEsubscriptions";

  function parseArgs(s) {
    const o = { subsTabOnly: true };
    if (typeof s !== "string" || s.includes("{{{")) return o;
    for (const kv of s.split("&")) {
      const [k, v] = kv.split("=");
      if (k) o[k] = v === "true" ? true : v === "false" ? false : v;
    }
    return o;
  }

  function readVarint(b, p) {
    let r = 0, s = 0;
    while (p < b.length) {
      const x = b[p++];
      r += (x & 0x7f) * Math.pow(2, s);
      if (x < 0x80) return [r, p];
      s += 7;
      if (s > 63) break;
    }
    throw new Error("bad varint");
  }

  function writeVarint(out, v) {
    while (v > 0x7f) { out.push((v % 128) | 0x80); v = Math.floor(v / 128); }
    out.push(v);
  }

  function bytesEqualStr(b, s) {
    if (b.length !== s.length) return false;
    for (let i = 0; i < s.length; i++) if (b[i] !== s.charCodeAt(i)) return false;
    return true;
  }

  // Rewrite top-level field 2 (browseId); every other field is copied byte for byte.
  function rewrite(buf) {
    const parts = [];
    let p = 0, changed = false;
    while (p < buf.length) {
      const start = p;
      const [key, p1] = readVarint(buf, p);
      const no = Math.floor(key / 8), wt = key % 8;
      p = p1;
      if (wt === 0) p = readVarint(buf, p)[1];
      else if (wt === 1) p += 8;
      else if (wt === 5) p += 4;
      else if (wt === 2) {
        const [len, p2] = readVarint(buf, p);
        if (p2 + len > buf.length) throw new Error("bad length");
        if (no === 2 && bytesEqualStr(buf.subarray(p2, p2 + len), FROM)) {
          const head = [];
          writeVarint(head, key);
          writeVarint(head, TO.length);
          for (let i = 0; i < TO.length; i++) head.push(TO.charCodeAt(i));
          parts.push(Uint8Array.from(head));
          p = p2 + len;
          changed = true;
          continue;
        }
        p = p2 + len;
      } else throw new Error("unsupported wire type " + wt);
      if (p > buf.length) throw new Error("truncated");
      parts.push(buf.subarray(start, p));
    }
    if (!changed) return null;
    const out = new Uint8Array(parts.reduce((n, x) => n + x.length, 0));
    let o = 0;
    for (const x of parts) { out.set(x, o); o += x.length; }
    return out;
  }

  try {
    const args = parseArgs(typeof $argument === "undefined" ? "" : $argument);
    const body = $request.body;
    if (!args.subsTabOnly || !(body instanceof Uint8Array)) return $done({});
    const out = rewrite(body);
    if (!out) return $done({});
    if (args.debug) console.log(`YouTube: browse ${FROM} -> ${TO}`);
    $done({ body: out });
  } catch (e) {
    console.log("YouTube request rewrite error: " + e.message);
    $done({});
  }
})();
