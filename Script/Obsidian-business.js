const body = JSON.stringify({
  company: "Apple Inc.",
  expiry: 407090880000,
  seats: 100,
});

$done({
  status: "HTTP/1.1 200 OK",
  headers: { "Content-Type": "application/json" },
  body,
});
