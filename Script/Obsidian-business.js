const body = JSON.stringify({
  company: "Acme Inc.",
  expiry: 4070908800,
  seats: 100,
});

$done({
  status: "HTTP/1.1 200 OK",
  headers: { "Content-Type": "application/json" },
  body,
});
