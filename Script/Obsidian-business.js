const body = JSON.stringify({
  company: "Apple Inc.",
  expiry: "2099-12-31",
  seats: 100,
});

$done({
  response: {
    status: 200,
    headers: { "Content-Type": "application/json" },
    body,
  },
});
