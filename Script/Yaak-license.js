const body = JSON.stringify({
  status: "active",
  data: {
    periodEnd: "2026-09-01T00:00:00Z",
    cancelAt: null,
  },
});

$done({
  response: {
    status: 200,
    headers: { "Content-Type": "application/json" },
    body,
  },
});
