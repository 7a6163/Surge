$done({
  response: {
    status: 200,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ kept: true, after: "2025-01-01T00:00:00" }),
  },
});
