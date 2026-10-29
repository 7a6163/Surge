const body = JSON.parse($request.body || "{}");
$done({
  response: {
    status: 200,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      url: body.bare || body.url || "https://x.com/u/status/0",
      state: "live",
      posted: new Date().toISOString(),
      opens: "2025-01-01T00:00:00.000Z",
      reward: "opal",
    }),
  },
});
