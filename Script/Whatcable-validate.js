const body = JSON.stringify({ valid: true });

$done({
  response: {
    status: 200,
    headers: { "Content-Type": "application/json" },
    body,
  },
});
