const body = JSON.stringify({
  business_id: "<string>",
  created_at: "2024-01-01T00:00:00Z",
  customer: {
    customer_id: "<string>",
    email: "<string>",
    name: "<string>",
    metadata: {},
    phone_number: "<string>",
  },
  id: "lki_123",
  license_key_id: "lic_123",
  name: "Production Server 1",
  product: {
    product_id: "<string>",
    name: "<string>",
  },
});

$done({
  response: {
    status: 200,
    headers: { "Content-Type": "application/json" },
    body,
  },
});
