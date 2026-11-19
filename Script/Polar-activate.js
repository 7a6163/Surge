const now = new Date().toISOString();

const body = {
  id: "a0b1c2d3-e4f5-6789-abcd-ef0123456789",
  license_key_id: "b1c2d3e4-f5a6-7890-bcde-f01234567890",
  label: "Noteline · MacIntel",
  meta: {},
  created_at: now,
  modified_at: null,
  license_key: {
    id: "b1c2d3e4-f5a6-7890-bcde-f01234567890",
    created_at: "2026-01-01T00:00:00.000Z",
    modified_at: null,
    organization_id: "1eb27c66-a49e-4467-ad36-59addb163d39",
    customer_id: "c2d3e4f5-a6b7-8901-cdef-012345678901",
    customer: {
      id: "c2d3e4f5-a6b7-8901-cdef-012345678901",
      email: "user@example.com",
      name: "Licensed User",
    },
    member_id: null,
    member: null,
    benefit_id: "d3e4f5a6-b7c8-9012-defa-123456789012",
    key: "NL_ACTIVATED_00000000",
    display_key: "****-0000",
    status: "granted",
    limit_activations: null,
    usage: 1,
    limit_usage: null,
    validations: 0,
    last_validated_at: null,
    expires_at: null,
  },
};

$done({
  response: {
    status: 200,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  },
});
