const color = $argument || "coral";

const friends = [
  { id: "f0", state: "joined",    name: "Alice",  best: true  },
  { id: "f1", state: "joined",    name: "Bob",    best: false },
  { id: "f2", state: "opened",    name: "Carol",  best: false },
  { id: "f3", state: "installed", name: "Dave",   best: false },
  { id: "f4", state: "accepted",  name: "Eve",    best: false },
  { id: "f5", state: "claimed",   name: "Frank",  best: false },
  { id: "f6", state: "joined",    name: "Grace",  best: false },
  { id: "f7", state: "joined",    name: "Hank",   best: false },
  { id: "f8", state: "joined",    name: "Ivy",    best: false },
  { id: "f9", state: "joined",    name: "Jack",   best: false },
];

const body = {
  posts: [
    { reward: "opal",   state: "live",      posted: "2026-08-01T00:00:00.000Z", url: "https://x.com/u/status/1", opens: "2026-08-02T00:00:00.000Z" },
    { reward: "chrome", state: "confirmed", posted: "2026-08-08T00:00:00.000Z", url: "https://x.com/u/status/2", opens: "2026-08-09T00:00:00.000Z" },
    { reward: "amber",  state: "unlocked",  posted: "2026-08-15T00:00:00.000Z", url: "https://x.com/u/status/3", opens: "2026-08-16T00:00:00.000Z" },
    { reward: null,      state: "done",      posted: "2026-08-22T00:00:00.000Z", url: "https://x.com/u/status/4", opens: "2026-08-23T00:00:00.000Z" },
    { reward: null,      state: "expired",   posted: "2026-08-29T00:00:00.000Z", url: "https://x.com/u/status/5", opens: "2026-08-30T00:00:00.000Z" },
    { reward: null,      state: "deleted",   posted: "2026-09-05T00:00:00.000Z", url: "https://x.com/u/status/6", opens: "2026-09-06T00:00:00.000Z" },
    { reward: null,      state: "pending",   posted: "2026-09-12T00:00:00.000Z", url: "https://x.com/u/status/7", opens: "2026-09-13T00:00:00.000Z" },
  ],
  friends,
  joined: 10,
  postAfter: "2025-01-01T00:00:00",
  left: 0,
  best: {
    name: friends[0].name,
    color,
    joined: true,
    here: true,
  },
};

$done({ body: JSON.stringify(body) });
