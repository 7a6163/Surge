const color = $argument || "coral";

const nameList = ["Alice", "Bob", "Carol", "Dave", "Eve", "Frank", "Grace", "Hank", "Ivy", "Jack"];
const friends = nameList.map((name, i) => ({
  id: "joined-" + i,
  state: "joined",
  name,
  best: i === 0,
}));

const body = {
  posts: [
    { reward: "opal",   state: "live", posted: "2026-09-01T00:00:00.000Z", url: "https://x.com/u/status/1", opens: "2026-09-02T00:00:00.000Z" },
    { reward: "chrome", state: "live", posted: "2026-09-15T00:00:00.000Z", url: "https://x.com/u/status/2", opens: "2026-09-16T00:00:00.000Z" },
    { reward: "amber",  state: "live", posted: "2026-10-01T00:00:00.000Z", url: "https://x.com/u/status/3", opens: "2026-10-02T00:00:00.000Z" },
  ],
  friends,
  joined: 10,
  postAfter: "2025-01-01T00:00:00",
  left: 5,
  best: {
    name: friends[0].name,
    color,
    joined: true,
    here: true,
  },
};

$done({ body: JSON.stringify(body) });
