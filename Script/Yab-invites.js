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
    {
      reward: "surprise",
      state: "live",
      posted: "2026-10-01T00:00:00.000Z",
      url: "https://x.com/u/status/1",
      opens: "2026-01-01T00:00:00.000Z",
    },
  ],
  friends,
  joined: 10,
  postAfter: "2026-01-01T00:00:00",
  left: 0,
  best: {
    name: friends[0].name,
    color,
    joined: true,
    here: true,
  },
};

$done({ body: JSON.stringify(body) });
