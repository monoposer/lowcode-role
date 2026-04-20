import http from "k6/http";
import { check, sleep } from "k6";

export const options = {
  vus: 20,
  duration: "15s",
  thresholds: {
    http_req_failed: ["rate<0.01"],
    http_req_duration: ["p(99)<500ms"],
  },
};

const url = __ENV.AUTHZ_URL || "http://127.0.0.1:8080/v1/authorize";
const payload = JSON.stringify({
  user: { sub: "u1", roles: ["admin"] },
  request: { action: "read", resource: { type: "anything", id: "1" } },
});

export default function () {
  const res = http.post(url, payload, {
    headers: { "Content-Type": "application/json" },
  });
  check(res, {
    "200": (r) => r.status === 200,
    allow: (r) => {
      try {
        const b = r.json();
        return b.allow === true;
      } catch {
        return false;
      }
    },
  });
  sleep(0.01);
}
