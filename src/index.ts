const encoder = new TextEncoder();
const encode = (pathname: string) => pathname.replace(/[!'()*]/g, (c) => "%" + c.charCodeAt(0).toString(16));
const hash = async (data: ArrayBufferView | ArrayBuffer) => crypto.subtle.digest("SHA-256", data);

const hex = (data: ArrayBuffer) =>
  Array.from(new Uint8Array(data))
    .map((x) => x.toString(16).padStart(2, "0"))
    .join("");

const hmac = async (key: string | ArrayBufferView | ArrayBuffer, data: string) => {
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    typeof key === "string" ? encoder.encode(key) : key,
    { name: "HMAC", hash: { name: "SHA-256" } },
    false,
    ["sign"],
  );

  return crypto.subtle.sign("HMAC", cryptoKey, encoder.encode(data));
};

const unsignableHeaders = [
  "authorization",
  "content-type",
  "content-length",
  "user-agent",
  "presigned-expires",
  "expect",
  "x-amzn-trace-id",
  "range",
  "connection",
];

export default ({
  accessKeyId,
  secretAccessKey,
  bucket,
  endpoint,
  region = endpoint.split(".")[1],
  secure = true,
  pathStyle = false,
  prefix = "/",
}: {
  accessKeyId: string;
  secretAccessKey: string;
  bucket: string;
  endpoint: string;
  region?: string;
  secure?: boolean;
  pathStyle?: boolean;
  prefix?: string;
}) => {
  const base = new URL(
    `http${secure ? "s" : ""}://${pathStyle ? `${endpoint}/${bucket}` : `${bucket}.${endpoint}`}${prefix}`,
  );

  let cacheDate: string;
  let promiseSigningKey: Promise<ArrayBuffer>;

  const getSigningKey = (date: string) => {
    if (cacheDate !== date) {
      cacheDate = date;

      promiseSigningKey = (async () => {
        const dateKey = await hmac("AWS4" + secretAccessKey, date);
        const dateRegionKey = await hmac(dateKey, region);
        const dateRegionServiceKey = await hmac(dateRegionKey, "s3");
        const signingKey = await hmac(dateRegionServiceKey, "aws4_request");
        return signingKey;
      })();
    }

    return promiseSigningKey;
  };

  return async (input: URL | RequestInfo, init: RequestInit = {}) => {
    if (typeof input === "string") {
      input = new URL(`.${input}`, base);
    } else if (input instanceof Request) {
      const { method, url, headers, body } = input;
      init = { method, headers, body, ...init };
      input = new URL(url, base);
    }

    const headers = (init.headers = new Headers(init.headers));

    if (!headers.has("Authorization")) {
      // https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html
      const { host, pathname, searchParams } = input;
      const method = init.method ?? "GET";

      let hashedPayload: string;

      if (headers.has("x-amz-content-sha256")) {
        hashedPayload = headers.get("x-amz-content-sha256")!;
      } else {
        let body = init.body;

        if (typeof body === "string") {
          body = init.body = encoder.encode(body);
          hashedPayload = hex(await hash(body));
        } else if (body && "byteLength" in body) {
          hashedPayload = hex(await hash(body));
        } else {
          hashedPayload = "UNSIGNED-PAYLOAD";
        }

        headers.set("x-amz-content-sha256", hashedPayload);
      }

      let timeStamp: string;

      if (headers.has("x-amz-date")) {
        timeStamp = headers.get("x-amz-date")!;
      } else {
        timeStamp = new Date().toISOString().replace(/[:-]|\.\d+/g, "");
        headers.set("x-amz-date", timeStamp);
      }

      const canonicalURI = encode(pathname);

      const seenKeys = new Set<string>();

      const canonicalQueryString = [...searchParams]
        .filter(([k]) => {
          if (!k || seenKeys.has(k)) {
            return false;
          }

          seenKeys.add(k);
          return true;
        })
        .map((pair) => pair.map((p) => encode(encodeURIComponent(p))))
        .sort(([k1], [k2]) => (k1 < k2 ? -1 : k1 > k2 ? 1 : 0))
        .map((pair) => pair.join("="))
        .join("&");

      const signableHeaders = ["host", ...headers.keys()]
        .filter((header) => !unsignableHeaders.includes(header))
        .sort();

      const canonicalHeaders = signableHeaders
        .map((header) => `${header}:${header === "host" ? host : headers.get(header) || ""}\n`)
        .join("");

      const signedHeaders = signableHeaders.join(";");
      const canonicalRequest = `${method}\n${canonicalURI}\n${canonicalQueryString}\n${canonicalHeaders}\n${signedHeaders}\n${hashedPayload}`;
      const date = timeStamp.slice(0, 8);
      const scope = `${date}/${region}/s3/aws4_request`;

      const stringToSign = `AWS4-HMAC-SHA256\n${timeStamp}\n${scope}\n${hex(
        await hash(encoder.encode(canonicalRequest)),
      )}`;

      const signature = hex(await hmac(await getSigningKey(date), stringToSign));

      headers.set(
        "Authorization",
        `AWS4-HMAC-SHA256 Credential=${accessKeyId}/${scope},SignedHeaders=${signedHeaders},Signature=${signature}`,
      );
    }

    for (let i = 0; i <= 10; i++) {
      try {
        const res = await fetch(input, init);

        if (res.status < 500 && res.status !== 429) {
          return res;
        }
      } catch {}

      await new Promise((resolve) => setTimeout(resolve, Math.random() * 50 * Math.pow(2, i)));
    }

    return fetch(input, init);
  };
};
