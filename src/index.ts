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
}: {
  accessKeyId: string;
  secretAccessKey: string;
  bucket: string;
  endpoint: string;
}) => {
  const base = new URL(`https://${bucket}.${endpoint}/`);
  const region = endpoint.split(".")[1];
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
      input = new URL(input, base);
    } else if (input instanceof Request) {
      const { method, url, headers, body } = input;
      init = { method, headers, body, ...init };
      input = new URL(url, base);
    }

    const headers = (init.headers = new Headers(init.headers));

    if (!headers.has("Authorization")) {
      // https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html
      const { host, pathname } = input;
      const method = init.method ?? "GET";

      let hashedPayload: string;

      if (headers.has("x-amz-content-sha256")) {
        hashedPayload = headers.get("x-amz-content-sha256")!;
      } else {
        let body = init.body;

        if (typeof body === "string") {
          body = init.body = encoder.encode(body);
          hashedPayload = hex(await hash(body));
          headers.set("Content-Length", body.byteLength.toString());
        } else if (body && "byteLength" in body) {
          hashedPayload = hex(await hash(body));
          headers.set("Content-Length", body.byteLength.toString());
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

      const signableHeaders = ["host", ...headers.keys()]
        .filter((header) => !unsignableHeaders.includes(header))
        .sort();

      const canonicalHeaders = signableHeaders
        .map((header) => `${header}:${header === "host" ? host : headers.get(header) || ""}\n`)
        .join("");

      const signedHeaders = signableHeaders.join(";");
      const canonicalRequest = `${method}\n${canonicalURI}\n\n${canonicalHeaders}\n${signedHeaders}\n${hashedPayload}`;
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

    return fetch(input, init);
  };
};
