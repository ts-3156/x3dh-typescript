const { subtle, getRandomValues } = (typeof window === "undefined") ? globalThis.crypto : window.crypto;

function exists<T>(v: T | null | undefined): v is NonNullable<T> {
  return typeof v !== "undefined" && v !== null;
}

function assertExists<T>(
  v: T | null | undefined,
  target = "",
): asserts v is NonNullable<T> {
  if (!exists(v)) {
    throw new Error(`${target} should be specified`.trim());
  }
}

interface PrekeyBundle {
  [key: string]: any;
}

interface X3DHData {
  [key: string]: any;
}

interface MessageHeader {
  [key: string]: any;
}

class PrivateKey {
  // Recommended, but not implemented in browsers
  // static ALGORITHM = { name: "X25519"} ;

  static ALGORITHM = { name: "ECDH", namedCurve: "P-256" };

  #key;

  constructor(key: CryptoKey) {
    this.#key = key;
  }

  async exchange(key: CryptoKey): Promise<ArrayBuffer> {
    return await subtle.deriveBits(
      { ...PrivateKey.ALGORITHM, public: key },
      this.#key,
      256,
    );
  }

  static async generate(): Promise<[PrivateKey, CryptoKey]> {
    const pair = await subtle.generateKey(
      PrivateKey.ALGORITHM,
      true,
      ["deriveBits"],
    );
    return [new PrivateKey(pair.privateKey), pair.publicKey];
  }
}

class SigningKey {
  // Recommended, but not implemented in browsers
  // static ALGORITHM = { name: "Ed25519" };

  static ALGORITHM = { name: "ECDSA", namedCurve: "P-256", hash: "SHA-256" };

  #key;

  constructor(key: CryptoKey) {
    this.#key = key;
  }

  async sign(data: ArrayBuffer): Promise<ArrayBuffer> {
    return await subtle.sign(SigningKey.ALGORITHM, this.#key, data);
  }

  static async generate(): Promise<[SigningKey, VerifyKey]> {
    const pair = await subtle.generateKey(
      SigningKey.ALGORITHM,
      false,
      ["sign", "verify"],
    );
    return [new SigningKey(pair.privateKey), new VerifyKey(pair.publicKey)];
  }
}

class VerifyKey {
  #key;

  constructor(key: CryptoKey) {
    this.#key = key;
  }

  async verify(signature: ArrayBuffer, data: ArrayBuffer) {
    await subtle.verify(SigningKey.ALGORITHM, this.#key, signature, data);
  }
}

class AES256GCM {
  async encrypt(key: ArrayBuffer, plaintext: Uint8Array, ad: ArrayBuffer): Promise<[ArrayBuffer, ArrayBuffer]> {
    const iv = crypto.getRandomValues(new Uint8Array(12)).buffer;
    return [
      await subtle.encrypt(
        { name: "AES-GCM", iv: iv, additionalData: ad },
        await this.keyFrom(key),
        plaintext,
      ),
      iv,
    ];
  }

  async decrypt(key: ArrayBuffer, ciphertext: ArrayBuffer, ad: ArrayBuffer, iv: ArrayBuffer): Promise<ArrayBuffer> {
    return await subtle.decrypt(
      { name: "AES-GCM", iv: iv, additionalData: ad },
      await this.keyFrom(key),
      ciphertext,
    );
  }

  async keyFrom(bytes: ArrayBuffer): Promise<CryptoKey> {
    return await subtle.importKey(
      "raw",
      bytes,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"],
    );
  }
}

async function generateKeyPair(): Promise<[PrivateKey, CryptoKey]> {
  return await PrivateKey.generate();
}

async function dh(privateKey: PrivateKey, publicKey: CryptoKey): Promise<ArrayBuffer> {
  return await privateKey.exchange(publicKey);
}

async function encodeKey(key: CryptoKey): Promise<ArrayBuffer> {
  return await subtle.exportKey("raw", key);
}

function concat(...args: ArrayBuffer[]): ArrayBuffer {
  let len = 0;
  for (const a of args) {
    len += a.byteLength;
  }

  let buf = new Uint8Array(len);
  let offset = 0;
  for (const a of args) {
    const out = new Uint8Array(a);
    buf.set(out, offset);
    offset += out.byteLength;
  }

  return buf.buffer;
}

async function hkdf(km: ArrayBuffer, n: number): Promise<ArrayBuffer> {
  const raw = concat(new ArrayBuffer(32), km);
  const ikm = await subtle.importKey("raw", raw, "HKDF", false, ["deriveBits"]);

  return await subtle.deriveBits(
    {
      name: "HKDF",
      salt: new ArrayBuffer(32),
      info: new TextEncoder().encode(`MyProtocol key${n + 1}`),
      hash: "SHA-256",
    },
    ikm,
    256,
  );
}

async function encrypt(key: ArrayBuffer, plaintext: string, ad: ArrayBuffer): Promise<[ArrayBuffer, ArrayBuffer]> {
  const cipher = new AES256GCM();
  return await cipher.encrypt(key, new TextEncoder().encode(plaintext), ad);
}

async function decrypt(key: ArrayBuffer, ciphertext: ArrayBuffer, ad: ArrayBuffer, iv: ArrayBuffer): Promise<String> {
  const cipher = new AES256GCM();
  return new TextDecoder().decode(
    await cipher.decrypt(key, ciphertext, ad, iv),
  );
}

class Person {
  #ik?: PrivateKey;
  #ik_pub?: CryptoKey;
  #spk?: PrivateKey;
  #spk_pub?: CryptoKey;
  #_sk?: SigningKey;
  #sk_pub?: VerifyKey;
  #spk_signature?: ArrayBuffer;
  #opk_set?: PrivateKey[];
  #opk_pub_set?: CryptoKey[];
  #sk?: ArrayBuffer;
  #ad?: ArrayBuffer;

  constructor() {
  }

  async initKeys() {
    [this.#ik, this.#ik_pub] = await generateKeyPair();
    [this.#spk, this.#spk_pub] = await generateKeyPair();

    [this.#_sk, this.#sk_pub] = await SigningKey.generate();
    this.#spk_signature = await this.#_sk.sign(await encodeKey(this.#spk_pub));

    const [opk, opk_pub] = await generateKeyPair();
    this.#opk_set = [opk];
    this.#opk_pub_set = [opk_pub];
  }

  prekeyBundle(): PrekeyBundle {
    return {
      ik_pub: this.#ik_pub,
      sk_pub: this.#sk_pub,
      spk_pub: this.#spk_pub,
      spk_signature: this.#spk_signature,
      opk_pub_set: this.#opk_pub_set,
    };
  }

  async initX3DHInitiator(bundle: PrekeyBundle) {
    // This value will be used for sending and receiving messages after X3DH.
    this.#spk_pub = bundle.spk_pub;

    await bundle.sk_pub.verify(bundle.spk_signature, await encodeKey(bundle.spk_pub));

    const [ek, ek_pub] = await generateKeyPair();

    assertExists(this.#ik);
    assertExists(this.#spk_pub);
    assertExists(bundle.ik_pub);
    assertExists(this.#ik_pub);
    const dh1 = await dh(this.#ik, this.#spk_pub);
    const dh2 = await dh(ek, bundle.ik_pub);
    const dh3 = await dh(ek, this.#spk_pub);
    const dh4 = await dh(ek, bundle.opk_pub);
    this.#sk = await hkdf(concat(dh1, dh2, dh3, dh4), 0);
    this.#ad = concat(await encodeKey(this.#ik_pub), await encodeKey(bundle.ik_pub));

    const [ciphertext, nonce] = await encrypt(this.#sk, "Initial message", this.#ad);

    return {
      ik_pub: this.#ik_pub,
      ek_pub: ek_pub,
      opk_id: bundle.opk_id,
      message: ciphertext,
      nonce: nonce,
    };
  }

  async initX3DHResponder(data: X3DHData) {
    assertExists(this.#opk_set);
    const opk = this.#opk_set[data.opk_id];

    assertExists(this.#spk);
    assertExists(this.#ik);
    assertExists(this.#spk);
    assertExists(this.#ik_pub);
    const dh1 = await dh(this.#spk, data.ik_pub);
    const dh2 = await dh(this.#ik, data.ek_pub);
    const dh3 = await dh(this.#spk, data.ek_pub);
    const dh4 = await dh(opk, data.ek_pub);
    this.#sk = await hkdf(concat(dh1, dh2, dh3, dh4), 0);
    this.#ad = concat(await encodeKey(data.ik_pub), await encodeKey(this.#ik_pub));

    return { message: await decrypt(this.#sk, data.message, this.#ad, data.nonce) };
  }

  async sendMessage(msg: string): Promise<[MessageHeader, ArrayBuffer]> {
    assertExists(this.#sk);
    assertExists(this.#ad);
    const [ciphertext, nonce] = await encrypt(this.#sk, msg, this.#ad);
    return [{ nonce: nonce }, ciphertext];
  }

  async receiveMessage(header: MessageHeader, ciphertext: ArrayBuffer) {
    assertExists(this.#sk);
    assertExists(this.#ad);
    return await decrypt(this.#sk, ciphertext, this.#ad, header.nonce);
  }
}

class Server {
  // Practically, Base64 encoding conversion must be applied to the data.

  #bundle?: PrekeyBundle;

  upload(bundle: PrekeyBundle) {
    this.#bundle = bundle;
  }

  download() {
    assertExists(this.#bundle);
    return {
      ik_pub: this.#bundle.ik_pub,
      sk_pub: this.#bundle.sk_pub,
      spk_pub: this.#bundle.spk_pub,
      spk_signature: this.#bundle.spk_signature,
      opk_id: 0,
      opk_pub: this.#bundle.opk_pub_set[0],
    };
  }
}

async function main() {
  const server = new Server();
  const alice = new Person();
  const bob = new Person();

  await alice.initKeys();
  await bob.initKeys();

  server.upload(bob.prekeyBundle());
  const prekeyBundle = server.download();

  const x3dhData: X3DHData = await alice.initX3DHInitiator(prekeyBundle);
  await bob.initX3DHResponder(x3dhData);

  const a1 = await alice.sendMessage("a1");
  console.log(await bob.receiveMessage(...a1));
  const b1 = await bob.sendMessage("b1");
  console.log(await bob.receiveMessage(...b1));

  const a2 = await alice.sendMessage("a2");
  console.log(await bob.receiveMessage(...a2));
  const b2 = await bob.sendMessage("b2");
  console.log(await bob.receiveMessage(...b2));
}

if (typeof window === "undefined") {
  // Run it in Deno.
  (async function () {
    await main();
  })();
}
