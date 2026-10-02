import {
  DeviceId,
  DecryptionSettings,
  DeviceLists,
  EncryptionAlgorithm,
  EncryptionSettings,
  KeysUploadRequest,
  OlmMachine,
  ToDeviceRequest,
  RoomId,
  RoomSettings,
  ProcessedToDeviceEventType,
  RequestType,
  UserId,
  initAsync,
} from "@matrix-org/matrix-sdk-crypto-wasm";

await initAsync();

const aliceUser = new UserId("@alice:example.com");
const bobUser = new UserId("@bob:example.com");
const aliceDevice = new DeviceId("ALICE_DEVICE");
const bobDevice = new DeviceId("BOB_DEVICE");

const charlieUser = new UserId("@charlie:example.com");
const charlieDevice = new DeviceId("CHARLIE_DEVICE");

const alice = await OlmMachine.initialize(aliceUser, aliceDevice);
const bob = await OlmMachine.initialize(bobUser, bobDevice);
const charlie = await OlmMachine.initialize(charlieUser, charlieDevice);

const bobRequests = await bob.outgoingRequests();
const bobUpload = bobRequests.find((request) => request instanceof KeysUploadRequest);
if (!bobUpload) throw new Error("Bob did not produce a keys upload request");

const bobUploadBody = JSON.parse(bobUpload.body);
const bobOneTimeEntries = Object.entries(bobUploadBody.one_time_keys);
await bob.markRequestAsSent(
  bobUpload.id,
  bobUpload.type,
  JSON.stringify({
    one_time_key_counts: { signed_curve25519: bobOneTimeEntries.length },
  }),
);

await alice.markRequestAsSent(
  "alice-key-query",
  RequestType.KeysQuery,
  JSON.stringify({
    device_keys: {
      "@bob:example.com": {
        BOB_DEVICE: bobUploadBody.device_keys,
      },
    },
    failures: {},
  }),
);

const claimRequest = await alice.getMissingSessions([bobUser]);
if (!claimRequest) throw new Error("Alice did not request a Bob session");

const [bobOneTimeId, bobOneTimeKey] = bobOneTimeEntries[0];
await alice.markRequestAsSent(
  claimRequest.id,
  claimRequest.type,
  JSON.stringify({
    one_time_keys: {
      "@bob:example.com": {
        BOB_DEVICE: {
          [bobOneTimeId]: bobOneTimeKey,
        },
      },
    },
    failures: {},
  }),
);

const aliceRequests = await alice.outgoingRequests();
const aliceUpload = aliceRequests.find((request) => request instanceof KeysUploadRequest);
if (!aliceUpload) throw new Error("Alice did not produce a keys upload request");

const aliceUploadBody = JSON.parse(aliceUpload.body);
await bob.markRequestAsSent(
  "bob-key-query",
  RequestType.KeysQuery,
  JSON.stringify({
    device_keys: {
      "@alice:example.com": {
        ALICE_DEVICE: aliceUploadBody.device_keys,
      },
    },
    failures: {},
  }),
);

const room = new RoomId("!decemsg-smoke:example.com");

for (const machine of [alice, bob]) {
  const settings = new RoomSettings();
  settings.algorithm = EncryptionAlgorithm.MegolmV1AesSha2;
  settings.onlyAllowTrustedDevices = false;
  await machine.setRoomSettings(room, settings);
}

const keyShareRequests = await alice.shareRoomKey(
  room,
  [new UserId("@bob:example.com")],
  new EncryptionSettings(),
);

if (keyShareRequests.length === 0) {
  throw new Error("Alice did not produce a room-key share request");
}

for (const request of keyShareRequests) {
  if (!(request instanceof ToDeviceRequest)) {
    throw new Error("Unexpected room-key request type");
  }
  const body = JSON.parse(request.body);
  const rawContent = body.messages["@bob:example.com"]["BOB_DEVICE"];
  if (!rawContent) throw new Error("Room-key share did not target Bob");
  const content = typeof rawContent === "string" ? JSON.parse(rawContent) : rawContent;

  const toDeviceEvent = {
    sender: "@alice:example.com",
    type: String(request.event_type),
    content,
  };
  const processed = await bob.receiveSyncChanges(
    JSON.stringify([toDeviceEvent]),
    new DeviceLists(),
    new Map(),
  );
  if (processed.length !== 1 || processed[0].type !== ProcessedToDeviceEventType.Decrypted) {
    throw new Error("Bob did not decrypt the room-key to-device event");
  }
}

const encryptedContent = await alice.encryptRoomEvent(
  room,
  "m.room.message",
  JSON.stringify({ msgtype: "m.text", body: "DeceMSG E2EE smoke test" }),
);

const encryptedEvent = JSON.stringify({
  type: "m.room.encrypted",
  event_id: "$smoke:example.com",
  origin_server_ts: Date.now(),
  sender: "@alice:example.com",
  content: JSON.parse(encryptedContent),
  unsigned: { age: 0 },
});

const decrypted = await bob.decryptRoomEvent(
  encryptedEvent,
  room,
  new DecryptionSettings(),
);

const clearEvent = JSON.parse(decrypted.event);
if (clearEvent.content?.body !== "DeceMSG E2EE smoke test") {
  throw new Error("Bob failed to decrypt Alice's ciphertext");
}



try {
  await charlie.decryptRoomEvent(
    encryptedEvent,
    room,
    new DecryptionSettings(),
  );
  throw new Error("Unauthorized Charlie device decrypted Alice's ciphertext");
} catch (error) {
  if (error?.code === undefined) throw error;
}

const tampered = JSON.parse(encryptedEvent);
tampered.content.ciphertext = Object.fromEntries(
  Object.entries(tampered.content.ciphertext).map(([key, value]) => [
    key,
    { ...value, body: value.body.slice(0, -2) + "AA" },
  ]),
);

try {
  await bob.decryptRoomEvent(
    JSON.stringify(tampered),
    room,
    new DecryptionSettings(),
  );
  throw new Error("Tampered ciphertext was accepted");
} catch (error) {
  if (error?.code === undefined) throw error;
}

console.log("DeceMSG E2EE smoke test passed: Alice encrypted, Bob decrypted, and no server-side plaintext step was used.");
