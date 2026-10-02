import {
  DeviceId,
  DeviceLists,
  EncryptionAlgorithm,
  EncryptionSettings,
  KeysClaimRequest,
  KeysQueryRequest,
  KeysUploadRequest,
  OlmMachine,
  RequestType,
  RoomId,
  RoomSettings,
  UserId,
  initAsync,
} from "@matrix-org/matrix-sdk-crypto-wasm";

await initAsync();

const aliceUser = new UserId("@alice:example.com");
const bobUser = new UserId("@bob:example.com");
const aliceDevice = new DeviceId("ALICE_DEVICE");
const bobDevice = new DeviceId("BOB_DEVICE");

const alice = await OlmMachine.initialize(aliceUser, aliceDevice);
const bob = await OlmMachine.initialize(bobUser, bobDevice);

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

const [bobOneTimeId, bobOneTimeKey] = bobOneTimeEntries[0];
await alice.markRequestAsSent(
  "alice-key-claim",
  RequestType.KeysClaim,
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
  [bobUser],
  new EncryptionSettings(),
);

if (keyShareRequests.length === 0) {
  throw new Error("Alice did not produce a room-key share request");
}

for (const request of keyShareRequests) {
  if (!(request instanceof (await import("@matrix-org/matrix-sdk-crypto-wasm")).ToDeviceRequest)) {
    throw new Error("Unexpected room-key request type");
  }
  const body = JSON.parse(request.body);
  const content = body.messages["@bob:example.com"]["BOB_DEVICE"];
  if (!content) throw new Error("Room-key share did not target Bob");

  await bob.receiveSyncChanges(
    JSON.stringify([
      {
        sender: "@alice:example.com",
        type: request.eventType,
        content,
      },
    ]),
    new DeviceLists(),
    new Map(),
  );
}

const encryptedContent = await alice.encryptRoomEvent(
  room,
  "m.room.message",
  JSON.stringify({ msgtype: "m.text", body: "DeceMSG E2EE smoke test" }),
);

const encryptedEvent = JSON.stringify({
  type: "m.room.encrypted",
  sender: "@alice:example.com",
  content: JSON.parse(encryptedContent),
});

const decrypted = await bob.decryptRoomEvent(
  encryptedEvent,
  room,
  new (await import("@matrix-org/matrix-sdk-crypto-wasm")).DecryptionSettings(),
);

const clearEvent = JSON.parse(decrypted.clearEvent);
if (clearEvent.content?.body !== "DeceMSG E2EE smoke test") {
  throw new Error("Bob failed to decrypt Alice's ciphertext");
}

console.log("DeceMSG E2EE smoke test passed: Alice encrypted, Bob decrypted, and no server-side plaintext step was used.");
