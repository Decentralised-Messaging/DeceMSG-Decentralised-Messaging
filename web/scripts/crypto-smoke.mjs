import {
  DeviceId,
  DecryptionSettings,
  DeviceLists,
  EncryptionAlgorithm,
  EncryptionSettings,
  KeysClaimRequest,
  KeysQueryRequest,
  KeysUploadRequest,
  OlmMachine,
  RequestType,
  ToDeviceRequest,
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
  console.log("to-device event:", JSON.stringify(toDeviceEvent));
  const processed = await bob.receiveSyncChanges(
    JSON.stringify([toDeviceEvent]),
    new DeviceLists(),
    new Map(),
  );
  console.log("processed room-key events:", processed.map((item) => item.type));
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

let decrypted;
try {
  decrypted = await bob.decryptRoomEvent(
    encryptedEvent,
    room,
    new DecryptionSettings(),
  );
} catch (error) {
  console.error("room decrypt failed:", error?.name, error?.message, error?.code);
  throw error;
}

const clearEvent = JSON.parse(decrypted.clearEvent);
if (clearEvent.content?.body !== "DeceMSG E2EE smoke test") {
  throw new Error("Bob failed to decrypt Alice's ciphertext");
}

console.log("DeceMSG E2EE smoke test passed: Alice encrypted, Bob decrypted, and no server-side plaintext step was used.");
