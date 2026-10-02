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
const bobSecondDevice = new DeviceId("BOB_DEVICE_2");

const charlieUser = new UserId("@charlie:example.com");
const charlieDevice = new DeviceId("CHARLIE_DEVICE");

const alice = await OlmMachine.initialize(aliceUser, aliceDevice);
const bob = await OlmMachine.initialize(bobUser, bobDevice);
const bobSecond = await OlmMachine.initialize(bobUser, bobSecondDevice);
const charlie = await OlmMachine.initialize(charlieUser, charlieDevice);

const bobRequests = await bob.outgoingRequests();
const bobUpload = bobRequests.find((request) => request instanceof KeysUploadRequest);
if (!bobUpload) throw new Error("Bob did not produce a keys upload request");
const bobUploadBody = JSON.parse(bobUpload.body);
await bob.markRequestAsSent(
  bobUpload.id,
  bobUpload.type,
  JSON.stringify({
    one_time_key_counts: {
      signed_curve25519: Object.keys(bobUploadBody.one_time_keys).length,
    },
  }),
);

const bobSecondRequests = await bobSecond.outgoingRequests();
const bobSecondUpload = bobSecondRequests.find((request) => request instanceof KeysUploadRequest);
if (!bobSecondUpload) throw new Error("Bob's second device did not produce a keys upload request");
const bobSecondUploadBody = JSON.parse(bobSecondUpload.body);
await bobSecond.markRequestAsSent(
  bobSecondUpload.id,
  bobSecondUpload.type,
  JSON.stringify({
    one_time_key_counts: {
      signed_curve25519: Object.keys(bobSecondUploadBody.one_time_keys).length,
    },
  }),
);

await alice.markRequestAsSent(
  "alice-key-query",
  RequestType.KeysQuery,
  JSON.stringify({
    device_keys: {
      "@bob:example.com": {
        BOB_DEVICE: bobUploadBody.device_keys,
        BOB_DEVICE_2: bobSecondUploadBody.device_keys,
        CHARLIE_DEVICE: charlieUploadBody.device_keys,
      },
    },
    failures: {},
  }),
);

const claimRequest = await alice.getMissingSessions([new UserId("@bob:example.com")]);
if (!claimRequest) throw new Error("Alice did not request a Bob session");

const claimBody = JSON.parse(claimRequest.body);
const oneTimeKeys = {};
for (const [deviceId, algorithms] of Object.entries(
  claimBody.one_time_keys["@bob:example.com"],
)) {
  const source = deviceId === "BOB_DEVICE" ? bobUploadBody : bobSecondUploadBody;
  const requestedAlgorithm = String(algorithms);
  const matching = Object.entries(source.one_time_keys).find(([name]) =>
    name.startsWith(requestedAlgorithm + ":"),
  );
  if (!matching) throw new Error("Missing one-time key for " + deviceId);
  oneTimeKeys[deviceId] = { [matching[0]]: matching[1] };
}

await alice.markRequestAsSent(
  claimRequest.id,
  claimRequest.type,
  JSON.stringify({
    one_time_keys: {
      "@bob:example.com": oneTimeKeys,
    },
    failures: {},
  }),
);

const charlieRequests = await charlie.outgoingRequests();
const charlieUpload = charlieRequests.find((request) => request instanceof KeysUploadRequest);
if (!charlieUpload) throw new Error("Charlie's device did not produce a keys upload request");
const charlieUploadBody = JSON.parse(charlieUpload.body);
await charlie.markRequestAsSent(
  charlieUpload.id,
  charlieUpload.type,
  JSON.stringify({
    one_time_key_counts: {
      signed_curve25519: Object.keys(charlieUploadBody.one_time_keys).length,
    },
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

for (const machine of [alice, bob, bobSecond]) {
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
  for (const [deviceId, machine] of [
    ["BOB_DEVICE", bob],
    ["BOB_DEVICE_2", bobSecond],
    ["CHARLIE_DEVICE", charlie],
  ]) {
    const rawContent = body.messages["@bob:example.com"][deviceId];
    if (!rawContent) throw new Error("Room-key share did not target " + deviceId);
    const content = typeof rawContent === "string" ? JSON.parse(rawContent) : rawContent;
    const toDeviceEvent = {
      sender: "@alice:example.com",
      type: String(request.event_type),
      content,
    };
    const processed = await machine.receiveSyncChanges(
      JSON.stringify([toDeviceEvent]),
      new DeviceLists(),
      new Map(),
    );
    if (
      processed.length !== 1 ||
      processed[0].type !== ProcessedToDeviceEventType.Decrypted
    ) {
      throw new Error(deviceId + " did not decrypt the room-key to-device event");
    }
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

for (const [deviceId, machine] of [
  ["BOB_DEVICE", bob],
  ["BOB_DEVICE_2", bobSecond],
]) {
  const decrypted = await machine.decryptRoomEvent(
    encryptedEvent,
    room,
    new DecryptionSettings(),
  );
  const clearEvent = JSON.parse(decrypted.event);
  if (clearEvent.content?.body !== "DeceMSG E2EE smoke test") {
    throw new Error(deviceId + " failed to decrypt Alice's ciphertext");
  }
}



const rotatedRoom = new RoomId("!decemsg-smoke-1:example.com");
for (const machine of [alice, bob, bobSecond]) {
  const settings = new RoomSettings();
  settings.algorithm = EncryptionAlgorithm.MegolmV1AesSha2;
  settings.onlyAllowTrustedDevices = false;
  await machine.setRoomSettings(rotatedRoom, settings);
}

const rotatedKeyRequests = await alice.shareRoomKey(
  rotatedRoom,
  [new UserId("@bob:example.com")],
  new EncryptionSettings(),
);

for (const request of rotatedKeyRequests) {
  const body = JSON.parse(request.body);
  for (const [deviceId, machine] of [
    ["BOB_DEVICE", bob],
    ["BOB_DEVICE_2", bobSecond],
  ]) {
    const rawContent = body.messages["@bob:example.com"][deviceId];
    if (!rawContent) throw new Error("Rotated room key did not target " + deviceId);
    const content = typeof rawContent === "string" ? JSON.parse(rawContent) : rawContent;
    const processed = await machine.receiveSyncChanges(
      JSON.stringify([{
        sender: "@alice:example.com",
        type: String(request.event_type),
        content,
      }]),
      new DeviceLists(),
      new Map(),
    );
    if (
      processed.length !== 1 ||
      processed[0].type !== ProcessedToDeviceEventType.Decrypted
    ) {
      throw new Error(deviceId + " did not decrypt the rotated room-key event");
    }
  }
}

const rotatedEncryptedContent = await alice.encryptRoomEvent(
  rotatedRoom,
  "m.room.message",
  JSON.stringify({ msgtype: "m.text", body: "Rotated E2EE message" }),
);
const rotatedEncryptedEvent = JSON.stringify({
  type: "m.room.encrypted",
  event_id: "$rotated:example.com",
  origin_server_ts: Date.now(),
  sender: "@alice:example.com",
  content: JSON.parse(rotatedEncryptedContent),
  unsigned: { age: 0 },
});

for (const [deviceId, machine] of [
  ["BOB_DEVICE", bob],
  ["BOB_DEVICE_2", bobSecond],
]) {
  const decrypted = await machine.decryptRoomEvent(
    rotatedEncryptedEvent,
    rotatedRoom,
    new DecryptionSettings(),
  );
  const clearEvent = JSON.parse(decrypted.event);
  if (clearEvent.content?.body !== "Rotated E2EE message") {
    throw new Error(deviceId + " failed to decrypt the rotated ciphertext");
  }
}

try {
  await charlie.decryptRoomEvent(
    rotatedEncryptedEvent,
    rotatedRoom,
    new DecryptionSettings(),
  );
  throw new Error("Revoked Charlie device decrypted ciphertext from the rotated room epoch");
} catch (error) {
  if (error?.code === undefined) throw error;
}

console.log("Alice encrypted, two authorized Bob devices decrypted, and a revoked device was excluded after room-key rotation.");
