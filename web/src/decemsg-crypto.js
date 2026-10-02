import {
  DeviceId,
  OlmMachine,
  RoomId,
  StoreHandle,
  UserId,
  initAsync,
} from "../vendor/matrix-sdk-crypto-wasm/index.mjs";

const CRYPTO_STORE_PREFIX = "decemsg-e2ee-v1";

export class DeceMSGCrypto {
  #machine = null;
  #store = null;
  #roomLocks = new Map();

  async initialize(userId, deviceId, storePassphrase) {
    await initAsync();

    const matrixUserId = new UserId(userId);
    const matrixDeviceId = new DeviceId(deviceId);
    const storeName = CRYPTO_STORE_PREFIX + "-" + deviceId;

    this.#store = await StoreHandle.open(storeName, storePassphrase);
    this.#machine = await OlmMachine.initFromStore(
      matrixUserId,
      matrixDeviceId,
      this.#store,
    );

    return {
      userId: this.#machine.userId.toString(),
      deviceId: this.#machine.deviceId.toString(),
    };
  }

  get isInitialized() {
    return this.#machine !== null;
  }

  get identityKeys() {
    if (!this.#machine) throw new Error("DeceMSG crypto is not initialized");
    return this.#machine.identityKeys;
  }

  async close() {
    this.#machine?.close();
    this.#machine = null;
    this.#store?.free();
    this.#store = null;
  }

  async encryptEvent(roomId, eventType, content) {
    const machine = this.#requireMachine();
    const matrixRoomId = new RoomId(roomId);
    return this.#withRoomLock(roomId, async () =>
      machine.encryptRoomEvent(
        matrixRoomId,
        eventType,
        JSON.stringify(content),
      )
    );
  }

  async decryptEvent(roomId, encryptedEvent, decryptionSettings) {
    const matrixRoomId = new RoomId(roomId);
    return this.#requireMachine().decryptRoomEvent(
      encryptedEvent,
      matrixRoomId,
      decryptionSettings,
    );
  }

  async outgoingRequests() {
    return this.#requireMachine().outgoingRequests();
  }

  async markRequestAsSent(requestId, requestType, response) {
    return this.#requireMachine().markRequestAsSent(
      requestId,
      requestType,
      response,
    );
  }

  async receiveToDeviceEvents(events, changedUsers = []) {
    const machine = this.#requireMachine();
    const payload = JSON.stringify(
      events.map((event) => ({
        type: event.event_type,
        sender: event.sender_user_id,
        content:
          typeof event.content === "string"
            ? JSON.parse(event.content)
            : event.content,
      })),
    );
    return machine.receiveSyncChanges(
      payload,
      { changed: changedUsers, left: [] },
      new Map(),
    );
  }

  #requireMachine() {
    if (!this.#machine) throw new Error("DeceMSG crypto is not initialized");
    return this.#machine;
  }

  async #withRoomLock(roomId, operation) {
    const previous = this.#roomLocks.get(roomId) ?? Promise.resolve();
    const current = previous.then(operation, operation);
    this.#roomLocks.set(roomId, current);
    try {
      return await current;
    } finally {
      if (this.#roomLocks.get(roomId) === current) {
        this.#roomLocks.delete(roomId);
      }
    }
  }
}
