import {
  DecryptionSettings,
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
  StoreHandle,
  ToDeviceRequest,
  UserId,
  initAsync,
} from "../vendor/matrix-sdk-crypto-wasm/index.mjs";

const CRYPTO_STORE_PREFIX = "decemsg-e2ee-v1";

function requestDescriptor(request) {
  if (request instanceof KeysUploadRequest) {
    return { requestType: "keys_upload", eventType: null };
  }
  if (request instanceof KeysQueryRequest) {
    return { requestType: "keys_query", eventType: null };
  }
  if (request instanceof KeysClaimRequest) {
    return { requestType: "keys_claim", eventType: null };
  }
  if (request instanceof ToDeviceRequest) {
    return {
      requestType: "to_device",
      eventType: request.event_type,
    };
  }
  throw new Error("Unsupported crypto request type: " + request.type);
}

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

  async initializeRoom(roomIdText) {
    const roomId = new RoomId(roomIdText);
    const settings = new RoomSettings();
    settings.algorithm = EncryptionAlgorithm.MegolmV1AesSha2;
    settings.onlyAllowTrustedDevices = false;
    await this.#machine.setRoomSettings(roomId, settings);
    return roomId;
  }

  async ensureRecipientSessions(chatId, roomIdText, recipientUserIds, sendRequest) {
    const roomId = await this.initializeRoom(roomIdText);
    const recipients = recipientUserIds.map((userId) => new UserId(userId));

    await this.#machine.updateTrackedUsers(recipients);
    await this.flushRequests(chatId, sendRequest);

    const missing = await this.#machine.getMissingSessions(recipients);
    if (missing) {
      await this.#sendRequest(chatId, missing, sendRequest);
    }

    const shareRequests = await this.#machine.shareRoomKey(
      roomId,
      recipients,
      new EncryptionSettings(),
    );
    for (const request of shareRequests) {
      await this.#sendRequest(chatId, request, sendRequest);
    }

    return roomId;
  }

  async encryptText(chatId, roomIdText, recipientUserIds, plaintext, sendRequest) {
    const recipients = Array.isArray(recipientUserIds)
      ? recipientUserIds
      : [recipientUserIds];
    const roomId = await this.ensureRecipientSessions(
      chatId,
      roomIdText,
      recipients,
      sendRequest,
    );
    const event = await this.#machine.encryptRoomEvent(
      roomId,
      "m.room.message",
      JSON.stringify({
        msgtype: "m.text",
        body: plaintext,
      }),
    );
    return event;
  }

  async decryptMessage(roomIdText, encryptedEvent) {
    const roomId = new RoomId(roomIdText);
    const decrypted = await this.#machine.decryptRoomEvent(
      encryptedEvent,
      roomId,
      new DecryptionSettings(),
    );
    return JSON.parse(decrypted.event);
  }

  async flushRequests(chatId, sendRequest) {
    const requests = await this.#machine.outgoingRequests();
    for (const request of requests) {
      if (
        !chatId &&
        (request instanceof KeysQueryRequest ||
          request instanceof KeysClaimRequest ||
          request instanceof ToDeviceRequest)
      ) {
        continue;
      }
      await this.#sendRequest(chatId, request, sendRequest);
    }
  }

  async receiveToDeviceEvents(events, sendRequest) {
    const payload = JSON.stringify(
      events.map((event) => ({
        sender: event.sender,
        type: event.event_type,
        content:
          typeof event.content === "string"
            ? JSON.parse(event.content)
            : event.content,
      })),
    );

    const changedDevices = new DeviceLists();
    const processed = await this.#machine.receiveSyncChanges(
      payload,
      changedDevices,
      new Map(),
    );

    return processed;
  }

  async sign(message) {
    if (!this.#machine) {
      throw new Error("DeceMSG crypto is not initialized");
    }
    return this.#machine.sign(message);
  }

  async close() {
    this.#machine?.close();
    this.#machine = null;
    this.#store?.free();
    this.#store = null;
  }

  async #sendRequest(chatId, request, sendRequest) {
    const descriptor = requestDescriptor(request);
    const response = await sendRequest({
      request_type: descriptor.requestType,
      request_id: request.id,
      body: JSON.parse(request.body),
      event_type: descriptor.eventType,
      chat_id: chatId,
    });

    await this.#machine.markRequestAsSent(
      request.id,
      request.type,
      JSON.stringify(response),
    );
    return response;
  }
}

if (typeof window !== "undefined") {
  window.DeceMSGCrypto = DeceMSGCrypto;
}
