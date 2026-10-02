class BrowserCryptoStore {
    constructor() {
        this.dbName = 'decemsg-crypto';
        this.storeName = 'device';
        this.keyId = 'primary-device';
    }

    open() {
        return new Promise((resolve, reject) => {
            const request = indexedDB.open(this.dbName, 1);
            request.onupgradeneeded = () => {
                const db = request.result;
                if (!db.objectStoreNames.contains(this.storeName)) {
                    db.createObjectStore(this.storeName, { keyPath: 'id' });
                }
            };
            request.onsuccess = () => resolve(request.result);
            request.onerror = () => reject(request.error);
        });
    }

    async getDevice() {
        const db = await this.open();
        return new Promise((resolve, reject) => {
            const request = db.transaction(this.storeName, 'readonly')
                .objectStore(this.storeName)
                .get(this.keyId);
            request.onsuccess = () => resolve(request.result || null);
            request.onerror = () => reject(request.error);
        });
    }

    async saveDevice(device) {
        const db = await this.open();
        return new Promise((resolve, reject) => {
            const request = db.transaction(this.storeName, 'readwrite')
                .objectStore(this.storeName)
                .put({ ...device, id: this.keyId });
            request.onsuccess = () => resolve();
            request.onerror = () => reject(request.error);
        });
    }

    async clearDevice() {
        const db = await this.open();
        return new Promise((resolve, reject) => {
            const request = db.transaction(this.storeName, 'readwrite')
                .objectStore(this.storeName)
                .delete(this.keyId);
            request.onsuccess = () => resolve();
            request.onerror = () => reject(request.error);
        });
    }

    async createDeviceKey() {
        if (!window.crypto?.subtle) {
            throw new Error('Web Crypto API is required for device security');
        }

        const keyPair = await window.crypto.subtle.generateKey(
            {
                name: 'ECDSA',
                namedCurve: 'P-256'
            },
            false,
            ['sign', 'verify']
        );

        const publicKey = await window.crypto.subtle.exportKey(
            'spki',
            keyPair.publicKey
        );

        const bytes = new Uint8Array(publicKey);
        let binary = '';
        bytes.forEach(byte => { binary += String.fromCharCode(byte); });

        return {
            keyPair,
            publicIdentityKey: btoa(binary)
        };
    }

    async ensureDevice(enroll) {
        let device = await this.getDevice();
        if (device?.deviceId && device.privateKey) {
            return device;
        }

        const generated = await this.createDeviceKey();
        const registered = await enroll(generated.publicIdentityKey);

        const storeKeyBytes = new Uint8Array(32);
        window.crypto.getRandomValues(storeKeyBytes);
        let storeKeyBinary = '';
        storeKeyBytes.forEach(byte => { storeKeyBinary += String.fromCharCode(byte); });

        device = {
            deviceId: registered.id,
            privateKey: generated.keyPair.privateKey,
            publicKey: generated.keyPair.publicKey,
            cryptoStorePassphrase: btoa(storeKeyBinary),
            createdAt: new Date().toISOString()
        };
        await this.saveDevice(device);
        return device;
    }

    async sign(data) {
        const device = await this.getDevice();
        if (!device?.privateKey) {
            throw new Error('Browser device key is not enrolled');
        }

        const bytes = new TextEncoder().encode(data);
        return window.crypto.subtle.sign(
            {
                name: 'ECDSA',
                hash: 'SHA-256'
            },
            device.privateKey,
            bytes
        );
    }
}

// DeceMSG - Frontend Application - Phase 2

class DeceMSGApp {
    constructor() {
        this.apiBase = '/api';
        this.token = localStorage.getItem('token');
        this.currentUser = null;
        this.chats = [];
        this.currentChat = null;
        this.ws = null;
        this.searchResults = [];
        this.onlineUsers = {};
        this.typingUsers = {};
        this.selectedFile = null;
        this.selectedMessage = null;
        this.pendingMembers = [];
        this.cryptoStore = new BrowserCryptoStore();
        this.device = null;
        this.e2ee = null;
        this.e2eeReady = false;
        
        this.init();
    }

    init() {
        // Initialize PWA
        this.initPWA();
        
        // Check authentication
        if (this.token) {
            this.showMainScreen();
            this.loadCurrentUser();
        } else {
            this.showLoginScreen();
        }
        
        this.bindEvents();
    }

    // PWA Initialization
    initPWA() {
        // Register service worker
        if ('serviceWorker' in navigator) {
            window.addEventListener('load', () => {
                navigator.serviceWorker.register('/ui/sw.js')
                    .then((registration) => {
                        console.log('SW registered:', registration.scope);
                        
                        // Check for updates
                        registration.addEventListener('updatefound', () => {
                            const newWorker = registration.installing;
                            newWorker.addEventListener('statechange', () => {
                                if (newWorker.state === 'installed' && navigator.serviceWorker.controller) {
                                    // New content available
                                    console.log('New content available, refresh to update');
                                }
                            });
                        });
                    })
                    .catch((error) => {
                        console.error('SW registration failed:', error);
                    });
            });
        }
        
        // Request notification permission
        if ('Notification' in window && Notification.permission === 'default') {
            this.requestNotificationPermission();
        }
    }

    async requestNotificationPermission() {
        try {
            const permission = await Notification.requestPermission();
            if (permission === 'granted') {
                console.log('Notification permission granted');
            }
        } catch (error) {
            console.error('Notification permission denied:', error);
        }
    }

    showNotification(title, body, options = {}) {
        if ('Notification' in window && Notification.permission === 'granted') {
            new Notification(title, {
                body,
                icon: '/ui/icon-192.png',
                badge: '/ui/icon-192.png',
                ...options
            });
        }
    }

    bindEvents() {
        // Login form
        document.getElementById('login-form').addEventListener('submit', (e) => {
            e.preventDefault();
            this.handleLogin();
        });

        // Registration form
        document.getElementById('register-form').addEventListener('submit', (e) => {
            e.preventDefault();
            this.handleRegister();
        });

        // Auth form toggles
        document.getElementById('btn-show-register').addEventListener('click', (e) => {
            e.preventDefault();
            this.showRegisterForm();
        });

        document.getElementById('btn-show-login').addEventListener('click', (e) => {
            e.preventDefault();
            this.showLoginForm();
        });

        // New chat button
        document.getElementById('btn-new-chat').addEventListener('click', () => {
            this.showNewChatModal();
        });

        // Settings button
        document.getElementById('btn-settings').addEventListener('click', () => {
            this.toggleAdminPanel();
        });

        // Logout button
        document.getElementById('btn-logout').addEventListener('click', () => {
            this.logout();
        });

        // Send message
        document.getElementById('btn-send').addEventListener('click', () => {
            this.sendMessage();
        });

        document.getElementById('message-input').addEventListener('keypress', (e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                this.sendMessage();
            }
        });

        // Typing indicator
        document.getElementById('message-input').addEventListener('input', () => {
            this.sendTypingIndicator(true);
        });

        // File attachment
        document.getElementById('btn-attach').addEventListener('click', () => {
            document.getElementById('file-input').click();
        });

        document.getElementById('file-input').addEventListener('change', (e) => {
            this.handleFileSelect(e);
        });

        document.getElementById('btn-remove-file').addEventListener('click', () => {
            this.removeSelectedFile();
        });

        // Search chats
        document.getElementById('search-chats').addEventListener('input', (e) => {
            this.filterChats(e.target.value);
        });

        // Modal close buttons
        document.getElementById('btn-close-modal').addEventListener('click', () => {
            this.hideNewChatModal();
        });

        document.getElementById('btn-cancel-chat').addEventListener('click', () => {
            this.hideNewChatModal();
        });

        document.getElementById('btn-start-chat').addEventListener('click', () => {
            this.startNewChat();
        });

        // Chat type toggle
        document.getElementById('btn-direct-chat').addEventListener('click', () => {
            this.setChatType('direct');
        });

        document.getElementById('btn-group-chat').addEventListener('click', () => {
            this.setChatType('group');
        });

        // Admin panel
        document.getElementById('btn-close-admin').addEventListener('click', () => {
            this.toggleAdminPanel();
        });

        // Admin tabs
        document.querySelectorAll('.tab-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                this.switchTab(e.target.dataset.tab);
            });
        });

        // Create user
        document.getElementById('btn-create-user').addEventListener('click', () => {
            this.showCreateUserModal();
        });

        document.getElementById('btn-close-user-modal').addEventListener('click', () => {
            this.hideCreateUserModal();
        });

        document.getElementById('create-user-form').addEventListener('submit', (e) => {
            e.preventDefault();
            this.createUser();
        });

        // Save config
        document.getElementById('btn-save-config').addEventListener('click', () => {
            this.saveConfig();
        });

        // Search users in admin
        document.getElementById('search-users').addEventListener('input', (e) => {
            this.loadUsers(e.target.value);
        });

        // Refresh stats button
        document.getElementById('btn-refresh-stats').addEventListener('click', () => {
            this.loadStats();
        });

        // Refresh logs button
        document.getElementById('btn-refresh-logs').addEventListener('click', () => {
            this.loadLogs();
        });

        // Create backup button
        document.getElementById('btn-create-backup').addEventListener('click', () => {
            this.createBackup();
        });

        // Back button (mobile)
        document.getElementById('btn-back').addEventListener('click', () => {
            document.getElementById('sidebar').classList.remove('hidden');
            document.getElementById('chat-content').classList.add('hidden');
        });

        // Chat info
        document.getElementById('btn-chat-info').addEventListener('click', () => {
            this.toggleChatInfoPanel();
        });

        document.getElementById('btn-close-chat-info').addEventListener('click', () => {
            this.toggleChatInfoPanel();
        });

        // Keep history toggle
        document.getElementById('keep-history-toggle').addEventListener('change', (e) => {
            this.updateChatSetting('keep_history', e.target.checked);
        });

        // Leave group
        document.getElementById('btn-leave-group').addEventListener('click', () => {
            this.leaveGroup();
        });

        // Reaction picker
        document.querySelectorAll('.reaction-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                this.addReaction(e.target.dataset.emoji);
            });
        });

        // Close reaction picker on click outside
        document.addEventListener('click', (e) => {
            if (!e.target.closest('.reaction-picker') && !e.target.closest('.message')) {
                this.hideReactionPicker();
            }
        });

        // Add member to group
        document.getElementById('btn-add-member').addEventListener('click', () => {
            this.showAddMemberModal();
        });

        document.getElementById('btn-close-add-member').addEventListener('click', () => {
            this.hideAddMemberModal();
        });

        document.getElementById('btn-search-member').addEventListener('click', () => {
            this.searchMember();
        });
    }

    // API Helpers
    async apiCall(endpoint, method = 'GET', body = null) {
        const headers = {
            'Content-Type': 'application/json'
        };
        
        if (this.token) {
            headers['Authorization'] = `Bearer ${this.token}`;
        }

        const options = { method, headers };
        
        if (body && method !== 'GET') {
            options.body = JSON.stringify(body);
        }

        const response = await fetch(`${this.apiBase}${endpoint}`, options);
        
        if (response.status === 401) {
            this.logout();
            throw new Error('Unauthorized');
        }

        if (response.status === 204) {
            return null;
        }

        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.detail || 'API Error');
        }

        return data;
    }

    // Device management contract
    async listDevices() {
        return this.apiCall('/auth/devices');
    }

    async enrollDevice(name, platform, publicIdentityKey) {
        return this.apiCall('/auth/devices', 'POST', {
            name,
            platform,
            public_identity_key: publicIdentityKey
        });
    }

    async revokeDevice(deviceId) {
        return this.apiCall(`/auth/devices/${deviceId}`, 'DELETE');
    }

    // Authentication
    async handleLogin() {
        const username = document.getElementById('login-username').value;
        const password = document.getElementById('login-password').value;
        const errorEl = document.getElementById('login-error');

        try {
            const formData = new URLSearchParams();
            formData.append('username', username);
            formData.append('password', password);

            const existingDevice = await this.cryptoStore.getDevice();
            const headers = {
                'Content-Type': 'application/x-www-form-urlencoded'
            };
            if (existingDevice?.deviceId) {
                headers['X-Device-ID'] = existingDevice.deviceId;
            }

            const response = await fetch(`${this.apiBase}/auth/login`, {
                method: 'POST',
                headers,
                body: formData
            });

            const data = await response.json();
            if (!response.ok) {
                throw new Error(data.detail || 'Login failed');
            }

            this.token = data.access_token;
            localStorage.setItem('token', this.token);

            this.device = await this.cryptoStore.ensureDevice(
                publicIdentityKey => this.enrollBrowserDevice(publicIdentityKey)
            );
            await this.initializeE2EE();

            await this.loadCurrentUser();
            this.showMainScreen();
            errorEl.classList.add('hidden');
        } catch (error) {
            errorEl.textContent = error.message;
            errorEl.classList.remove('hidden');
        }
    }

    async enrollBrowserDevice(publicIdentityKey) {
        return this.apiCall('/auth/devices', 'POST', {
            name: 'Browser',
            platform: 'web',
            public_identity_key: publicIdentityKey
        });
    }

    async initializeE2EE() {
        if (!this.device?.deviceId || !this.device?.cryptoStorePassphrase) {
            throw new Error('Encrypted device storage is not initialized');
        }
        if (!window.DeceMSGCrypto) {
            throw new Error('E2EE browser crypto bundle is unavailable');
        }

        this.e2ee = new window.DeceMSGCrypto();
        await this.e2ee.initialize(
            '@' + this.currentUser.username + ':' + this.currentUser.domain,
            this.device.deviceId,
            this.device.cryptoStorePassphrase
        );
        await this.e2ee.flushRequests(null, payload => this.sendCryptoRequest(payload));
        this.e2eeReady = true;
        this.startCryptoSync();
    }

    async sendCryptoRequest(payload) {
        return this.apiCall('/crypto/requests', 'POST', payload);
    }

    startCryptoSync() {
        if (this.cryptoSyncTimer) {
            clearInterval(this.cryptoSyncTimer);
        }
        this.cryptoSyncTimer = setInterval(() => {
            this.pollCryptoEvents().catch(error => {
                console.error('E2EE sync failed:', error);
            });
        }, 1500);
        this.pollCryptoEvents().catch(error => {
            console.error('Initial E2EE sync failed:', error);
        });
    }

    async pollCryptoEvents() {
        if (!this.e2eeReady) return;
        const result = await this.apiCall('/crypto/to-device');
        if (!result.events?.length) return;

        await this.e2ee.receiveToDeviceEvents(result.events, payload => this.sendCryptoRequest(payload));
        await this.apiCall('/crypto/to-device/ack', 'POST', result.events.map(event => event.id));
    }

    roomIdForChat(chat) {
        return '!' + chat.id + ':' + this.currentUser.domain;
    }

    async recipientMatrixUserId(chat) {
        const other = chat.members.find(member => member.user_id !== this.currentUser.id);
        if (!other?.user) {
            throw new Error('E2EE currently requires a local direct-chat recipient');
        }
        return '@' + other.user.username + ':' + other.user.domain;
    }

    async handleRegister() {
        const username = document.getElementById('reg-username').value.trim();
        const displayName = document.getElementById('reg-display-name').value.trim();
        const password = document.getElementById('reg-password').value;
        const confirm = document.getElementById('reg-password-confirm').value;
        const errorEl = document.getElementById('register-error');
        const usernamePattern = /^[a-zA-Z0-9_]+$/;

        errorEl.classList.add('hidden');

        if (username.length < 3 || !usernamePattern.test(username)) {
            errorEl.textContent = 'Username must be at least 3 characters and contain only letters, numbers, or underscores.';
            errorEl.classList.remove('hidden');
            return;
        }
        if (!displayName) {
            errorEl.textContent = 'Display name is required.';
            errorEl.classList.remove('hidden');
            return;
        }
        if (password.length < 6) {
            errorEl.textContent = 'Password must be at least 6 characters.';
            errorEl.classList.remove('hidden');
            return;
        }
        if (password !== confirm) {
            errorEl.textContent = 'Passwords do not match.';
            errorEl.classList.remove('hidden');
            return;
        }

        try {
            await this.apiCall('/auth/register', 'POST', {
                username,
                display_name: displayName,
                password
            });

            // Auto-login for a seamless registration flow
            const formData = new URLSearchParams();
            formData.append('username', username);
            formData.append('password', password);

            const response = await fetch(`${this.apiBase}/auth/login`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: formData
            });
            const data = await response.json();
            if (!response.ok) {
                throw new Error(data.detail || 'Login failed after registration');
            }

            this.token = data.access_token;
            localStorage.setItem('token', this.token);
            this.device = await this.cryptoStore.ensureDevice(
                publicIdentityKey => this.enrollBrowserDevice(publicIdentityKey)
            );
            await this.loadCurrentUser();
            this.showMainScreen();
        } catch (error) {
            errorEl.textContent = error.message;
            errorEl.classList.remove('hidden');
        }
    }

    logout() {
        this.token = null;
        localStorage.removeItem('token');
        this.currentUser = null;
        
        if (this.ws) {
            this.ws.close();
            this.ws = null;
        }
        
        this.showLoginScreen();
    }

    async loadCurrentUser() {
        try {
            this.currentUser = await this.apiCall('/auth/me');
            if (!this.device) {
                this.device = await this.cryptoStore.getDevice();
            }
            if (!this.e2eeReady && this.device) {
                await this.initializeE2EE();
            }
            const sidebarName = document.getElementById('sidebar-user-name');
            if (sidebarName) {
                sidebarName.textContent = this.currentUser.display_name;
                document.getElementById('sidebar-user-avatar').textContent = this.getInitials(this.currentUser.display_name);
            }
            this.connectWebSocket();
            this.loadChats();
            
            if (this.currentUser.is_admin) {
                this.loadAdminConfig();
            }
        } catch (error) {
            console.error('Failed to load current user:', error);
            this.logout();
        }
    }

    // Screens
    showLoginScreen() {
        document.getElementById('login-screen').classList.add('active');
        document.getElementById('main-screen').classList.remove('active');
        this.checkPublicRegistration();
    }

    async checkPublicRegistration() {
        const toggle = document.getElementById('register-toggle');
        try {
            const config = await this.apiCall('/auth/config');
            const allowed = config.allow_public_registration;
            toggle.classList.toggle('hidden', !allowed);
            if (!allowed) {
                this.showLoginForm();
            }
        } catch (error) {
            console.error('Failed to check registration config:', error);
            toggle.classList.add('hidden');
        }
    }

    showRegisterForm() {
        document.getElementById('login-form').classList.add('hidden');
        document.getElementById('login-error').classList.add('hidden');
        document.getElementById('register-toggle').classList.add('hidden');
        document.getElementById('register-form').classList.remove('hidden');
        document.getElementById('login-toggle').classList.remove('hidden');
        document.getElementById('register-error').classList.add('hidden');
        document.getElementById('login-username').value = '';
        document.getElementById('login-password').value = '';
    }

    showLoginForm() {
        document.getElementById('register-form').classList.add('hidden');
        document.getElementById('login-toggle').classList.add('hidden');
        document.getElementById('register-error').classList.add('hidden');
        document.getElementById('login-form').classList.remove('hidden');
        const allowed = !document.getElementById('register-toggle').classList.contains('hidden');
        if (allowed) {
            document.getElementById('register-toggle').classList.remove('hidden');
        }
        document.getElementById('reg-password').value = '';
        document.getElementById('reg-password-confirm').value = '';
    }

    showMainScreen() {
        document.getElementById('login-screen').classList.remove('active');
        document.getElementById('main-screen').classList.add('active');
    }

    // WebSocket
    connectWebSocket() {
        if (this.ws) {
            this.ws.close();
        }

        const wsUrl = `${window.location.protocol === "https:" ? "wss:" : "ws:"}//${window.location.host}/ws`;
        
        this.ws = new WebSocket(wsUrl);

        this.ws.onopen = () => {
            // Authenticate as the first WebSocket application frame.
            this.ws.send(JSON.stringify({
                type: 'authenticate',
                token: this.token
            }));
        };

        this.ws.onmessage = (event) => {
            const data = JSON.parse(event.data);
            if (data.type === 'authenticated') {
                console.log('WebSocket authenticated');
                this.chats.forEach(chat => {
                    this.ws.send(JSON.stringify({
                        type: 'join_chat',
                        chat_id: chat.id
                    }));
                });
                return;
            }
            this.handleWebSocketMessage(data);
        };

        this.ws.onclose = () => {
            console.log('WebSocket disconnected');
            // Reconnect after 3 seconds
            setTimeout(() => this.connectWebSocket(), 3000);
        };

        this.ws.onerror = (error) => {
            console.error('WebSocket error:', error);
        };
    }

    handleWebSocketMessage(data) {
        switch (data.type) {
            case 'new_message':
                this.handleNewMessage(data.message, data.chat_id);
                break;
            case 'reaction_update':
                this.updateMessageReactions(data);
                break;
            case 'presence':
                this.updatePresence(data.user_id, data.is_online);
                break;
            case 'typing':
                this.showTypingIndicator(data);
                break;
            case 'read_receipt':
                this.updateReadReceipt(data);
                break;
            case 'push_notification':
                this.showNotification(data.title || 'New Message', data.body);
                break;
        }
    }

    async handleNewMessage(message, chatId) {
        const isCurrentChat = this.currentChat && this.currentChat.id === chatId;
        
        if (isCurrentChat) {
            // Add message to current chat
            await this.appendMessage(message);
            this.scrollToBottom();
            
            // Send read receipt
            this.sendReadReceipt(chatId, message.id);
        } else {
            // Show push notification if not focused
            if (document.hidden) {
                this.showNotification(
                    message.sender?.display_name || 'New Message',
                    message.content || 'Sent you a message'
                );
            }
        }
        
        // Update chat list
        this.loadChats();
    }

    sendTypingIndicator(isTyping) {
        if (this.ws && this.ws.readyState === WebSocket.OPEN && this.currentChat) {
            this.ws.send(JSON.stringify({
                type: 'typing',
                chat_id: this.currentChat.id,
                is_typing: isTyping
            }));
        }
    }

    showTypingIndicator(data) {
        if (this.currentChat && this.currentChat.id === data.chat_id && data.user_id !== this.currentUser?.id) {
            const indicator = document.getElementById('typing-indicator');
            indicator.classList.remove('hidden');
            
            // Hide after 3 seconds
            clearTimeout(this.typingTimeout);
            this.typingTimeout = setTimeout(() => {
                indicator.classList.add('hidden');
            }, 3000);
        }
    }

    // Chats
    async loadChats() {
        try {
            this.chats = await this.apiCall('/chats');
            this.renderChatList();
            
            // Fetch presence for all users
            this.fetchPresence();
        } catch (error) {
            console.error('Failed to load chats:', error);
        }
    }

    async fetchPresence() {
        const allUserIds = new Set();
        this.chats.forEach(chat => {
            chat.members.forEach(m => allUserIds.add(m.user_id));
        });
        
        if (allUserIds.size > 0) {
            try {
                const presence = await this.apiCall(`/presence?user_ids=${Array.from(allUserIds).join(',')}`);
                this.onlineUsers = presence;
                this.updateChatStatuses();
            } catch (error) {
                console.error('Failed to fetch presence:', error);
            }
        }
    }

    updateChatStatuses() {
        document.querySelectorAll('.chat-item').forEach(item => {
            const chatId = item.dataset.chatId;
            const chat = this.chats.find(c => c.id === chatId);
            if (chat && chat.type === 'direct') {
                const otherMember = chat.members.find(m => m.user_id !== this.currentUser?.id);
                if (otherMember) {
                    const isOnline = this.onlineUsers[otherMember.user_id];
                    const presenceEl = item.querySelector('.presence-dot');
                    if (presenceEl) {
                        presenceEl.classList.toggle('online', isOnline);
                    }
                }
            }
        });
    }

    renderChatList() {
        const container = document.getElementById('chat-list');
        container.innerHTML = '';

        this.chats.forEach(chat => {
            const chatEl = this.createChatElement(chat);
            container.appendChild(chatEl);
        });
    }

    createChatElement(chat) {
        const div = document.createElement('div');
        div.className = 'chat-item';
        div.dataset.chatId = chat.id;
        
        // Get chat name and avatar
        let name = chat.name;
        let avatar = '';
        let isOnline = false;
        
        if (chat.type === 'direct') {
            const otherMember = chat.members.find(m => m.user_id !== this.currentUser?.id);
            if (otherMember?.user) {
                name = otherMember.user.display_name || otherMember.user.username;
                avatar = this.getInitials(name);
                isOnline = this.onlineUsers[otherMember.user_id];
            }
        } else {
            avatar = chat.name ? this.getInitials(chat.name) : '?';
        }

        const lastMessage = chat.last_message;
        const preview = lastMessage ? this.truncate(lastMessage.content, 40) : 'No messages yet';

        div.innerHTML = `
            <div class="avatar">${avatar}</div>
            <div class="chat-item-info">
                <div class="chat-item-header">
                    <span class="chat-item-name">${this.escapeHtml(name || 'Unknown')}</span>
                    <span class="chat-item-time">${this.formatTime(lastMessage?.created_at)}</span>
                </div>
                <div class="chat-item-preview">
                    ${this.escapeHtml(preview)}
                    ${chat.unread_count > 0 ? `<span class="unread-badge">${chat.unread_count}</span>` : ''}
                </div>
            </div>
        `;

        div.addEventListener('click', () => this.openChat(chat));

        return div;
    }

    filterChats(query) {
        const items = document.querySelectorAll('.chat-item');
        const lowerQuery = query.toLowerCase();

        items.forEach(item => {
            const name = item.querySelector('.chat-item-name').textContent.toLowerCase();
            item.style.display = name.includes(lowerQuery) ? 'flex' : 'none';
        });
    }

    async openChat(chat) {
        this.currentChat = chat;
        
        // Update UI
        document.querySelectorAll('.chat-item').forEach(el => {
            el.classList.toggle('active', el.dataset.chatId === chat.id);
        });

        // Show chat content
        document.getElementById('no-chat-selected').classList.add('hidden');
        document.getElementById('chat-content').classList.remove('hidden');

        // Update header
        const nameEl = document.getElementById('chat-name');
        const statusEl = document.getElementById('chat-status');
        
        if (chat.type === 'direct') {
            const otherMember = chat.members.find(m => m.user_id !== this.currentUser?.id);
            if (otherMember?.user) {
                nameEl.textContent = otherMember.user.display_name || otherMember.user.username;
                const isOnline = this.onlineUsers[otherMember.user_id];
                statusEl.innerHTML = `<span class="presence-dot ${isOnline ? 'online' : ''}"></span> <span class="status-text">${isOnline ? 'online' : 'offline'}</span>`;
            }
        } else {
            nameEl.textContent = chat.name || 'Group Chat';
            statusEl.innerHTML = `<span class="status-text">${chat.members.length} members</span>`;
        }

        // Load messages
        await this.loadMessages(chat.id);

        // Join WebSocket room
        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
            this.ws.send(JSON.stringify({
                type: 'join_chat',
                chat_id: chat.id
            }));
        }

        // Mobile: hide sidebar
        if (window.innerWidth <= 768) {
            document.getElementById('sidebar').classList.add('hidden');
        }
    }

    async loadMessages(chatId) {
        try {
            const messages = await this.apiCall(`/chats/${chatId}/messages`);
            this.renderMessages(messages);
            this.scrollToBottom();
        } catch (error) {
            console.error('Failed to load messages:', error);
        }
    }

    async renderMessages(messages) {
        const container = document.getElementById('messages-container');
        container.innerHTML = '';

        for (const msg of messages) {
            await this.appendMessage(msg);
        }
    }

    async appendMessage(msg) {
        const container = document.getElementById('messages-container');
        const div = document.createElement('div');
        div.className = `message ${msg.sender_id === this.currentUser?.id ? 'sent' : 'received'}`;
        div.dataset.messageId = msg.id;

        const senderName = msg.sender?.display_name || msg.sender?.username || 'Unknown';
        const isCurrentUser = msg.sender_id === this.currentUser?.id;

        // Build message content
        let contentHtml = '';
        if (msg.message_type === 'image' && msg.file_url) {
            contentHtml = `<img src="${msg.file_url}" class="message-image" onclick="app.previewImage('${msg.file_url}')">`;
        } else if (msg.message_type === 'file' && msg.file_url) {
            const icon = this.getFileIcon(msg.file_name);
            contentHtml = `<a href="${msg.file_url}" class="message-file" target="_blank">
                <span class="file-icon">${icon}</span>
                <div class="file-details">
                    <div class="file-name">${this.escapeHtml(msg.file_name || 'File')}</div>
                    <div class="file-size">${this.formatFileSize(msg.file_size)}</div>
                </div>
            </a>`;
        } else {
            let displayContent = msg.content;
            try {
                const encryptedContent = JSON.parse(msg.content);
                if (
                    this.e2eeReady &&
                    encryptedContent &&
                    encryptedContent.algorithm &&
                    encryptedContent.ciphertext
                ) {
                    const senderMatrixId = isCurrentUser
                        ? '@' + this.currentUser.username + ':' + this.currentUser.domain
                        : '@' + msg.sender.username + ':' + msg.sender.domain;
                    const encryptedEvent = JSON.stringify({
                        type: 'm.room.encrypted',
                        sender: senderMatrixId,
                        content: encryptedContent
                    });
                    const decrypted = await this.e2ee.decryptMessage(
                        this.roomIdForChat(this.currentChat),
                        encryptedEvent
                    );
                    displayContent = decrypted.body || decrypted.content?.body || '[Encrypted message]';
                }
            } catch (error) {
                displayContent = '[Unable to decrypt message]';
                console.error('E2EE message decryption failed:', error);
            }
            contentHtml = this.escapeHtml(displayContent);
        }

        // Build reactions
        let reactionsHtml = '';
        if (msg.reactions && Object.keys(msg.reactions).length > 0) {
            const reactions = Object.entries(msg.reactions)
                .map(([emoji, data]) => {
                    const isMyReaction = data.user_ids?.includes(this.currentUser?.id);
                    return `<span class="reaction-badge ${isMyReaction ? 'my-reaction' : ''}" data-emoji="${emoji}">${emoji} <span class="count">${data.count}</span></span>`;
                })
                .join('');
            reactionsHtml = `<div class="message-reactions">${reactions}</div>`;
        }

        // Read receipt
        let readReceipt = '';
        if (msg.sender_id === this.currentUser?.id) {
            readReceipt = '<span class="read-receipt">✓</span>';
        }

        div.innerHTML = `
            ${!isCurrentUser ? `<div class="message-header"><span class="message-sender">${this.escapeHtml(senderName)}</span></div>` : ''}
            <div class="message-content">${contentHtml}</div>
            <div class="message-footer">
                <span class="message-time">${this.formatTime(msg.created_at)}</span>
                ${readReceipt}
            </div>
            ${reactionsHtml}
        `;

        // Add click handler for reactions
        div.addEventListener('contextmenu', (e) => {
            e.preventDefault();
            this.showReactionPicker(e, msg.id);
        });

        container.appendChild(div);
    }

    showReactionPicker(event, messageId) {
        this.selectedMessage = messageId;
        const picker = document.getElementById('reaction-picker');
        const rect = event.target.getBoundingClientRect();
        
        picker.style.top = `${rect.bottom + 5}px`;
        picker.style.left = `${rect.left}px`;
        picker.classList.remove('hidden');
    }

    hideReactionPicker() {
        document.getElementById('reaction-picker').classList.add('hidden');
        this.selectedMessage = null;
    }

    async addReaction(emoji) {
        if (!this.selectedMessage || !this.currentChat) return;
        
        try {
            await this.apiCall(`/messages/${this.selectedMessage}/reactions`, 'POST', { emoji });
            this.hideReactionPicker();
            await this.loadMessages(this.currentChat.id);
        } catch (error) {
            console.error('Failed to add reaction:', error);
        }
    }

    updateMessageReactions(data) {
        if (this.currentChat && this.currentChat.id === data.chat_id) {
            this.loadMessages(data.chat_id);
        }
    }

    updateReadReceipt(data) {
        const msgEl = document.querySelector(`[data-message-id="${data.message_id}"]`);
        if (msgEl) {
            const receipt = msgEl.querySelector('.read-receipt');
            if (receipt) {
                receipt.textContent = '✓✓';
                receipt.classList.add('read');
            }
        }
    }

    sendReadReceipt(chatId, messageId) {
        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
            this.ws.send(JSON.stringify({
                type: 'read',
                chat_id: chatId,
                message_id: messageId
            }));
        }
    }

    async sendMessage() {
        const input = document.getElementById('message-input');
        const content = input.value.trim();

        if (!this.currentChat) return;

        try {
            if (this.selectedFile) {
                throw new Error('Encrypted file messages are not enabled yet');
            }
            if (!this.e2eeReady) {
                throw new Error('E2EE is not ready');
            }

            const recipient = await this.recipientMatrixUserId(this.currentChat);
            const encryptedEvent = await this.e2ee.encryptText(
                this.currentChat.id,
                this.roomIdForChat(this.currentChat),
                recipient,
                content || 'Sent a message',
                payload => this.sendCryptoRequest(payload)
            );

            await this.apiCall(`/chats/${this.currentChat.id}/messages`, 'POST', {
                encrypted_content: encryptedEvent,
                message_type: 'text'
            });

            input.value = '';
            this.removeSelectedFile();
            await this.loadMessages(this.currentChat.id);
            
            this.sendTypingIndicator(false);

        } catch (error) {
            console.error('Failed to send message:', error);
        }
    }

    async uploadFile(file) {
        const formData = new FormData();
        formData.append('file', file);

        const response = await fetch(`${this.apiBase}/upload`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${this.token}`
            },
            body: formData
        });

        if (!response.ok) {
            throw new Error('File upload failed');
        }

        return response.json();
    }

    handleFileSelect(event) {
        const file = event.target.files[0];
        if (!file) return;

        this.selectedFile = file;

        const previewContainer = document.getElementById('file-preview-container');
        const imagePreview = document.getElementById('file-preview-image');
        const filePreview = document.getElementById('file-preview-info');
        const fileName = document.getElementById('file-preview-name');

        previewContainer.classList.remove('hidden');

        if (file.type.startsWith('image/')) {
            imagePreview.src = URL.createObjectURL(file);
            imagePreview.classList.remove('hidden');
            filePreview.classList.add('hidden');
        } else {
            imagePreview.classList.add('hidden');
            filePreview.classList.remove('hidden');
            fileName.textContent = file.name;
        }
    }

    removeSelectedFile() {
        this.selectedFile = null;
        document.getElementById('file-preview-container').classList.add('hidden');
        document.getElementById('file-input').value = '';
    }

    previewImage(url) {
        window.open(url, '_blank');
    }

    getFileIcon(filename) {
        const ext = filename?.split('.').pop()?.toLowerCase();
        const icons = {
            'pdf': '📄',
            'doc': '📝', 'docx': '📝',
            'txt': '📃',
            'xls': '📊', 'xlsx': '📊',
            'zip': '📦', 'rar': '📦',
            'mp3': '🎵', 'wav': '🎵',
            'mp4': '🎬', 'avi': '🎬'
        };
        return icons[ext] || '📎';
    }

    formatFileSize(bytes) {
        if (!bytes) return '';
        const sizes = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(1024));
        return `${(bytes / Math.pow(1024, i)).toFixed(1)} ${sizes[i]}`;
    }

    // New Chat Modal
    showNewChatModal() {
        document.getElementById('new-chat-modal').classList.remove('hidden');
        this.pendingMembers = [];
        this.renderSelectedMembers();
    }

    hideNewChatModal() {
        document.getElementById('new-chat-modal').classList.add('hidden');
        document.getElementById('new-chat-username').value = '';
        document.getElementById('group-name').value = '';
        document.getElementById('group-members').value = '';
        this.pendingMembers = [];
    }

    setChatType(type) {
        const directBtn = document.getElementById('btn-direct-chat');
        const groupBtn = document.getElementById('btn-group-chat');
        const directForm = document.getElementById('direct-chat-form');
        const groupForm = document.getElementById('group-chat-form');

        if (type === 'direct') {
            directBtn.classList.add('active');
            groupBtn.classList.remove('active');
            directForm.classList.remove('hidden');
            groupForm.classList.add('hidden');
        } else {
            directBtn.classList.remove('active');
            groupBtn.classList.add('active');
            directForm.classList.add('hidden');
            groupForm.classList.remove('hidden');
        }
    }

    renderSelectedMembers() {
        const container = document.getElementById('selected-members');
        container.innerHTML = '';
        
        this.pendingMembers.forEach(member => {
            const div = document.createElement('div');
            div.className = 'selected-member';
            div.innerHTML = `
                ${this.escapeHtml(member.display_name || member.username)}
                <button data-user-id="${member.id}">×</button>
            `;
            div.querySelector('button').addEventListener('click', () => {
                this.pendingMembers = this.pendingMembers.filter(m => m.id !== member.id);
                this.renderSelectedMembers();
            });
            container.appendChild(div);
        });
    }

    async startNewChat() {
        const directBtn = document.getElementById('btn-direct-chat');
        
        try {
            if (directBtn.classList.contains('active')) {
                const username = document.getElementById('new-chat-username').value.trim();
                if (!username) {
                    alert('Please enter a username');
                    return;
                }

                let targetUsername = username;
                if (username.includes('#')) {
                    const parts = username.split('#');
                    targetUsername = parts[0];
                }

                const users = await this.apiCall(`/users/search?q=${targetUsername}`);
                const targetUser = users.find(u => u.username === targetUsername);

                if (!targetUser) {
                    alert('User not found');
                    return;
                }

                const chat = await this.apiCall('/chats', 'POST', {
                    type: 'direct',
                    member_ids: [targetUser.id]
                });

                this.hideNewChatModal();
                this.loadChats();
                this.openChat(chat);

            } else {
                const groupName = document.getElementById('group-name').value.trim();

                if (!groupName) {
                    alert('Please enter a group name');
                    return;
                }

                const memberIds = this.pendingMembers.map(m => m.id);
                
                const chat = await this.apiCall('/chats', 'POST', {
                    type: 'group',
                    name: groupName,
                    member_ids: memberIds
                });

                this.hideNewChatModal();
                this.loadChats();
                this.openChat(chat);
            }
        } catch (error) {
            console.error('Failed to start chat:', error);
            alert(error.message);
        }
    }

    // Chat Info Panel
    toggleChatInfoPanel() {
        const panel = document.getElementById('chat-info-panel');
        panel.classList.toggle('hidden');
        
        if (!panel.classList.contains('hidden') && this.currentChat) {
            this.loadChatInfo();
        }
    }

    async loadChatInfo() {
        if (!this.currentChat) return;

        const infoName = document.getElementById('info-name');
        const infoType = document.getElementById('info-type');
        const infoAvatar = document.getElementById('info-avatar');
        
        if (this.currentChat.type === 'direct') {
            const otherMember = this.currentChat.members.find(m => m.user_id !== this.currentUser?.id);
            if (otherMember?.user) {
                infoName.textContent = otherMember.user.display_name || otherMember.user.username;
                infoAvatar.textContent = this.getInitials(otherMember.user.display_name);
            }
            infoType.textContent = 'Direct Message';
            document.querySelector('.group-only').classList.add('hidden');
        } else {
            infoName.textContent = this.currentChat.name || 'Group Chat';
            infoAvatar.textContent = this.getInitials(this.currentChat.name);
            infoType.textContent = `${this.currentChat.members.length} members`;
            document.querySelector('.group-only').classList.remove('hidden');
        }

        const membersList = document.getElementById('members-list');
        membersList.innerHTML = '';
        
        this.currentChat.members.forEach(member => {
            const isAdmin = member.role === 'admin';
            const div = document.createElement('div');
            div.className = 'member-item';
            div.innerHTML = `
                <div class="avatar">${this.getInitials(member.user?.display_name || member.user?.username)}</div>
                <div class="member-info">
                    <div class="member-name">${this.escapeHtml(member.user?.display_name || member.user?.username)}</div>
                    <div class="member-role">${isAdmin ? 'Admin' : 'Member'}</div>
                </div>
                ${this.currentChat.type === 'group' && (this.currentUser?.is_admin || isAdmin) && member.user_id !== this.currentUser?.id ? `
                    <div class="member-actions">
                        <button class="btn-secondary" onclick="app.removeMember('${member.user_id}')">Remove</button>
                    </div>
                ` : ''}
            `;
            membersList.appendChild(div);
        });

        document.getElementById('keep-history-toggle').checked = this.currentChat.keep_history;
    }

    async updateChatSetting(setting, value) {
        if (!this.currentChat) return;

        try {
            await this.apiCall(`/chats/${this.currentChat.id}`, 'PUT', { [setting]: value });
            this.currentChat[setting] = value;
        } catch (error) {
            console.error('Failed to update chat setting:', error);
        }
    }

    async removeMember(userId) {
        if (!this.currentChat) return;

        try {
            await this.apiCall(`/chats/${this.currentChat.id}/members/${userId}`, 'DELETE');
            await this.loadChats();
            this.currentChat = this.chats.find(c => c.id === this.currentChat.id);
            this.loadChatInfo();
        } catch (error) {
            console.error('Failed to remove member:', error);
        }
    }

    async leaveGroup() {
        if (!this.currentChat || this.currentChat.type !== 'group') return;

        try {
            await this.apiCall(`/chats/${this.currentChat.id}/members/${this.currentUser?.id}`, 'DELETE');
            this.toggleChatInfoPanel();
            this.loadChats();
        } catch (error) {
            console.error('Failed to leave group:', error);
        }
    }

    showAddMemberModal() {
        document.getElementById('add-member-modal').classList.remove('hidden');
        document.getElementById('add-member-username').value = '';
        document.getElementById('search-member-result').innerHTML = '';
    }

    hideAddMemberModal() {
        document.getElementById('add-member-modal').classList.add('hidden');
    }

    async searchMember() {
        const username = document.getElementById('add-member-username').value.trim();
        if (!username) return;

        try {
            const users = await this.apiCall(`/users/search?q=${username}`);
            const resultDiv = document.getElementById('search-member-result');
            
            if (users.length === 0) {
                resultDiv.innerHTML = '<p>No users found</p>';
                return;
            }

            const user = users[0];
            const isAlreadyMember = this.currentChat?.members.some(m => m.user_id === user.id);
            const isPending = this.pendingMembers.some(m => m.id === user.id);

            resultDiv.innerHTML = `
                <div class="user-item">
                    <div class="avatar">${this.getInitials(user.display_name)}</div>
                    <div class="user-item-info">
                        <div class="user-item-name">${this.escapeHtml(user.display_name)}</div>
                        <div class="user-item-email">@${this.escapeHtml(user.username)}</div>
                    </div>
                    ${!isAlreadyMember && !isPending ? `
                        <button class="btn-primary" onclick='app.addPendingMember(${JSON.stringify(user).replace(/"/g, '&quot;')})'>Add</button>
                    ` : isPending ? '<span>Already added</span>' : '<span>Already in chat</span>'}
                </div>
            `;
        } catch (error) {
            console.error('Failed to search member:', error);
        }
    }

    addPendingMember(user) {
        if (!this.pendingMembers.find(m => m.id === user.id)) {
            this.pendingMembers.push(user);
            this.renderSelectedMembers();
        }
        this.hideAddMemberModal();
    }

    // Admin Panel
    toggleAdminPanel() {
        const panel = document.getElementById('admin-panel');
        panel.classList.toggle('hidden');
        
        if (!panel.classList.contains('hidden')) {
            this.loadUsers();
            this.loadStats();
        }
    }

    switchTab(tabName) {
        document.querySelectorAll('.tab-btn').forEach(btn => {
            btn.classList.toggle('active', btn.dataset.tab === tabName);
        });

        document.querySelectorAll('.tab-content').forEach(content => {
            content.classList.toggle('active', content.id === `tab-${tabName}`);
        });
    }

    async loadUsers(search = '') {
        try {
            const data = await this.apiCall(`/users?search=${search}`);
            this.renderUserList(data.users);
        } catch (error) {
            console.error('Failed to load users:', error);
        }
    }

    renderUserList(users) {
        const container = document.getElementById('user-list');
        container.innerHTML = '';

        users.forEach(user => {
            const div = document.createElement('div');
            div.className = 'user-item';
            div.innerHTML = `
                <div class="avatar">${this.getInitials(user.display_name)}</div>
                <div class="user-item-info">
                    <div class="user-item-name">${this.escapeHtml(user.display_name)}</div>
                    <div class="user-item-email">@${this.escapeHtml(user.username)}#${this.escapeHtml(user.domain)}</div>
                </div>
                <div class="user-item-actions">
                    ${user.is_active ? 
                        `<button class="btn-secondary" onclick="app.deactivateUser('${user.id}')">Deactivate</button>` :
                        `<button class="btn-primary" onclick="app.activateUser('${user.id}')">Activate</button>`
                    }
                </div>
            `;
            container.appendChild(div);
        });
    }

    async createUser() {
        const username = document.getElementById('new-user-username').value.trim();
        const displayName = document.getElementById('new-user-display-name').value.trim();
        const password = document.getElementById('new-user-password').value;
        const confirmPassword = document.getElementById('new-user-password-confirm').value;
        const isAdmin = document.getElementById('new-user-is-admin').checked;
        const errorEl = document.getElementById('create-user-error');

        errorEl.classList.add('hidden');

        const usernamePattern = /^[a-zA-Z0-9_]+$/;
        if (username.length < 3 || !usernamePattern.test(username)) {
            errorEl.textContent = 'Username must be at least 3 characters and contain only letters, numbers, or underscores.';
            errorEl.classList.remove('hidden');
            return;
        }
        if (!displayName) {
            errorEl.textContent = 'Display name is required.';
            errorEl.classList.remove('hidden');
            return;
        }
        if (password.length < 6) {
            errorEl.textContent = 'Password must be at least 6 characters.';
            errorEl.classList.remove('hidden');
            return;
        }
        if (password !== confirmPassword) {
            errorEl.textContent = 'Passwords do not match.';
            errorEl.classList.remove('hidden');
            return;
        }

        try {
            await this.apiCall('/users', 'POST', {
                username,
                display_name: displayName,
                password,
                is_admin: isAdmin
            });

            this.hideCreateUserModal();
            this.loadUsers();
        } catch (error) {
            errorEl.textContent = error.message;
            errorEl.classList.remove('hidden');
        }
    }

    async deactivateUser(userId) {
        try {
            await this.apiCall(`/users/${userId}`, 'PUT', { is_active: false });
            this.loadUsers(document.getElementById('search-users').value);
        } catch (error) {
            alert(error.message);
        }
    }

    async activateUser(userId) {
        try {
            await this.apiCall(`/users/${userId}`, 'PUT', { is_active: true });
            this.loadUsers(document.getElementById('search-users').value);
        } catch (error) {
            alert(error.message);
        }
    }

    showCreateUserModal() {
        document.getElementById('create-user-modal').classList.remove('hidden');
        document.getElementById('create-user-error').classList.add('hidden');
    }

    hideCreateUserModal() {
        document.getElementById('create-user-modal').classList.add('hidden');
        document.getElementById('create-user-form').reset();
        document.getElementById('create-user-error').classList.add('hidden');
    }

    async loadAdminConfig() {
        try {
            const config = await this.apiCall('/admin/config');
            document.getElementById('config-public-registration').checked = config.allow_public_registration;
            document.getElementById('config-user-group-creation').checked = config.allow_user_group_creation;
            document.getElementById('config-keep-history').checked = config.default_keep_history;
            document.getElementById('config-max-file-size').value = config.max_file_size_mb;
            document.getElementById('config-domain').value = config.domain;
            document.getElementById('config-title').value = config.title;
            document.getElementById('config-federation').checked = config.federation_enabled;
            
            // Update server info
            document.getElementById('server-version').textContent = '0.1.0';
            document.getElementById('server-domain').textContent = config.domain;
            document.getElementById('server-db-type').textContent = 'SQLite';
        } catch (error) {
            console.error('Failed to load config:', error);
        }
    }

    async saveConfig() {
        const statusEl = document.getElementById('config-save-status');
        
        try {
            const configData = {
                allow_public_registration: document.getElementById('config-public-registration').checked,
                allow_user_group_creation: document.getElementById('config-user-group-creation').checked,
                default_keep_history: document.getElementById('config-keep-history').checked,
                max_file_size_mb: parseInt(document.getElementById('config-max-file-size').value),
                title: document.getElementById('config-title').value,
                federation_enabled: document.getElementById('config-federation').checked
            };
            
            await this.apiCall('/admin/config', 'PUT', configData);
            
            statusEl.textContent = 'Settings saved successfully!';
            statusEl.className = 'save-status success';
            setTimeout(() => {
                statusEl.textContent = '';
                statusEl.className = 'save-status';
            }, 3000);
        } catch (error) {
            statusEl.textContent = error.message;
            statusEl.className = 'save-status error';
        }
    }

    async loadStats() {
        try {
            const stats = await this.apiCall('/admin/stats');
            this.renderStats(stats);
        } catch (error) {
            console.error('Failed to load stats:', error);
        }
    }

    renderStats(stats) {
        // Update overview cards
        document.getElementById('stat-total-users').textContent = stats.total_users;
        document.getElementById('stat-total-chats').textContent = stats.total_chats;
        document.getElementById('stat-total-messages').textContent = stats.total_messages;
        document.getElementById('stat-storage').textContent = `${stats.storage_used_mb} MB`;
        
        // Update activity stats
        document.getElementById('stat-active-24h').textContent = stats.active_users_24h;
        document.getElementById('stat-active-7d').textContent = stats.active_users_7d;
        document.getElementById('stat-active-30d').textContent = stats.active_users_30d;
        
        // Update uptime
        const uptime = this.formatUptime(stats.uptime_seconds);
        document.getElementById('stat-uptime').textContent = uptime;
        
        // Update user count in user tab
        document.getElementById('total-users-count').textContent = `Total: ${stats.total_users}`;
    }
    
    formatUptime(seconds) {
        const hours = Math.floor(seconds / 3600);
        const minutes = Math.floor((seconds % 3600) / 60);
        const secs = seconds % 60;
        return `${hours}:${minutes.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
    }

    async loadUsers(search = '') {
        try {
            const data = await this.apiCall(`/users?search=${search}`);
            this.renderUserList(data.users);
            document.getElementById('total-users-count').textContent = `Total: ${data.total}`;
        } catch (error) {
            console.error('Failed to load users:', error);
        }
    }

    renderUserList(users) {
        const container = document.getElementById('user-list');
        container.innerHTML = '';

        if (users.length === 0) {
            container.innerHTML = '<p class="empty-message">No users found</p>';
            return;
        }

        users.forEach(user => {
            const div = document.createElement('div');
            div.className = 'user-item';
            
            const onlineIndicator = user.is_active ? '<span class="presence-dot online"></span>' : '<span class="presence-dot"></span>';
            
            div.innerHTML = `
                <div class="avatar">${this.getInitials(user.display_name)}</div>
                <div class="user-item-info">
                    <div class="user-item-name">${this.escapeHtml(user.display_name)} ${user.is_admin ? '👑' : ''}</div>
                    <div class="user-item-email">@${this.escapeHtml(user.username)}#${this.escapeHtml(user.domain)}</div>
                </div>
                <div class="user-item-actions">
                    ${user.is_active ? 
                        `<button class="btn-secondary btn-small" onclick="app.deactivateUser('${user.id}')">Deactivate</button>` :
                        `<button class="btn-primary btn-small" onclick="app.activateUser('${user.id}')">Activate</button>`
                    }
                </div>
            `;
            container.appendChild(div);
        });
    }

    async createBackup() {
        const statusEl = document.getElementById('backup-status');
        
        try {
            statusEl.textContent = 'Creating backup...';
            statusEl.className = 'backup-status';
            
            const result = await this.apiCall('/admin/backup', 'POST');
            
            statusEl.textContent = `Backup created: ${result.backup_path}`;
            statusEl.className = 'backup-status success';
            
            this.loadBackupList();
            
            setTimeout(() => {
                statusEl.textContent = '';
                statusEl.className = 'backup-status';
            }, 5000);
        } catch (error) {
            statusEl.textContent = error.message;
            statusEl.className = 'backup-status error';
        }
    }

    loadBackupList() {
        const container = document.getElementById('backup-list');
        // For now, show a message about backups
        container.innerHTML = `
            <div class="backup-item">
                <div>
                    <div class="backup-name">Manual backup created</div>
                    <div class="backup-date">Check data/backups folder</div>
                </div>
            </div>
        `;
    }

    async loadLogs() {
        const lines = document.getElementById('log-lines').value;
        const container = document.getElementById('log-content');
        
        try {
            const result = await this.apiCall(`/admin/logs?lines=${lines}`);
            
            if (result.logs && result.logs.length > 0) {
                container.textContent = result.logs.join('');
            } else {
                container.textContent = 'No logs available';
            }
        } catch (error) {
            container.textContent = `Error loading logs: ${error.message}`;
        }
    }

    // Utility Methods
    getInitials(name) {
        if (!name) return '?';
        return name.split(' ').map(n => n[0]).join('').toUpperCase().slice(0, 2);
    }

    escapeHtml(text) {
        if (!text) return '';
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    truncate(text, maxLength) {
        if (!text) return '';
        if (text.length <= maxLength) return text;
        return text.slice(0, maxLength) + '...';
    }

    formatTime(timestamp) {
        if (!timestamp) return '';
        const date = new Date(timestamp);
        const now = new Date();
        
        if (date.toDateString() === now.toDateString()) {
            return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        }
        
        const yesterday = new Date(now);
        yesterday.setDate(yesterday.getDate() - 1);
        
        if (date.toDateString() === yesterday.toDateString()) {
            return 'Yesterday';
        }
        
        return date.toLocaleDateString([], { month: 'short', day: 'numeric' });
    }

    scrollToBottom() {
        const container = document.getElementById('messages-container');
        container.scrollTop = container.scrollHeight;
    }

    updatePresence(userId, isOnline) {
        this.onlineUsers[userId] = isOnline;
        this.updateChatStatuses();
        
        if (this.currentChat && this.currentChat.type === 'direct') {
            const otherMember = this.currentChat.members.find(m => m.user_id === userId);
            if (otherMember) {
                const statusEl = document.getElementById('chat-status');
                statusEl.innerHTML = `<span class="presence-dot ${isOnline ? 'online' : ''}"></span> <span class="status-text">${isOnline ? 'online' : 'offline'}</span>`;
            }
        }
    }
}

// Initialize app
const app = new DeceMSGApp();
