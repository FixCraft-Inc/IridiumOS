(() => {
	const DEFAULT_OPTIONS = {
		requireDarkMode: true,
		requireNotifications: true,
		requireGeolocation: true,
		clearOnFailure: true,
		onStatusChange: null,
	};

	const ISSUE_TEXT = {
		'dark-mode': 'Enable dark mode in your operating system or browser.',
		'notifications': 'Allow notifications for this site so we can reach you across .hostforever.org.',
		'geolocation': 'Allow location access so location-aware services function correctly.',
	};

	class PermissionGuardInstance {
		constructor(options) {
			this.options = Object.assign({}, DEFAULT_OPTIONS, options || {});
			this.darkQuery = window.matchMedia ? window.matchMedia('(prefers-color-scheme: dark)') : null;
			this.overlayEl = null;
			this.issuesListEl = null;
			this.retryBtnEl = null;
			this.geoPermissionStatus = null;
			this.lastFailureSignature = null;
			this.lastClearedSignature = null;
			this.clearPromise = null;
			this.isRequesting = false;
			this.started = false;
		}

		start() {
			if (this.started) return this;
			this.started = true;
			this.attachListeners();
			this.enforce();
			return this;
		}

		attachListeners() {
			if (this.darkQuery) {
				const handler = () => this.enforce();
				if (typeof this.darkQuery.addEventListener === 'function') {
					this.darkQuery.addEventListener('change', handler);
				} else if (typeof this.darkQuery.addListener === 'function') {
					this.darkQuery.addListener(handler);
				}
			}
			window.addEventListener('focus', () => this.enforce(), { passive: true });
			document.addEventListener('visibilitychange', () => {
				if (!document.hidden) this.enforce();
			});
		}

		ensureOverlay() {
			if (this.overlayEl) return;
			this.overlayEl = document.createElement('div');
			Object.assign(this.overlayEl.style, {
				position: 'fixed',
				inset: '0',
				display: 'none',
				alignItems: 'center',
				justifyContent: 'center',
				background: 'rgba(3, 6, 12, 0.96)',
				color: '#f8fafc',
				zIndex: '2147483647',
				fontFamily: 'system-ui,-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif',
				padding: '24px',
				textAlign: 'center',
			});
			this.overlayEl.setAttribute('role', 'alert');
			this.overlayEl.innerHTML = [
				'<div style="max-width:520px;width:100%;">',
				'<h1 style="margin:0 0 16px;font-size:24px;font-weight:700;">Action required</h1>',
				'<p style="margin:0 auto 22px;line-height:1.6;font-size:16px;color:#cdd5e7;">Allow the required permissions and enable dark mode to continue.</p>',
				'<ul data-permission-issues style="margin:0 0 22px;padding:0;list-style:none;text-align:left;"></ul>',
				'<button data-permission-retry style="display:inline-flex;align-items:center;justify-content:center;padding:12px 24px;border-radius:999px;border:0;background:#2563eb;color:#fff;font-weight:600;font-size:15px;cursor:pointer;">Retry permission check</button>',
				'<p style="margin-top:18px;font-size:13px;color:#90a6d8;">We will keep checking automatically while this window remains open.</p>',
				'</div>'
			].join('');
			document.body.appendChild(this.overlayEl);
			this.issuesListEl = this.overlayEl.querySelector('[data-permission-issues]');
			this.retryBtnEl = this.overlayEl.querySelector('[data-permission-retry]');
			if (this.retryBtnEl) {
				this.retryBtnEl.addEventListener('click', (event) => {
					event.preventDefault();
					this.attemptPermissionRequests();
				});
			}
		}

		showOverlay(issues) {
			this.ensureOverlay();
			if (!this.overlayEl) return;
			this.overlayEl.style.display = 'flex';
			this.overlayEl.setAttribute('aria-hidden', 'false');
			if (!this.issuesListEl) return;
			this.issuesListEl.innerHTML = '';
			issues.forEach((code) => {
				const item = document.createElement('li');
				Object.assign(item.style, {
					marginBottom: '12px',
					padding: '12px 14px',
					borderRadius: '14px',
					background: 'rgba(15, 23, 42, 0.78)',
					color: '#f1f5f9',
					fontSize: '15px',
					lineHeight: '1.5',
				});
				item.textContent = (this.options.issueText && this.options.issueText[code]) || ISSUE_TEXT[code] || code;
				this.issuesListEl.appendChild(item);
			});
		}

		hideOverlay() {
			if (!this.overlayEl) return;
			this.overlayEl.style.display = 'none';
			this.overlayEl.setAttribute('aria-hidden', 'true');
		}

		clearCookies() {
			try {
				const cookies = document.cookie ? document.cookie.split(';') : [];
				if (!cookies.length) return;
				const host = window.location.hostname;
				const hostParts = host.split('.');
				const domains = new Set(['', host]);
				if (hostParts.length > 1) {
					domains.add('.' + hostParts.slice(-2).join('.'));
				}
				domains.add('.hostforever.org');
				cookies.forEach((entry) => {
					const eqIndex = entry.indexOf('=');
					const name = (eqIndex >= 0 ? entry.slice(0, eqIndex) : entry).trim();
					domains.forEach((domain) => {
						const domainAttr = domain ? 'domain=' + domain + ';' : '';
						document.cookie = name + '=;expires=Thu, 01 Jan 1970 00:00:00 GMT;path=/;' + domainAttr;
					});
				});
			} catch (error) {
				console.warn('Permission guard failed to clear cookies', error);
			}
		}

		async clearCaches() {
			if (!('caches' in window)) return;
			try {
				const keys = await caches.keys();
				await Promise.all(keys.map((key) => caches.delete(key)));
			} catch (error) {
				console.warn('Permission guard failed to clear CacheStorage', error);
			}
		}

		async clearIndexedDB() {
			if (!window.indexedDB || typeof window.indexedDB.databases !== 'function') return;
			try {
				const dbs = await window.indexedDB.databases();
				await Promise.all(
					dbs.map((db) => {
						if (!db || !db.name) return Promise.resolve();
						return new Promise((resolve) => {
							const request = window.indexedDB.deleteDatabase(db.name);
							request.onsuccess = request.onerror = request.onblocked = () => resolve();
						});
					}),
				);
			} catch (error) {
				console.warn('Permission guard failed to clear IndexedDB', error);
			}
		}

		async performClear(signature) {
			if (!this.options.clearOnFailure) return;
			if (!signature || signature === this.lastClearedSignature) return;
			this.lastClearedSignature = signature;
			if (this.clearPromise) return;
			this.clearPromise = (async () => {
				try {
					this.clearCookies();
					try {
						window.localStorage && window.localStorage.clear();
					} catch {}
					try {
						window.sessionStorage && window.sessionStorage.clear();
					} catch {}
					await Promise.all([this.clearCaches(), this.clearIndexedDB()]);
				} finally {
					this.clearPromise = null;
				}
			})();
		}

		async getGeolocationState() {
			if (!this.options.requireGeolocation) return 'skipped';
			if (!navigator.geolocation) return 'denied';
			if (navigator.permissions && navigator.permissions.query) {
				try {
					if (!this.geoPermissionStatus) {
						this.geoPermissionStatus = await navigator.permissions.query({ name: 'geolocation' });
						const handler = () => this.enforce();
						if (typeof this.geoPermissionStatus.addEventListener === 'function') {
							this.geoPermissionStatus.addEventListener('change', handler);
						} else {
							this.geoPermissionStatus.onchange = handler;
						}
					}
					return this.geoPermissionStatus.state;
				} catch (error) {
					console.warn('Permission guard could not query geolocation permission', error);
				}
			}
			return 'prompt';
		}

		async attemptPermissionRequests() {
			if (this.isRequesting) return;
			this.isRequesting = true;
			this.ensureOverlay();
			if (this.retryBtnEl) {
				this.retryBtnEl.disabled = true;
				this.retryBtnEl.textContent = 'Requesting...';
			}
			try {
				if (this.options.requireNotifications && typeof Notification !== 'undefined' && Notification.permission !== 'granted' && Notification.requestPermission) {
					try {
						const result = Notification.requestPermission();
						if (result && typeof result.then === 'function') {
							await result;
						}
					} catch (error) {
						console.warn('Notification permission request failed', error);
					}
				}
				if (this.options.requireGeolocation && navigator.geolocation && navigator.geolocation.getCurrentPosition) {
					await new Promise((resolve) => {
						navigator.geolocation.getCurrentPosition(
							() => resolve(true),
							() => resolve(false),
							{ enableHighAccuracy: false, timeout: 10000 },
						);
					});
				}
			} finally {
				if (this.retryBtnEl) {
					this.retryBtnEl.disabled = false;
					this.retryBtnEl.textContent = 'Retry permission check';
				}
				this.isRequesting = false;
				this.enforce();
			}
		}

		async enforce() {
			const issues = [];
			const status = {
				darkMode: this.options.requireDarkMode ? (this.darkQuery ? this.darkQuery.matches : false) : true,
				notifications: this.options.requireNotifications && typeof Notification !== 'undefined' ? Notification.permission : (this.options.requireNotifications ? 'denied' : 'granted'),
				geolocation: await this.getGeolocationState(),
			};
			if (this.options.requireDarkMode && !status.darkMode) issues.push('dark-mode');
			if (this.options.requireNotifications && status.notifications !== 'granted') issues.push('notifications');
			if (this.options.requireGeolocation && status.geolocation !== 'granted') issues.push('geolocation');
			const signature = issues.slice().sort().join(',');
			if (issues.length) {
				this.showOverlay(issues);
				if (signature && signature !== this.lastFailureSignature) {
					this.performClear(signature);
				}
			} else {
				this.hideOverlay();
				this.lastClearedSignature = null;
			}
			this.lastFailureSignature = signature;
			if (typeof this.options.onStatusChange === 'function') {
				this.options.onStatusChange({
					allGranted: issues.length === 0,
					issues,
					status,
				});
			}
		}
	}

	function start(options) {
		const guard = new PermissionGuardInstance(options);
		return guard.start();
	}

	window.PermissionGuard = {
		start,
	};
})();
