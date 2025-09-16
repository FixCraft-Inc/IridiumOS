class ExploreApp extends App {
	name = "Explore";
	package = "anura.explore";
	icon = "/assets/icons/explore.png";
	hidden = false;

	css = css`
		background-color: var(--theme-bg);
		color: var(--theme-fg);
		width: 100%;
		height: 100%;
		display: flex;
		flex-direction: row;

		#sidebar {
			width: 22rem;
			padding: 1rem;
			padding-left: 0;

			& div {
				padding-block: 0.7rem;
				font-size: 1.1rem;
				border-radius: 0 3rem 3rem 0;
				padding-left: 1.25em;
				display: flex;
				align-items: center;
				gap: 0.5rem;
				font-weight: 600;
				width: 100%;

				transition: 0.2s;
			}

			& div.selected {
				color: color-mix(in srgb, var(--theme-accent) 35%, var(--theme-fg));
				background-color: color-mix(
					in srgb,
					var(--theme-accent) 30%,
					transparent
				);
				font-weight: 700;

				transition: 0.15s ease;
			}
		}

		h1 {
			font-size: 2em;
		}

		article {
			width: 100%;
			height: 100%;
			overflow-y: auto;
		}

		a,
		a:link {
			color: var(--theme-accent);
		}

		a:visited {
			color: var(--theme-accent);
		}

		#body {
			font-size: 1.05rem;
			padding: 1rem;
			padding-left: 2rem;

			& p {
				margin-block: 0.5rem;
			}

			& p img {
				width: 1.05rem;
				height: 1.05rem;
				top: 0.2rem;
				position: relative;
				margin-right: 0.2rem;
			}

			& span:has(img) {
				gap: 0.2rem;
				align-items: center;
				font-weight: 600;
			}

			& code {
				background-color: var(--theme-secondary-bg);
				padding: 0.1rem 0.3rem;
				border-radius: 0.2rem;
				font-family: var(--theme-font-mono);
			}

			& h2 {
				margin-block: 1.5rem 0;
			}

			& h2:first-of-type {
				margin-block-start: 0.25rem;
			}
		}

		.head {
			display: flex;
			flex-direction: row;

			gap: 1rem;
			align-items: center;

			& img {
				width: 2.5rem;
				height: 2.5rem;
			}
		}

		/* Extra polish for FixCraft section */
		.badges {
			display: flex;
			flex-wrap: wrap;
			gap: 0.5rem;
			margin: 0.5rem 0 1rem;
		}
		.badge {
			display: inline-flex;
			align-items: center;
			gap: 0.35rem;
			border-radius: 999px;
			padding: 0.25rem 0.6rem;
			background: color-mix(
				in srgb,
				var(--theme-accent) 18%,
				var(--theme-secondary-bg)
			);
			color: color-mix(in srgb, var(--theme-fg) 85%, var(--theme-accent));
			font-weight: 600;
			font-size: 0.9rem;
		}
		.badge .material-symbols-outlined {
			font-size: 1rem;
			line-height: 1;
		}

		.callout {
			background: var(--theme-secondary-bg);
			border-left: 4px solid var(--theme-accent);
			padding: 0.75rem 1rem;
			border-radius: 0.5rem;
			margin: 1rem 0;
		}
		.muted {
			opacity: 0.8;
			font-size: 0.95rem;
		}

		::-webkit-scrollbar {
			width: 8px;
		}

		::-webkit-scrollbar-thumb {
			background-color: var(--theme-secondary-bg);
			border-radius: 8px;
		}

		::-webkit-scrollbar-button {
			display: none;
		}
	`;

	constructor() {
		super();
	}

	whatsnew = (
		<div id="body">
			<h1>What's new in AnuraOS {anura.version.pretty}?</h1>
			<p>
				This version resolves a bug where certain portions of the OOBE were
				displayed incorrectly. The release notes for AnuraOS 2.1.0 continue
				below.
			</p>
			<h2>Experimental OPFS filesystem driver</h2>
			<p>
				AnuraOS 2.1 includes an experimental filesystem driver for the Origin
				Private File System (OPFS). This greatly improves the speed of file
				operations. You can enable it in{" "}
				<span>
					<a href="javascript:anura.apps['anura.ui.settings'].open();">
						<img src="/assets/icons/settings.png" alt="Settings Icon" />
						Settings
					</a>
					.
				</span>
			</p>
			<h2>VSCode Support</h2>
			<p>
				AnuraOS 2.1 is the first version to include support for Visual Studio
				Code. You can download it from the Developer Repository in{" "}
				<span>
					<img
						src="/apps/marketplace.app/playstore.webp"
						alt="Marketplace Icon"
					/>
					<a href="javascript:anura.apps['anura.store'].open();">Marketplace</a>
					.
				</span>
			</p>
			<h2>Other changes</h2>
			<ul>
				<li>Added WebDAV endpoint at /dav/*</li>
				<li>Fix UI bugs in the file picker</li>
			</ul>
		</div>
	);

	/* NEW: FixCraft & Network section */
	fxcraft = (
		<div id="body">
			<h1>FixCraft Edge &amp; Security</h1>
			<div class="badges">
				<span class="badge">
					<span class="material-symbols-outlined">vpn_lock</span>
					Always-On VPN
				</span>
				<span class="badge">
					<span class="material-symbols-outlined">shield_lock</span>
					Cloudflare WAF
				</span>
				<span class="badge">
					<span class="material-symbols-outlined">language</span>
					Multi-domain Rehost
				</span>
			</div>

			<h2>Embedded, admin-managed VPN (unchangeable)</h2>
			<p>
				This build includes an OS-level, always-on VPN gateway managed by the
				administrator. It cannot be disabled or modified by users. All outbound
				traffic is forced through the VPN to protect origin IP and enforce
				network policy.
			</p>
			<div class="callout">
				<strong>Managed setting:</strong> Network/VPN controls are read-only for
				non-admin users.{" "}
				<a href="javascript:anura.apps['anura.settings'].open();">
					Open Settings
				</a>
			</div>

			<h2>Cloudflare-protected edge</h2>
			<p>
				All public endpoints sit behind Cloudflare (orange-cloud proxy) with
				<strong> Full (strict) SSL</strong>, DDoS mitigation, and WAF rules.
				This prevents direct exposure of the origin server and adds an extra
				security layer.{" "}
				<a href="javascript:anura.apps['anura.browser'].open(['https://developers.cloudflare.com/ssl/origin-configuration/ssl-modes/full-strict/']);">
					Learn about Full (strict)
				</a>
				.
			</p>

			<h2>Rehosting on request</h2>
			<p>
				Need access under your organization’s domain? We support whitelabeled
				rehosts across multiple domains (e.g., <code>fixcraft.jp</code>,
				<code> *.it.com</code>, etc.). Requests require proof of organization
				block/need and administrator approval.
			</p>
			<p class="muted">
				Submit a request:{" "}
				<a href="javascript:anura.apps['anura.browser'].open(['https://fixcraft.org/rehost']);">
					fixcraft.org/rehost
				</a>{" "}
				(or contact your FixCraft admin).
			</p>

			<h2>At a glance</h2>
			<ul>
				<li>
					Origin IP never exposed to end-users; all traffic goes via VPN →
					Cloudflare.
				</li>
				<li>VPN policy is enforced by OS; user-side toggles are disabled.</li>
				<li>Custom rehost domains available upon verified request.</li>
			</ul>
		</div>
	);

	v86 = () => (
		<div id="body" class="v86">
			<h1>Using the x86 Subsystem</h1>
			<p>
				AnuraOS includes an x86 subsystem (based on{" "}
				<a
					href="javascript:anura.apps['anura.browser'].open(['https://github.com/copy/v86']);" // using dreamland on:click or html onclick makes the link not blue
				>
					v86
				</a>
				), which lets you run real Linux within Anura.
				{anura.x86 === undefined && (
					<p>
						It seems like you dont have the subsystem enabled. You can install
						it from{" "}
						<span>
							<img src="/assets/icons/settings.png" alt="Settings icon" />
							<a href="javascript:anura.apps['anura.settings'].open();">
								Settings
							</a>
						</span>
						.
					</p>
				)}
				{anura.x86 !== undefined && (
					<p>
						You can open a terminal using the{" "}
						<span>
							<img src="/assets/icons/terminal.png" alt="v86 Terminal Icon" />
							<a href="javascript:anura.apps['anura.ashell'].open(['--cmd', '/usr/bin/x86-run.ajs']);">
								v86 Terminal
							</a>
						</span>{" "}
						app.
					</p>
				)}
			</p>
			<p>
				The x86 subsystem is based on an Alpine Linux, a lightweight distro
				commonly used in containers. To install packages, you can run{" "}
				<code>apk add &lt;package&gt;</code>.
			</p>
			<p>
				If you want to create a shortcut for an X11 app in the launcher, you can
				do so from{" "}
				<span>
					<img src="/assets/icons/settings.png" alt="Settings icon" />
					<a href="javascript:anura.apps['anura.settings'].open();">Settings</a>
				</span>
				.
			</p>
		</div>
	);

	welcome = (
		<div id="body">
			<div class="head">
				<img src="/icon.png" alt="AnuraOS Logo" />
				<h1>Welcome to AnuraOS!</h1>
			</div>
			<h2>What is AnuraOS?</h2>
			<p>
				AnuraOS is a desktop environment made for development that runs right in
				your browser. It features full Linux emulation and a robust app
				ecosystem.
			</p>
			<h2>Getting Started</h2>
			<p>
				AnuraOS functions just like your average desktop: you can launch apps
				from the launcher (accessible via the button in the bottom-left, or
				pressing the Meta key), drag windows around, and pin apps to the
				taskbar. AnuraOS is visually based off of Google's ChromeOS.
			</p>

			<h2>Get new apps</h2>
			<p>
				To install more native Anura apps, you can head to the{" "}
				<span>
					<img
						src="/apps/marketplace.app/playstore.webp"
						alt="Marketplace Icon"
					/>
					<a href="javascript:anura.apps['anura.store'].open();">Marketplace</a>
					.
				</span>
			</p>
			<h2>Customize your experience</h2>
			<p>
				AnuraOS has robust customization features. You can change the wallpaper
				and system colors using{" "}
				<span>
					<a href="javascript:anura.apps['anura.wallpaper'].open();">
						<img
							src="/assets/icons/wallpaper.png"
							alt="Wallpaper Selector Icon"
						/>
						Wallpaper &amp; Style
					</a>
				</span>
				.
			</p>
			<p>
				For advanced users, Anura will execute any files in the /usr/init folder
				as JavaScript code on boot.
			</p>
		</div>
	);
	state: Stateful<{
		screen?: HTMLElement;
	}> = $state({
		screen: this.welcome,
	});

	page = async () => (
		<div class={this.css}>
			<div id="sidebar">
				<div
					on:click={() => {
						this.state.screen = this.welcome;
					}}
					class:selected={use(this.state.screen, (sc) => sc === this.welcome)}
				>
					<span class="material-symbols-outlined">kid_star</span>
					Welcome
				</div>
				<div
					on:click={() => {
						this.state.screen = this.whatsnew;
					}}
					class:selected={use(this.state.screen, (sc) => sc === this.whatsnew)}
				>
					<span class="material-symbols-outlined">history</span>
					What's new
				</div>
				<div
					on:click={() => {
						this.state.screen = this.v86();
					}}
					class:selected={use(this.state.screen, (sc: HTMLElement) =>
						sc.classList.contains("v86"),
					)}
				>
					<span class="material-symbols-outlined">memory</span>
					x86 Subsystem
				</div>
				<div
					on:click={() => {
						this.state.screen = this.fxcraft;
					}}
					class:selected={use(this.state.screen, (sc) => sc === this.fxcraft)}
				>
					<span class="material-symbols-outlined">shield_lock</span>
					FixCraft Edge
				</div>
			</div>
			<article>{use(this.state.screen)}</article>
		</div>
	);

	async open(args: string[] = []): Promise<WMWindow | undefined> {
		const win = anura.wm.create(this, {
			title: "Explore AnuraOS",
			width: `calc(${window.innerHeight * 0.6}px * 16 / 10)`, // manually calculating to prevent wonky behaviour on window resize
			height: `${window.innerHeight * 0.6}px`,
		});
		win.content.style.backgroundColor = "var(--theme-bg)";
		win.content.style.color = "var(--theme-fg)";
		win.content.style.height = "calc(100% - 24px)"; // very dirty hack
		win.content.appendChild(await this.page());

		return win;
	}
}
