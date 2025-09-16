class AboutApp extends App {
	name = "About Anura";
	package = "anura.about";
	icon = "/assets/icons/aboutapp.png";

	page = () => (
		<div class="aboutapp-container">
			<div class="aboutapp-logo">
				<div
					class="aboutapp-logo-img"
					title="About AnuraOS"
					on:click={() => {
						alert("Why?");
					}}
				></div>
			</div>
			<div class="aboutapp-logo-divider"></div>
			<div class="aboutapp-content">
				<p class="aboutapp-title">AnuraOS (FXC)</p>
				<p class="aboutapp-version">
					Version {anura.version.pretty} ({anura.version.codename}) — OS build:
					Iridium Edition™ <code>{this.getOSBuild()}</code>
				</p>
				<p>© FixCraft Inc. All rights reserved. (Credits: Mercury Workshop)</p>
				<br />
				{$if(
					anura.settings.get("x86-disabled"),
					<p>
						Anura x86 subsystem disabled. <br /> Enable it in{" "}
						<button
							on:click={() => {
								anura.apps["anura.settings"].open();
							}}
							class="aboutapp-link-button"
						>
							Settings
						</button>
						.
					</p>,
					<p>Anura x86 subsystem enabled.</p>,
				)}

				<br />

				{$if(
					anura.settings.get("bootFromOPFS"),
					<p>Anura is booting from OPFS.</p>,
					<p>Anura OPFS boot disabled.</p>,
				)}

				<br />
				<br />

				<p>
					This product is licensed under the{" "}
					<button
						on:click={() => {
							anura.apps["anura.browser"].open([
								"https://github.com/MercuryWorkshop/anuraOS/blob/main/LICENSE",
							]);
						}}
						class="aboutapp-link-button"
					>
						GNU AGPLv3
					</button>
					. This is a fork of AnuraOS.
				</p>
				<br />
				<p class="aboutapp-motto">
					FixCraft Inc. ® — software development company and mass rehost
					provider.
					<br />
					“Break the rules or the rules will break you.” — F1.
				</p>
				<br />
				<div class="aboutapp-actions">
					<button
						class="aboutapp-secondary-button"
						on:click={async () => {
							const diag = `AnuraOS ${anura.version.pretty} (${anura.version.codename}) | Iridium Edition ${this.getOSBuild()}
	x86: ${anura.settings.get("x86-disabled") ? "disabled" : "enabled"} | OPFS: ${anura.settings.get("bootFromOPFS") ? "on" : "off"}`;
							try {
								await navigator.clipboard.writeText(diag);
								alert("Diagnostics copied.");
							} catch {
								alert("Copy failed.");
							}
						}}
					>
						Copy diagnostics
					</button>
				</div>
			</div>
		</div>
	);

	constructor() {
		super();
	}

	async open(args: string[] = []): Promise<WMWindow | undefined> {
		let fullscreenEasterEgg = false;

		if (args.length > 0) {
			if (args.includes("fullscreen-easter-egg")) {
				fullscreenEasterEgg = true;
			}
			if (args.includes("fuller-screen-easter-egg")) {
				// You asked for it
				document.body.style.background =
					"url(/assets/images/idol.gif) no-repeat center center fixed";

				anura.wm.windows.forEach((win) => {
					// No animation
					win.deref()!.element.style.display = "none";
					win.deref()!.close();
				});

				taskbar.element.remove();

				document.title = "Lagtrain";

				const icon = document.querySelector(
					"link[rel~='icon']",
				)! as HTMLLinkElement;

				icon.type = "image/gif";
				icon.href = "/assets/images/idol.gif";

				return;
			}
		}

		const aboutview = anura.wm.create(this, {
			title: "",
			width: "580px",
			height: fullscreenEasterEgg ? "560px" : "600px",
			resizable: false,
		});

		if (fullscreenEasterEgg) {
			aboutview.content.appendChild(
				<div style="background: url(/assets/images/idol.gif); width: 100%; height: 100%; background-size: contain; background-repeat: no-repeat;"></div>,
			);
		} else {
			aboutview.content.appendChild(this.page());
		}

		// make borderless
		aboutview.content.style.position = "absolute";
		aboutview.content.style.height = "100%";
		aboutview.content.style.display = "inline-block";

		const container = aboutview.content.parentElement;

		(container!.querySelector(".title") as any).style["background-color"] =
			"rgba(0, 0, 0, 0)";

		return aboutview;
	}

	getOSBuild(): string {
		return anura.settings.get("milestone").slice(0, 7);
	}
}
