# Facet Value Definitions

**Generated from `ontology/homeiot.ttl` — do not edit by hand.** Regenerate with
`python3 scripts/make_facet_copies.py`.

Each facet below is single-valued: choose exactly one value, or `unsure`.

## `actuatesPhysical` — actuates physical

Whether the device can cause a physical change in the home, as opposed to only sensing or reporting.

- **`true`**
- **`false`**
- **`unsure`** — the product name does not identify the device well
  enough to judge, or the facet does not apply. A real answer; use it.

## `actuationConsequence` — actuation consequence

How severe the physical consequence is when the device acts.

- **`ComfortActuation`** — *comfort*
  <br>Reversible and non-damaging: compromise changes the occupants' comfort or convenience and leaves no lasting physical effect once reverted.
- **`NoActuation`** — *no physical actuation*
  <br>The device has no physical actuator: compromise can expose or falsify data but cannot change anything in the physical world. The zero point of the scale — hiot:actuatesPhysical is false exactly when this value holds, so the two are one judgment and not independent evidence.
- **`PropertyActuation`** — *property / access*
  <br>Compromise can breach the physical security of the home or damage property, without putting a person at risk of injury — it can grant physical entry, or start or stop the flow of something costly.
- **`SafetyActuation`** — *safety*
  <br>Compromise can injure a person or start a fire: the device commands enough heat, current, or mechanical force to harm an occupant or the building itself.
- **`unsure`** — the product name does not identify the device well
  enough to judge, or the facet does not apply. A real answer; use it.

## `capturesAV` — captures audio/video

Whether the device has a camera or an always-listening microphone.

- **`true`**
- **`false`**
- **`unsure`** — the product name does not identify the device well
  enough to judge, or the facet does not apply. A real answer; use it.

## `cloudDependence` — cloud dependence

Whether the device's primary control path requires the vendor's cloud service.

- **`CloudOptional`** — *cloud-optional*
  <br>Local control works; cloud adds remote access and is the common default.
- **`CloudRequired`** — *cloud-required*
  <br>Primary control path traverses vendor cloud; the device is inert without it.
- **`LocalOnly`** — *local-only*
  <br>Fully controllable with no vendor cloud reachable.
- **`unsure`** — the product name does not identify the device well
  enough to judge, or the facet does not apply. A real answer; use it.

## `computeTier` — compute tier

The software substrate the device runs on.

- **`AndroidDerived`** — *Android-derived*
  <br>Android, or a vendor fork of AOSP. Inherits the mobile platform's userland and its CVE stream.
- **`EmbeddedLinux`** — *embedded Linux*
  <br>Full network/web stack, busybox userland, often a vendor CGI admin interface. The tier that carries injection and traversal weaknesses.
- **`McuClass`** — *MCU-class (no OS)*
  <br>Bare-metal microcontroller. Weaknesses skew to memory safety; no web stack to attack.
- **`Rtos`** — *RTOS*
  <br>Runs a real-time OS kernel (FreeRTOS, Zephyr, ThreadX): task scheduling and a network stack, but no general-purpose userland, filesystem, or shell. Sits between hiot:McuClass (bare metal) and hiot:EmbeddedLinux (full userland).
- **`unsure`** — the product name does not identify the device well
  enough to judge, or the facet does not apply. A real answer; use it.

## `consumerAvailability` — consumer availability

Whether a non-expert consumer can buy and install the device themselves.

- **`InstallerChannel`** — *installer channel*
  <br>Normally specified and commissioned by a trade installer, even when technically purchasable.
- **`MixedChannel`** — *mixed channel*
  <br>Sold both at retail and through trade installers, with the same or near-identical product lines available in each channel.
- **`RetailConsumer`** — *retail consumer*
  <br>Bought off the shelf and self-installed by a non-expert.
- **`unsure`** — the product name does not identify the device well
  enough to judge, or the facet does not apply. A real answer; use it.

## `dataSensitivity` — data sensitivity

The most sensitive kind of data the device handles.

- **`AvStreamData`** — *audio/video stream*
  <br>Captures or relays live or recorded audio or video of the home's interior or its surroundings.
- **`BiometricData`** — *biometric*
  <br>Fingerprint/face templates or physiological signals.
- **`NoData`** — *no sensitive data*
  <br>Handles nothing about the occupants — only its own operational state, from which no inference about the household can be drawn. Strictly the complement of hiot:TelemetryData: if state or usage traces would support occupancy inference, the value is TelemetryData, not NoData.
- **`TelemetryData`** — *telemetry*
  <br>State and usage traces. Occupancy inference is the privacy risk, not content.
- **`unsure`** — the product name does not identify the device well
  enough to judge, or the facet does not apply. A real answer; use it.

## `firmwareUpdateModel` — firmware update model

The mechanism by which new firmware reaches the device.

- **`ManualFlash`** — *manual flash*
  <br>Updating requires the owner to obtain a firmware image and transfer it to the device by hand: a local upload page, USB, SD card, or a serial/JTAG header.
- **`NoUpdatePath`** — *no update path*
  <br>The device has no mechanism to receive new firmware at all; the shipped image is final. Distinct from hiot:Unmaintained on hiot:patchResponsibility, which states that no fix is being issued rather than that none could be delivered.
- **`OtaAutomatic`** — *automatic OTA*
  <br>The device fetches and applies firmware over the network on its own, with no owner action required.
- **`OtaUserInitiated`** — *user-initiated OTA*
  <br>The device can fetch firmware over the network, but the transfer starts only when the owner approves or triggers it.
- **`unsure`** — the product name does not identify the device well
  enough to judge, or the facet does not apply. A real answer; use it.

## `formFactor` — form factor

Whether the device is fixed in place, moved around the home, or carried on the body.

- **`Fixed`** — *fixed*
  <br>Installed in one place and not normally moved once mounted or sited.
- **`Portable`** — *portable*
  <br>Moved freely around the home during normal use, but not carried on the body.
- **`Worn`** — *worn*
  <br>Carried on the body during normal use.
- **`unsure`** — the product name does not identify the device well
  enough to judge, or the facet does not apply. A real answer; use it.

## `hasWebAdminUI` — has web admin UI

Whether the device typically exposes an HTTP(S) administrative interface on the local network.

- **`true`**
- **`false`**
- **`unsure`** — the product name does not identify the device well
  enough to judge, or the facet does not apply. A real answer; use it.

## `placement` — placement

Where the device is sited.

- **`Either`** — *either*
  <br>Product lines exist for both indoor and outdoor siting, and the category contains both. Note this is a MIXED value on a single-valued facet — the one place the existing vocabulary already admits within-category heterogeneity rather than forcing a summary.
- **`Indoor`** — *indoor*
  <br>Sited inside the dwelling.
- **`Outdoor`** — *outdoor*
  <br>Sited outside the weather envelope, which also implies physical accessibility to anyone who can reach the property.
- **`unsure`** — the product name does not identify the device well
  enough to judge, or the facet does not apply. A real answer; use it.

## `supportLifetime` — support lifetime

Whether the vendor publishes an end-of-support date or minimum support duration.

- **`DeclaredLifetime`** — *declared end-of-support*
  <br>The vendor publishes a date, or a minimum duration from purchase, through which the product will receive security updates. Assessed as of the study's pinned 2026-08-05 snapshot vintage: regulation (UK PSTI, EU CRA) is changing declaration practice quickly, so this value is a statement about that date and not a timeless property of the category.
- **`UndeclaredLifetime`** — *undeclared*
  <br>The consumer-IoT norm: no published support window, so a disclosed CVE can stay live indefinitely. Assessed as of the study's pinned 2026-08-05 snapshot vintage, for the reason given on hiot:DeclaredLifetime.
- **`unsure`** — the product name does not identify the device well
  enough to judge, or the facet does not apply. A real answer; use it.

---

# Multi-valued facets

**These are answered differently from everything above.** Give **every** value that is common for the category, `|`-separated (`AppOnlyAdmin|LocalWebAdmin`), not just the most typical one. `unsure` stands alone as a whole-cell answer and is never mixed with real values.

Common for the category, not merely possible: a route found on a few outlier products does not belong in the set. A facet that ends up true of all 24 categories discriminates nothing, so a one-value answer is a normal outcome.

## `adminModel` — administration model

Where the owner goes to change the device's settings. List every interface the category commonly offers.

- **`AppOnlyAdmin`** — *app-only*
  <br>Administration happens solely through a vendor mobile app; there is no browser-reachable admin surface on the device or in a portal.
- **`CloudPortalAdmin`** — *cloud portal*
  <br>Administration happens through a vendor-hosted web portal. The owner authenticates to the vendor's service rather than to the device, so the credential and the device sit on opposite sides of the internet.
- **`LocalWebAdmin`** — *local web admin*
  <br>An HTTP admin surface on the LAN — the classic consumer-IoT exposure.
- **`NoAdminInterface`** — *no admin interface*
  <br>The device exposes no administrative surface of its own; whatever configuration exists is applied through another device, or the device is not configurable at all. EXCLUSIVE: although hiot:adminModel is multi-valued, this value may not be combined with any other — a device either has an admin surface or it has none.
- **`unsure`** — you could not tell even after looking. A real answer; use it rather than guessing a set.

## `alsoDeployedIn` — also deployed in

Which non-residential settings the same product line is genuinely sold into and used in. Residential is true of every category by definition and does not need listing; answer `none` for a category sold to households only.

Optional: `none` is a real answer here.

- **`Commercial`** — *commercial*
  <br>A business, institutional, or public-facing premises with facilities or IT staff responsible for the installed equipment.
- **`Industrial`** — *industrial*
  <br>A plant, utility, or process-control environment, where equipment is engineered and commissioned rather than bought and installed.
- **`Prosumer`** — *prosumer*
  <br>A small office, home office, or owner-run small business, administered by its owner rather than by dedicated IT staff.
- **`Residential`** — *residential*
  <br>A private dwelling: a house, an apartment, or the domestic parts of a multi-occupancy building.
- **`unsure`** — you could not tell even after looking. A real answer; use it rather than guessing a set.

## `credentialModel` — credential model

How the owner's access to the device is established at first use. List every scheme the category commonly ships with.

- **`AccountBound`** — *cloud-account bound*
  <br>The device holds no independent credential of its own; access is authorised by the owner's vendor-cloud account, so the account's authentication is effectively the device's authentication.
- **`CertificateBound`** — *certificate / attestation bound*
  <br>Per-device attestation, as Matter requires.
- **`DefaultPassword`** — *shipped default password*
  <br>The CWE-798 case: a documented or hardcoded credential present until the owner changes it, which most never do.
- **`ForcedCredentialSetup`** — *forced setup credential*
  <br>Setup refuses to complete until a unique credential is chosen.
- **`NoCredential`** — *no credential*
  <br>Possession of the radio link is the only authentication — common on cheap mesh leaves.
- **`unsure`** — you could not tell even after looking. A real answer; use it rather than guessing a set.

## `pairingModel` — pairing model

How the device is enrolled onto the network when the owner sets it up. List every route that is common for the category.

- **`AccountLinked`** — *cloud-account linked*
  <br>Enrollment completes by binding the device to the owner's vendor-cloud account; the device is not usable until that link exists.
- **`BleProvisioned`** — *BLE provisioning*
  <br>Enrolled over Bluetooth Low Energy: the setup app connects to the device's BLE advertisement and hands it network credentials.
- **`MeshJoin`** — *mesh join (Zigbee/Z-Wave/Thread)*
  <br>Enrolled by joining a low-power mesh through its coordinator, typically during a permit-join window opened on the controller.
- **`QrPaired`** — *QR / setup-code paired*
  <br>Enrolled by scanning a printed code that carries the device's identity and a setup passcode, as in the Matter and HomeKit onboarding models.
- **`SoftApPaired`** — *SoftAP setup*
  <br>Enrolled through a temporary access point the device itself broadcasts: the owner joins that network and hands over the real network credentials, after which the setup AP closes.
- **`WpsPaired`** — *WPS*
  <br>Enrolled using Wi-Fi Protected Setup: the owner pushes a button or enters a PIN on the router, and the device joins without the network passphrase being entered on it.
- **`unsure`** — you could not tell even after looking. A real answer; use it rather than guessing a set.

## `patchResponsibility` — patch responsibility

Who has to act before a released security fix is actually running on the device. List every arrangement common in the category.

- **`InstallerPatched`** — *installer-serviced*
  <br>Updating is normally done by the trade installer who commissioned the device, not by the resident.
- **`Unmaintained`** — *unmaintained*
  <br>No one is issuing fixes: the vendor has exited the market or the model is past support. Orthogonal to hiot:firmwareUpdateModel — this states that no fix is forthcoming, not that the device lacks a mechanism to receive one, so an unmaintained device may still have working OTA.
- **`UserPatched`** — *user-initiated*
  <br>A fix exists but reaches the device only when the owner acts: accepts a prompt, presses update in an app, or downloads and applies an image.
- **`VendorPatched`** — *vendor-pushed*
  <br>The vendor delivers the fix and the device applies it without the owner doing anything.
- **`unsure`** — you could not tell even after looking. A real answer; use it rather than guessing a set.

## `topology` — network topology

How the device is reached on the network. List every route that is common for the category.

- **`DirectIP`** — *directly addressable*
  <br>Has its own IP address on the home network and can be reached directly by a client on that network, with no hub or mesh relaying on its behalf. At category granularity this is not exclusive with hiot:MeshLeaf: a category can contain both Wi-Fi and Zigbee variants of the same product, and both values then apply.
- **`HubMediated`** — *hub-mediated*
  <br>Control passes through a separate controller; the hub is the exposed surface, not the device.
- **`MeshLeaf`** — *mesh leaf*
  <br>Reachable only through a mesh (Zigbee/Z-Wave/Thread), never routable from the internet on its own.
- **`unsure`** — you could not tell even after looking. A real answer; use it rather than guessing a set.
