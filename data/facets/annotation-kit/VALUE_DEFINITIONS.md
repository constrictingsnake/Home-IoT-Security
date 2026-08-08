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
