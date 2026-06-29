# Product Categories + Keyword Modifiers

All keywords grouped into **similar-product categories**. Brands and protocols are **not** categories —
they're **modifiers**: terms you AND onto a generic device keyword to bias results toward consumer
smart devices and filter out industrial/enterprise noise (e.g. `camera` is noisy; `ip camera`,
`wifi camera`, or `hikvision camera` narrows it to home IoT).

How to read each category:
- **Devices** — the core device-type search terms.
- **Brands** — vendor/CPE modifiers most associated with this category.
- **Protocols** — the ecosystem/transport terms most relevant here (the full global pool also applies).

> Terms from the original keyword list are kept; **expanded** entries add common consumer brands,
> device variants, and components that frequently appear in IoT CVEs. Categories 12–14 are new groups
> the original list didn't cover. A few entries (EV/solar in 13; prosumer brands like ubiquiti/mikrotik
> in 8) sit on the edge of home scope — flagged where relevant.

---

## Global modifiers (apply to every category)

AND any of these with a device keyword to skew toward consumer smart devices:

- **Generic smart terms:** `smart`, `wifi`, `wi-fi`, `wireless`, `connected`, `ip`, `app-controlled`, `cloud`, `remote control`
- **Umbrella terms:** `iot`, `internet of things`, `smart home`, `home automation`, `smart device`, `smart appliance`
- **Protocols / radios:** `zigbee`, `z-wave` / `zwave`, `thread`, `matter`, `homekit`, `google home`, `alexa`, `mqtt`, `coap`, `6lowpan`, `bluetooth`, `ble`, `bluetooth low energy`, `nfc`, `wlan`, `lora` / `lorawan`
- **Platforms / ecosystems:** `home assistant`, `homeassistant`, `smartthings`, `hubitat`, `openhab`, `homey`, `tuya smart`, `smart life`, `google nest`, `apple home`, `siri`, `airplay`, `google assistant`
- **Firmware / components** (high-yield for IoT CVEs — embedded chips, OSes, and web stacks reused across home devices): `esp32`, `esp8266`, `espressif`, `tasmota`, `esphome`, `realtek`, `mediatek`, `broadcom`, `hisilicon`, `allwinner`, `busybox`, `dropbear`, `goahead`, `boa`, `lighttpd`, `mini_httpd`, `uclibc`, `freertos`, `rtos`, `openwrt`, `dd-wrt`
- **Cross-category brands** (span many groups — white-label or broad ecosystems): `xiaomi`, `tuya`, `samsung smartthings`, `aqara`, `wyze`, `bosch`, `honeywell`, `nest`, `eufy`, `switchbot`, `shelly`, `sonoff`

---

## 1. Cameras, doorbells & monitors
- **Devices:** ip camera, network camera, security camera, surveillance camera, cctv camera, wifi camera, wireless camera, outdoor camera, indoor camera, ptz camera, pan-tilt camera, dome camera, bullet camera, pet camera, webcam, video doorbell, smart doorbell, doorbell camera, baby monitor, nanny cam, nvr, network video recorder, dvr
- **Brands:** hikvision, dahua, ezviz, ring, arlo, wyze, reolink, eufy, blink, tapo, kasa, foscam, amcrest, lorex, swann, night owl, zmodo, geeni, merkury, vstarcam, ubiquiti, unifi, axis, vivotek, uniview, simplisafe, nest, google nest cam, anker, xiaomi, tuya, bosch
- **Protocols:** wifi, ip, onvif, rtsp, p2p, homekit, alexa

## 2. Locks & access control
- **Devices:** smart lock, door lock, smart deadbolt, electronic lock, keyless lock, fingerprint lock, biometric lock, wifi lock, bluetooth lock, smart latch, smart padlock, garage door opener, smart garage door, door access, access control
- **Brands:** nuki, yale, august, schlage, kwikset, ultraloq, level, lockly, eufy, igloohome, tedee, sifely, switchbot, wyze, aqara, philips, samsung, xiaomi
- **Protocols:** zigbee, z-wave, matter, thread, ble, nfc, homekit

## 3. Alarms, sensors & detectors
- **Devices:** motion sensor, pir sensor, door sensor, window sensor, contact sensor, occupancy sensor, presence sensor, vibration sensor, glass break sensor, tilt sensor, temperature sensor, humidity sensor, air quality sensor, smoke detector, smart smoke detector, heat detector, co detector, co2 detector, carbon monoxide detector, gas detector, water leak sensor, leak detector, flood sensor, smart alarm, home alarm, alarm system, security system, siren, panic button, doorbell chime
- **Brands:** bosch, honeywell, ring, simplisafe, abode, scout, frontpoint, vivint, fibaro, ecolink, first alert, kidde, x-sense, develco, aqara, samsung smartthings, sonoff, eufy, xiaomi, nest
- **Protocols:** zigbee, z-wave, matter, thread, mqtt, ble

## 4. Climate & air
- **Devices:** thermostat, smart thermostat, hvac controller, smart hvac, smart radiator valve, trv, thermostatic valve, smart heater, heat pump, mini split, smart vent, smart air conditioner, smart ac, smart fan, ceiling fan, tower fan, smart air purifier, smart humidifier, smart dehumidifier
- **Brands:** nest, ecobee, honeywell, resideo, hive, drayton, tado, sensibo, mysa, emerson sensi, netatmo, daikin, mitsubishi electric, midea, gree, dyson, levoit, coway, blueair, lg smart, xiaomi, tuya
- **Protocols:** zigbee, z-wave, matter, homekit, google home, alexa

## 5. Plugs, switches & lighting
- **Devices:** smart plug, smart outlet, smart socket, power plug, smart wall plug, smart power strip, smart relay, smart switch, wall switch, in-wall switch, light switch, dimmer switch, smart dimmer, scene switch, smart button, wireless switch, energy monitor, smart breaker, smart light, smart bulb, smart lamp, led bulb, wifi bulb, rgb bulb, smart lighting, led strip, light strip
- **Brands:** shelly, sonoff, wemo (belkin), tp-link, kasa, tapo, lutron, lutron caseta, philips hue, ikea tradfri, govee, nanoleaf, lifx, yeelight, sengled, meross, gosund, teckin, treatlife, feit, wiz, cync, leviton, emporia, athom, refoss, tuya, wyze, xiaomi, aqara
- **Protocols:** zigbee, z-wave, matter, thread, wifi, mqtt

## 6. Major appliances / white goods
- **Devices:** smart fridge, smart refrigerator, smart oven, smart range, smart cooker, smart microwave, smart dishwasher, smart washer, smart washing machine, smart dryer, smart coffee maker, smart kettle, air fryer, smart pressure cooker, smart toaster, smart freezer, wine cooler, smart vacuum, vacuum cleaner, robot vacuum, robotic vacuum, robot cleaner, robot mop, smart scale, smart toilet, smart water heater
- **Brands:** lg smart, samsung smartthings, whirlpool, ge appliances, bosch, miele, haier, electrolux, midea, roborock, ecovacs, irobot, roomba, shark, eufy, dreame, neato, narwal, tineco, instant pot, june, anova, xiaomi
- **Protocols:** wifi, matter, google home, alexa

## 7. Hubs, bridges & controllers
- **Devices:** smart hub, home hub, home automation hub, smart home hub, iot hub, iot gateway, zigbee hub, zigbee gateway, zigbee coordinator, zwave hub, z-wave controller, matter hub, matter controller, thread border router, border router, smart bridge, bridge, gateway, home controller, home automation controller
- **Brands:** samsung smartthings, aqara, ikea tradfri, ikea dirigera, philips hue bridge, home assistant, hubitat, homey, wink, vera, fibaro, aeotec, conbee, zooz, sonoff zbbridge, nabu casa, xiaomi, tuya
- **Protocols:** zigbee, z-wave, thread, matter, mqtt, coap, homekit
- *Note:* bare `bridge` / `gateway` are very noisy — only use them AND-ed with a brand or protocol.

## 8. Networking & home gateways
- **Devices:** home router, wifi router, wireless router, smart router, gaming router, travel router, lte router, 5g router, modem router, residential gateway, home gateway, broadband router, cable modem, dsl modem, ont, home access point, wifi access point, mesh wifi, wifi extender, range extender, wifi repeater, powerline adapter, poe switch, network switch, home firewall
- **Brands:** tp-link (tplink), d-link (dlink), netgear, orbi, deco, asus, tenda, linksys, belkin, eero, google wifi, google nest wifi, fritzbox, avm, zyxel, ubiquiti, unifi, mikrotik, huawei, zte, arris, technicolor, sagemcom, synology, qnap, draytek, actiontec
- **Protocols:** wifi, wifi 6, wireless, openwrt
- *Note:* ubiquiti/mikrotik/zyxel/draytek lean prosumer — include but expect enterprise CVE overlap.

## 9. Speakers, voice & displays
- **Devices:** smart speaker, voice assistant, smart display, smart screen, smart clock, smart alarm clock
- **Brands / ecosystems:** amazon echo, echo dot, echo show, alexa, google home, google nest hub, apple homepod, sonos, bose, lenovo, facebook portal, harman kardon, jbl, xiaomi
- **Protocols:** wifi, alexa, google assistant, siri, airplay, homekit

## 10. Entertainment / media
- **Devices:** smart TV, set-top box, streaming box, streaming stick, media player, media streamer, smart projector, tv box, android tv, google tv
- **Brands:** lg smart, samsung smartthings, roku, amazon fire tv, apple tv, chromecast, nvidia shield, tivo, xiaomi
- **Protocols:** wifi, dlna, chromecast, airplay

## 11. Sleep & bed
- **Devices:** sleep tracker, sleep monitor, bedside monitor, under-mattress sensor, sleep sensor, contactless sleep monitor, smart bed, smart mattress
- **Brands:** withings, eight sleep, sleep number, emfit, beautyrest, tempur, google nest hub (sleep sensing)
- **Protocols:** wifi, ble
- *Note (existing scope issue):* wearables (Fitbit/Apple Watch/Oura/Garmin/Whoop) are personal/mobile — keep separate.

## 12. Shades, blinds & coverings *(new group)*
- **Devices:** smart blinds, smart shades, motorized blinds, motorized shades, roller shade, smart curtain, curtain motor, smart shutter, window covering
- **Brands:** somfy, lutron serena, soma, switchbot, ikea fyrtur, aqara curtain, zemismart, graywind, tuya, xiaomi
- **Protocols:** zigbee, z-wave, matter, ble, wifi

## 13. Energy, EV & utilities *(new group — some entries push home scope)*
- **Devices:** ev charger, evse, home battery, solar inverter, smart meter, energy monitor, smart panel, smart breaker, smart water heater, sub-meter
- **Brands:** tesla powerwall, wallbox, juicebox, chargepoint home, enphase, solaredge, sense, emporia, span
- **Protocols:** wifi, ocpp, modbus
- *Note:* EV chargers / solar inverters are residential but borderline on the "monitor/automate/control the home environment" function — scope-flag if you add them.

## 14. Outdoor, garden & pet *(new group)*
- **Devices:** smart sprinkler, irrigation controller, smart irrigation, robot lawn mower, robot mower, weather station, smart garden, pool controller, smart pool, pet feeder, smart feeder, smart litter box, pet camera, pet tracker, smart bird feeder
- **Brands:** rachio, rainbird, orbit b-hyve, gardena, husqvarna automower, worx landroid, netatmo weather, ecowitt, ambient weather, petlibro, petnet, sureflap, litter-robot, whisker, furbo
- **Protocols:** wifi, ble, lora

---

## How to use the modifiers in keyword search

1. **Broad pass:** search the bare device term (`thermostat`) to capture everything.
2. **Narrowing pass:** if a term is noisy/generic, AND it with a modifier from this category or the
   global pool (`thermostat zigbee`, `thermostat ecobee`, `smart thermostat`) to bias toward consumer
   smart devices.
3. **Brand sweep:** search each category's brands directly to catch devices whose description never
   uses the generic device word — but remember multi-market brands (`honeywell`, `bosch`, `samsung`,
   `ubiquiti`) also return industrial/enterprise hits, so pair them with a device term.
4. **Firmware/component sweep:** the firmware/component modifiers (`esp32`, `tasmota`, `busybox`,
   `goahead`, `realtek`…) catch IoT CVEs that name the chip/stack but not the product — high recall,
   so verify hits against a device or brand term.
