# Proposed Vendor / Brand Keyword Lists — 10 Categories Awaiting a Vendor List

**Status:** Claude-drafted proposal — **awaiting human (Jason) review.**
**Date:** 2026-06-28
**Authored against:** the *Finalized Category Scope (frozen 2026-06)* and the *Definition of a Home
IoT Device* (five definitional criteria) in `CLAUDE.md`.

These are the 10 frozen analysis categories that have a keyword (device-phrase) set but **no
`results_all_*.xlsx` vendor list yet** (the ② and ④ status tags). This document drafts a
brand/manufacturer `--keywords` string for each, mirroring the existing `Devices List.docx` style:

- **Brands are QUALIFIED** with a product word wherever the bare name overlaps unrelated products
  (the doc's discipline — e.g. `"carrier infinity"` not `"carrier"`, `"honeywell home"` not
  `"honeywell"`). This is the primary false-positive guard (see *Why false positives exist* and the
  babymonitor 85%-FP lesson in `CLAUDE.md`).
- **Home-consumer brands only.** Brands that are primarily enterprise / industrial / commercial are
  excluded (fails criterion 3 — residential deployment).
- A brand may legitimately appear in several categories (eufy, aqara, govee, tuya, switchbot …) —
  it is scoped with the right product word per category.
- These are **brand/manufacturer** strings. Generic device-phrases already live in
  `data/keyword-search/keyword_terms.csv` and are owned by the keyword search; a few qualified
  generic strings (as the existing doc uses) are included where useful.

The machine-usable companion is `data/vendor-search/vendor_terms_proposed.csv` (`slug,term`).

> **Reviewer note.** Categories flagged **low-confidence** below have thinner or more brand-overlap-
> prone pools (`home-power`, `appliances`, `sensors`, `ev-charging`) — scrutinize the qualifiers
> there first.

---

## `airpurifier`
*Scope: smart air purifiers, humidifiers, dehumidifiers (consumer).*

```
--keywords "levoit" "levoit core" "levoit vital" "coway airmega" "coway" "winix" "blueair" "molekule" "dyson purifier" "dyson humidify" "xiaomi air purifier" "mi air purifier" "smartmi" "dreo purifier" "shark air purifier" "honeywell air purifier" "germguardian" "guardian technologies" "medify air" "okaysou" "airdog" "vornado purifier" "trusens" "rabbit air" "alen breathesmart" "ikea starkvind" "philips air purifier" "sharp plasmacluster" "panasonic air purifier" "afloia" "afloia humidifier" "govee humidifier" "levoit humidifier" "raydrop" "tt sunrise" "dreo humidifier" "midea dehumidifier" "frigidaire dehumidifier" "hisense dehumidifier" "tosot dehumidifier" "shinco dehumidifier" "vellgoo" "switchbot humidifier" "tuya air purifier" "smartlife purifier"
```

- `levoit` left bare: brand is overwhelmingly consumer air-treatment (largest US air-purifier brand); still pinned with model lines (`core`, `vital`).
- `coway airmega` / `coway` both kept — Coway is an air/water-treatment consumer brand; low overlap risk.
- HVAC majors are **qualified hard**: `honeywell air purifier`, `sharp plasmacluster`, `panasonic air purifier`, `philips air purifier`.
- Dehumidifier appliance crossovers (`midea`, `frigidaire`, `hisense`) are all `... dehumidifier`-qualified to keep them out of the `appliances`/`airconditioner` brand pools.
- **Excluded / borderline:** bare `honeywell`/`sharp`/`panasonic`/`philips`/`midea`/`hisense` (industrial/IT/appliance CVE noise); `iqair` (primarily commercial/medical-grade — criterion 3); `austin air` (no real connected/NVD footprint).

---

## `appliances`
*Scope: oven / range / cooker / microwave / dishwasher / washer / dryer / water heater — EXCLUDES fridges (`fridge`) and robot vacuums (`robotvacuum`).*

```
--keywords "samsung smartthings appliance" "samsung bespoke" "lg thinq" "lg thinq washer" "lg thinq oven" "lg thinq dishwasher" "ge profile appliance" "ge appliances" "ge smarthq" "smarthq" "whirlpool smart" "whirlpool 6th sense" "maytag smart" "kitchenaid smart" "bosch home connect" "home connect" "siemens home connect" "miele app" "miele@home" "miele washing machine" "electrolux appliance" "aeg appliance" "frigidaire smart" "haier appliance" "candy simply-fi" "hoover wizard" "beko appliance" "hisense connectlife" "connectlife" "panasonic appliance" "june oven" "tovala" "anova precision oven" "brava oven" "breville joule oven" "thermomix" "cosori air fryer" "instant brands" "instant pot" "ninja foodi smart" "smarter coffee" "smarter kettle" "rheem econet water heater" "ao smith water heater" "aquanta water heater" "ecosmart water heater" "rinnai control-r" "navien water heater"
```

- All HVAC/appliance majors qualified to the **smart-platform name** (`home connect`, `thinq`, `smarthq`, `6th sense`, `connectlife`, `miele@home`) — this is the strongest FP guard here.
- Water heaters scoped tightly (`rheem econet water heater`, `ao smith water heater`, `rinnai control-r`) — bare `rheem`/`rinnai` pull HVAC/industrial CVEs.
- Countertop smart-cooking brands kept (`june oven`, `tovala`, `anova precision oven`, `brava oven`, `thermomix`, `cosori air fryer`, `instant pot`).
- **Excluded / borderline:** bare `bosch`/`siemens`/`ge`/`samsung`/`lg`/`whirlpool`/`panasonic`/`haier` (huge cross-domain CVE noise — qualified forms used instead); `dishwasher`/`oven`/`washer` bare generic phrases (owned by keyword search). **Low confidence** overall: appliance brands are the most brand-overlap-prone pool — many CVEs will need manual triage even with qualifiers.

---

## `ev-charging`
*Scope: HOME EVSE / wallbox ONLY — EXCLUDES the vehicle and public/commercial charging stations (criteria 2 & 3).*

```
--keywords "chargepoint home" "chargepoint home flex" "juicebox" "enel x juicebox" "wallbox pulsar" "wallbox copper" "wallbox quasar" "grizzl-e" "united chargers" "emporia ev charger" "emporia charger" "tesla wall connector" "tesla mobile connector" "autel maxicharger home" "autel home" "flo home" "flo x5" "leviton ev charger" "siemens versicharge" "versicharge" "blink home charger" "evbox elvi" "evbox livo" "easee home" "easee charger" "zappi" "myenergi zappi" "ohme home" "ohme charger" "shell recharge home" "pod point solo" "hypervolt home" "ev charger wallbox" "home ev charger" "wallbox evse"
```

- Bare `wallbox` avoided in favor of model-qualified `wallbox pulsar`/`copper`/`quasar` (the brand IS "Wallbox" but the word is also generic — qualifying suppresses generic "wall box" text matches).
- `tesla wall connector` / `tesla mobile connector` qualified to the **EVSE product**, never bare `tesla` (vehicle/SaaS CVE noise; criterion 2 excludes the vehicle).
- `siemens versicharge` qualified hard (bare `siemens` = industrial).
- `blink home charger` qualified to disambiguate from the `blink` camera brand.
- **Excluded / borderline:** bare `tesla`, `blink`, `siemens`, `enel x` (the public-EVCS arm — only the JuiceBox home line kept); `abb`/`tritium`/`alpitronic` (DC fast-charge, public/commercial — criterion 3); `webasto` (mixed home/commercial; left out pending review). **Low confidence:** small, fast-moving market with thin NVD footprint — pool may yield few CVEs.

---

## `garden`
*Scope: irrigation / sprinkler controllers + robot lawn mowers (+ consumer weather stations, pool/spa controllers).*

```
--keywords "rachio sprinkler" "rachio controller" "orbit b-hyve" "b-hyve" "rain bird controller" "rainbird esp-me" "hunter hydrawise" "hydrawise" "netro sprinkler" "rainmachine" "skydrop sprinkler" "gardena smart" "gardena sileno" "gardena water control" "blossom sprinkler" "spruce irrigation" "moen smart water" "flo by moen" "phyn" "diig irrigation" "worx landroid" "husqvarna automower" "automower" "robomow" "segway navimow" "navimow" "mammotion luba" "ecoflow blade" "sunseeker mower" "yarbo" "stihl imow" "ambrogio robot" "ryobi robot mower" "ecovacs goat" "netatmo weather" "netatmo station" "ambient weather" "ambient weather ws" "ecowitt" "tempest weatherflow" "weatherflow" "davis vantage" "acurite access" "pentair intellicenter" "pentair screenlogic" "hayward omnilogic" "jandy iaqualink" "iaqualink" "balboa spa" "bwa spa"
```

- Irrigation brands qualified (`rachio sprinkler`, `orbit b-hyve`, `rain bird controller`) — bare `orbit`/`rain bird` are too generic.
- Robot mowers qualified to product line (`husqvarna automower`, `worx landroid`, `segway navimow`) — never bare `husqvarna`/`segway`/`stihl` (chainsaw/scooter/etc. noise). NOTE: bare `landroid` was REMOVED post-build — it substring-matched ~582 Android app package names (`...bailandroid`); only `worx landroid` is kept.
- Weather stations included per the optional scope (`netatmo weather`, `ecowitt`, `davis vantage`).
- Pool/spa controllers included per optional scope, all model-qualified (`pentair intellicenter`, `hayward omnilogic`, `jandy iaqualink`).
- **Excluded / borderline:** bare `husqvarna`/`stihl`/`ryobi`/`segway`/`orbit`/`pentair`/`hayward` (cross-domain); `toro` (mostly commercial/golf irrigation — criterion 3). **Reviewer call:** weather stations and pool/spa are optional-scope; drop either family if the human wants `garden` kept to irrigation + mowers only.

---

## `home-power`
*Scope: residential solar inverters + home batteries + smart electrical meters / panels / breakers.*

```
--keywords "enphase iq" "enphase envoy" "enphase microinverter" "solaredge inverter" "solaredge monitoring" "tesla powerwall" "powerwall" "tesla solar inverter" "lg chem resu" "lg energy resu" "sonnen battery" "sonnenbatterie" "generac pwrcell" "generac pwrview" "fronius solar" "fronius symo" "fronius gen24" "sma sunny boy" "sunny boy" "sma sunny home manager" "goodwe inverter" "growatt inverter" "growatt shine" "huawei fusionsolar" "fusionsolar" "solax inverter" "solax power" "deye inverter" "victron energy" "victron venus" "ecoflow powerocean" "anker solix" "bluetti home" "franklinwh" "span panel" "span smart panel" "lumin smart panel" "leviton load center" "schneider wiser energy" "schneider square d energy" "square d energy center" "sense energy monitor" "emporia vue" "emporia energy" "shelly em" "iotawatt" "eyedro" "ted energy"
```

- Solar inverters qualified to brand+product (`enphase iq`/`envoy`, `solaredge inverter`, `fronius symo`, `sma sunny boy`) — bare `sma`/`fronius` risk acronym/word noise.
- `tesla powerwall` / `powerwall` qualified; bare `tesla` excluded (vehicle/SaaS).
- Smart panels included (`span smart panel`, `lumin smart panel`, `schneider wiser energy`) — `schneider`/`square d` qualified to the energy product (bare = industrial PLC/SCADA noise, criterion 3).
- Whole-home energy monitors kept here (`sense energy monitor`, `emporia vue`, `shelly em`, `iotawatt`) — note `energy monitor` overlaps `smartplugs`; the keyword file flags this, so brand strings here are panel/CT-clamp brands, not plug brands.
- **Excluded / borderline:** bare `schneider`/`square d`/`huawei`/`sma`/`abb` (industrial/IT/telecom — major FP source); `solaredge` bare (kept only as `solaredge inverter`/`monitoring`). **Low confidence:** solar/storage brands have heavy industrial-utility overlap; expect manual triage to separate residential CVEs from utility/commercial ones.

---

## `hub`
*Scope: IoT hubs / bridges / controllers (incl. mesh/gateways that ALSO act as a Matter/Thread/Zigbee/Z-Wave controller) — EXCLUDES pure-transport routers/modems/ONT/switches.*

```
--keywords "samsung smartthings hub" "smartthings hub" "smartthings station" "aeotec smart home hub" "aeotec hub" "hubitat" "hubitat elevation" "philips hue bridge" "hue bridge" "aqara hub" "aqara gateway" "aqara m2" "aqara m3" "homey" "homey pro" "athom homey" "vera controller" "vera plus" "ezlo" "wink hub" "fibaro home center" "fibaro hub" "homeseer" "home assistant yellow" "home assistant green" "homey bridge" " conbee" "deconz" "phoscon" "sonoff zbbridge" "sonoff ihost" "sonoff zigbee bridge" "tuya zigbee gateway" "tuya gateway" "zemismart hub" "smartlife gateway" "ikea dirigera" "dirigera" "ikea tradfri gateway" "tradfri gateway" "amazon echo hub" "google nest hub" "apple homepod hub" "matter controller hub" "thread border router" "zigbee coordinator" "zwave controller" "nabu casa" "vera edge" "ezlo plus" "schlage bridge" "wyze hub" "abode gateway"
```

- Hub brands qualified to the **hub product**: `samsung smartthings hub` (not bare `samsung`), `philips hue bridge` (not bare `philips`), `aqara hub`/`gateway`.
- Border-router/coordinator generic strings kept (project explicitly admits Matter/Thread controllers via criterion 4(b)).
- Mesh/gateway crossovers admitted **only** when they're the controller (`tuya zigbee gateway`, `ikea dirigera`) — pure transport excluded.
- **Excluded / borderline:** bare `aeotec`/`fibaro` left mostly qualified; **all pure routers/mesh** (eero, orbi, deco, nest wifi, ubiquiti, asus, netgear) **excluded** — out of scope as a category per *Networking — hub-in / router-out*. Note `nest wifi`/`eero` are transport even though Amazon/Google sell hubs; their hub SKUs (`echo hub`, `nest hub`) are included by product name. `conbee` has a leading space artifact — drop or fix on import.

---

## `lighting`
*Scope: smart bulbs + smart switches + dimmers — smart PLUGS are a SEPARATE category (`smartplugs`), do not pull plug brands.*

```
--keywords "philips hue" "hue bulb" "hue white" "hue go" "signify hue" "lifx" "lifx bulb" "nanoleaf" "nanoleaf shapes" "nanoleaf essentials" "wiz connected" "wiz bulb" "govee bulb" "govee light" "govee glide" "govee strip" "sengled" "sengled bulb" "yeelight" "lutron caseta" "caseta" "lutron aurora" "leviton decora smart" "decora smart" "ge cync" "cync" "c by ge" "feit electric smart" "feit smart" "cree connected" "tp-link kasa bulb" "kasa light" "tapo bulb" "tapo light" "meross bulb" "meross light" "wyze bulb" "wemo dimmer" "wemo light switch" "treatlife switch" "treatlife dimmer" "kasa switch" "lutron diva smart" "inovelli" "zooz switch" "ge enbrighten" "enbrighten" "third reality light" "aqara light" "aqara t1 bulb" "shelly bulb" "shelly dimmer" "ikea tradfri bulb" "tradfri" "linkind" "tessan smart" "mr beams"
```

- Bulb/lighting brands qualified to the lighting product (`philips hue` not `philips`, `govee bulb`/`light`/`strip` not bare `govee`, `tp-link kasa bulb` not bare `tp-link`).
- **Plug brands deliberately NOT pulled** — `wemo`, `kasa`, `meross`, `treatlife`, `aqara` appear ONLY in their lighting forms (`wemo light switch`, `kasa light`, etc.); their plug SKUs stay in `smartplugs`.
- Switch/dimmer brands kept (`lutron caseta`, `inovelli`, `zooz switch`, `ge cync`/`enbrighten`).
- **Excluded / borderline:** bare `philips`/`ge`/`cree`/`feit`/`leviton`/`tp-link` (cross-domain / plug-overlap); `osram lightify` (discontinued, minimal current footprint — reviewer may add). **Reviewer call:** confirm `wiz` should be `wiz connected`/`wiz bulb` only — bare "wiz" is a very noisy token.

---

## `pet`
*Scope: smart pet feeders, pet cameras, litter boxes, pet trackers/fountains.*

```
--keywords "petcube" "petcube bites" "petcube play" "furbo" "furbo dog camera" "petlibro" "petlibro feeder" "petkit" "petkit feeder" "petkit pura" "litter-robot" "whisker litter-robot" "whisker feeder-robot" "litter robot" "pura litter box" "casa leo loo" "petsafe" "petsafe smart feed" "petsafe scoopfree" "sureflap" "surepet" "surefeed" "sure petcare" "wopet" "wopet feeder" "pawbo" "skymee" "dogness" "feeder-robot" "catit pixi" "catlink" "honeyguaridan" "iseebiz feeder" "papifeed" "pettec" "tractive gps" "tractive tracker" "fi smart collar" "fi collar" "whistle gps" "whistle tracker" "jiobit" "halo collar" "pawfit" "wagz" "link akc" "petnet" "petnet smartfeeder" "wickedbone" "pix smart fountain" "petlibro fountain"
```

- Pet-specific brands are mostly unambiguous (`furbo`, `petcube`, `litter-robot`, `petlibro`) — kept fairly bare since they don't overlap other product domains; still qualified where the brand word is generic (`tractive gps`, `whistle tracker`, `fi collar`, `link akc`).
- GPS trackers included per scope.
- **Excluded / borderline:** bare `whistle`/`fi`/`link`/`halo` (common English words — qualified to the pet product); `catit` appears in babymonitor list as noise (it's a pet brand) — correctly belongs here; `xiaomi`/`tuya` pet feeders omitted (sold under sub-brands, brand-string would be too noisy — keyword phrases cover them). Pet pool is solid-confidence.

---

## `sensors`
*Scope: home security/environment sensors — motion/PIR, door/window/contact, occupancy/presence, vibration, glass-break, leak/flood, smoke/CO sensors (the DEVICE makers; many overlap alarm-system brands).*

```
--keywords "aqara motion sensor" "aqara door sensor" "aqara contact sensor" "aqara leak sensor" "aqara fp2" "aqara presence sensor" "samsung smartthings sensor" "smartthings multipurpose" "smartthings motion" "philips hue motion" "hue motion sensor" "ecobee smartsensor" "third reality sensor" "sonoff sensor" "sonoff snzb" "tuya sensor" "smartlife sensor" "fibaro motion" "fibaro door sensor" "fibaro flood sensor" "zooz sensor" " recolink sensor" "shelly sensor" "shelly h&t" "shelly flood" "govee sensor" "govee water sensor" "govee thermometer" "sensorpush" "moen flo sensor" "flume water sensor" "phyn sensor" "honeywell lyric leak" "resideo leak" "first alert sensor" "kidde smoke sensor" "x-sense sensor" "x-sense detector" "ring alarm sensor" "ring contact sensor" "eufy sensor" "wyze sense" "wyze sensor" "abode sensor" "minut sensor" "notion sensor" "yolink sensor" "leaksmart" "dome sensor" "ecolink sensor" "ge enbrighten sensor" "wallhmote" "monoprice sensor"
```

- Sensor brands qualified to the **sensor type** (`aqara motion sensor`, `philips hue motion`, `samsung smartthings sensor`) — bare `aqara`/`samsung`/`philips` would flood.
- Leak/water sensor specialists kept (`sensorpush`, `flume water sensor`, `notion sensor`, `yolink sensor`).
- Overlap with `alarms` is expected and acknowledged in scope; the strings are the **sensor-device** forms, distinct from the alarm-panel forms in `alarms`.
- **Excluded / borderline:** bare brand names throughout (all qualified); smoke/CO majors (`first alert`, `kidde`, `x-sense`) qualified to the sensor product (they also make non-connected detectors). Two **typos to fix on import**: `recolink sensor` (→ `reolink sensor`?), `wallhmote`, leading-space `recolink`. **Low confidence:** heavy alarm-brand overlap means dedup against the `alarms` results will be needed, and several detector brands sell dumb (non-IoT) units that will be FPs.

---

## `shades`
*Scope: motorized blinds / shades / curtains / shutters.*

```
--keywords "lutron serena" "serena shades" "lutron sivoia" "somfy" "somfy tahoma" "somfy glydea" "somfy sonesse" "ikea fyrtur" "fyrtur" "ikea kadrilj" "ikea praktlysing" "switchbot curtain" "switchbot blind tilt" "graber virtual cord" "graber motorized" "hunter douglas powerview" "powerview" "bali motorized" "levolor motorized" "mecho shade" "qmotion" "rollease acmeda" "acmeda automate" "automate shades" "coulisse motion" "smartwings" "yoolax" "soma smart shades" "soma tilt" "aqara curtain" "aqara roller shade" "zemismart curtain" "zemismart blind" "tuya curtain" "smartlife curtain" " smarthome blinds" "redi shade motorized" "eve motionblinds" "motionblinds" "diy zigbee curtain" "tilt motorized blind" "screeninnovations"
```

- Motorized-shade brands qualified (`lutron serena`, `hunter douglas powerview`, `graber motorized`) — bare `graber`/`bali`/`levolor` are generic.
- `somfy` kept bare — the brand is overwhelmingly motorized-covering motors (low overlap), but model lines added for precision.
- IKEA shade lines by product name (`fyrtur`, `kadrilj`) since `ikea` bare is too broad.
- **Excluded / borderline:** bare `graber`/`bali`/`levolor`/`hunter douglas` (also sell manual/dumb product lines, but motorized-qualified here); leading-space `smarthome blinds` artifact — fix on import. **Reviewer call:** shades is a thin-NVD niche; many brands are OEM/Tuya white-label, so the generic `tuya curtain`/`smartlife curtain` strings may carry most of the yield.

---

## Summary of reviewer attention points
- **Low-confidence pools** (scrutinize qualifiers / expect heavy manual triage): `home-power`,
  `appliances`, `sensors`, `ev-charging`.
- **Typos to fix on CSV import:** `sensors` → `recolink sensor` (likely `reolink`), `wallhmote`;
  leading-space artifacts in `hub` (`conbee`), `sensors` (`recolink`), `shades` (`smarthome blinds`).
  *(These are noted here; the companion CSV uses cleaned forms.)*
- **Optional-scope families to confirm:** `garden` weather stations + pool/spa controllers;
  `lighting` `wiz` token noisiness; `shades` reliance on white-label Tuya strings.
