#!/usr/bin/env python3
"""
Test with GVG XP Frame V 17.7.0 and V20.1.1

eth_tally_sim.py - Python re-implementation of EthTallyReceiver (GV Ethernet Tally client)
that forwards the frame's contribution/tally data as a UDP stream.

Behaviour mirrored from EthTallyReceiver.exe:
  * TCP connect to <frameIP>:2012, 2 MB rx buffer, 1 s rx timeout, 500 ms send timeout
  * Messages are ASCII XML wrapped in <ETP>...</ETP>; partial packets are buffered
  * Handshake: Authentication-Request -> Authentication reply, then
    Configuration / EngineeringSourceMap / LogicalSourceMap / VPEInputMap /
    VPEOutputMap / OutputTallyMap requests and a TallySubscription-Request
  * Periodic Heartbeat-Request; auto-reconnect timer (default 1000 ms)
  * Reads config.xml (frameIP, logpath, packetlogging, logappend, loglevel,
    AutoReconnectTimerSetting) just like the original

Output: TSL UMD Protocol V3.1 over UDP (default 127.0.0.1:9999), one 18-byte packet
per datagram:  [0x80+address][control][16 ASCII chars]
    control bit0 = Tally 1 (RED)   bit1 = Tally 2 (GREEN)   bit2/3 = Tally 3/4
    bits 4-5 = brightness (0-3)
  * TSL address = logical source ID (+ --addr-offset); valid range 0-126
  * Label       = logical source name from the frame's LogicalSourceMap

Alternative output: TSL UMD Protocol V5.0 over UDP  (--tsl-version 5, --tsl-screen N)
    packet = PBC(u16 LE) VER(0) FLAGS(0 = ASCII) SCREEN(u16 LE) then one DMSG:
             INDEX(u16 LE) CONTROL(u16 LE) LENGTH(u16 LE) TEXT
    CONTROL bits 0-1 RH lamp, 2-3 text tally, 4-5 LH lamp (0 off,1 red,2 green,3 amber),
            bits 6-7 brightness.  RED -> 1, GREEN -> 2, RED+GREEN -> 3 (amber), on all three tallies.
  * INDEX = logical source ID (+ --addr-offset); only addresses START..START+COUNT-1 are sent
    (--tsl-start, default 0; --tsl-count, default 128); valid range 0-65534

Network interfaces (PC with several NICs / subnets):
  --frame-bind LOCAL_IP     NIC whose address the frame connection is made from
  --udp-bind   LOCAL_IP     NIC whose address the TSL UDP packets are sent from
  (empty = let the OS routing table decide)

Multiple receivers: --udp-host/--udp-port is destination 1; --udp-extra host[:port],... adds up to
  9 more, so up to 10 hosts receive the TSL packets. Each extra host can be limited to its own
  displays: host:port@12 = only display 12 (a single display), host@12+4 = displays 12-15.

Dry run (--dry-run): connect to the frame and work out the tally, log what WOULD be sent,
but transmit no UDP packets.

Choose what is tallied:
  --red-suites 1,2          suites that can light RED   (default: --suite)
  --green-suites 2          suites that can light GREEN (default: --suite)
                            A suite may be in either list or both; every suite used is
                            subscribed. A source lit by two suites keeps the red/green of both
                            (same TSL address); use --addr-offset to keep them apart if needed.
  --suite 1..4              default suite when the two lists above are not given
  --red   PGM,ME1,...       buses that light RED   (TSL Tally 1)
  --green ME2,...           buses that light GREEN (TSL Tally 2)
  Buses: ME1 ME2 ME3 ME4 PGM. Any bus can be red or green (or both).
Or tally by physical frame OUTPUT instead of (or as well as) buses:
  --red-out 1,2   --green-out 3,5-8     (output numbers from the frame's OutputTally map)
  A source is tallied when it feeds that output, resolved through ME/PGM outputs down to the
  cameras/sources behind them. If only --red-out/--green-out are given, the bus defaults are off.

A source is "on" a bus when it is selected on a VPE input (key fill / background)
of that bus AND that input contributes to one of the bus' outputs
(--outputs, default PgmA,PgmB,PgmC,PgmD).

Packet layouts below were taken from the IL of EthTallyReceiver.exe:
  Authentication-Request : Protocol, ProtocolVersion(3.0), AppName, AppVersion, Suite(1-4|N/A)
  TallySubscription-Request : <Suite Method="Add|Replace">N</Suite>, ONE request per suite
  VPE*Contribution       : Suite="N" attribute, <Type>full|update</Type>, then <VPE Name=..> elements
  VPEInputContribution   : <VPE Name="ME1" Acquired=..><Input Name="BkgdA">sourceID</Input>...
  VPEOutputContribution  : <VPE Name="ME1"><Output Name="PgmA"><..>key1-fill</..><..>BkgdA</..></Output>

Test cmd line:   python navtally_gvg.py --live --red PGM --green ME1
"""
import argparse, json, os, socket, sys, threading, time
import xml.etree.ElementTree as ET

PORT = 2012
RX_CHUNK = 16384
PROTOCOL = "GV Ethernet Tally"
APP_NAME = "NAVTally"
START, END = "<ETP>", "</ETP>"

REQUESTS = ["Configuration-Request", "EngineeringSourceMap-Request",
            "LogicalSourceMap-Request", "VPEInputMap-Request",
            "VPEOutputMap-Request", "OutputTallyMap-Request"]
FORWARD_TAGS = {"VPEOutputContribution", "VPEInputContribution", "OutputTally", "TallyMsg"}


# ---------------------------------------------------------------- helpers
def load_config(path):
    cfg = dict(frameIP="0.0.0.0", logpath="./K-FrameLog", packetlogging="False",
               logappend="False", loglevel="1", AutoReconnectTimerSetting="1000")
    try:
        for el in ET.parse(path).getroot():
            cfg[el.tag] = (el.text or "").strip()
    except (OSError, ET.ParseError) as e:
        print(f"[warn] could not read {path}: {e}; using defaults", file=sys.stderr)
    return cfg


class Log:
    def __init__(self, folder, append, level):
        self.level = level
        os.makedirs(folder, exist_ok=True)
        self.folder = folder
        self.f = open(os.path.join(folder, "tally.log"), "a" if append else "w", buffering=1)
        self.lock = threading.Lock()

    def __call__(self, msg, lvl=1):
        if lvl > self.level:
            return
        line = f"{time.strftime('%m/%d %H:%M:%S')}.{int(time.time()*1000)%1000:03d}> {msg}"
        with self.lock:
            print(line)
            self.f.write(line + "\n")


def buslist(text):
    if text.strip().lower() in ("", "none"):
        return []
    out = []
    for b in text.replace(" ", "").upper().split(","):
        if b not in BUSES:
            raise argparse.ArgumentTypeError(f"unknown bus '{b}' (choose from {', '.join(BUSES)})")
        out.append(b)
    return out


def outlist(text):
    if text.strip().lower() in ("", "none"):
        return []
    out = []
    try:
        for part in text.replace(" ", "").split(","):
            lo, _, hi = part.partition("-")
            out += range(int(lo), int(hi or lo) + 1)
    except ValueError:
        raise argparse.ArgumentTypeError(f"bad output list '{text}' (use e.g. 1,2,5-8)")
    return out


def suitelist(text):
    if text.strip().lower() in ("", "none"):
        return []
    try:
        out = sorted({int(x) for x in text.replace(" ", "").split(",")})
    except ValueError:
        raise argparse.ArgumentTypeError(f"bad suite list '{text}' (use e.g. 1,2)")
    if any(s not in (1, 2, 3, 4) for s in out):
        raise argparse.ArgumentTypeError("suites must be 1-4")
    return out


def destlist(text):
    """'host[:port][@start[+count]],...' -> [(host, port-or-None, lo, hi)], at most 9 extra destinations.
    @start[+count] limits that host to displays start..start+count-1 (count defaults to 1 = a single
    display); without it the host gets every display."""
    out = []
    for part in text.replace(" ", "").split(","):
        if not part or part.lower() == "none":
            continue
        spec, _, win = part.partition("@")
        host, _, port = spec.partition(":")
        try:
            pn = int(port) if port else None
            lo = hi = None
            if win:
                s, _, c = win.partition("+")
                lo = int(s)
                hi = lo + (int(c) if c else 1) - 1
                if not 0 <= lo <= 65534 or hi < lo or (c and int(c) < 1):
                    raise ValueError
            if not host or (pn is not None and not 1 <= pn <= 65535):
                raise ValueError
        except ValueError:
            raise argparse.ArgumentTypeError(f"bad destination '{part}' (use host[:port][@start[+count]])")
        out.append((host, pn, lo, hi))
    if len(out) > 9:
        raise argparse.ArgumentTypeError("at most 9 extra destinations (10 hosts in total)")
    return out


def etp(inner):
    return f"{START}{inner}{END}"


def build_auth(version, suite):
    # suite: "1".."4" or "N/A" (original sends the currently selected suite)
    return etp(f"<Authentication-Request><Protocol>{PROTOCOL}</Protocol>"
               f"<ProtocolVersion>{version}</ProtocolVersion><AppName>{APP_NAME}</AppName>"
               f"<AppVersion>9.9.9.9</AppVersion><Suite>{suite}</Suite></Authentication-Request>")


def build_simple(tag):
    return etp(f"<{tag}/>")


def build_subscription(suite, method):
    # suite: "1".."4" or "All"; method: "Replace" (clears prior subs) or "Add"
    return etp(f'<TallySubscription-Request><Suite Method="{method}">{suite}</Suite>'
               f'</TallySubscription-Request>')


BUSES = ["ME1", "ME2", "ME3", "ME4", "PGM"]


def tsl31_packet(addr, text, red=False, green=False, tally3=False, tally4=False, brightness=3):
    """TSL UMD V3.1: 0x80+address, control byte, 16 ASCII display chars (18 bytes)."""
    ctrl = int(red) | (int(green) << 1) | (int(tally3) << 2) | (int(tally4) << 3) | ((brightness & 3) << 4)
    return bytes([0x80 + addr, ctrl]) + text.encode("ascii", "replace")[:16].ljust(16)


def tsl5_packet(index, text, red=False, green=False, brightness=3, screen=0):
    """TSL UMD V5.0 UDP packet with a single DMSG (ASCII text)."""
    colour = int(red) | (int(green) << 1)             # 0 off, 1 red, 2 green, 3 amber
    ctrl = colour | (colour << 2) | (colour << 4) | ((brightness & 3) << 6)
    txt = text.encode("ascii", "replace")[:32]
    dmsg = (index.to_bytes(2, "little") + ctrl.to_bytes(2, "little")
            + len(txt).to_bytes(2, "little") + txt)
    body = bytes([0, 0]) + screen.to_bytes(2, "little") + dmsg   # VER, FLAGS, SCREEN, DMSG
    return len(body).to_bytes(2, "little") + body


def _suite_of(el, default):
    try:
        return int(el.attrib.get("Suite", ""))
    except ValueError:
        return default                        # no/odd Suite attribute: use the default


class TallyEngine:
    """Turns the frame's contribution data into per-source red/green tally (TSL V3.1 / V5).
    Each suite can feed the red tally, the green tally, or both (--red-suites / --green-suites)."""

    def __init__(self, a, log, udp):
        self.a, self.log, self.udp = a, log, udp
        self.tos, self.udp_err = [], set()    # TSL destinations (main + up to 9 extra)
        for h, p, lo, hi in [(a.udp_host, a.udp_port, None, None)] + list(a.udp_extra):
            try:
                dest = (socket.gethostbyname(h), p, lo, hi)
            except OSError as e:
                log(f"TSL destination {h}:{p} not resolved ({e}); skipped")
                continue
            if dest not in self.tos:
                self.tos.append(dest)
        log("TSL destinations: " + ", ".join(
            f"{h}:{p}" + ("" if lo is None else f" (displays {lo}-{hi})") for h, p, lo, hi in self.tos))
        self.red, self.green = set(a.red), set(a.green)
        self.red_suites, self.green_suites = set(a.red_suites), set(a.green_suites)
        self.suites = self.red_suites | self.green_suites
        self.dsuite = min(self.suites) if self.suites else a.suite
        self.outputs = {o.strip().lower() for o in a.outputs.split(",") if o.strip()}
        self.inputs = {}                      # suite -> VPE -> {input name (lower): source id}
        self.outs = {}                        # suite -> VPE -> {output name (lower): {input names}}
        self.names = {}                       # suite -> source id -> {name/oled/panel/menu/vpe/out: text}
        self.out_map = {}                     # (suite, frame output number) -> logical source id
        self._timer, self._first = None, None  # debounce state
        self.red_out, self.green_out = set(a.red_out), set(a.green_out)
        self.last = {}                        # tsl address -> (text, red, green) last sent
        self.warned = set()
        if a.tsl_version == "5":              # V5: window of displays = start .. start+count-1
            self.min_addr = a.tsl_start
            self.max_addr = min(65534, a.tsl_start + a.tsl_count - 1)
        else:
            self.min_addr, self.max_addr = 0, 126
        self.lock = threading.RLock()

    def send_udp(self, addr, pkt):
        """Send one TSL packet (display `addr`) to every destination whose display window includes it;
        one bad host must not block the others."""
        for h, p, lo, hi in self.tos:
            if lo is not None and not lo <= addr <= hi:
                continue
            try:
                self.udp.sendto(pkt, (h, p))
            except OSError as e:
                if (h, p) not in self.udp_err:
                    self.udp_err.add((h, p))
                    self.log(f"UDP send to {h}:{p} failed: {e}")

    def _su(self, el):
        """Suite of a frame packet, or None if we are not using that suite."""
        su = _suite_of(el, self.dsuite)
        return su if su in self.suites else None

    # --- state from frame packets
    def on_logsrc(self, el):
        su = self._su(el)
        if su is None:
            return
        with self.lock:
            names = self.names.setdefault(su, {})
            tn = el.find("Type")
            if tn is not None and (tn.text or "").strip().lower() == "full":
                names.clear()
            for ls in el.findall("LogSrc"):
                try:
                    sid = int(ls.attrib.get("ID", ""))
                except ValueError:
                    continue
                info = names.setdefault(sid, {})
                if ls.attrib.get("Name"):
                    info["name"] = ls.attrib["Name"]
                for c in ls:
                    key = c.tag.lower()
                    if key in ("name", "oled", "panel", "menu"):
                        info[key] = ((c.text or "").strip() or c.attrib.get("Name")
                                     or c.attrib.get("Value") or "").strip()
                    elif key == "vpe_id":     # this source IS the output of that VPE (ME/PGM bus)
                        info["vpe"] = (c.text or "").strip().upper()
                    elif key == "out_id":
                        info["out"] = (c.text or "").strip().lower()
        self.schedule()

    def on_vpe_input(self, el):
        su = self._su(el)
        if su is None:
            return
        with self.lock:
            inputs = self.inputs.setdefault(su, {})
            tn = el.find("Type")
            if tn is not None and (tn.text or "").strip().lower() == "full":
                inputs.clear()
            for vpe in el.findall("VPE"):
                d = inputs.setdefault(vpe.attrib.get("Name", "").upper(), {})
                for i in vpe.findall("Input"):
                    try:
                        d[i.attrib.get("Name", "").lower()] = int((i.text or "").strip())
                    except ValueError:
                        d.pop(i.attrib.get("Name", "").lower(), None)
        self.schedule()

    def on_vpe_output(self, el):
        su = self._su(el)
        if su is None:
            return
        with self.lock:
            outs = self.outs.setdefault(su, {})
            tn = el.find("Type")
            if tn is not None and (tn.text or "").strip().lower() == "full":
                outs.clear()
            for vpe in el.findall("VPE"):
                d = outs.setdefault(vpe.attrib.get("Name", "").upper(), {})
                for o in vpe.findall("Output"):
                    names = {(c.text or "").strip().lower() for c in o if (c.text or "").strip()}
                    if not names and (o.text or "").strip():       # tolerate "a,b,c" text form
                        names = {x.lower() for x in (o.text or "").replace(",", " ").split()}
                    d[o.attrib.get("Name", "").lower()] = names
        self.schedule()

    def on_output_tally(self, el):
        with self.lock:
            tn = el.find("Type")
            if tn is not None and (tn.text or "").strip().lower() == "full":
                self.out_map.clear()
            for o in el.findall("Output"):
                su = _suite_of(o, _suite_of(el, self.dsuite))
                if su not in self.suites:
                    continue                  # output belongs to a suite we do not use
                try:
                    self.out_map[(su, int(o.attrib["OutNum"]))] = int(o.attrib.get("LogSrc", "0"))
                except (KeyError, ValueError):
                    pass
        self.schedule()

    def schedule(self):
        """Debounce: the frame sends the end of a transition as several packets (bus contribution,
        source assignment...). Applying each one separately makes the tally flash through
        impossible in-between states, so wait until the burst has settled, then apply once."""
        if self.a.settle <= 0:
            return self.refresh()
        with self.lock:
            now = time.monotonic()
            if self._first is None:
                self._first = now
            if self._timer:
                self._timer.cancel()
            delay = max(0.0, min(self.a.settle, self._first + self.a.max_settle - now))
            self._timer = threading.Timer(delay, self._flush)
            self._timer.daemon = True
            self._timer.start()

    def _flush(self):
        with self.lock:
            self._timer = self._first = None
            self.refresh()

    def reset(self):
        """Frame link lost: forget contribution state so every tally goes dark."""
        with self.lock:
            if self._timer:
                self._timer.cancel()
            self._timer = self._first = None
            self.inputs.clear()
            self.outs.clear()
        self.refresh()

    # --- tally logic
    def resolve(self, su, sid, _seen=None):
        """Sources behind logical source `sid` of suite `su`. A plain source is itself; a source that
        is the output of an ME/PGM (VPE_ID/OUT_ID) expands to whatever contributes to that output."""
        _seen = _seen or set()
        if not sid or sid in _seen:
            return set()
        _seen = _seen | {sid}
        info = self.names.get(su, {}).get(sid, {})
        vpe, out = info.get("vpe"), info.get("out")
        if not (vpe and out):
            return {sid}
        res = set()
        for iname in self.outs.get(su, {}).get(vpe, {}).get(out, ()):
            if iname.endswith("-cut") and not self.a.include_cuts:
                continue
            res |= self.resolve(su, self.inputs.get(su, {}).get(vpe, {}).get(iname), _seen=_seen)
        return res

    def sources_on(self, su, bus):
        srcs = set()
        for oname, in_names in self.outs.get(su, {}).get(bus, {}).items():
            if oname not in self.outputs:
                continue
            for iname in in_names:
                if iname.endswith("-cut") and not self.a.include_cuts:
                    continue
                srcs |= self.resolve(su, self.inputs.get(su, {}).get(bus, {}).get(iname))
        return srcs

    def sources_on_outputs(self, su, nums):
        srcs = set()
        for n in nums:
            if (su, n) in self.out_map:
                srcs |= self.resolve(su, self.out_map[(su, n)])
            elif any(k[0] == su for k in self.out_map) and ("o", su, n) not in self.warned:
                self.warned.add(("o", su, n))
                self.log(f"Output {n} is not in the frame's output map for suite {su}")
        return srcs

    def label(self, sid):
        """Label for a source: first suite (lowest number) that knows a name for it."""
        for su in sorted(self.names):
            info = self.names[su].get(sid)
            if info:
                return info.get(self.a.label) or info.get("name") or f"SRC {sid}"
        return f"SRC {sid}"

    def colour_sources(self, suites, buses, outs):
        srcs = set()
        for su in suites:
            for b in buses:
                srcs |= self.sources_on(su, b)
            srcs |= self.sources_on_outputs(su, outs)
        return srcs

    def refresh(self, force=False):
        with self.lock:
            red = self.colour_sources(self.red_suites, self.red, self.red_out)
            green = self.colour_sources(self.green_suites, self.green, self.green_out)
            all_ids = set(red) | set(green)
            for names in self.names.values():
                all_ids |= set(names)
            for sid in sorted(all_ids):
                addr = sid + self.a.addr_offset
                if not self.min_addr <= addr <= self.max_addr:
                    self.warned.add(sid)
                    continue
                state = (self.label(sid), sid in red, sid in green)
                if force or self.last.get(addr) != state:
                    if self.a.tsl_version == "5":
                        pkt = tsl5_packet(addr, state[0], state[1], state[2],
                                          brightness=self.a.brightness, screen=self.a.tsl_screen)
                    else:
                        pkt = tsl31_packet(addr, state[0], state[1], state[2], brightness=self.a.brightness)
                    if not self.a.dry_run:
                        self.send_udp(addr, pkt)
                    if self.last.get(addr, (None, None, None))[1:] != state[1:] or addr not in self.last:
                        self.log(f"{'[DRY] ' if self.a.dry_run else ''}TSL{self.a.tsl_version} addr {addr:5d} '{state[0]}' "
                                 f"{'RED ' if state[1] else ''}{'GREEN' if state[2] else ''}"
                                 f"{'off' if not (state[1] or state[2]) else ''}")
                    self.last[addr] = state
            far = {w for w in self.warned if isinstance(w, int)}
            if far and not getattr(self, "_warned_once", False):
                self._warned_once = True
                self.log(f"{len(far)} sources (IDs {min(far)}-{max(far)}) map to TSL "
                         f"addresses outside {self.min_addr}-{self.max_addr} and are not sent; use --addr-offset to shift the range")


# ---------------------------------------------------------------- client
class TallyClient:
    def __init__(self, a, cfg, log):
        self.a, self.cfg, self.log = a, cfg, log
        self.ip = a.frame_ip or cfg["frameIP"]
        self.port = a.port
        self.reconnect_s = int(cfg["AutoReconnectTimerSetting"]) / 1000.0
        self.dump = cfg["packetlogging"].lower() == "true"
        self.dumper = None
        self.sock = None
        self.suite = str(a.suite)
        self.buf = ""
        self.frame_info = {}
        self.last_rx = 0
        self.stop = threading.Event()
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        if a.udp_bind:                        # choose the NIC / subnet the TSL packets leave from
            try:
                self.udp.bind((a.udp_bind, 0))
            except OSError as e:
                sys.exit(f"Cannot bind TSL UDP output to interface {a.udp_bind}: {e}")
            log(f"TSL UDP output bound to interface {a.udp_bind}")
        self.engine = TallyEngine(a, log, self.udp)

    # --- socket handling
    def connect(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2 * 1024 * 1024)
        s.settimeout(5)
        try:
            if self.a.frame_bind and not self.a.mock:
                s.bind((self.a.frame_bind, 0))   # choose the NIC / subnet for frame traffic
            s.connect((self.ip, self.port))
        except OSError:
            s.close()
            raise
        s.settimeout(1.0)                    # ReceiveTimeout 1000 ms
        self.sock = s
        self.buf = ""
        via = f" via {self.a.frame_bind}" if self.a.frame_bind and not self.a.mock else ""
        self.log(f"Connecting to frame {s.getpeername()[0]}:{s.getpeername()[1]}{via}")
        if self.dump and not self.dumper:
            self.dumper = open(os.path.join(self.log.folder, "packet.xml"), "a", buffering=1)
        self.send(build_auth(self.a.proto_version, self.auth_suite()))

    def sub_suites(self):
        return sorted(self.engine.suites) or [self.a.suite]

    def auth_suite(self):
        s = self.sub_suites()
        return "ALL" if self.a.all_suites or len(s) > 1 else str(s[0])

    def send(self, text):
        self.sock.settimeout(0.5)            # SendTimeout 500 ms
        self.sock.sendall(text.encode("ascii"))
        self.sock.settimeout(1.0)
        self.log(f"TX {text}", 2)
        if self.dumper:
            self.dumper.write(f'<Packet Sent="Date Time:{time.strftime("%m-%d-%Y %H:%M:%S")}"/>\n{text}\n')

    def close(self):
        try:
            if self.sock:
                self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        if self.sock:
            self.sock.close()
        self.sock = None
        self.log("Disconnected from frame " + self.ip)
        self.engine.reset()

    # --- main loops
    def run(self):
        threading.Thread(target=self.heartbeat_loop, daemon=True).start()
        threading.Thread(target=self.refresh_loop, daemon=True).start()
        while not self.stop.is_set():
            try:
                if not self.sock:
                    self.connect()
                self.receive_once()
            except socket.timeout:
                continue
            except (OSError, ET.ParseError) as e:
                self.log(f"No Frame Conn. Error: {e}")
                self.close()
                time.sleep(self.reconnect_s)  # AutoReconnectTimerSetting
            time.sleep(0.01)

    def heartbeat_loop(self):
        while not self.stop.wait(self.a.heartbeat):
            if self.sock:
                try:
                    self.send(build_simple("Heartbeat-Request"))
                except OSError as e:
                    self.log(f"Heartbeat send failed: {e}")
                    self.close()

    def refresh_loop(self):                   # periodic resend heals lost UDP datagrams
        while not self.stop.wait(self.a.refresh):
            self.engine.refresh(force=True)

    def receive_once(self):
        data = self.sock.recv(RX_CHUNK)
        if not data:
            raise OSError("frame closed the connection")
        self.last_rx = time.time()
        self.buf += data.decode("ascii", "replace")
        self.log(f"Total bytes received: {len(data)}; SB: {len(self.buf)}", 3)
        while True:                           # ExtractPacket
            s = self.buf.find(START)
            if s < 0:
                self.buf = ""
                return
            e = self.buf.find(END, s)
            if e < 0:
                self.buf = self.buf[s:]       # keep partial packet
                return
            pkt = self.buf[s:e + len(END)]
            self.buf = self.buf[e + len(END):]
            self.log(f"Found packet {len(pkt)} bytes", 2)
            if self.dumper:
                self.dumper.write(f'<Packet Received="Date Time:{time.strftime("%m-%d-%Y %H:%M:%S")}"/>\n{pkt}\n')
            self.handle(pkt)

    # --- packet handling
    def handle(self, pkt):
        try:
            root = ET.fromstring(pkt)
        except ET.ParseError:
            self.log("Invalid packet")
            return
        for el in root:
            tag = el.tag
            if tag == "Authentication":
                self.on_auth(el)
            elif tag == "Heartbeat":
                self.log("Heart Beat Check respond from frame " + self.ip)
            elif tag == "VPEInputContribution":
                self.engine.on_vpe_input(el)
            elif tag == "VPEOutputContribution":
                self.engine.on_vpe_output(el)
            elif tag == "OutputTally":
                self.engine.on_output_tally(el)
            elif tag == "LogicalSourceMap":
                self.engine.on_logsrc(el)
            else:                             # Configuration, OutputTally, TallyMsg...
                self.log(f"Parsed {tag} packet")

    def on_auth(self, el):
        info = {c.tag: (c.text or "").strip() for c in el}
        info.update(el.attrib)
        self.frame_info = info
        self.log(f"Connected to frame {self.ip} {info}")
        for r in REQUESTS:
            self.send(build_simple(r))
        # one subscription request per suite in use (first Replace, the rest Add);
        # --all-suites mirrors the original app's capture (Suite "ALL")
        if self.a.all_suites:
            self.send(build_subscription("ALL", "Replace"))
        else:
            for i, su in enumerate(self.sub_suites()):
                self.send(build_subscription(su, "Replace" if i == 0 else "Add"))


# ---------------------------------------------------------------- mock frame
def mock_frame(port, stop):
    """Tiny stand-in for the switcher so the script can be tested offline."""
    srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port)); srv.listen(1); srv.settimeout(0.5)
    while not stop.is_set():
        try:
            c, _ = srv.accept()
        except socket.timeout:
            continue
        c.settimeout(0.5)
        n = 0; subs = set()
        while not stop.is_set():
            try:
                d = c.recv(4096).decode()
            except socket.timeout:
                d = ""
            except OSError:
                break
            if d == "" and False:
                break
            if "Authentication-Request" in d:
                c.sendall(etp("<Authentication><Protocol>GV Ethernet Tally</Protocol><Version>1.0</Version>"
                              "<Manufacturer>Grass Valley</Manufacturer><Model>MOCK-FRAME</Model>"
                              "<SystemVersion>0.0</SystemVersion></Authentication>").encode())
            if "Heartbeat-Request" in d:
                c.sendall(etp("<Heartbeat/>").encode())
            import re
            for su in re.findall(r'<Suite Method="\w+">(\w+)</Suite>', d):
                subs.add(su)
                c.sendall(etp(f'<LogicalSourceMap Suite="{su}"><Type>full</Type>'
                              + "".join(f'<LogSrc Type="Fixed" ID="{i}"><Name>{nm}</Name></LogSrc>'
                                        for i, nm in [(1, "CAM 1"), (2, "CAM 2"), (3, "CAM 3"), (4, "VT 1")])
                              + '</LogicalSourceMap>').encode())
                c.sendall(etp(f'<VPEInputContribution Suite="{su}"><Type>full</Type>'
                              '<VPE Name="ME1" Acquired="true"><Input Name="BkgdA">1</Input><Input Name="BkgdB">2</Input>'
                              '<Input Name="key1-fill">4</Input><Input Name="key1-cut">4</Input></VPE>'
                              '<VPE Name="ME2" Acquired="true"><Input Name="BkgdA">3</Input></VPE>'
                              '<VPE Name="PGM" Acquired="true"><Input Name="BkgdA">1</Input></VPE>'
                              '</VPEInputContribution>').encode())
                c.sendall(etp(f'<VPEOutputContribution Suite="{su}"><Type>full</Type>'
                              '<VPE Name="ME1" Acquired="true"><Output Name="PgmA"><Input>BkgdA</Input></Output>'
                              '<Output Name="PvwA"><Input>BkgdB</Input></Output></VPE>'
                              '<VPE Name="ME2" Acquired="true"><Output Name="PgmA"><Input>BkgdA</Input></Output></VPE>'
                              '<VPE Name="PGM" Acquired="true"><Output Name="PgmA"><Input>BkgdA</Input></Output></VPE>'
                              '</VPEOutputContribution>').encode())
            if subs:
                time.sleep(0.6); n += 1
                for su in sorted(subs):       # ME1 program flips A/B, key1 on every other step
                    bg, pv = ("BkgdB", "BkgdA") if n % 2 else ("BkgdA", "BkgdB")
                    key = "<Input>key1-fill</Input><Input>key1-cut</Input>" if n % 2 == 0 else ""
                    c.sendall(etp(f'<VPEOutputContribution Suite="{su}"><Type>update</Type>'
                                  f'<VPE Name="ME1"><Output Name="PgmA"><Input>{bg}</Input>{key}</Output>'
                                  f'<Output Name="PvwA"><Input>{pv}</Input></Output></VPE>'
                                  '</VPEOutputContribution>').encode())
        c.close()
    srv.close()


# ---------------------------------------------------------------- main
def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--config", default="config.xml")
    p.add_argument("--frame-ip", help="override frameIP from config.xml")
    p.add_argument("--port", type=int, default=PORT)
    p.add_argument("--frame-bind", default="", metavar="LOCAL_IP",
                   help="local IPv4 address (NIC) to use for the TCP link to the frame; default: OS routing")
    p.add_argument("--udp-bind", default="", metavar="LOCAL_IP",
                   help="local IPv4 address (NIC) to send the TSL UDP packets from; default: OS routing")
    p.add_argument("--udp-host", default="127.0.0.1")
    p.add_argument("--udp-port", type=int, default=9999)
    p.add_argument("--udp-extra", type=destlist, default=[], metavar="HOST[:PORT][@START[+COUNT]],...",
                   help="additional TSL UDP destinations (up to 9; with --udp-host that is 10 hosts). "
                        "Port defaults to --udp-port. @START[+COUNT] sends that host only displays "
                        "START..START+COUNT-1 (COUNT defaults to 1, a single display)")
    p.add_argument("--heartbeat", type=float, default=5.0, help="heartbeat period, s")
    p.add_argument("--proto-version", default="3.0")
    p.add_argument("--suite", type=int, choices=[1, 2, 3, 4], default=1,
                   help="default suite for --red-suites / --green-suites")
    p.add_argument("--red-suites", type=suitelist, default=None, metavar="SUITES",
                   help="suites that can light RED, e.g. 1 or 1,2 or 'none' (default: --suite)")
    p.add_argument("--green-suites", type=suitelist, default=None, metavar="SUITES",
                   help="suites that can light GREEN, e.g. 2 or 1,2 or 'none' (default: --suite)")
    p.add_argument("--red", type=buslist, default=None, metavar="BUSES",
                   help="buses lighting RED / TSL Tally 1, comma list of ME1,ME2,ME3,ME4,PGM or 'none' (default PGM, unless --red-out/--green-out given)")
    p.add_argument("--green", type=buslist, default=None, metavar="BUSES",
                   help="buses lighting GREEN / TSL Tally 2 (default ME1, unless --red-out/--green-out given)")
    p.add_argument("--red-out", type=outlist, default=[], metavar="OUTPUTS",
                   help="frame output numbers lighting RED, e.g. 1,2,5-8 (sources feeding those outputs)")
    p.add_argument("--green-out", type=outlist, default=[], metavar="OUTPUTS",
                   help="frame output numbers lighting GREEN")
    p.add_argument("--outputs", default="PgmA,PgmB,PgmC,PgmD",
                   help="which VPE outputs count as 'on the bus' (PgmA-D,PvwA,PvwC,LAPA-D)")
    p.add_argument("--include-cuts", action="store_true", help="also tally key-cut sources (default: fills/backgrounds only)")
    p.add_argument("--tsl-version", choices=["3.1", "5"], default="3.1",
                   help="UDP output protocol: TSL UMD V3.1 (default) or V5.0")
    p.add_argument("--tsl-screen", type=int, default=0,
                   help="TSL V5 screen number (0-65534; 65535 = all screens)")
    p.add_argument("--tsl-start", type=int, default=0,
                   help="TSL V5: first display address that is sent (0-65534)")
    p.add_argument("--tsl-count", type=int, default=128,
                   help="TSL V5: number of displays sent, starting at --tsl-start (default 128)")
    p.add_argument("--dry-run", action="store_true",
                   help="connect and compute tally but do not send any UDP packets (log only)")
    p.add_argument("--addr-offset", type=int, default=0,
                   help="TSL address = logical source ID + offset (V3.1: 0-126; V5: see --tsl-start/--tsl-count)")
    p.add_argument("--label", choices=["name", "oled", "panel", "menu"], default="name", help="which source name goes in the 16-char label")
    p.add_argument("--all-suites", action="store_true",
                   help="authenticate/subscribe with Suite ALL (as the original app did); --suite still selects what is tallied")
    p.add_argument("--replay", metavar="PACKET_XML", help="offline: replay the Received packets of a packet.xml capture")
    p.add_argument("--replay-delay", type=float, default=0.3, help="seconds between replayed packets")
    p.add_argument("--settle", type=float, default=0.08,
                   help="seconds to wait for a burst of frame updates to finish before changing tally "
                        "(removes end-of-transition flashes; 0 = apply every packet immediately)")
    p.add_argument("--max-settle", type=float, default=0.25,
                   help="never delay a tally change longer than this many seconds")
    p.add_argument("--brightness", type=int, choices=[0, 1, 2, 3], default=3)
    p.add_argument("--refresh", type=float, default=2.0, help="resend all tally state every N s")
    p.add_argument("--mock", action="store_true", help="run against a built-in fake frame on 127.0.0.1")
    p.add_argument("--seconds", type=float, default=0, help="exit after N seconds (0 = run forever)")
    a = p.parse_args()
    if not 0 <= a.tsl_start <= 65534:
        p.error("--tsl-start must be 0-65534")
    if not 1 <= a.tsl_count <= 65535:
        p.error("--tsl-count must be 1-65535")
    a.udp_extra = [(h, p or a.udp_port, lo, hi) for h, p, lo, hi in a.udp_extra]
    if a.red_suites is None:
        a.red_suites = [a.suite]
    if a.green_suites is None:
        a.green_suites = [a.suite]
    by_out = bool(a.red_out or a.green_out)
    if a.red is None:
        a.red = [] if by_out else ["PGM"]
    if a.green is None:
        a.green = [] if by_out else ["ME1"]

    cfg = load_config(a.config)
    log = Log(cfg["logpath"], cfg["logappend"].lower() == "true", int(cfg["loglevel"]))
    stop = threading.Event()
    if a.mock:
        a.frame_ip = "127.0.0.1"
        threading.Thread(target=mock_frame, args=(a.port, stop), daemon=True).start()
        time.sleep(0.3)
    cl = TallyClient(a, cfg, log)
    if a.replay:
        import re
        text = open(a.replay, encoding="utf-8", errors="replace").read()
        for m in re.finditer(r'<Packet (Received|Sent)=[^>]*/>\s*(<ETP>.*?</ETP>)', text, re.S):
            if m.group(1) == "Received" and "<Authentication>" not in m.group(2):
                cl.handle(m.group(2))
                time.sleep(a.replay_delay)
        time.sleep(a.settle + 0.1)
        cl.engine.refresh(force=True)
        return
    if a.seconds:
        threading.Timer(a.seconds, lambda: (cl.stop.set(), stop.set())).start()
    try:
        cl.run()
    except KeyboardInterrupt:
        pass
    finally:
        cl.stop.set(); stop.set()
        if cl.sock:
            cl.close()


if __name__ == "__main__":
    main()
