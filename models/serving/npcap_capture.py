"""Windows low-latency capture, streamed as ordinary pcap to ingest's tshark parser.

Npcap immediate mode avoids the driver's roughly 500 ms quiet-link buffering.
No sampling or packet filters: timestamps, packet bytes and dissectors stay intact.
"""
from __future__ import annotations

import ctypes as ct
import os
import re
import struct
import subprocess
import time
from pathlib import Path


class Timeval(ct.Structure):
    _fields_ = [("seconds", ct.c_int32), ("microseconds", ct.c_int32)]


class PacketHeader(ct.Structure):
    _fields_ = [("ts", Timeval), ("captured", ct.c_uint32), ("length", ct.c_uint32)]


class CaptureStats(ct.Structure):
    _fields_ = [("received", ct.c_uint32), ("dropped", ct.c_uint32), ("interface_dropped", ct.c_uint32),
                ("captured", ct.c_uint32)]  # Windows pcap_stat includes ps_capt


def resolve_interface(interface: str, listing: str) -> str:
    for line in listing.splitlines():
        match = re.fullmatch(r"(\d+)\. (\\Device\\NPF_\S+) \((.*)\)", line.strip())
        if match and interface in (match[1], match[2], match[3]):
            return match[2]
    raise OSError(f"Npcap interface not found: {interface}")


def pcap_header(linktype: int) -> bytes:
    return struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 262144, linktype)


def pcap_record(seconds: int, microseconds: int, payload: bytes, original_length: int) -> bytes:
    return struct.pack("<IIII", seconds, microseconds, len(payload), original_length) + payload


class NpcapCapture:
    def __init__(self, interface: str, tshark: str):
        if os.name != "nt":
            raise OSError("Npcap immediate capture is available only on Windows")
        directory = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "Npcap"
        # Keep the DLL directory active while Npcap's dependent DLLs are loaded.
        self.dll_directory = os.add_dll_directory(str(directory))
        self.handle = None
        self.state = {"mode": "npcap_immediate", "received": 0, "dropped": 0, "interface_dropped": 0}
        try:
            self.api = ct.CDLL(str(directory / "wpcap.dll"))
            self._bind()
            listing = subprocess.check_output([tshark, "-D"], text=True, stderr=subprocess.DEVNULL)
            device = resolve_interface(interface, listing)
            error = ct.create_string_buffer(256)
            self.handle = self.api.pcap_create(device.encode(), error)
            if not self.handle:
                raise OSError(error.value.decode(errors="replace"))
            for name, value in (("pcap_set_snaplen", 262144), ("pcap_set_promisc", 1),
                                ("pcap_set_timeout", 10), ("pcap_set_buffer_size", 8 * 1024 * 1024),
                                ("pcap_set_immediate_mode", 1)):
                if getattr(self.api, name)(self.handle, value) != 0:
                    raise OSError(f"{name}: {self.error()}")
            if self.api.pcap_activate(self.handle) < 0:
                raise OSError(f"pcap_activate: {self.error()}")
            if self.api.pcap_setnonblock(self.handle, 1, error) != 0:
                raise OSError(error.value.decode(errors="replace"))
            self.linktype = self.api.pcap_datalink(self.handle)
            if self.linktype < 0:
                raise OSError(f"pcap_datalink: {self.error()}")
        except Exception:
            self.close()
            raise

    def _bind(self):
        specs = {
            "pcap_create": ([ct.c_char_p, ct.c_char_p], ct.c_void_p),
            "pcap_geterr": ([ct.c_void_p], ct.c_char_p),
            "pcap_activate": ([ct.c_void_p], ct.c_int),
            "pcap_datalink": ([ct.c_void_p], ct.c_int),
            "pcap_close": ([ct.c_void_p], None),
            "pcap_setnonblock": ([ct.c_void_p, ct.c_int, ct.c_char_p], ct.c_int),
            "pcap_next_ex": ([ct.c_void_p, ct.POINTER(ct.POINTER(PacketHeader)),
                              ct.POINTER(ct.POINTER(ct.c_ubyte))], ct.c_int),
            "pcap_stats": ([ct.c_void_p, ct.POINTER(CaptureStats)], ct.c_int),
        }
        for name in ("pcap_set_snaplen", "pcap_set_promisc", "pcap_set_timeout", "pcap_set_buffer_size",
                     "pcap_set_immediate_mode"):
            specs[name] = ([ct.c_void_p, ct.c_int], ct.c_int)
        for name, (args, result) in specs.items():
            fn = getattr(self.api, name)
            fn.argtypes, fn.restype = args, result

    def error(self) -> str:
        return self.api.pcap_geterr(self.handle).decode(errors="replace")

    def packets(self):
        header, data = ct.POINTER(PacketHeader)(), ct.POINTER(ct.c_ubyte)()
        last_stats = time.monotonic()
        while True:
            result = self.api.pcap_next_ex(self.handle, ct.byref(header), ct.byref(data))
            if result == 1:
                h = header.contents
                yield pcap_record(h.ts.seconds, h.ts.microseconds, ct.string_at(data, h.captured), h.length)
            elif result == 0:
                yield None
                time.sleep(.001)
            else:
                raise OSError(f"Npcap read failed ({result}): {self.error()}")
            if time.monotonic() - last_stats >= 1:
                stats = CaptureStats()
                if self.api.pcap_stats(self.handle, ct.byref(stats)) == 0:
                    self.state.update(received=stats.received, dropped=stats.dropped,
                                      interface_dropped=stats.interface_dropped)
                last_stats = time.monotonic()

    def pump(self, output, stop) -> None:
        output.write(pcap_header(self.linktype))
        output.flush()
        pending = bytearray()
        flushed = time.monotonic()
        for record in self.packets():
            if stop.is_set():
                break
            if record:
                pending.extend(record)
            # Bound the pipe batch to 64 KiB / 2 ms; quiet packets flush immediately.
            if pending and (record is None or len(pending) >= 65536 or time.monotonic() - flushed >= .002):
                output.write(pending)
                output.flush()
                pending.clear()
                flushed = time.monotonic()
        if pending:
            output.write(pending)
            output.flush()

    def close(self):
        if self.handle:
            self.api.pcap_close(self.handle)
            self.handle = None
        self.dll_directory.close()
