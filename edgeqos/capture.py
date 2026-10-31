"""Bounded AF_PACKET receive queue and kernel-side snapshot length."""
import ctypes
import socket

SNAPLEN = 96  # Ethernet + two VLAN tags + maximum IPv4 header + transport ports.
RECEIVE_BYTES = 4 * 1024 * 1024


def open_capture(interface):
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    try:
        # CAP_NET_ADMIN is already part of the service. This changes only this
        # socket, avoiding a machine-wide rmem_max/sysctl change.
        forced = True
        try:
            sock.setsockopt(socket.SOL_SOCKET, 33, RECEIVE_BYTES)  # SO_RCVBUFFORCE
        except OSError:
            forced = False
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, RECEIVE_BYTES)

        class Instruction(ctypes.Structure):
            _fields_ = [('code', ctypes.c_ushort), ('jt', ctypes.c_ubyte),
                        ('jf', ctypes.c_ubyte), ('k', ctypes.c_uint32)]

        class Program(ctypes.Structure):
            _fields_ = [('length', ctypes.c_ushort),
                        ('instructions', ctypes.POINTER(Instruction))]

        instructions = (Instruction * 1)(Instruction(0x06, 0, 0, SNAPLEN))  # RET K
        program = Program(1, instructions)
        sock.setsockopt(socket.SOL_SOCKET, 26, bytes(program))  # SO_ATTACH_FILTER
        sock.bind((interface, 0))
        sock.settimeout(.5)
        return sock, dict(snapshot_bytes=SNAPLEN, kernel_snapshot_filter=True,
                          buffer_forced=forced,
                          receive_buffer_bytes=sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF))
    except Exception:
        sock.close()
        raise
