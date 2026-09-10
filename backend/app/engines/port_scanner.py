import socket
import asyncio
from app.net_guard import assert_target_allowed, TargetNotAllowed

COMMON_PORTS = {
    80: 'HTTP',
    443: 'HTTPS',
    21: 'FTP',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    53: 'DNS',
    110: 'POP3',
    143: 'IMAP',
    465: 'SMTPS',
    587: 'Mail Message Submission',
    993: 'IMAPS',
    995: 'POP3S',
    3306: 'MySQL',
    3389: 'RDP',
    5432: 'PostgreSQL',
    8080: 'HTTP-Proxy',
    8443: 'HTTPS-Alt'
}

async def scan_port(ip, port, timeout=1.0):
    conn = asyncio.open_connection(ip, port)
    try:
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        writer.close()
        await writer.wait_closed()
        return port, True
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return port, False

async def scan_host_ports(hostname, ports_to_scan=None):
    if ports_to_scan is None:
        ports_to_scan = list(COMMON_PORTS.keys())

    try:
        assert_target_allowed(hostname)
    except TargetNotAllowed as e:
        return {"hostname": hostname, "open_ports": [], "error": str(e)}

    try:
        ip = socket.gethostbyname(hostname)
    except socket.gaierror:
        return {"hostname": hostname, "open_ports": [], "error": "DNS Resolution Failed"}

    tasks = [scan_port(ip, port) for port in ports_to_scan]
    results = await asyncio.gather(*tasks)

    open_ports = []
    for port, is_open in results:
        if is_open:
            open_ports.append({
                "port": port,
                "service": COMMON_PORTS.get(port, "Unknown")
            })
            
    return {"hostname": hostname, "ip": ip, "open_ports": open_ports}

def run_port_scan(hostname):
    """Synchronous wrapper for asyncio port scan."""
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    return loop.run_until_complete(scan_host_ports(hostname))
