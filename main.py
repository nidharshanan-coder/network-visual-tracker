import dpkt, socket
import dpkt.ip6  # IPv6 support
import geoip2.database
import pandas as pd
from pathlib import Path
from typing import Optional


def _ip_to_str(ip_obj) -> Optional[str]:
    """Return textual IP (v4/v6) from dpkt ip obj (dpkt.ip.IP or dpkt.ip6.IP6)."""
    try:
        if isinstance(ip_obj, dpkt.ip.IP):
            return socket.inet_ntoa(ip_obj)
        elif isinstance(ip_obj, (bytes, bytearray)):  # raw address bytes
            # try v4 first by length
            if len(ip_obj) == 4:
                return socket.inet_ntoa(ip_obj)
            elif len(ip_obj) == 16:
                return socket.inet_ntop(socket.AF_INET6, ip_obj)
        elif isinstance(ip_obj, dpkt.ip6.IP6):
            return socket.inet_ntop(socket.AF_INET6, ip_obj)
    except Exception:
        return None
    return None


def process_pcap_to_df(pcap_bytes_or_path, geoip_db_path: str) -> pd.DataFrame:
    """
    Parses a PCAP (file-like or path), returns a DataFrame of connections:
    Source IP, Destination IP, Source Country, Destination Country.
    Supports IPv4 and IPv6.
    """
    reader = geoip2.database.Reader(geoip_db_path)

    # Open PCAP from bytes-like object or path
    if hasattr(pcap_bytes_or_path, "read"):
        pcap = dpkt.pcap.Reader(pcap_bytes_or_path)
    else:
        with open(pcap_bytes_or_path, "rb") as f:
            pcap = dpkt.pcap.Reader(f)

    rows = []
    for _, buf in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            # Only IP frames
            if not isinstance(ip, (dpkt.ip.IP, dpkt.ip6.IP6)):
                continue

            src_ip = _ip_to_str(ip.src)
            dst_ip = _ip_to_str(ip.dst)
            if not src_ip or not dst_ip:
                continue

            def country_of(ipaddr: str) -> str:
                try:
                    rec = reader.city(ipaddr)
                    return (rec.country.name or "Unknown") if rec and rec.country else "Unknown"
                except Exception:
                    return "Unknown"

            rows.append({
                "Source IP": src_ip,
                "Destination IP": dst_ip,
                "Source Country": country_of(src_ip),
                "Destination Country": country_of(dst_ip),
            })
        except Exception:
            continue

    return pd.DataFrame(rows)


def write_kml_from_df(
    df: "pd.DataFrame",
    output_path: str,
    name: str = "Network Flows",
    geoip_db_path: Optional[str] = "GeoLite2-City.mmdb",
    local_fallback: Optional[tuple] = None,  # (lon, lat) used for private IPs (v4/v6)
) -> str:
    """
    Draws a LineString per Source->Destination (unique pairs).
    - Public IPs: geolocated via GeoLite2 (IPv4+IPv6).
    - Private IPs: if local_fallback is provided, uses that lon/lat.
    - Adds endpoint markers and RED lines (like your screenshot).
    - Wraps results in a Folder named "output".
    """
    from xml.sax.saxutils import escape
    import geoip2.database
    import ipaddress

    def is_private(ip_str: str) -> bool:
        try:
            return ipaddress.ip_address(ip_str).is_private
        except Exception:
            return False

    reader = geoip2.database.Reader(geoip_db_path) if geoip_db_path else None

    def lonlat(ipaddr: str):
        # Private → use fallback if provided
        if is_private(ipaddr):
            return local_fallback
        if not reader:
            return None
        try:
            city = reader.city(ipaddr)
            if not city or not city.location:
                return None
            # KML uses lon,lat
            return (city.location.longitude, city.location.latitude)
        except Exception:
            return None

    kml = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<kml xmlns="http://www.opengis.net/kml/2.2">',
        f'<Document><name>{escape(name)}</name>',
        # Styles: RED lines, red endpoint icons (aabbggrr; ff=opaque, rr=red)
        '<Style id="flowLine"><LineStyle><width>2.5</width><color>ff0000ff</color></LineStyle></Style>',
        '<Style id="endpoint"><IconStyle><color>ff0000ff</color><scale>1.1</scale>'
        '<Icon><href>http://maps.google.com/mapfiles/kml/paddle/red-circle.png</href></Icon>'
        '</IconStyle></Style>',
        '<Folder><name>output</name><visibility>1</visibility>',
    ]

    pairs = df.drop_duplicates(subset=["Source IP", "Destination IP"])
    placed = set()

    for _, row in pairs.iterrows():
        src_ip = row["Source IP"]
        dst_ip = row["Destination IP"]
        src = lonlat(src_ip)
        dst = lonlat(dst_ip)

        # Endpoint markers (once)
        if src and (src_ip, src) not in placed:
            kml += [
                '<Placemark><styleUrl>#endpoint</styleUrl>',
                f'<name>{escape(src_ip)}</name>',
                f'<Point><coordinates>{src[0]},{src[1]},0</coordinates></Point>',
                '</Placemark>',
            ]
            placed.add((src_ip, src))
        if dst and (dst_ip, dst) not in placed:
            kml += [
                '<Placemark><styleUrl>#endpoint</styleUrl>',
                f'<name>{escape(dst_ip)}</name>',
                f'<Point><coordinates>{dst[0]},{dst[1]},0</coordinates></Point>',
                '</Placemark>',
            ]
            placed.add((dst_ip, dst))

        # Draw line if both ends known
        if src and dst:
            kml += [
                '<Placemark><styleUrl>#flowLine</styleUrl>',
                f'<name>{escape(src_ip)} → {escape(dst_ip)}</name>',
                '<visibility>1</visibility>',
                '<LineString><tessellate>1</tessellate><coordinates>',
                f'{src[0]},{src[1]},0 {dst[0]},{dst[1]},0',
                '</coordinates></LineString>',
                '</Placemark>',
            ]

    kml += ['</Folder>', '</Document></kml>']
    Path(output_path).write_text("\n".join(kml), encoding="utf-8")
    return output_path
