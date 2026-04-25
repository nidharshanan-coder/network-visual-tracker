import geoip2.database

try:
    geoip_db = geoip2.database.Reader('GeoLite2-City.mmdb')
    ip_address = "10.3.2.219"  # Google's public DNS, should always work
    response = geoip_db.city(ip_address)

    print(f"✅ {ip_address} is in the database!")
    print(f"📍 Location: {response.location.latitude}, {response.location.longitude}")

except Exception as e:
    print(f"❌ Error: {e}")