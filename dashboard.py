import streamlit as st
import pandas as pd
import hashlib
from pathlib import Path

from main import process_pcap_to_df, write_kml_from_df

st.set_page_config(page_title="SecureNet Vision - Security Dashboard", layout="wide")
st.title("SecureNet Vision — Security Dashboard")
st.caption("Upload a PCAP to analyze connections, export a KML, and visualize results in Google Earth or inline.")

# --- Session init ---
if "last_kml_path" not in st.session_state:
    st.session_state["last_kml_path"] = None

# --- Settings sidebar ---
st.sidebar.header("Settings")
geoip_path = st.sidebar.text_input(
    "GeoLite2 City DB path",
    value=r"D:\Network visual tracker\GeoLite2-City.mmdb"
)
default_kml_name = st.sidebar.text_input("KML filename", value="output.kml")

st.sidebar.markdown("---")
use_local_for_private = st.sidebar.checkbox("Treat private IPs as Local Network", value=True)
# Example coordinates (adjust to your location)
local_lat = st.sidebar.number_input("Local latitude", value=13.0827)
local_lon = st.sidebar.number_input("Local longitude", value=80.2707)

st.markdown("### Upload PCAP")
uploaded = st.file_uploader("Choose a .pcap file", type=["pcap"])

# --- Google Maps + KML inline renderer (auto fit to bounds) ---
def render_kml_inline_on_gmaps(kml_text: str, google_maps_api_key: str):
    from streamlit.components.v1 import html
    safe_kml = kml_text.replace("</script>", "<\\/script>")
    html_content = f"""
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="initial-scale=1, width=device-width"/>
<style>
  html, body, #map {{ height: 100%; margin: 0; padding: 0; }}
  #map {{ height: 600px; width: 100%; border-radius: 12px; }}
</style>
<script src="https://cdn.jsdelivr.net/gh/geocodezip/geoxml3@master/polys/geoxml3.js"></script>
<script src="https://cdn.jsdelivr.net/gh/geocodezip/geoxml3@master/ProjectedOverlay.js"></script>
<script src="https://maps.googleapis.com/maps/api/js?key={google_maps_api_key}"></script>
<script>
  function init() {{
    var map = new google.maps.Map(document.getElementById('map'), {{
      center: {{lat: 20.0, lng: 0.0}}, zoom: 2, mapTypeId: 'terrain'
    }});

    var kmlText = `{safe_kml}`;
    var parser = new DOMParser();
    var kmlDoc = parser.parseFromString(kmlText, "text/xml");

    var geoParser = new geoXML3.parser({{
      map: map,
      singleInfoWindow: true,
      afterParse: function(docs) {{
        try {{
          var bounds = new google.maps.LatLngBounds();
          docs.forEach(function(doc) {{
            (doc.markers||[]).forEach(function(m) {{ bounds.extend(m.getPosition()); }});
            (doc.gpolylines||[]).forEach(function(line) {{
              line.getPath().forEach(function(ll) {{ bounds.extend(ll); }});
            }});
          }});
          if (!bounds.isEmpty()) {{
            map.fitBounds(bounds);
          }}
        }} catch(e) {{
          console.log("fitBounds error", e);
        }}
      }}
    }});
    geoParser.parseKmlString(new XMLSerializer().serializeToString(kmlDoc));
  }}
  window.onload = init;
</script>
</head>
<body>
  <div id="map"></div>
</body>
</html>
"""
    html(html_content, height=620, scrolling=False)

if uploaded is not None:
    st.success("PCAP uploaded. Processing…")

    # --- Data Integrity: compute SHA-256 of the uploaded PCAP ---
    try:
        uploaded.seek(0)
        file_bytes = uploaded.read()
        sha256_hash = hashlib.sha256(file_bytes).hexdigest()
        uploaded.seek(0)  # reset for downstream parsing

        st.markdown("#### File Integrity Verification")
        st.write("SHA-256 hash of the uploaded file:")
        st.code(sha256_hash, language="text")
    except Exception as e:
        st.warning(f"Could not compute file hash: {e}")

    try:
        df = process_pcap_to_df(uploaded, geoip_path)

        if df.empty:
            st.warning("No IP traffic found in this PCAP (or parsing failed).")
        else:
            # --- Metrics
            col1, col2, col3 = st.columns(3)
            col1.metric("Total Packets Parsed", len(df))
            col2.metric("Unique Flows", len(df.drop_duplicates(subset=["Source IP", "Destination IP"])))
            col3.metric("Unique Destinations", df["Destination IP"].nunique())

            # --- Table
            st.subheader("Connections (sample)")
            st.dataframe(df.head(200), use_container_width=True)

            st.divider()

            # === KML Export & Visualization ===
            st.subheader("KML Export & Visualization")
            colA, colB = st.columns([1, 2], gap="large")

            with colA:
                if st.button("Generate KML"):
                    out_path = write_kml_from_df(
                        df,
                        default_kml_name,
                        name="Network Flows",
                        geoip_db_path=geoip_path,
                        local_fallback=(local_lon, local_lat) if use_local_for_private else None,
                    )
                    st.session_state["last_kml_path"] = out_path
                    st.success(f"KML generated: {out_path}")

                kml_ready_path = st.session_state.get("last_kml_path")
                if kml_ready_path and Path(kml_ready_path).exists():
                    with open(kml_ready_path, "rb") as f:
                        st.download_button(
                            "Download KML",
                            f,
                            file_name=Path(kml_ready_path).name,
                            mime="application/vnd.google-earth.kml+xml"
                        )
                else:
                    st.caption("Click Generate KML to enable download and previews.")

            with colB:
                # Open in Google Earth Web via public URL
                st.markdown("Open in Google Earth Web")
                st.caption("Paste a PUBLIC URL to your KML (for example, GitHub raw, S3, or a Google Drive direct link).")
                kml_public_url = st.text_input(
                    "KML public URL (optional)",
                    placeholder="https://raw.githubusercontent.com/your/repo/main/output.kml"
                )
                if kml_public_url:
                    import urllib.parse
                    earth_url = "https://earth.google.com/web?url=" + urllib.parse.quote(kml_public_url, safe="")
                    st.link_button("Open in Google Earth Web", earth_url)
                st.caption("Alternatively, drag and drop the downloaded KML into https://earth.google.com/web .")

            # Inline Map Preview (Google Maps + KML)
            st.markdown("Inline Map Preview (Google Maps + KML)")
            gmaps_key = st.text_input("Google Maps JavaScript API Key (for inline preview)", type="password")
            kml_ready_path = st.session_state.get("last_kml_path")
            if gmaps_key and kml_ready_path and Path(kml_ready_path).exists():
                try:
                    kml_text = Path(kml_ready_path).read_text(encoding="utf-8", errors="ignore")
                    render_kml_inline_on_gmaps(kml_text, gmaps_key)
                except Exception as e:
                    st.error(f"Inline map could not be rendered: {e}")
            elif gmaps_key and (not kml_ready_path):
                st.info("Generate the KML first; the inline preview will appear here.")

            st.divider()

            # --- Top Destination Countries (robust)
            st.subheader("Top Destination Countries")
            try:
                top = (
                    df["Destination Country"]
                    .value_counts(dropna=False)
                    .rename_axis("Country")
                    .reset_index(name="Count")
                )
                if not top.empty and {"Country", "Count"}.issubset(top.columns):
                    st.bar_chart(top.set_index("Country"))
                else:
                    st.caption("No destination country data to chart.")
            except Exception as e:
                st.caption(f"Chart unavailable: {e}")

    except Exception as e:
        st.error(f"Error: {e}\nVerify that your GeoLite2 database path is correct and the PCAP is valid.")
else:
    st.info("Upload a .pcap file to begin.")
