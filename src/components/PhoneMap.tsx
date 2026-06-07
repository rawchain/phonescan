"use client";

import { useEffect, useMemo, useState } from "react";
import { MapContainer, TileLayer, Marker, Popup } from "react-leaflet";
import L from "leaflet";
import "leaflet/dist/leaflet.css";

interface PhoneMapProps {
  location: string; // e.g. "California, US" or "United Kingdom"
}

interface NominatimResult {
  lat: string;
  lon: string;
  display_name: string;
}

export default function PhoneMap({ location }: PhoneMapProps) {
  const [coords, setCoords] = useState<{ lat: number; lon: number } | null>(null);

  // Fix broken default marker icons in Next.js / webpack
  useEffect(() => {
    L.Icon.Default.mergeOptions({
      iconUrl:       "https://unpkg.com/leaflet@1.9.4/dist/images/marker-icon.png",
      iconRetinaUrl: "https://unpkg.com/leaflet@1.9.4/dist/images/marker-icon-2x.png",
      shadowUrl:     "https://unpkg.com/leaflet@1.9.4/dist/images/marker-shadow.png",
    });
  }, []);

  // Geocode the location string via Nominatim (no key required)
  useEffect(() => {
    if (!location) return;
    const controller = new AbortController();
    fetch(
      `https://nominatim.openstreetmap.org/search?q=${encodeURIComponent(location)}&format=json&limit=1`,
      {
        headers: { "User-Agent": "PhoneScan/1.0" },
        signal: controller.signal,
      }
    )
      .then(r => r.json())
      .then((results: NominatimResult[]) => {
        if (results && results.length > 0) {
          setCoords({ lat: parseFloat(results[0].lat), lon: parseFloat(results[0].lon) });
        }
      })
      .catch(() => {}); // silently fail — map just won't show
    return () => controller.abort();
  }, [location]);

  // Orange pin — inside useMemo so L.Icon() only runs on the client (never during SSR)
  const orangeIcon = useMemo(() => new L.Icon({
    iconUrl:       "https://raw.githubusercontent.com/pointhi/leaflet-color-markers/master/img/marker-icon-orange.png",
    iconRetinaUrl: "https://raw.githubusercontent.com/pointhi/leaflet-color-markers/master/img/marker-icon-2x-orange.png",
    shadowUrl:     "https://unpkg.com/leaflet@1.9.4/dist/images/marker-shadow.png",
    iconSize:    [25, 41] as L.PointTuple,
    iconAnchor:  [12, 41] as L.PointTuple,
    popupAnchor: [1, -34] as L.PointTuple,
    shadowSize:  [41, 41] as L.PointTuple,
  }), []);

  if (!coords) return null;

  // Zoom 6 = country/region level — appropriate for phone geolocation (less precise than IP)
  return (
    <div>
      <MapContainer
        center={[coords.lat, coords.lon]}
        zoom={6}
        scrollWheelZoom={false}
        style={{ height: "220px", width: "100%" }}
        attributionControl={false}
      >
        <TileLayer
          url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
          attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>'
        />
        <Marker position={[coords.lat, coords.lon]} icon={orangeIcon}>
          <Popup>
            <span style={{ fontFamily: "monospace", fontSize: "12px" }}>
              📞 {location}
              <br />
              <span style={{ color: "#888", fontSize: "11px" }}>approximate region</span>
            </span>
          </Popup>
        </Marker>
      </MapContainer>
      <div className="font-mono text-[10px] tracking-[2px] text-[var(--muted)] mt-2 text-center">
        {"// APPROXIMATE REGION · not exact location"}
      </div>
    </div>
  );
}
