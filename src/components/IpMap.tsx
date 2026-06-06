"use client";

import { useEffect, useMemo } from "react";
import { MapContainer, TileLayer, Marker, Popup } from "react-leaflet";
import L from "leaflet";
import "leaflet/dist/leaflet.css";

interface IpMapProps {
  lat: number;
  lon: number;
  city: string | null;
  region: string | null;
  country: string | null;
}

export default function IpMap({ lat, lon, city, region, country }: IpMapProps) {
  // Fix broken default marker icons in Next.js / webpack
  useEffect(() => {
    L.Icon.Default.mergeOptions({
      iconUrl:       "https://unpkg.com/leaflet@1.9.4/dist/images/marker-icon.png",
      iconRetinaUrl: "https://unpkg.com/leaflet@1.9.4/dist/images/marker-icon-2x.png",
      shadowUrl:     "https://unpkg.com/leaflet@1.9.4/dist/images/marker-shadow.png",
    });
  }, []);

  // Red pin marker — inside useMemo so L.Icon() only runs on the client (never during SSR)
  const redIcon = useMemo(() => new L.Icon({
    iconUrl:       "https://raw.githubusercontent.com/pointhi/leaflet-color-markers/master/img/marker-icon-red.png",
    iconRetinaUrl: "https://raw.githubusercontent.com/pointhi/leaflet-color-markers/master/img/marker-icon-2x-red.png",
    shadowUrl:     "https://unpkg.com/leaflet@1.9.4/dist/images/marker-shadow.png",
    iconSize:    [25, 41] as L.PointTuple,
    iconAnchor:  [12, 41] as L.PointTuple,
    popupAnchor: [1, -34] as L.PointTuple,
    shadowSize:  [41, 41] as L.PointTuple,
  }), []);

  const locationLabel = [city, region, country].filter(Boolean).join(", ") || "Unknown location";

  // Zoom 8 = city-region level — general area, not pinpoint (privacy best practice for IP geo)
  return (
    <MapContainer
      center={[lat, lon]}
      zoom={8}
      scrollWheelZoom={false}
      style={{ height: "300px", width: "100%" }}
      attributionControl={false}
    >
      <TileLayer
        url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
        attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>'
      />
      <Marker position={[lat, lon]} icon={redIcon}>
        <Popup>
          <span style={{ fontFamily: "monospace", fontSize: "12px" }}>
            📍 {locationLabel}
            <br />
            <span style={{ color: "#888", fontSize: "11px" }}>approximate location</span>
          </span>
        </Popup>
      </Marker>
    </MapContainer>
  );
}
