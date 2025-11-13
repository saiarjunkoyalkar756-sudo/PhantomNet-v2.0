import { MapContainer, TileLayer, Marker, Popup } from 'react-leaflet';
import L from 'leaflet';
import 'leaflet/dist/leaflet.css';

// Custom icons for different threat levels
const defaultIcon = new L.Icon({
  iconUrl:
    'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.7.1/images/marker-icon.png',
  iconRetinaUrl:
    'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.7.1/images/marker-icon-2x.png',
  shadowUrl:
    'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.7.1/images/marker-shadow.png',
  iconSize: [25, 41],
  iconAnchor: [12, 41],
  popupAnchor: [1, -34],
  shadowSize: [41, 41],
});

const anomalyIcon = new L.Icon({
  iconUrl:
    'https://raw.githubusercontent.com/pointhi/leaflet-color-markers/master/img/marker-icon-2x-orange.png',
  iconRetinaUrl:
    'https://raw.githubusercontent.com/pointhi/leaflet-color-markers/master/img/marker-icon-2x-orange.png',
  shadowUrl:
    'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.7.1/images/marker-shadow.png',
  iconSize: [25, 41],
  iconAnchor: [12, 41],
  popupAnchor: [1, -34],
  shadowSize: [41, 41],
});

const threatIcon = new L.Icon({
  iconUrl:
    'https://raw.githubusercontent.com/pointhi/leaflet-color-markers/master/img/marker-icon-2x-red.png',
  iconRetinaUrl:
    'https://raw.githubusercontent.com/pointhi/leaflet-color-markers/master/img/marker-icon-2x-red.png',
  shadowUrl:
    'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.7.1/images/marker-shadow.png',
  iconSize: [25, 41],
  iconAnchor: [12, 41],
  popupAnchor: [1, -34],
  shadowSize: [41, 41],
});

const blacklistedIcon = new L.Icon({
  iconUrl:
    'https://raw.githubusercontent.com/pointhi/leaflet-color-markers/master/img/marker-icon-2x-black.png',
  iconRetinaUrl:
    'https://raw.githubusercontent.com/pointhi/leaflet-color-markers/master/img/marker-icon-2x-black.png',
  shadowUrl:
    'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.7.1/images/marker-shadow.png',
  iconSize: [25, 41],
  iconAnchor: [12, 41],
  popupAnchor: [1, -34],
  shadowSize: [41, 41],
});

const getMarkerIcon = (log) => {
  if (log.is_blacklisted) return blacklistedIcon;
  if (log.is_verified_threat) return threatIcon;
  if (log.is_anomaly) return anomalyIcon;
  return defaultIcon;
};

const GeoMap = ({ locations }) => {
  return (
    <MapContainer
      center={[20, 0]}
      zoom={2}
      style={{ height: '100vh', width: '100%' }}
    >
      <TileLayer
        url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
        attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
      />
      {locations.map(
        (location, index) =>
          location.lat &&
          location.lon && (
            <Marker
              key={index}
              position={[location.lat, location.lon]}
              icon={getMarkerIcon(location)}
            >
              <Popup>
                <b>IP:</b> {location.ip} <br />
                <b>Location:</b> {location.city}, {location.country} <br />
                {location.attack_type && (
                  <>
                    <b>Attack Type:</b> {location.attack_type} (
                    {location.confidence_score
                      ? `${(location.confidence_score * 100).toFixed(2)}%`
                      : 'N/A'}
                    ) <br />
                  </>
                )}
                {location.is_anomaly && (
                  <>
                    <b>Anomaly:</b> Yes (
                    {location.anomaly_score
                      ? location.anomaly_score.toFixed(2)
                      : 'N/A'}
                    ) <br />
                  </>
                )}
                {location.is_verified_threat && (
                  <>
                    <b>Verified Threat:</b> Yes <br />
                  </>
                )}
                {location.is_blacklisted && (
                  <>
                    <b>Blacklisted:</b> Yes <br />
                  </>
                )}
                <b>Data:</b> {location.data}
              </Popup>
            </Marker>
          ),
      )}
    </MapContainer>
  );
};

export default GeoMap;
