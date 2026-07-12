from threatzone import ThreatZone, ThreatZoneError

client = ThreatZone(api_key="dummy-key-for-verification")

assert issubclass(ThreatZoneError, Exception)

print("threatzone imported and ThreatZone client initialized successfully.")
