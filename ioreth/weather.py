#!/usr/bin/env python3
"""
Weather forecast module for APRS bot
Provides weather forecasts via National Weather Service API (US) and OpenWeatherMap (fallback/international)
"""
import logging
import requests
import re
from typing import Optional, Tuple

logger = logging.getLogger(__name__)

class WeatherForecast:
    """Fetches weather forecasts for zip codes or city/state/country"""
    
    # National Weather Service API (US only, no API key needed)
    NWS_API_BASE = "https://api.weather.gov"
    
    # OpenWeatherMap API (requires API key, configure in aprsbot.conf)
    OWM_API_BASE = "https://api.openweathermap.org/data/2.5"
    
    def __init__(self, openweathermap_api_key: Optional[str] = None):
        """
        Initialize weather forecast service
        
        Args:
            openweathermap_api_key: Optional API key for OpenWeatherMap (for non-US locations)
        """
        self.owm_api_key = openweathermap_api_key
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': '(APRS Bot Weather Service, contact via APRS)',
            'Accept': 'application/json'
        })
    
    def get_forecast(self, query: str) -> str:
        """
        Get weather forecast for a location
        
        Args:
            query: Either a US zip code (5 digits) or "city,state" or "city,country"
        
        Returns:
            Formatted weather forecast string suitable for APRS message
        """
        query = query.strip()
        
        # Check if it's a US zip code
        if re.match(r'^\d{5}$', query):
            return self._get_forecast_by_zip(query)
        else:
            # Try to parse as city,state or city,country
            return self._get_forecast_by_location(query)
    
    def _get_forecast_by_zip(self, zipcode: str) -> str:
        """Get forecast using US zip code via NWS API"""
        try:
            # First, get lat/lon from zip code using NWS geocoding
            # Note: NWS doesn't have direct zip lookup, so we use a geocoding service
            # For production, you might want to use a dedicated geocoding API
            
            # Try NWS API directly with coordinates from zip
            # This is a simplified approach - in production you'd want proper geocoding
            lat, lon = self._geocode_zip(zipcode)
            if lat is None or lon is None:
                return f"Could not locate zip code {zipcode}"
            
            return self._get_nws_forecast(lat, lon, zipcode)
            
        except Exception as e:
            logger.error(f"Error getting forecast for zip {zipcode}: {e}")
            return f"Weather service error for {zipcode}. Try again later."
    
    def _get_forecast_by_location(self, location: str) -> str:
        """Get forecast by city,state or city,country"""
        try:
            # Parse location string
            parts = [p.strip() for p in location.split(',')]
            if len(parts) < 2:
                return "Format: 'city,state' or 'city,country' or use 5-digit zip"
            
            city = parts[0]
            region = parts[1]  # state or country code
            
            # Try to geocode and get forecast
            lat, lon = self._geocode_location(city, region)
            if lat is None or lon is None:
                return f"Could not locate {location}"
            
            # Try NWS first (for US locations)
            if len(region) == 2 and region.upper() in self._us_state_codes():
                return self._get_nws_forecast(lat, lon, location)
            
            # Fall back to OpenWeatherMap for international
            if self.owm_api_key:
                return self._get_owm_forecast(lat, lon, location)
            else:
                return "International weather requires API key. US locations only."
                
        except Exception as e:
            logger.error(f"Error getting forecast for {location}: {e}")
            return f"Weather service error. Try again later."
    
    def _geocode_zip(self, zipcode: str) -> Tuple[Optional[float], Optional[float]]:
        """Convert US zip code to lat/lon"""
        try:
            # Using a simple free geocoding service
            # In production, consider using Google Maps API, Nominatim, or similar
            url = f"https://api.zippopotam.us/us/{zipcode}"
            response = self.session.get(url, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                lat = float(data['places'][0]['latitude'])
                lon = float(data['places'][0]['longitude'])
                return lat, lon
        except Exception as e:
            logger.error(f"Geocoding error for zip {zipcode}: {e}")
        
        return None, None
    
    def _geocode_location(self, city: str, region: str) -> Tuple[Optional[float], Optional[float]]:
        """Convert city,state/country to lat/lon"""
        try:
            # Using OpenStreetMap Nominatim (free, no API key)
            url = "https://nominatim.openstreetmap.org/search"
            params = {
                'q': f"{city}, {region}",
                'format': 'json',
                'limit': 1
            }
            headers = {
                'User-Agent': 'APRS-Bot/1.0'
            }
            response = requests.get(url, params=params, headers=headers, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                if data:
                    lat = float(data[0]['lat'])
                    lon = float(data[0]['lon'])
                    return lat, lon
        except Exception as e:
            logger.error(f"Geocoding error for {city}, {region}: {e}")
        
        return None, None
    
    def _get_nws_forecast(self, lat: float, lon: float, location: str) -> str:
        """Get forecast from National Weather Service API"""
        try:
            # Get grid point
            point_url = f"{self.NWS_API_BASE}/points/{lat:.4f},{lon:.4f}"
            point_resp = self.session.get(point_url, timeout=10)
            
            if point_resp.status_code != 200:
                logger.warning(f"NWS point lookup failed: {point_resp.status_code}")
                return f"NWS unavailable for {location}"
            
            point_data = point_resp.json()
            forecast_url = point_data['properties']['forecast']
            
            # Get forecast
            forecast_resp = self.session.get(forecast_url, timeout=10)
            if forecast_resp.status_code != 200:
                return f"Forecast unavailable for {location}"
            
            forecast_data = forecast_resp.json()
            periods = forecast_data['properties']['periods']
            
            # Format first two periods (today/tonight or similar)
            if len(periods) >= 2:
                p1 = periods[0]
                p2 = periods[1]
                
                msg = f"{location}: {p1['name']}: {p1['shortForecast']}, {p1['temperature']}°{p1['temperatureUnit']}. "
                msg += f"{p2['name']}: {p2['shortForecast']}, {p2['temperature']}°{p2['temperatureUnit']}."
                
                # Truncate if too long for APRS (67 char limit per message)
                if len(msg) > 67:
                    msg = msg[:64] + "..."
                
                return msg
            else:
                return f"{location}: Forecast data incomplete"
                
        except Exception as e:
            logger.error(f"NWS forecast error: {e}")
            return f"Weather service temporarily unavailable"
    
    def _get_owm_forecast(self, lat: float, lon: float, location: str) -> str:
        """Get forecast from OpenWeatherMap API"""
        if not self.owm_api_key:
            return "OpenWeatherMap API key not configured"
        
        try:
            url = f"{self.OWM_API_BASE}/forecast"
            params = {
                'lat': lat,
                'lon': lon,
                'appid': self.owm_api_key,
                'units': 'imperial',
                'cnt': 2  # Next 2 forecast periods
            }
            
            response = self.session.get(url, params=params, timeout=10)
            if response.status_code != 200:
                return f"Weather service error ({response.status_code})"
            
            data = response.json()
            forecasts = data.get('list', [])
            
            if forecasts:
                f = forecasts[0]
                temp = round(f['main']['temp'])
                desc = f['weather'][0]['description'].title()
                
                msg = f"{location}: {desc}, {temp}°F"
                
                # Add next period if available
                if len(forecasts) > 1:
                    f2 = forecasts[1]
                    temp2 = round(f2['main']['temp'])
                    desc2 = f2['weather'][0]['description'].title()
                    msg += f". Later: {desc2}, {temp2}°F"
                
                if len(msg) > 67:
                    msg = msg[:64] + "..."
                
                return msg
            else:
                return f"No forecast available for {location}"
                
        except Exception as e:
            logger.error(f"OpenWeatherMap error: {e}")
            return "Weather service temporarily unavailable"
    
    def _us_state_codes(self) -> set:
        """Return set of US state abbreviations"""
        return {
            'AL', 'AK', 'AZ', 'AR', 'CA', 'CO', 'CT', 'DE', 'FL', 'GA',
            'HI', 'ID', 'IL', 'IN', 'IA', 'KS', 'KY', 'LA', 'ME', 'MD',
            'MA', 'MI', 'MN', 'MS', 'MO', 'MT', 'NE', 'NV', 'NH', 'NJ',
            'NM', 'NY', 'NC', 'ND', 'OH', 'OK', 'OR', 'PA', 'RI', 'SC',
            'SD', 'TN', 'TX', 'UT', 'VT', 'VA', 'WA', 'WV', 'WI', 'WY'
        }
