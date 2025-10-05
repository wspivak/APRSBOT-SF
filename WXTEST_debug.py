#!/usr/bin/env python3
"""
Debug script for testing OpenWeatherMap API directly
"""
import requests
import json

###############################################
# Replace with your actual API key
API_KEY = "Enter KEY"  # Put your full key here
###########################################

def test_owm_api():
    """Test OpenWeatherMap API with different endpoints"""
    
    print("=" * 60)
    print("OpenWeatherMap API Debug Test")
    print("=" * 60)
    
    # Test coordinates for London
    lat, lon = 51.5074, -0.1278
    
    print(f"\nAPI Key: {API_KEY[:8]}... (length: {len(API_KEY)})")
    print(f"Testing location: London (lat={lat}, lon={lon})")
    
    # Test 1: Current Weather (One Call API 3.0 - NEW)
    print("\n" + "-" * 60)
    print("Test 1: One Call API 3.0 (current weather)")
    print("-" * 60)
    url1 = "https://api.openweathermap.org/data/3.0/onecall"
    params1 = {
        'lat': lat,
        'lon': lon,
        'appid': API_KEY,
        'units': 'imperial',
        'exclude': 'minutely,hourly,daily,alerts'
    }
    
    try:
        resp1 = requests.get(url1, params=params1, timeout=10)
        print(f"Status Code: {resp1.status_code}")
        if resp1.status_code == 200:
            data = resp1.json()
            print("SUCCESS! Response:")
            print(json.dumps(data.get('current', {}), indent=2)[:500])
        else:
            print(f"ERROR Response: {resp1.text}")
    except Exception as e:
        print(f"Exception: {e}")
    
    # Test 2: Current Weather API 2.5 (should work with free tier)
    print("\n" + "-" * 60)
    print("Test 2: Current Weather API 2.5")
    print("-" * 60)
    url2 = "https://api.openweathermap.org/data/2.5/weather"
    params2 = {
        'lat': lat,
        'lon': lon,
        'appid': API_KEY,
        'units': 'imperial'
    }
    
    try:
        resp2 = requests.get(url2, params=params2, timeout=10)
        print(f"Status Code: {resp2.status_code}")
        if resp2.status_code == 200:
            data = resp2.json()
            print("SUCCESS! Response:")
            print(json.dumps(data, indent=2)[:800])
        else:
            print(f"ERROR Response: {resp2.text}")
    except Exception as e:
        print(f"Exception: {e}")
    
    # Test 3: By city name
    print("\n" + "-" * 60)
    print("Test 3: Current Weather by City Name")
    print("-" * 60)
    url3 = "https://api.openweathermap.org/data/2.5/weather"
    params3 = {
        'q': 'London,UK',
        'appid': API_KEY,
        'units': 'imperial'
    }
    
    try:
        resp3 = requests.get(url3, params=params3, timeout=10)
        print(f"Status Code: {resp3.status_code}")
        if resp3.status_code == 200:
            data = resp3.json()
            print("SUCCESS! Response:")
            temp = data['main']['temp']
            desc = data['weather'][0]['description']
            print(f"  Temperature: {temp}°F")
            print(f"  Conditions: {desc}")
        else:
            print(f"ERROR Response: {resp3.text}")
    except Exception as e:
        print(f"Exception: {e}")
    
    # Test 4: Check API key status
    print("\n" + "-" * 60)
    print("Test 4: API Key Validation")
    print("-" * 60)
    url4 = "https://api.openweathermap.org/data/2.5/weather"
    params4 = {
        'q': 'London',
        'appid': API_KEY
    }
    
    try:
        resp4 = requests.get(url4, params=params4, timeout=10)
        if resp4.status_code == 200:
            print("✓ API Key is VALID and ACTIVE")
        elif resp4.status_code == 401:
            print("✗ API Key is INVALID or NOT ACTIVATED")
            print("  Possible reasons:")
            print("  - Key not activated yet (wait up to 2 hours)")
            print("  - Wrong key copied")
            print("  - Account not verified")
        elif resp4.status_code == 429:
            print("✗ Rate limit exceeded")
        else:
            print(f"? Unexpected status: {resp4.status_code}")
            print(f"  Response: {resp4.text}")
    except Exception as e:
        print(f"Exception: {e}")
    
    print("\n" + "=" * 60)
    print("Debug test complete")
    print("=" * 60)

if __name__ == "__main__":
    test_owm_api()
