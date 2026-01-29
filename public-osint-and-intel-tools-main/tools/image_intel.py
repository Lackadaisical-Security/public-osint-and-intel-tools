import requests
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS
import io
from typing import Dict, Any, Optional
from urllib.parse import urlparse
import os

class ImageIntel:
    def __init__(self):
        self.session = requests.Session()
        
    def analyze_image(self, image_source: str) -> Dict[str, Any]:
        """Analyze image from URL or file path"""
        results = {
            'source': image_source,
            'metadata': {},
            'exif_data': {},
            'gps_data': None,
            'file_info': {},
            'error': None
        }
        
        try:
            # Load image
            image = self._load_image(image_source)
            
            if image:
                # Basic file info
                results['file_info'] = {
                    'format': image.format,
                    'mode': image.mode,
                    'size': image.size,
                    'width': image.width,
                    'height': image.height
                }
                
                # Extract EXIF data
                exif_data = self._extract_exif(image)
                if exif_data:
                    results['exif_data'] = exif_data
                    
                    # Extract GPS data if available
                    gps_data = self._extract_gps(exif_data)
                    if gps_data:
                        results['gps_data'] = gps_data
                        
        except Exception as e:
            results['error'] = str(e)
            
        return results
    
    def _load_image(self, source: str) -> Optional[Image.Image]:
        """Load image from URL or file path"""
        try:
            if source.startswith(('http://', 'https://')):
                response = self.session.get(source, timeout=10)
                return Image.open(io.BytesIO(response.content))
            else:
                return Image.open(source)
        except:
            return None
    
    def _extract_exif(self, image: Image.Image) -> Dict[str, Any]:
        """Extract EXIF data from image"""
        exif_data = {}
        
        try:
            info = image._getexif()
            if info:
                for tag, value in info.items():
                    tag_name = TAGS.get(tag, tag)
                    
                    # Handle special cases
                    if tag_name == 'GPSInfo':
                        continue  # Process separately
                    elif isinstance(value, bytes):
                        try:
                            value = value.decode()
                        except:
                            value = str(value)
                            
                    exif_data[tag_name] = value
                    
        except:
            pass
            
        return exif_data
    
    def _extract_gps(self, exif_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Extract GPS coordinates from EXIF data"""
        try:
            gps_info = {}
            
            if 'GPSInfo' in exif_data:
                for key in exif_data['GPSInfo']:
                    tag_name = GPSTAGS.get(key, key)
                    gps_info[tag_name] = exif_data['GPSInfo'][key]
                    
                # Convert GPS coordinates to decimal degrees
                if all(k in gps_info for k in ['GPSLatitude', 'GPSLongitude', 
                                                'GPSLatitudeRef', 'GPSLongitudeRef']):
                    lat = self._convert_to_degrees(gps_info['GPSLatitude'])
                    lon = self._convert_to_degrees(gps_info['GPSLongitude'])
                    
                    if gps_info['GPSLatitudeRef'] == 'S':
                        lat = -lat
                    if gps_info['GPSLongitudeRef'] == 'W':
                        lon = -lon
                        
                    return {
                        'latitude': lat,
                        'longitude': lon,
                        'google_maps_url': f'https://www.google.com/maps?q={lat},{lon}',
                        'raw_gps_data': gps_info
                    }
                    
        except:
            pass
            
        return None
    
    def _convert_to_degrees(self, value):
        """Convert GPS coordinates to decimal degrees"""
        d = float(value[0])
        m = float(value[1])
        s = float(value[2])
        return d + (m / 60.0) + (s / 3600.0)
    
    def reverse_image_search_urls(self, image_url: str) -> Dict[str, str]:
        """Generate reverse image search URLs"""
        encoded_url = requests.utils.quote(image_url)
        
        return {
            'google': f'https://www.google.com/searchbyimage?image_url={encoded_url}',
            'tineye': f'https://tineye.com/search?url={encoded_url}',
            'yandex': f'https://yandex.com/images/search?url={encoded_url}&rpt=imageview',
            'bing': f'https://www.bing.com/images/search?q=imgurl:{encoded_url}&view=detailv2&iss=sbi'
        }
