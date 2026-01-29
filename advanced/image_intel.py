import requests
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS
import io
import hashlib
import json
from typing import Dict, Any, List
from datetime import datetime
import base64

class ImageIntel:
    def __init__(self):
        self.session = requests.Session()
        
    def analyze_image(self, image_path_or_url: str) -> Dict[str, Any]:
        """Analyze image for intelligence gathering"""
        results = {
            'source': image_path_or_url,
            'timestamp': datetime.now().isoformat(),
            'file_info': {},
            'metadata': {},
            'exif_data': {},
            'gps_location': {},
            'hashes': {},
            'reverse_search_urls': {},
            'potential_manipulation': False
        }
        
        # Load image
        image_data = self._load_image(image_path_or_url)
        if not image_data:
            return {'error': 'Failed to load image'}
        
        # Calculate hashes
        results['hashes'] = self._calculate_hashes(image_data)
        
        # Open image with PIL
        try:
            image = Image.open(io.BytesIO(image_data))
            
            # Basic file info
            results['file_info'] = {
                'format': image.format,
                'mode': image.mode,
                'size': image.size,
                'width': image.width,
                'height': image.height,
                'file_size_bytes': len(image_data)
            }
            
            # Extract EXIF data
            exif_data = self._extract_exif(image)
            results['exif_data'] = exif_data
            
            # Extract GPS coordinates if available
            results['gps_location'] = self._extract_gps(exif_data)
            
            # Check for potential manipulation
            results['potential_manipulation'] = self._check_manipulation(image, exif_data)
            
            # Generate reverse search URLs
            results['reverse_search_urls'] = self._generate_reverse_search_urls(image_path_or_url)
            
        except Exception as e:
            results['error'] = str(e)
        
        return results
    
    def _load_image(self, source: str) -> bytes:
        """Load image from URL or file path"""
        try:
            if source.startswith(('http://', 'https://')):
                response = self.session.get(source, timeout=30)
                return response.content
            else:
                with open(source, 'rb') as f:
                    return f.read()
        except:
            return None
    
    def _calculate_hashes(self, image_data: bytes) -> Dict[str, str]:
        """Calculate various hashes of the image"""
        return {
            'md5': hashlib.md5(image_data).hexdigest(),
            'sha1': hashlib.sha1(image_data).hexdigest(),
            'sha256': hashlib.sha256(image_data).hexdigest(),
            'sha512': hashlib.sha512(image_data).hexdigest()
        }
    
    def _extract_exif(self, image: Image) -> Dict[str, Any]:
        """Extract EXIF metadata from image"""
        exif_data = {}
        
        try:
            exifdata = image.getexif()
            
            for tag_id, value in exifdata.items():
                tag = TAGS.get(tag_id, tag_id)
                
                # Handle different data types
                if isinstance(value, bytes):
                    try:
                        value = value.decode()
                    except:
                        value = str(value)
                elif isinstance(value, (list, tuple)):
                    value = str(value)
                
                exif_data[tag] = value
                
            # Extract thumbnail if available
            if hasattr(exifdata, '_get_merged_dict'):
                merged = exifdata._get_merged_dict()
                if 'thumbnail' in merged:
                    exif_data['has_thumbnail'] = True
                    
        except:
            pass
        
        return exif_data
    
    def _extract_gps(self, exif_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract GPS coordinates from EXIF data"""
        gps_info = {}
        
        if 'GPSInfo' in exif_data:
            gps_data = exif_data['GPSInfo']
            
            try:
                # Parse GPS data
                if isinstance(gps_data, dict):
                    for key, value in gps_data.items():
                        decode = GPSTAGS.get(key, key)
                        gps_info[decode] = value
                    
                    # Convert to decimal degrees
                    lat = self._convert_to_degrees(gps_info.get('GPSLatitude', []))
                    lon = self._convert_to_degrees(gps_info.get('GPSLongitude', []))
                    
                    if lat and lon:
                        # Apply hemisphere
                        if gps_info.get('GPSLatitudeRef') == 'S':
                            lat = -lat
                        if gps_info.get('GPSLongitudeRef') == 'W':
                            lon = -lon
                        
                        gps_info['decimal'] = {
                            'latitude': lat,
                            'longitude': lon
                        }
                        
                        # Generate map URLs
                        gps_info['map_urls'] = {
                            'google_maps': f"https://www.google.com/maps?q={lat},{lon}",
                            'openstreetmap': f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}&zoom=15"
                        }
                        
                        # Reverse geocode
                        gps_info['location_name'] = self._reverse_geocode(lat, lon)
            except:
                pass
        
        return gps_info
    
    def _convert_to_degrees(self, value: List) -> float:
        """Convert GPS coordinates to decimal degrees"""
        try:
            if len(value) >= 3:
                degrees = float(value[0])
                minutes = float(value[1]) / 60.0
                seconds = float(value[2]) / 3600.0
                return degrees + minutes + seconds
        except:
            pass
        return None
    
    def _reverse_geocode(self, lat: float, lon: float) -> str:
        """Get location name from coordinates"""
        try:
            response = self.session.get(
                f"https://nominatim.openstreetmap.org/reverse",
                params={
                    'lat': lat,
                    'lon': lon,
                    'format': 'json'
                },
                headers={'User-Agent': 'OSINT-Toolkit/1.0'},
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json()
                return data.get('display_name', 'Unknown location')
        except:
            pass
        
        return 'Could not determine location'
    
    def _check_manipulation(self, image: Image, exif_data: Dict[str, Any]) -> bool:
        """Check for signs of image manipulation"""
        signs_of_manipulation = []
        
        # Check if software tags indicate editing
        software = exif_data.get('Software', '').lower()
        editing_software = ['photoshop', 'gimp', 'paint', 'editor', 'modified']
        
        for editor in editing_software:
            if editor in software:
                signs_of_manipulation.append(f"Edited with {software}")
        
        # Check for inconsistent timestamps
        if 'DateTime' in exif_data and 'DateTimeOriginal' in exif_data:
            if exif_data['DateTime'] != exif_data['DateTimeOriginal']:
                signs_of_manipulation.append("Modified timestamp detected")
        
        # Check for missing expected EXIF data
        if image.format == 'JPEG' and not exif_data:
            signs_of_manipulation.append("Missing EXIF data (possibly removed)")
        
        return len(signs_of_manipulation) > 0
    
    def _generate_reverse_search_urls(self, image_url: str) -> Dict[str, str]:
        """Generate URLs for reverse image searches"""
        urls = {}
        
        if image_url.startswith(('http://', 'https://')):
            urls['google'] = f"https://www.google.com/searchbyimage?image_url={image_url}"
            urls['tineye'] = f"https://tineye.com/search?url={image_url}"
            urls['yandex'] = f"https://yandex.com/images/search?rpt=imageview&url={image_url}"
            urls['bing'] = f"https://www.bing.com/images/search?q=imgurl:{image_url}&view=detailv2&iss=sbi"
        else:
            urls['note'] = "Upload image manually to reverse search engines"
            urls['google'] = "https://images.google.com/"
            urls['tineye'] = "https://tineye.com/"
            urls['yandex'] = "https://yandex.com/images/"
            urls['bing'] = "https://www.bing.com/visualsearch"
        
        return urls
    
    def extract_text_from_image(self, image_path_or_url: str) -> Dict[str, Any]:
        """Extract text from image using OCR"""
        try:
            import pytesseract
            
            image_data = self._load_image(image_path_or_url)
            if not image_data:
                return {'error': 'Failed to load image'}
            
            image = Image.open(io.BytesIO(image_data))
            
            # Extract text
            text = pytesseract.image_to_string(image)
            
            # Extract text with confidence scores
            data = pytesseract.image_to_data(image, output_type=pytesseract.Output.DICT)
            
            words = []
            for i in range(len(data['text'])):
                if int(data['conf'][i]) > 0:
                    words.append({
                        'text': data['text'][i],
                        'confidence': data['conf'][i]
                    })
            
            return {
                'full_text': text,
                'words': words,
                'language': pytesseract.image_to_osd(image)
            }
            
        except ImportError:
            return {'error': 'pytesseract not installed. Install with: pip install pytesseract'}
        except Exception as e:
            return {'error': str(e)}
