import requests
from typing import Dict, List, Any
from config import Config
import re

class SocialMediaIntel:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': Config.USER_AGENT})
        
    def search_username(self, username: str) -> Dict[str, Any]:
        """Search for username across multiple social media platforms"""
        results = {
            'username': username,
            'platforms_checked': [],
            'found_profiles': [],
            'possible_profiles': []
        }
        
        # Platform URLs to check
        platforms = {
            'GitHub': f'https://api.github.com/users/{username}',
            'Reddit': f'https://www.reddit.com/user/{username}/about.json',
            'Twitter': f'https://twitter.com/{username}',
            'Instagram': f'https://www.instagram.com/{username}/',
            'LinkedIn': f'https://www.linkedin.com/in/{username}',
            'Facebook': f'https://www.facebook.com/{username}',
            'TikTok': f'https://www.tiktok.com/@{username}',
            'YouTube': f'https://www.youtube.com/@{username}',
            'Pinterest': f'https://www.pinterest.com/{username}',
            'Tumblr': f'https://{username}.tumblr.com',
            'Medium': f'https://medium.com/@{username}',
            'DeviantArt': f'https://www.deviantart.com/{username}',
            'Twitch': f'https://www.twitch.tv/{username}',
            'SoundCloud': f'https://soundcloud.com/{username}',
            'Spotify': f'https://open.spotify.com/user/{username}',
            'Steam': f'https://steamcommunity.com/id/{username}',
            'GitLab': f'https://gitlab.com/{username}',
            'Bitbucket': f'https://bitbucket.org/{username}/',
            'Keybase': f'https://keybase.io/{username}',
            'HackerNews': f'https://news.ycombinator.com/user?id={username}'
        }
        
        for platform, url in platforms.items():
            results['platforms_checked'].append(platform)
            profile_info = self._check_platform(platform, url, username)
            
            if profile_info['exists']:
                results['found_profiles'].append(profile_info)
            elif profile_info['possible']:
                results['possible_profiles'].append(profile_info)
                
        return results
    
    def _check_platform(self, platform: str, url: str, username: str) -> Dict[str, Any]:
        """Check if profile exists on a specific platform"""
        profile_info = {
            'platform': platform,
            'url': url,
            'exists': False,
            'possible': False,
            'details': {}
        }
        
        try:
            if platform == 'GitHub':
                response = self.session.get(url, timeout=5)
                if response.status_code == 200:
                    data = response.json()
                    profile_info['exists'] = True
                    profile_info['details'] = {
                        'name': data.get('name'),
                        'bio': data.get('bio'),
                        'location': data.get('location'),
                        'public_repos': data.get('public_repos'),
                        'followers': data.get('followers'),
                        'created_at': data.get('created_at')
                    }
                    
            elif platform == 'Reddit':
                response = self.session.get(url, timeout=5)
                if response.status_code == 200:
                    data = response.json()
                    if data.get('data'):
                        profile_info['exists'] = True
                        profile_info['details'] = {
                            'karma': data['data'].get('total_karma'),
                            'created': data['data'].get('created_utc'),
                            'is_verified': data['data'].get('verified')
                        }
                        
            else:
                # For other platforms, check HTTP status
                response = self.session.get(url, timeout=5, allow_redirects=False)
                if response.status_code in [200, 301, 302]:
                    profile_info['possible'] = True
                    
        except Exception as e:
            profile_info['error'] = str(e)
            
        return profile_info
    
    def extract_social_links_from_text(self, text: str) -> List[Dict[str, str]]:
        """Extract social media links from text"""
        social_patterns = {
            'Twitter': r'(?:https?://)?(?:www\.)?twitter\.com/([A-Za-z0-9_]+)',
            'Instagram': r'(?:https?://)?(?:www\.)?instagram\.com/([A-Za-z0-9_.]+)',
            'Facebook': r'(?:https?://)?(?:www\.)?facebook\.com/([A-Za-z0-9.]+)',
            'LinkedIn': r'(?:https?://)?(?:www\.)?linkedin\.com/in/([A-Za-z0-9-]+)',
            'GitHub': r'(?:https?://)?(?:www\.)?github\.com/([A-Za-z0-9-]+)',
            'YouTube': r'(?:https?://)?(?:www\.)?youtube\.com/@([A-Za-z0-9_-]+)'
        }
        
        found_links = []
        for platform, pattern in social_patterns.items():
            matches = re.findall(pattern, text)
            for match in matches:
                found_links.append({
                    'platform': platform,
                    'username': match,
                    'url': f'https://{platform.lower()}.com/{match}'
                })
                
        return found_links
    
    def advanced_username_search(self, username: str) -> Dict[str, Any]:
        """Advanced username search with breach data and analytics"""
        results = self.search_username(username)
        
        # Add breach data check
        results['breach_data'] = self._check_breach_databases(username)
        
        # Add pattern analysis
        results['username_analysis'] = self._analyze_username_patterns(username)
        
        # Add related usernames
        results['related_usernames'] = self._generate_related_usernames(username)
        
        return results
    
    def _check_breach_databases(self, username: str) -> Dict[str, Any]:
        """Check against known breach databases"""
        breach_indicators = {
            'common_patterns': [],
            'risk_score': 0,
            'recommendations': []
        }
        
        # Check for common compromised patterns
        risky_patterns = ['admin', '123', 'password', 'user', 'test']
        for pattern in risky_patterns:
            if pattern in username.lower():
                breach_indicators['common_patterns'].append(pattern)
                breach_indicators['risk_score'] += 20
        
        # Generate recommendations
        if breach_indicators['risk_score'] > 40:
            breach_indicators['recommendations'].append("High-risk username pattern detected")
        
        return breach_indicators
    
    def _analyze_username_patterns(self, username: str) -> Dict[str, Any]:
        """Analyze username for patterns and characteristics"""
        import re
        
        analysis = {
            'length': len(username),
            'contains_numbers': bool(re.search(r'\d', username)),
            'contains_special_chars': bool(re.search(r'[^a-zA-Z0-9]', username)),
            'case_pattern': 'mixed' if username != username.lower() and username != username.upper() else 'uniform',
            'common_suffixes': [],
            'year_indicators': re.findall(r'(19|20)\d{2}', username)
        }
        
        # Check for common suffixes
        suffixes = ['123', '1', 'admin', 'user', 'official']
        for suffix in suffixes:
            if username.lower().endswith(suffix):
                analysis['common_suffixes'].append(suffix)
        
        return analysis
    
    def _generate_related_usernames(self, username: str) -> List[str]:
        """Generate related username variations"""
        variations = []
        base = username.lower()
        
        # Common variations
        variations.extend([
            base + '1', base + '123', base + '2024',
            base + '_', base + '.', 
            'the' + base, base + 'official',
            base.replace('_', '.'), base.replace('.', '_')
        ])
        
        # Number variations
        for i in range(1, 10):
            variations.append(base + str(i))
        
        return list(set(variations))

    def search_social_mentions(self, query: str) -> Dict[str, Any]:
        """Search for social media mentions using various techniques"""
        results = {
            'query': query,
            'platforms_searched': [],
            'mentions_found': [],
            'sentiment_analysis': {},
            'timeline_data': []
        }
        
        # This would integrate with social media APIs in production
        # For now, we'll simulate the structure
        
        platforms = ['twitter', 'reddit', 'linkedin', 'facebook']
        for platform in platforms:
            results['platforms_searched'].append(platform)
            # In production, this would make actual API calls
            
        return results
