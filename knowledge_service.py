#!/usr/bin/env python3
"""
Enterprise Knowledge Service
Lifecycle data provider with endoflife.date API, vendor integrations, and vulnerability enrichment
"""

import asyncio
import aiohttp
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
import re
import hashlib
import sqlite3
from pathlib import Path

from enterprise_architecture import LifecycleProvider, LifecycleInfo, OSFacts

logger = logging.getLogger(__name__)

class EndOfLifeDateProvider(LifecycleProvider):
    """Production endoflife.date API integration with caching and fallback"""
    
    def __init__(self, config: Dict[str, Any]):
        self.base_url = config.get("base_url", "https://endoflife.date/api")
        self.cache_ttl = config.get("cache_ttl", 86400)  # 24 hours
        self.timeout = aiohttp.ClientTimeout(total=30)
        
        # Local cache database
        self.cache_db = config.get("cache_db", "eol_cache.db")
        self.init_cache_db()
        
        # Product mappings for endoflife.date
        self.product_mappings = {
            "windows-server": "windows-server",
            "windows": "windows",
            "ubuntu": "ubuntu",
            "rhel": "rhel",
            "centos": "centos",
            "debian": "debian",
            "sles": "suse-linux-enterprise-server",
            "cisco-ios": "cisco-ios",
            "cisco-iosxr": "cisco-ios-xr", 
            "cisco-nxos": "cisco-nx-os",
            "junos": "juniper-junos",
            "arista-eos": "arista-eos",
            "fortios": "fortinet-fortios",
            "panos": "palo-alto-pan-os"
        }
        
        # Rate limiting
        self.rate_limiter = AsyncRateLimiter(calls=60, period=60)  # 60 calls per minute
    
    def init_cache_db(self):
        """Initialize SQLite cache database"""
        
        Path(self.cache_db).parent.mkdir(parents=True, exist_ok=True)
        
        conn = sqlite3.connect(self.cache_db)
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS eol_cache (
                product TEXT,
                version TEXT,
                eol_date TEXT,
                eos_date TEXT,
                lts BOOLEAN,
                latest_version TEXT,
                source TEXT,
                fetched_at TEXT,
                raw_data TEXT,
                PRIMARY KEY (product, version)
            )
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_fetched_at ON eol_cache(fetched_at)
        """)
        
        conn.commit()
        conn.close()
    
    async def get_lifecycle_info(self, product: str, version: str) -> Optional[LifecycleInfo]:
        """Get lifecycle information for a product/version"""
        
        # Check cache first
        cached_info = await self._get_from_cache(product, version)
        if cached_info:
            return cached_info
        
        # Map product to endoflife.date format
        eol_product = self.product_mappings.get(product, product)
        
        try:
            # Fetch from endoflife.date API
            lifecycle_info = await self._fetch_from_api(eol_product, version)
            
            if lifecycle_info:
                # Cache the result
                await self._store_in_cache(product, version, lifecycle_info)
                return lifecycle_info
            
            # Try fallback methods
            return await self._get_fallback_info(product, version)
            
        except Exception as e:
            logger.error(f"Error getting lifecycle info for {product} {version}: {e}")
            return await self._get_fallback_info(product, version)
    
    async def _get_from_cache(self, product: str, version: str) -> Optional[LifecycleInfo]:
        """Get lifecycle info from cache"""
        
        try:
            conn = sqlite3.connect(self.cache_db)
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT * FROM eol_cache 
                WHERE product = ? AND version = ?
            """, (product, version))
            
            row = cursor.fetchone()
            conn.close()
            
            if row:
                fetched_at = datetime.fromisoformat(row[7])
                
                # Check if cache is still valid
                if datetime.now() - fetched_at < timedelta(seconds=self.cache_ttl):
                    return LifecycleInfo(
                        product=row[0],
                        version=row[1],
                        eol_date=datetime.fromisoformat(row[2]) if row[2] else None,
                        eos_date=datetime.fromisoformat(row[3]) if row[3] else None,
                        lts=bool(row[4]),
                        latest_version=row[5],
                        source=row[6],
                        fetched_at=fetched_at
                    )
            
            return None
            
        except Exception as e:
            logger.debug(f"Cache lookup failed: {e}")
            return None
    
    async def _store_in_cache(self, product: str, version: str, info: LifecycleInfo):
        """Store lifecycle info in cache"""
        
        try:
            conn = sqlite3.connect(self.cache_db)
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT OR REPLACE INTO eol_cache 
                (product, version, eol_date, eos_date, lts, latest_version, source, fetched_at, raw_data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                product,
                version,
                info.eol_date.isoformat() if info.eol_date else None,
                info.eos_date.isoformat() if info.eos_date else None,
                info.lts,
                info.latest_version,
                info.source,
                info.fetched_at.isoformat(),
                ""  # raw_data placeholder
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Failed to cache lifecycle info: {e}")
    
    async def _fetch_from_api(self, product: str, version: str) -> Optional[LifecycleInfo]:
        """Fetch lifecycle info from endoflife.date API"""
        
        await self.rate_limiter.acquire()
        
        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                # Get product lifecycle data
                url = f"{self.base_url}/{product}.json"
                
                async with session.get(url) as response:
                    if response.status != 200:
                        logger.debug(f"Product {product} not found in endoflife.date")
                        return None
                    
                    data = await response.json()
                    
                    # Find matching version
                    version_info = self._find_version_match(data, version)
                    
                    if version_info:
                        return self._parse_eol_data(product, version, version_info, data)
                    
                    return None
                    
        except Exception as e:
            logger.error(f"API fetch failed for {product}: {e}")
            return None
    
    def _find_version_match(self, data: List[Dict], target_version: str) -> Optional[Dict]:
        """Find best matching version in endoflife.date response"""
        
        if not data or not target_version:
            return None
        
        # First try exact match
        for version_info in data:
            cycle = str(version_info.get("cycle", ""))
            if cycle == target_version:
                return version_info
        
        # Try partial matches
        for version_info in data:
            cycle = str(version_info.get("cycle", ""))
            
            # Handle major.minor matching
            if "." in target_version:
                target_major_minor = ".".join(target_version.split(".")[:2])
                if cycle == target_major_minor:
                    return version_info
            
            # Handle major version matching
            target_major = target_version.split(".")[0]
            if cycle == target_major:
                return version_info
        
        # Try fuzzy matching for special cases
        for version_info in data:
            cycle = str(version_info.get("cycle", ""))
            
            # Windows Server special cases
            if "2019" in target_version and "2019" in cycle:
                return version_info
            if "2016" in target_version and "2016" in cycle:
                return version_info
            if "2012" in target_version and "2012" in cycle:
                return version_info
        
        # Return latest if no match (for reference)
        return data[0] if data else None
    
    def _parse_eol_data(
        self, 
        product: str, 
        version: str, 
        version_info: Dict, 
        all_data: List[Dict]
    ) -> LifecycleInfo:
        """Parse endoflife.date response into LifecycleInfo"""
        
        # Parse dates
        eol_date = None
        eos_date = None
        
        eol_str = version_info.get("eol")
        if eol_str and eol_str != "false":
            try:
                if isinstance(eol_str, bool):
                    eol_date = None if not eol_str else datetime.now()
                else:
                    eol_date = datetime.strptime(str(eol_str), "%Y-%m-%d")
            except:
                logger.debug(f"Failed to parse EOL date: {eol_str}")
        
        support_str = version_info.get("support")
        if support_str and support_str != "false":
            try:
                if isinstance(support_str, bool):
                    eos_date = None if not support_str else datetime.now()
                else:
                    eos_date = datetime.strptime(str(support_str), "%Y-%m-%d")
            except:
                logger.debug(f"Failed to parse EOS date: {support_str}")
        
        # Check if LTS
        lts = version_info.get("lts", False)
        
        # Get latest version
        latest_version = None
        if all_data:
            latest_info = all_data[0]  # First item is usually latest
            latest_version = str(latest_info.get("cycle", ""))
        
        return LifecycleInfo(
            product=product,
            version=version,
            eol_date=eol_date,
            eos_date=eos_date,
            lts=lts,
            latest_version=latest_version,
            source="endoflife.date",
            fetched_at=datetime.now()
        )
    
    async def _get_fallback_info(self, product: str, version: str) -> Optional[LifecycleInfo]:
        """Get fallback lifecycle info for unknown products"""
        
        # Static fallback data for common products
        fallback_data = {
            "windows-server": {
                "2008": {"eol": "2020-01-14", "eos": "2023-01-10"},
                "2008-r2": {"eol": "2020-01-14", "eos": "2023-01-10"},
                "2012": {"eol": "2023-10-10", "eos": "2026-10-10"},
                "2012-r2": {"eol": "2023-10-10", "eos": "2026-10-10"},
                "2016": {"eol": "2027-01-12", "eos": "2029-01-12"},
                "2019": {"eol": "2029-01-09", "eos": "2031-01-09"},
                "2022": {"eol": "2031-10-14", "eos": "2033-10-14"}
            },
            "ubuntu": {
                "14.04": {"eol": "2019-04-25", "eos": "2024-04-25"},
                "16.04": {"eol": "2021-04-30", "eos": "2026-04-30"},
                "18.04": {"eol": "2023-05-31", "eos": "2028-05-31"},
                "20.04": {"eol": "2025-04-23", "eos": "2030-04-23"},
                "22.04": {"eol": "2027-04-21", "eos": "2032-04-21"}
            },
            "rhel": {
                "6": {"eol": "2020-11-30", "eos": "2024-06-30"},
                "7": {"eol": "2024-06-30", "eos": "2026-06-30"},
                "8": {"eol": "2029-05-31", "eos": "2032-05-31"},
                "9": {"eol": "2032-05-31", "eos": "2035-05-31"}
            }
        }
        
        product_data = fallback_data.get(product, {})
        version_data = product_data.get(version)
        
        if version_data:
            try:
                eol_date = datetime.strptime(version_data["eol"], "%Y-%m-%d")
                eos_date = datetime.strptime(version_data["eos"], "%Y-%m-%d")
                
                return LifecycleInfo(
                    product=product,
                    version=version,
                    eol_date=eol_date,
                    eos_date=eos_date,
                    lts=False,
                    latest_version=None,
                    source="fallback",
                    fetched_at=datetime.now()
                )
            except:
                pass
        
        return None
    
    async def refresh_cache(self) -> None:
        """Refresh expired cache entries"""
        
        logger.info("Refreshing EOL cache...")
        
        try:
            conn = sqlite3.connect(self.cache_db)
            cursor = conn.cursor()
            
            # Find expired entries
            cutoff = datetime.now() - timedelta(seconds=self.cache_ttl)
            cursor.execute("""
                SELECT DISTINCT product, version FROM eol_cache 
                WHERE fetched_at < ?
            """, (cutoff.isoformat(),))
            
            expired_entries = cursor.fetchall()
            conn.close()
            
            logger.info(f"Found {len(expired_entries)} expired cache entries")
            
            # Refresh each entry
            for product, version in expired_entries:
                try:
                    await self.get_lifecycle_info(product, version)
                    await asyncio.sleep(1)  # Rate limiting
                except Exception as e:
                    logger.error(f"Failed to refresh {product} {version}: {e}")
                    
        except Exception as e:
            logger.error(f"Cache refresh failed: {e}")
    
    async def get_product_list(self) -> List[str]:
        """Get list of supported products from endoflife.date"""
        
        try:
            await self.rate_limiter.acquire()
            
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                url = f"{self.base_url}/products.json"
                
                async with session.get(url) as response:
                    if response.status == 200:
                        products = await response.json()
                        return products
                    else:
                        return list(self.product_mappings.keys())
                        
        except Exception as e:
            logger.error(f"Failed to get product list: {e}")
            return list(self.product_mappings.keys())

class VulnerabilityEnricher:
    """Enrich lifecycle data with vulnerability information"""
    
    def __init__(self, config: Dict[str, Any]):
        self.kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        self.nvd_api_key = config.get("nvd_api_key")
        self.cache_ttl = config.get("vuln_cache_ttl", 3600)  # 1 hour
        self.vuln_cache = {}
    
    async def enrich_with_vulnerabilities(
        self, 
        lifecycle_info: LifecycleInfo,
        os_facts: OSFacts
    ) -> Dict[str, Any]:
        """Enrich lifecycle info with vulnerability data"""
        
        enrichment = {
            "kev_vulnerabilities": [],
            "high_risk_cves": [],
            "vulnerability_count": 0,
            "last_updated": datetime.now().isoformat()
        }
        
        try:
            # Get CISA KEV data
            kev_vulns = await self._get_kev_vulnerabilities(
                lifecycle_info.product, 
                lifecycle_info.version
            )
            enrichment["kev_vulnerabilities"] = kev_vulns
            
            # Get high-risk CVEs if NVD API key available
            if self.nvd_api_key:
                cves = await self._get_nvd_vulnerabilities(
                    lifecycle_info.product,
                    lifecycle_info.version
                )
                enrichment["high_risk_cves"] = cves
            
            enrichment["vulnerability_count"] = (
                len(kev_vulns) + len(enrichment["high_risk_cves"])
            )
            
        except Exception as e:
            logger.error(f"Vulnerability enrichment failed: {e}")
        
        return enrichment
    
    async def _get_kev_vulnerabilities(self, product: str, version: str) -> List[Dict]:
        """Get CISA Known Exploited Vulnerabilities"""
        
        cache_key = f"kev_{product}_{version}"
        
        if cache_key in self.vuln_cache:
            cached_time, data = self.vuln_cache[cache_key]
            if datetime.now() - cached_time < timedelta(seconds=self.cache_ttl):
                return data
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(self.kev_url) as response:
                    if response.status == 200:
                        kev_data = await response.json()
                        
                        # Filter relevant vulnerabilities
                        relevant_vulns = []
                        product_keywords = self._get_product_keywords(product)
                        
                        for vuln in kev_data.get("vulnerabilities", []):
                            vuln_product = vuln.get("vendorProject", "").lower()
                            vuln_product += " " + vuln.get("product", "").lower()
                            
                            if any(keyword in vuln_product for keyword in product_keywords):
                                relevant_vulns.append({
                                    "cve_id": vuln.get("cveID"),
                                    "vendor": vuln.get("vendorProject"),
                                    "product": vuln.get("product"),
                                    "description": vuln.get("shortDescription"),
                                    "date_added": vuln.get("dateAdded"),
                                    "due_date": vuln.get("dueDate")
                                })
                        
                        # Cache result
                        self.vuln_cache[cache_key] = (datetime.now(), relevant_vulns)
                        return relevant_vulns
            
            return []
            
        except Exception as e:
            logger.error(f"KEV lookup failed: {e}")
            return []
    
    async def _get_nvd_vulnerabilities(self, product: str, version: str) -> List[Dict]:
        """Get high-severity CVEs from NVD (requires API key)"""
        
        # Placeholder for NVD API integration
        # Would implement CPE-based lookups here
        return []
    
    def _get_product_keywords(self, product: str) -> List[str]:
        """Get search keywords for product"""
        
        keyword_map = {
            "windows-server": ["microsoft", "windows", "server"],
            "windows": ["microsoft", "windows"],
            "ubuntu": ["canonical", "ubuntu"],
            "rhel": ["red hat", "rhel", "enterprise linux"],
            "centos": ["centos"],
            "cisco-ios": ["cisco", "ios"],
            "cisco-iosxr": ["cisco", "ios xr"],
            "cisco-nxos": ["cisco", "nx-os"],
            "junos": ["juniper", "junos"],
            "arista-eos": ["arista", "eos"]
        }
        
        return keyword_map.get(product, [product])

class ProductNormalizer:
    """Advanced product normalization with fuzzy matching and CPE mapping"""
    
    def __init__(self):
        self.normalization_rules = self._load_normalization_rules()
        self.cpe_mappings = self._load_cpe_mappings()
    
    def _load_normalization_rules(self) -> Dict[str, List[Tuple[str, str, str]]]:
        """Load comprehensive normalization rules"""
        
        return {
            "windows": [
                (r"Microsoft Windows Server (\d{4})(.*)", "windows-server", r"\1"),
                (r"Windows Server (\d{4})(.*)", "windows-server", r"\1"),
                (r"Windows (\d+\.?\d*)", "windows", r"\1"),
                (r"Microsoft Windows (\d+)", "windows", r"\1"),
            ],
            "linux": [
                (r"Ubuntu (\d+\.\d+)", "ubuntu", r"\1"),
                (r"Red Hat Enterprise Linux.*?(\d+)", "rhel", r"\1"),
                (r"RHEL (\d+)", "rhel", r"\1"),
                (r"CentOS.*?(\d+)", "centos", r"\1"),
                (r"Debian GNU/Linux (\d+)", "debian", r"\1"),
                (r"SUSE Linux Enterprise Server (\d+)", "sles", r"\1"),
                (r"SLES (\d+)", "sles", r"\1"),
            ],
            "network": [
                (r"Cisco IOS.*?Version (\d+\.\d+)", "cisco-ios", r"\1"),
                (r"Cisco IOS XR.*?Version (\d+\.\d+\.\d+)", "cisco-iosxr", r"\1"),
                (r"Cisco Nexus.*?version (\d+\.\d+)", "cisco-nxos", r"\1"),
                (r"Juniper.*?JUNOS (\d+\.\d+)", "junos", r"\1"),
                (r"Arista.*?EOS (\d+\.\d+\.\d+)", "arista-eos", r"\1"),
                (r"FortiOS v(\d+\.\d+)", "fortios", r"\1"),
                (r"PAN-OS (\d+\.\d+)", "panos", r"\1"),
            ]
        }
    
    def _load_cpe_mappings(self) -> Dict[str, str]:
        """Load CPE (Common Platform Enumeration) mappings"""
        
        return {
            "windows-server-2019": "cpe:2.3:o:microsoft:windows_server_2019:-:*:*:*:*:*:*:*",
            "windows-server-2016": "cpe:2.3:o:microsoft:windows_server_2016:-:*:*:*:*:*:*:*",
            "windows-10": "cpe:2.3:o:microsoft:windows_10:-:*:*:*:*:*:*:*",
            "ubuntu-20.04": "cpe:2.3:o:canonical:ubuntu_linux:20.04:*:*:*:lts:*:*:*",
            "ubuntu-18.04": "cpe:2.3:o:canonical:ubuntu_linux:18.04:*:*:*:lts:*:*:*",
            "rhel-8": "cpe:2.3:o:redhat:enterprise_linux:8.0:*:*:*:*:*:*:*",
            "rhel-7": "cpe:2.3:o:redhat:enterprise_linux:7.0:*:*:*:*:*:*:*",
        }
    
    async def normalize_os_facts(self, os_facts: OSFacts) -> OSFacts:
        """Normalize OS facts to standard format"""
        
        if os_facts.product and os_facts.version:
            # Already normalized, but validate
            return await self._validate_normalization(os_facts)
        
        # Extract raw OS string
        raw_strings = self._extract_raw_strings(os_facts)
        
        # Apply normalization rules
        for category, rules in self.normalization_rules.items():
            for pattern, product_template, version_template in rules:
                for raw_string in raw_strings:
                    match = re.search(pattern, raw_string, re.IGNORECASE)
                    if match:
                        os_facts.product = product_template
                        os_facts.version = match.expand(version_template)
                        os_facts.confidence = 0.9
                        
                        # Add CPE if available
                        cpe_key = f"{os_facts.product}-{os_facts.version}"
                        if cpe_key in self.cpe_mappings:
                            os_facts.raw_data["cpe"] = self.cpe_mappings[cpe_key]
                        
                        return os_facts
        
        # Fallback: try fuzzy matching
        return await self._fuzzy_normalize(os_facts, raw_strings)
    
    def _extract_raw_strings(self, os_facts: OSFacts) -> List[str]:
        """Extract all possible OS strings from raw data"""
        
        strings = []
        
        # Add any string values from raw_data
        for key, value in os_facts.raw_data.items():
            if isinstance(value, str) and len(value) > 5:
                strings.append(value)
            elif isinstance(value, dict):
                # For nested data (like WinRM JSON)
                for subkey, subvalue in value.items():
                    if isinstance(subvalue, str) and len(subvalue) > 5:
                        strings.append(subvalue)
        
        return strings
    
    async def _validate_normalization(self, os_facts: OSFacts) -> OSFacts:
        """Validate and improve existing normalization"""
        
        # Check if product/version combination is valid
        valid_combinations = {
            "windows-server": ["2008", "2008-r2", "2012", "2012-r2", "2016", "2019", "2022"],
            "windows": ["7", "8", "8.1", "10", "11"],
            "ubuntu": ["14.04", "16.04", "18.04", "20.04", "22.04", "24.04"],
            "rhel": ["6", "7", "8", "9"],
            "centos": ["6", "7", "8"],
        }
        
        product = os_facts.product
        version = os_facts.version
        
        if product in valid_combinations:
            if version not in valid_combinations[product]:
                # Try to fix common version issues
                if product == "ubuntu" and "." not in version:
                    # Try to add .04 for Ubuntu major versions
                    if f"{version}.04" in valid_combinations[product]:
                        os_facts.version = f"{version}.04"
                        os_facts.confidence = min(os_facts.confidence, 0.8)
        
        return os_facts
    
    async def _fuzzy_normalize(self, os_facts: OSFacts, raw_strings: List[str]) -> OSFacts:
        """Fuzzy matching for difficult cases"""
        
        # Common product indicators
        product_indicators = {
            "windows": ["windows", "microsoft", "win32"],
            "ubuntu": ["ubuntu", "canonical"],
            "rhel": ["red hat", "rhel", "enterprise linux"],
            "centos": ["centos"],
            "cisco": ["cisco", "ios"],
            "juniper": ["juniper", "junos"],
        }
        
        for raw_string in raw_strings:
            raw_lower = raw_string.lower()
            
            for product_key, indicators in product_indicators.items():
                if any(indicator in raw_lower for indicator in indicators):
                    os_facts.product = product_key
                    os_facts.confidence = 0.5  # Low confidence for fuzzy match
                    
                    # Try to extract version
                    version_match = re.search(r'(\d+\.?\d*)', raw_string)
                    if version_match:
                        os_facts.version = version_match.group(1)
                    
                    break
        
        return os_facts

class AsyncRateLimiter:
    """Async rate limiter for API calls"""
    
    def __init__(self, calls: int, period: int):
        self.calls = calls
        self.period = period
        self.call_times = []
        self.lock = asyncio.Lock()
    
    async def acquire(self):
        """Acquire rate limit token"""
        async with self.lock:
            now = datetime.now()
            
            # Remove old calls outside the period
            cutoff = now - timedelta(seconds=self.period)
            self.call_times = [t for t in self.call_times if t > cutoff]
            
            # Check if we can make a call
            if len(self.call_times) >= self.calls:
                # Calculate sleep time
                oldest_call = min(self.call_times)
                sleep_time = (oldest_call + timedelta(seconds=self.period) - now).total_seconds()
                if sleep_time > 0:
                    await asyncio.sleep(sleep_time)
                    return await self.acquire()  # Retry
            
            # Record this call
            self.call_times.append(now)

# Example usage
async def demo_knowledge_service():
    """Demonstrate knowledge service capabilities"""
    
    config = {
        "base_url": "https://endoflife.date/api",
        "cache_ttl": 86400,
        "cache_db": "demo_eol_cache.db"
    }
    
    provider = EndOfLifeDateProvider(config)
    normalizer = ProductNormalizer()
    enricher = VulnerabilityEnricher({})
    
    # Test cases
    test_cases = [
        ("windows-server", "2019"),
        ("ubuntu", "20.04"),
        ("cisco-ios", "15.1"),
        ("rhel", "8")
    ]
    
    for product, version in test_cases:
        print(f"\nTesting {product} {version}:")
        
        # Get lifecycle info
        lifecycle_info = await provider.get_lifecycle_info(product, version)
        
        if lifecycle_info:
            print(f"  EOL: {lifecycle_info.eol_date}")
            print(f"  EOS: {lifecycle_info.eos_date}")
            print(f"  Days to EOL: {lifecycle_info.days_to_eol}")
            print(f"  Source: {lifecycle_info.source}")
            
            # Create dummy OS facts for enrichment
            os_facts = OSFacts(
                ci_id="test",
                collected_at=datetime.now(),
                product=product,
                version=version,
                raw_data={}
            )
            
            # Test vulnerability enrichment
            vuln_data = await enricher.enrich_with_vulnerabilities(lifecycle_info, os_facts)
            print(f"  KEV Vulns: {len(vuln_data['kev_vulnerabilities'])}")
        else:
            print("  No lifecycle data found")

if __name__ == "__main__":
    asyncio.run(demo_knowledge_service())