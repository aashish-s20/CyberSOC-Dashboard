import re
import ipaddress
from datetime import datetime, timezone
from models.db import db
from models.threat import ThreatIndicator, ThreatIntelHistory

def validate_and_classify_ioc(query):
    """
    Validates a query string and classifies it into an IOC type:
    - IPv4 Address
    - Domain Name
    - URL
    - SHA-256 Hash
    
    If it is invalid, raises ValueError.
    """
    query = query.strip()
    if not query:
        raise ValueError("Search query cannot be empty.")

    # 1. Check SHA-256 Hash format
    if re.match(r'^[a-fA-F0-9]{64}$', query):
        return 'SHA-256 Hash', query

    # 2. Check IPv4 format
    try:
        ipaddress.IPv4Address(query)
        return 'IPv4 Address', query
    except ValueError:
        pass

    # 3. Check URL format
    # Matches http/https with host name and optional port/path
    url_pattern = r'^https?://([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,10}(:\d+)?(/.*)?$'
    localhost_url_pattern = r'^https?://(localhost|127\.0\.0\.1|198\.51\.100\.45)(:\d+)?(/.*)?$'
    if re.match(url_pattern, query) or re.match(localhost_url_pattern, query):
        return 'URL', query

    # 4. Check Domain Name format
    domain_pattern = r'^([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,10}$'
    if re.match(domain_pattern, query):
        return 'Domain Name', query

    # Fallback/Invalid
    raise ValueError("Invalid format. Please specify a valid IPv4 Address, Domain Name, URL (http/https), or 64-character SHA-256 Hash.")

def lookup_threat_intel(query, user_id):
    """
    Looks up the IOC in the database registry, logs it to history, and returns details.
    """
    ioc_type, clean_query = validate_and_classify_ioc(query)
    
    # Query database for exact indicator match
    indicator = ThreatIndicator.query.filter(ThreatIndicator.ioc.ilike(clean_query)).first()
    
    if indicator:
        reputation = indicator.reputation_score
        risk = indicator.risk_level
        status = indicator.status
        category = indicator.category
        description = indicator.description
    else:
        # Default safe report for unknown but valid IOCs
        reputation = 100
        risk = 'Low'
        status = 'Safe'
        category = 'Unknown'
        description = "No threat signatures found in threat intelligence feeds. The IOC appears to be safe."
        
    # Log to history
    history = ThreatIntelHistory(
        user_id=user_id,
        ioc=clean_query,
        ioc_type=ioc_type,
        reputation_score=reputation,
        risk_level=risk,
        status=status,
        category=category
    )
    db.session.add(history)
    db.session.commit()
    
    return {
        'ioc': clean_query,
        'ioc_type': ioc_type,
        'reputation_score': reputation,
        'risk_level': risk,
        'status': status,
        'category': category,
        'description': description
    }
