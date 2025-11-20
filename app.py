import re
import json
import hashlib
import socket

import requests
import dns.resolver

HIBP_API_KEY = "9554e982a8eb4f8b8e06f137adc399de"


#HELPER FUNCTION

def validate_email_format(email: str) -> bool:
    """
    Basic RFC-style email format validation using regex.
    """
    pattern = r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$"
    return re.match(pattern, email) is not None


def get_domain(email: str) -> str:
    """
    Extracts the domain part from an email address.
    """
    return email.split("@", 1)[1].lower().strip()


#OSINT CHECKS

def reputation_emailrep(email: str) -> dict:

    print("\n[+] Checking Email Reputation (Fallback Engine)...")

    domain = email.split("@")[1]

    reputation = {
        "status": "ok",
        "email": email,
        "domain": domain,
        "checks": {}
    }

    # 1 - Check if domain resolves at all
    try:
        socket.gethostbyname(domain)
        reputation["checks"]["domain_resolves"] = True
    except Exception:
        reputation["checks"]["domain_resolves"] = False

    # 2 - Check if MX exists
    try:
        mx_answers = dns.resolver.resolve(domain, "MX")
        reputation["checks"]["mx_valid"] = True if mx_answers else False
    except Exception:
        reputation["checks"]["mx_valid"] = False

    # 3 - Simple DNS blacklist check
    blacklist_domains = [
        "zen.spamhaus.org",
        "bl.spamcop.net",
    ]

    blacklisted = False
    for bl in blacklist_domains:
        try:
            query = ".".join(reversed(domain.split("."))) + "." + bl
            dns.resolver.resolve(query, "A")
            blacklisted = True
            break
        except Exception:
            continue

    reputation["checks"]["blacklisted"] = blacklisted

    # Simple "score"
    if not reputation["checks"]["domain_resolves"]:
        reputation["overall"] = "bad"
    elif reputation["checks"]["blacklisted"]:
        reputation["overall"] = "bad"
    elif not reputation["checks"]["mx_valid"]:
        reputation["overall"] = "suspicious"
    else:
        reputation["overall"] = "good"

    # keep a simple key for the summary
    reputation["reputation"] = reputation["overall"]
    return reputation


# Backwards-compatible name that main() calls
def emailrep_lookup(email: str) -> dict:

    return reputation_emailrep(email)


def hibp_breach_lookup(email: str) -> dict:
    print("\n[+] Checking Data Breaches (HaveIBeenPwned)...")

    if not HIBP_API_KEY or "YOUR_HIBP_API_KEY_HERE" in HIBP_API_KEY:
        return {
            "status": "skipped",
            "reason": "HIBP check requires a paid API key"
        }

    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
    headers = {
        "hibp-api-key": HIBP_API_KEY,
        "user-agent": "Student-Email-OSINT-Tool"
    }

    try:
        resp = requests.get(url, headers=headers, timeout=10)

        if resp.status_code == 200:
            return {
                "status": "breached",
                "details": resp.json()
            }
        elif resp.status_code == 404:
            return {"status": "no_breaches"}
        elif resp.status_code == 401:
            return {
                "status": "error",
                "error": "401 Unauthorized (API key invalid or missing)."
            }
        else:
            return {
                "status": "error",
                "error": f"HIBP returned HTTP {resp.status_code}"
            }
    except Exception as e:
        return {"status": "error", "error": f"HIBP request failed: {e}"}


def gravatar_lookup(email: str) -> dict:
    """
    Checks if the email has a public Gravatar profile picture.
    """
    print("\n[+] Checking Gravatar (Profile Picture)...")
    hashed_email = hashlib.md5(email.strip().lower().encode()).hexdigest()
    url = f"https://www.gravatar.com/{hashed_email}.json"

    try:
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            entry = data.get("entry", [])[0]
            return {
                "status": "found",
                "name": entry.get("displayName", "N/A"),
                "profile_image": entry.get("thumbnailUrl", "N/A")
            }
        elif resp.status_code == 404:
            return {"status": "not_found", "message": "No public Gravatar profile."}
        else:
            return {"status": "error", "error": f"Gravatar returned HTTP {resp.status_code}"}
    except Exception as e:
        return {"status": "error", "error": f"Gravatar request failed: {e}"}


def dns_osint(domain: str) -> dict:
    """
    Collects DNS-based OSINT:
      - A record (IPv4)
      - MX records (mail servers)
      - SPF (TXT containing v=spf1)
      - DMARC (TXT containing v=DMARC1 on _dmarc.domain)
    """
    print("\n[+] Performing DNS OSINT on domain:", domain)
    result = {
        "domain": domain,
        "a_records": [],
        "mx_records": [],
        "spf_record": None,
        "dmarc_record": None
    }

    # A record
    try:
        ip = socket.gethostbyname(domain)
        result["a_records"].append(ip)
    except Exception:
        result["a_records"].append("No A record / DNS lookup failed")

    resolver = dns.resolver.Resolver()

    # MX records
    try:
        mx_answers = resolver.resolve(domain, "MX")
        result["mx_records"] = [str(r.exchange).rstrip(".") for r in mx_answers]
    except Exception:
        result["mx_records"].append("No MX records found or lookup failed")

    # SPF (TXT containing 'v=spf1')
    try:
        txt_answers = resolver.resolve(domain, "TXT")
        for r in txt_answers:
            txt = b"".join(r.strings).decode("utf-8", errors="ignore")
            if "v=spf1" in txt.lower():
                result["spf_record"] = txt
                break
        if result["spf_record"] is None:
            result["spf_record"] = "SPF record not found / lookup failed"
    except Exception:
        result["spf_record"] = "SPF record not found / lookup failed"

    # DMARC (_dmarc.domain TXT containing 'v=DMARC1')
    try:
        dmarc_domain = f"_dmarc.{domain}"
        dmarc_answers = resolver.resolve(dmarc_domain, "TXT")
        for r in dmarc_answers:
            txt = b"".join(r.strings).decode("utf-8", errors="ignore")
            if "v=DMARC1" in txt.upper():
                result["dmarc_record"] = txt
                break
        if result["dmarc_record"] is None:
            result["dmarc_record"] = "No DMARC record found"
    except Exception:
        result["dmarc_record"] = "DMARC record not found / lookup failed"

    return result


#MAIN APPLICATION

def main():
    print("===== ADVANCED EMAIL OSINT MACHINE =====")
    email1 = input("Enter an Email Address: ").strip()

    # 1) Basic format validation
    print("\n[+] Validating email format...")
    is_valid = validate_email_format(email1)
    if not is_valid:
        print("[-] Email format looks INVALID. Stopping OSINT checks.")
        return

    print("[+] Email format looks valid.\n")
    domain = get_domain(email1)
    print(f"[+] Extracted domain: {domain}\n")

    print("Running OSINT checks...\n")

    # 2) Run checks
    emailrep_data = emailrep_lookup(email1)
    hibp_data = hibp_breach_lookup(email1)
    gravatar_data = gravatar_lookup(email1)
    dns_data = dns_osint(domain)

    # 3) Combine results
    results = {
        "email": email1,
        "domain": domain,
        "format_valid": is_valid,
        "reputation_emailrep": emailrep_data,
        "breach_info_hibp": hibp_data,
        "gravatar": gravatar_data,
        "dns": dns_data
    }

    # 4) Pretty JSON output
    print("\n========== RESULTS  ==========")
    print(json.dumps(results, indent=4))

    # 5) Human-readable summary
    print("\n==========  SUMMARY ==========")

    # Email reputation quick verdict
    if isinstance(emailrep_data, dict) and emailrep_data.get("reputation"):
        print(f"[+] Email reputation (fallback): {emailrep_data['reputation']}")
    else:
        print("[!] Email reputation: Not available (error or rate limit).")

    # HIBP
    hibp_status = hibp_data.get("status", "unknown")
    if hibp_status == "breached":
        print("[!] HIBP: Account appears in known data breaches.")
    elif hibp_status == "no_breaches":
        print("[+] HIBP: No breaches reported.")
    elif hibp_status == "skipped":
        print("[!] HIBP: Skipped (no API key configured) – explain this in your report.")
    else:
        print(f"[!] HIBP: {hibp_data.get('error', 'Unknown error')}")

    # Gravatar
    if gravatar_data.get("status") == "found":
        print("[+] Gravatar: Public profile found.")
    elif gravatar_data.get("status") == "not_found":
        print("[-] Gravatar: No public profile.")
    else:
        print(f"[!] Gravatar: {gravatar_data.get('error', 'Unknown error')}")

    # DNS summary
    print(f"[+] A records: {dns_data.get('a_records')}")
    print(f"[+] MX records: {dns_data.get('mx_records')}")
    print(f"[+] SPF: {dns_data.get('spf_record')}")
    print(f"[+] DMARC: {dns_data.get('dmarc_record')}")

    print("\n===== END OF REPORT =====")


if __name__ == "__main__":
    main()
