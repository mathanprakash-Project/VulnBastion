"""Test RAG retrieval against realistic risk descriptions."""
from rag_agent import retrieve_controls

# Simulated top-5 risks from your risk register
real_risks = [
    {
        "name": "CitrixBleed (CVE-2023-4966)",
        "query": "Citrix NetScaler session token theft buffer over-read vulnerability allowing authentication bypass",
        "expected_families": ["SI", "RA", "SC"],
    },
    {
        "name": "End-of-life Windows Server 2012",
        "query": "unsupported operating system no security patches available legacy infrastructure",
        "expected_families": ["SA", "SI", "CM"],
    },
    {
        "name": "Weak MFA on admin accounts",
        "query": "multi-factor authentication missing for privileged administrator accounts",
        "expected_families": ["IA", "AC"],
    },
    {
        "name": "Unencrypted backups",
        "query": "backup data stored without encryption at rest data confidentiality",
        "expected_families": ["SC", "CP", "MP"],
    },
    {
        "name": "Missing security logging",
        "query": "audit logs not collected or monitored for security events",
        "expected_families": ["AU", "SI"],
    },
]

def test_realistic_queries():
    passed = 0
    failed = 0
    
    for risk in real_risks:
        print(f"\n{'='*70}")
        print(f"Risk: {risk['name']}")
        print(f"Query: {risk['query']}")
        print(f"Expected families: {risk['expected_families']}")
        print("-" * 70)
        
        hits = retrieve_controls(risk["query"], top_k=5)
        
        # Check if any expected family appears in top 5
        hit_families = [h["identifier"].split("-")[0] for h in hits]
        match = any(f in hit_families for f in risk["expected_families"])
        
        for h in hits:
            marker = "✓" if h["identifier"].split("-")[0] in risk["expected_families"] else " "
            print(f"  {marker} [{h['identifier']}] {h['name']} (dist={h['distance']:.3f})")
        
        if match:
            print(f"  → PASS (found expected family)")
            passed += 1
        else:
            print(f"  → FAIL (no expected family in top 5)")
            failed += 1
    
    print(f"\n{'='*70}")
    print(f"RESULTS: {passed}/{len(real_risks)} passed, {failed} failed")
    print(f"{'='*70}")

if __name__ == "__main__":
    test_realistic_queries()