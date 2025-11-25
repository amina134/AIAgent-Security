# test_agent.py

import os
import django
import json

# 1. Configure Django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "projet_ds1.settings")
django.setup()

# 2. Import your agent and FAISS builder
from security_agent.ai_detector import MiniLMSecurityAgent

print("🚀 Initializing AI Agent...")
agent = MiniLMSecurityAgent()
print("Agent ready!\n")

# ---------------------------------------------
# TEST REQUESTS
# ---------------------------------------------

normal_request = {
    "path": "/profile/5",
    "query_params": {"user_id": "5"},
    "post_data": {},
    "headers": {},
    "method": "GET",
    "user_context": {"user_id": 5}
}

sqli_request = {
    "path": "/search",
    "query_params": {"q": "1' OR '1'='1"},
    "post_data": {},
    "headers": {},
    "method": "GET",
    "user_context": {"user_id": 1}
}

idor_request = {
    "path": "/profile/9",
    "query_params": {"user_id": "9"},
    "post_data": {},
    "headers": {},
    "method": "GET",
    "user_context": {"user_id": 4}
}

obfuscated_request = {
    "path": "/login",
    "query_params": {"password": "MTEnIE9SICcxJz0nMQ=="},
    "post_data": {},
    "headers": {},
    "method": "POST",
    "user_context": {"user_id": 2}
}

# ---------------------------------------------
print("🔍 Analyzing requests...\n")

print("Normal request ➜")
print(agent.analyze_request(normal_request), "\n")

print("SQL Injection request ➜")
print(agent.analyze_request(sqli_request), "\n")

print("IDOR request ➜")
print(agent.analyze_request(idor_request), "\n")

print("Obfuscated SQLi (Base64) ➜")
print(agent.analyze_request(obfuscated_request), "\n")

print("\n========== EXTRA TESTS ==========")

# Obfuscated SQL Injection (Base64)
obf = "dXNlcj0xJyBPUiAnMSc9JzE="
print("\nObfuscated SQLi →")
print(agent.analyze_request({"payload": obf}))

# Hex SQL Injection
hex_sql = "757365723d3127204f52202731273d2731"
print("\nHex SQLi →")
print(agent.analyze_request({"payload": hex_sql}))

# IDOR attack
idor = "/api/user?id=9"
print("\nIDOR Attack →")
print(agent.analyze_request({"payload": idor, "user_id": 5}))

# Simple SQL Injection
sqli = "q=1' OR '1'='1"
print("\nSimple SQLi →")
print(agent.analyze_request({"payload": sqli}))
