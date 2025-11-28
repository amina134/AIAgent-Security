import numpy as np
import faiss
from sentence_transformers import SentenceTransformer
from pathlib import Path      
from django.conf import settings
import logging
import json
from tools.storage import save_suspicious_payload
import re
from typing import Dict, List, Any
from .clustering import ClusterManager
logger = logging.getLogger(__name__)
CLUSTER_META_PATH = Path(settings.BASE_DIR) / "security_data/cluster_meta.json"
CENTROIDS_PATH = Path(settings.BASE_DIR) / "security_data/cluster_centroids.npy"

class MiniLMSecurityAgent:
    """
    AI Security Agent for detecting injection attacks
    NOT for IDOR/CSRF (those need application-level protection)
    """

    def __init__(self):
     
        self.model_name = "all-MiniLM-L6-v2"
        self.model = None
        self.threat_patterns_index = None
        self.threat_threshold = 0.70
        # Load cluster meta first
        self.cluster_index = None
        self._load_cluster_meta()
        try:
            from tools.faiss_index import load_cluster_index
            self.cluster_index = load_cluster_index()
        except Exception as e:
            print(f"Error loading FAISS index: {e}")

        # Known attack patterns for AI similarity matching
        self.known_threats = self._get_threat_patterns()
        
        # Regex patterns for different attack types
        self.regex_patterns = {
            'SQL Injection': [
                r"(?i)(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|CREATE)\b.*\b(FROM|INTO|TABLE|DATABASE)\b)",
                r"(?i)('|\"|`)\s*(OR|AND)\s+['\"`]?[0-9]+['\"`]?\s*=\s*['\"`]?[0-9]+",
                r"(;\s*(DROP|DELETE|UPDATE|INSERT))",
                r"(?i)(--|\#|/\*|\*/)",  # SQL comments
            ],
            'XSS': [
                r"(?i)(<script[^>]*>.*?</script>)",
                r"(?i)(javascript:)", 
                r"(?i)(on\w+\s*=\s*['\"]?[^'\"]*['\"]?)",
                r"(?i)(<iframe|<embed|<object)",
            ],
            'Path Traversal': [
                r"(\.\.[\\/]){2,}",  # Multiple ../
                r"(?i)[\\/]etc[\\/]passwd",
                r"(?i)[\\/]windows[\\/]system32",
            ],
            'Command Injection': [
                r"(;\s*(ls|dir|cat|rm|del|mkdir|whoami|id)\b)",
                r"(\|\s*(ls|dir|cat|rm|del|whoami)\b)",
                r"(`[^`]*`)",  # Backticks for command substitution
                r"(\$\([^\)]*\))",  # $() command substitution
            ],
            'SSRF': [
                # Internal IP addresses
                r"(?i)(http://|https://)?(10\.\d{1,3}\.\d{1,3}\.\d{1,3})",  # 10.x.x.x
                r"(?i)(http://|https://)?(192\.168\.\d{1,3}\.\d{1,3})",  # 192.168.x.x
                r"(?i)(http://|https://)?(172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3})",  # 172.16-31.x.x
                # AWS metadata endpoint
                r"(?i)169\.254\.169\.254",
                # File protocol
                r"(?i)file:///",
                
            ],
            'LDAP Injection': [
                r"(\*\)(\(|\|))",
                r"(\)\(.*\*)",
            ],
            'XML Injection': [
                r"(?i)<!ENTITY",
                r"(?i)<!DOCTYPE",
            ]
        }
        
        self.initialize_detector()
    # --------------------------------------------------------
    #  CSRF DETECTION LOGIC
    # --------------------------------------------------------
    def detect_csrf_attack(self, request_data):
        method = request_data.get("method")
        query = request_data.get("query_params", {})

        # If a state-changing operation is done via GET → suspicious
        if method == "GET" and ("amount" in query or "to_account" in query):
            return True  # CSRF attempt

        return False
    # end of csrf funcrion-------------------------------------------------------
    def is_suspicious(self, text: str) -> bool:
        """
        Simple wrapper for quickly checking if a single string is malicious.
        Uses regex + AI similarity detection.
        """
        # 1. Check regex
        regex_hits = self._check_regex_patterns(text)
        if regex_hits:
            return True
        
        # 2. Check AI similarity
        ai_hits = self._check_ai_similarity(text)
        if ai_hits:
            return True
        
        return False

    def _get_threat_patterns(self):
        """Extended threat patterns for AI similarity matching"""
        return [
            # SQL Injection variations
            "SELECT * FROM users WHERE username = 'admin' OR '1'='1'",
            "admin' OR 1=1--", 
            "'; DROP TABLE users; --",
            "UNION SELECT username, password FROM users",
            "' UNION SELECT NULL, NULL--",
            "1' AND '1'='1",
            
            # XSS variations
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert('XSS')",
            "<svg onload=alert(1)>",
            "<iframe src=javascript:alert(1)>",
            
            # Path Traversal
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//etc/passwd",
            
            # Command Injection
            "; ls -la", 
            "| cat /etc/passwd",
            "&& whoami",
            "`id`",
            "$(whoami)",
            
            # SSRF patterns
            "http://localhost:8000/admin",
            "http://127.0.0.1/secret",
            "http://169.254.169.254/latest/meta-data/",
            "file:///etc/passwd",
            "http://10.0.0.1/internal",
            "http://192.168.1.1/admin",
        ]
    
    def initialize_detector(self):
        """Initialize the MiniLM model and FAISS index"""
        try:
            logger.info(f"Loading model {self.model_name}...")
            self.model = SentenceTransformer(self.model_name)
            self._build_threat_index()
            logger.info("Security Agent initialized successfully")
        except Exception as e:
            logger.error(f"Error initializing agent: {e}")
            raise
    
    def _build_threat_index(self):
        """Build FAISS index from known threat patterns"""
        threat_embeddings = self.model.encode(self.known_threats)
        dimension = threat_embeddings.shape[1]
        
        # Use Inner Product (cosine similarity after normalization)
        self.threat_patterns_index = faiss.IndexFlatIP(dimension)
        
        # Normalize embeddings for cosine similarity
        faiss.normalize_L2(threat_embeddings)
        self.threat_patterns_index.add(threat_embeddings)
    
    def analyze_request(self, request_data: Dict) -> Dict[str, Any]:
        """
        Main analysis function - analyzes request for security threats
            
        Args:
            request_data: Dictionary containing request information
                - path: URL path
                - query_params: GET parameters
                - post_data: POST data
                - headers: HTTP headers (optional)
                - user_context: user info (must contain `user_id`)
        """

        user_id = request_data.get("user_context", {}).get("user_id")
        print("user iddddddd from request",user_id)
        ids = self._extract_ids(request_data)

        print("🔥 DEBUG — Extracted IDs:", ids)

        idor_threats = []
        #----------------------------------
        #CSRF  detection first
        # csrf_threat = self._check_csrf(request_data)
        # if csrf_threat:
        #     return {
        #         "error": "CSRF violation",
        #         "blocked": True,
        #         "threats": [csrf_threat]
        #     }

        # -----------------------------
        # ✅ IDOR DETECTION FIRST
        # -----------------------------
        for found_id in ids:
            if user_id is None:
                continue  # Cannot check IDOR if user not authenticated

            try:
                found_id = int(found_id)
                expected = int(user_id)
            except Exception:
                continue

            # If ID does NOT belong to current user → BLOCK
            if found_id != expected:
                idor_threats.append({
                    "text": f"Unauthorized access attempt to resource ID={found_id}",
                    "type": "IDOR",
                    "detection_method": "idor_check",
                    "confidence": 0.95
                })

        # ❗ If IDOR detected → block immediately
        if idor_threats:
            return {
                "blocked": True,
                "error": "IDOR violation detected",
                "threats": idor_threats
            }

        # -------------------------------------------------------
        # NO IDOR FOUND → Continue with SQLi / XSS / SSRF checks
        # -------------------------------------------------------

        threats_detected = []
        request_texts = self._extract_request_features(request_data)

        for text in request_texts:
            if not text or len(text.strip()) < 2:
                continue

            # Step 1: Fast regex detection (SQLi, XSS, etc.)
            regex_threats = self._check_regex_patterns(text)
            threats_detected.extend(regex_threats)

            # Step 2: AI similarity (MiniLM + FAISS)
            ai_threats = []
            if not regex_threats:
                ai_threats = self._check_ai_similarity(text)
                threats_detected.extend(ai_threats)
            # Step 3: Save embedding if any threat detected
            if regex_threats or ai_threats:
                embedding = self.model.encode([text]).astype(np.float32)
                save_suspicious_payload(text, embedding)

            # Remove duplicates
            unique_threats = self._deduplicate_threats(threats_detected)

        return {
            "is_malicious": len(unique_threats) > 0,
            "blocked": len(unique_threats) > 0,
            "threats_detected": unique_threats,
            "overall_risk_score": self._calculate_overall_risk(unique_threats),
            "recommendation": self._generate_recommendation(unique_threats)
        }



    




    def _check_regex_patterns(self, text: str) -> List[Dict]:
        """
        Check text against regex patterns for known attack types
        Fast first-line defense
        """
        threats = []
        
        for threat_type, patterns in self.regex_patterns.items():
            for pattern in patterns:
                match = re.search(pattern, text, re.IGNORECASE | re.DOTALL)
                if match:
                    threats.append({
                        'text': text[:200],  # Limit length
                        'type': threat_type,
                        'detection_method': 'regex',
                        'confidence': 0.95,
                        'pattern': pattern,
                        'matched_text': match.group(0)[:100]
                    })
                    break  # One match per type is enough
        
        return threats
    
    def _check_ai_similarity(self, text: str) -> List[Dict]:
        """
        Check text similarity against known threat patterns using AI
        Catches variations and obfuscated attacks
        """
        threats = []
        
        try:
            threat_score = self._calculate_threat_similarity(text)
            
            if threat_score > self.threat_threshold:
                threat_type = self._classify_threat_type(text)
                threats.append({
                    'text': text[:200],
                    'type': threat_type,
                    'detection_method': 'ai_similarity', 
                    'confidence': round(threat_score, 2),
                    'similarity_score': round(threat_score, 2)
                })
        except Exception as e:
            logger.error(f"Error in AI similarity check: {e}")
        
        return threats
    
    def _calculate_threat_similarity(self, text: str) -> float:
        """Calculate cosine similarity with known threat patterns"""
        try:
            # Encode the text
            text_embedding = self.model.encode([text])
            
            # Normalize for cosine similarity
            faiss.normalize_L2(text_embedding)
            
            # Search for top 3 most similar patterns
            scores, indices = self.threat_patterns_index.search(text_embedding, 3)
            
            # Return maximum similarity score
            return float(np.max(scores)) if scores.size > 0 else 0.0
        
        except Exception as e:
            logger.error(f"Error calculating threat similarity: {e}")
            return 0.0
    
    def _extract_request_features(self, request_data: Dict) -> List[str]:
        """Extract text features from different parts of the request"""
        features = []
        
        # URL path
        if 'path' in request_data:
            features.append(str(request_data['path']))
        
        # Query parameters
        if 'query_params' in request_data:
            params = request_data['query_params']
            if isinstance(params, dict):
                for key, value in params.items():
                    features.append(f"{key}={value}")
                    features.append(str(value))  # Check value separately
        
        # POST data
        if 'post_data' in request_data:
            post_data = request_data['post_data']
            if isinstance(post_data, dict):
                for key, value in post_data.items():
                    features.append(f"{key}={value}")
                    features.append(str(value))
            else:
                features.append(str(post_data))
        
        # HTTP Headers (optional, check for XSS in User-Agent, Referer, etc.)
        if 'headers' in request_data:
            for key, value in request_data['headers'].items():

                # NEVER send these to AI similarity
                key_l = key.lower()
                if key_l in ['host', 'origin', 'referer', 'cookie', 'user-agent']:
                    continue

                # Only analyze suspicious custom headers (almost never)
                if key_l.startswith('x-'):
                    features.append(f"{key}={value}")

            
        
        # Filter out empty strings and ensure minimum length
        return [str(f) for f in features if f and len(str(f).strip()) > 1]
    
    def _classify_threat_type(self, text: str) -> str:
        """Classify the type of threat based on text content"""
        text_lower = text.lower()
        
        # SQL Injection keywords
        sql_keywords = ['select', 'union', 'drop', 'insert', 'update', 'delete', 'where', '--', '/*']
        if any(kw in text_lower for kw in sql_keywords):
            return 'SQL Injection'
        
        # XSS keywords
        xss_keywords = ['<script', 'javascript:', 'onerror', '<iframe', 'onload', '<svg']
        if any(kw in text_lower for kw in xss_keywords):
            return 'XSS'
        
        # Path Traversal
        if '../' in text or '..\\' in text or '/etc/' in text_lower:
            return 'Path Traversal'
        
        # Command Injection
        cmd_keywords = [';', '|', '&&', '`', '$(', 'rm ', 'ls ', 'cat ']
        if any(cmd in text_lower for cmd in cmd_keywords):
            return 'Command Injection'
        
        # SSRF
        ssrf_keywords = ['localhost', '127.0.0.1', '169.254', 'file://', '192.168', '10.']
        if any(kw in text_lower for kw in ssrf_keywords):
            return 'SSRF'
        
        return 'Suspicious Pattern'
    
    def _deduplicate_threats(self, threats: List[Dict]) -> List[Dict]:
        """Remove duplicate threat detections"""
        seen = set()
        unique = []
        
        for threat in threats:
            # Create unique key based on text and type
            key = (threat['text'][:100], threat['type'])
            if key not in seen:
                seen.add(key)
                unique.append(threat)
        
        return unique
    
    def _calculate_overall_risk(self, threats: List[Dict]) -> float:
        """Calculate overall risk score (0-100)"""
        if not threats:
            return 0.0
        
        # Use the highest confidence score
        max_confidence = max(threat.get('confidence', 0.5) for threat in threats)
        
        # Scale to 0-100
        return round(max_confidence * 100, 2)
    
    def _generate_recommendation(self, threats: List[Dict]) -> str:
        """Generate security recommendation based on detected threats"""
        if not threats:
            return "REQUEST_SAFE"
        
        # Get all threat types
        threat_types = [t['type'] for t in threats]
        
        # Return recommendation based on highest priority threat
        if 'SQL Injection' in threat_types:
            return "BLOCK_SQL_INJECTION"
        elif 'Command Injection' in threat_types:
            return "BLOCK_COMMAND_INJECTION"
        elif 'SSRF' in threat_types:
            return "BLOCK_SSRF"
        elif 'XSS' in threat_types:
            return "BLOCK_XSS"
        elif 'Path Traversal' in threat_types:
            return "BLOCK_PATH_TRAVERSAL"
        else:
            return "BLOCK_SUSPICIOUS"
    
    def _extract_ids(self, request_data: Dict) -> List[int]:
        ids = []

        # --- Extract numeric IDs from query parameters ---
        for key, value in request_data.get("query_params", {}).items():
            if "id" in key.lower():     # matches id, user_id, account_id, productId
                try:
                    ids.append(int(value))
                except:
                    pass

        # --- Extract numeric IDs from POST data ---
        for key, value in request_data.get("query_params", {}).items():
            
            if "id" in key.lower():
                # Handle both list and single values
                if isinstance(value, list):
                    for v in value:
                        try:
                            ids.append(int(v))
                        except:
                            pass
                else:
                    try:
                        ids.append(int(value))
                    except:
                        pass

        # --- Extract IDs from URL path ---
        path_parts = request_data.get("path", "").split("/")
        for part in path_parts:
            if part.isdigit():
                ids.append(int(part))

        return ids
    def _load_cluster_meta(self):
        try:
            with open(CLUSTER_META_PATH, "r") as f:
                self.cluster_meta = json.load(f)
            self.cluster_centroids = np.load(CENTROIDS_PATH).astype(np.float32)
        except Exception:
            self.cluster_meta = {}
            self.cluster_centroids = None

    def _get_cluster_risk(self, text: str):
        if self.cluster_index is None or self.model is None:
            return 0.0, 0.0

        emb = self.model.encode([text]).astype(np.float32)
        faiss.normalize_L2(emb)
        scores, idxs = self.cluster_index.search(emb, 1)
        score = float(scores[0][0])
        idx = int(idxs[0][0])

        if score < 0.45:
            return 0.0, 0.6

        cluster_info = self.cluster_meta.get(str(idx)) or self.cluster_meta.get(idx)
        if cluster_info:
            return float(cluster_info.get("risk", 0.3)), 0.0

        return 0.2, 0.2

    def _count_regex_hits(self, text: str):
        hits = 0
        for patterns in self.regex_patterns.values():
            for pat in patterns:
                if re.search(pat, text, re.IGNORECASE | re.DOTALL):
                    hits += 1
                    break
        return hits

    def _compute_risk_score(self, text: str, similarity_score: float):
        regex_score = min(1.0, self._count_regex_hits(text)/3.0)
        cluster_risk, new_cluster_penalty = self._get_cluster_risk(text)
        risk_score = (similarity_score * 0.5) + (cluster_risk * 0.3) + (regex_score * 0.2) + new_cluster_penalty
        return round(max(0.0, min(1.0, risk_score)), 3)
    














































































































































































# import base64
# import urllib.parse
# import binascii
# from .models import SuspiciousPayload
# from sentence_transformers import SentenceTransformer
# import json
# import numpy as np
# import faiss
# def decode_obfuscated_text(text):
#     decoded_texts = [text]

#     # URL decode
#     try:
#         url_decoded = urllib.parse.unquote(text)
#         if url_decoded != text:
#             decoded_texts.append(url_decoded)
#     except:
#         pass

#     # Base64 decode
#     try:
#         b64_decoded = base64.b64decode(text).decode('utf-8')
#         decoded_texts.append(b64_decoded)
#     except:
#         pass

#     # Hex decode
#     try:
#         hex_decoded = binascii.unhexlify(text.replace("\\x","")).decode('utf-8')
#         decoded_texts.append(hex_decoded)
#     except:
#         pass

#     return decoded_texts




# model = SentenceTransformer("all-MiniLM-L6-v2")

# def store_new_malicious_payload(raw_text, threat_type="Unknown", confidence=0.80):
#     """Save newly detected malicious payload into DB + embedding - FIXED"""
#     try:
#         vector = model.encode([raw_text])[0].astype(np.float32)
        
#         # ✅ Normalize the vector before storing
#         faiss.normalize_L2(vector.reshape(1, -1))
#         vector = vector.reshape(-1)  # Back to 1D
        
#         payload = SuspiciousPayload.objects.create(
#             raw_text=raw_text[:500],
#             detection_method="ai_similarity",
#             confidence=confidence,
#             status=threat_type,
#         )
        
#         # Save normalized vector
#         payload.vector = vector.tolist()
#         payload.save()

#         print(f"🔥 Saved new malicious payload to DB: {threat_type}")
#         return payload
    
#     except Exception as e:
#         print("❌ Error saving malicious payload:", e)

# def rebuild_faiss_index():
#     """Rebuild FAISS index from all stored malicious payloads - FIXED VERSION"""
#     data = SuspiciousPayload.objects.exclude(vector=None)

#     if not data:
#         print("⚠️ No stored payloads, FAISS index empty.")
#         # Use Inner Product for cosine similarity
#         return faiss.IndexFlatIP(384)

#     vectors = []

#     for payload in data:
#         try:
#             vectors.append(np.array(payload.vector, dtype=np.float32))
#         except:
#             continue

#     vectors = np.array(vectors)
    
#     # ✅ CRITICAL: Normalize vectors for cosine similarity
#     faiss.normalize_L2(vectors)
    
#     dimension = vectors.shape[1]
    
#     # ✅ Use Inner Product (cosine similarity) instead of L2 distance
#     index = faiss.IndexFlatIP(dimension)
    
#     index.add(vectors)
#     print(f"🔥 FAISS index rebuilt with {len(vectors)} vectors (Cosine Similarity)")

#     return index