# security_agent/ai_detector.py
import os
import re
import json
import logging
from pathlib import Path
from typing import Dict, List, Any, Tuple
from tools.storage import load_all_payloads
import numpy as np
import faiss
from sentence_transformers import SentenceTransformer
from django.conf import settings

from tools.storage import save_suspicious_payload  # your existing storage function

logger = logging.getLogger(__name__)

# Paths
BASE_DIR = Path(settings.BASE_DIR)
SECURITY_DIR = BASE_DIR / "security_data"
EMB_PATH = SECURITY_DIR / "embeddings.npy"
CLUSTER_META_PATH = SECURITY_DIR / "cluster_meta.json"
CENTROIDS_PATH = SECURITY_DIR / "cluster_centroids.npy"
#  persisted index path if you want to store on disk
EMB_INDEX_PATH = SECURITY_DIR / "embeddings_index.faiss"

# Config
MODEL_NAME = "all-MiniLM-L6-v2"
EMB_DIM = 384               # dimensionality for MiniLM
THREAT_SIM_THRESHOLD = 0.85 # similarity threshold vs known threat patterns
STORED_SIM_THRESHOLD = 0.75 # similarity threshold vs stored suspicious embeddings
SAVE_ON_DETECT = True       # whether to call save_suspicious_payload when detection occurs


class MiniLMSecurityAgent:
    """
    AI Security Agent for detecting injection attacks using:
      - fast regex rules
      - semantic similarity vs known threat patterns
      - semantic similarity vs previously saved suspicious embeddings (self-learning)
    """

    def __init__(self):
        self.model_name = MODEL_NAME
        self.model: SentenceTransformer | None = None
        self.payloads = load_all_payloads() 
        # FAISS indexes
        # - threat_patterns_index: IndexFlatIP on normalized known threat patterns
        # - embeddings_index: IndexFlatIP on normalized stored embeddings (self-learned)
        self.threat_patterns_index = None
        self.embeddings_index = None
   
        # metadata
        self.known_threats: List[str] = []
        self.cluster_meta: Dict = {}
        self.cluster_index = None  # optional cluster index if you build one

        # thresholds
        self.threat_threshold = THREAT_SIM_THRESHOLD
        self.stored_threshold = STORED_SIM_THRESHOLD

        # regex patterns (kept from your code)
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
                r"(\.\.[\\/]){2,}",
                r"(?i)[\\/]etc[\\/]passwd",
                r"(?i)[\\/]windows[\\/]system32",
            ],
            'Command Injection': [
                r"(;\s*(ls|dir|cat|rm|del|mkdir|whoami|id)\b)",
                r"(\|\s*(ls|dir|cat|rm|del|whoami)\b)",
                r"(`[^`]*`)",
                r"(\$\([^\)]*\))",
            ],
            'SSRF': [
                r"(?i)(http://|https://)?(10\.\d{1,3}\.\d{1,3}\.\d{1,3})",
                r"(?i)(http://|https://)?(192\.168\.\d{1,3}\.\d{1,3})",
                r"(?i)(http://|https://)?(172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3})",
                r"(?i)169\.254\.169\.254",
                r"(?i)file:///",
            ],
            'LDAP Injection': [
                r"(\*\)(\(|\|))",
                r"(\)\(.*\*)",
            ],
            'XML Injection': [
                r"(?i)<!ENTITY",
                r"(?i)<!DOCTYPE",
            ],
        }

        # initialize heavy components
        self._ensure_dirs()
        self._init_model_and_indexes()
        # load cluster meta if present (optional)
        self._load_cluster_meta()
   
    # -------------------------
    # Initialization / helpers
    # -------------------------
    def _ensure_dirs(self):
        SECURITY_DIR.mkdir(parents=True, exist_ok=True)

    def _init_model_and_indexes(self):
        """Lazy-load the model and build FAISS indexes (threat patterns + stored embeddings)."""
        try:
            logger.info("Loading SentenceTransformer model...")
            self.model = SentenceTransformer(self.model_name)

            # 1) load known threats and build threat_patterns_index
            self.known_threats = self._get_threat_patterns()
            emb = self.model.encode(self.known_threats, convert_to_numpy=True).astype(np.float32)
            # normalize for cosine similarity using inner product
            faiss.normalize_L2(emb)
            d = emb.shape[1] if emb.ndim == 2 else EMB_DIM
            self.threat_patterns_index = faiss.IndexFlatIP(d)
            if emb.shape[0] > 0:
                self.threat_patterns_index.add(emb)

            # 2) load stored embeddings (self-learned) and build embeddings_index
            if EMB_PATH.exists():
                stored = np.load(str(EMB_PATH)).astype(np.float32)
                # ensure shape (N, D)
                if stored.ndim == 1:
                    stored = stored.reshape(1, -1)
                faiss.normalize_L2(stored)
                self.embeddings_index = faiss.IndexFlatIP(stored.shape[1])
                if stored.shape[0] > 0:
                    self.embeddings_index.add(stored)
            else:
                # empty index with EMB_DIM
                self.embeddings_index = faiss.IndexFlatIP(EMB_DIM)

            logger.info("Model and FAISS indexes initialized.")
        except Exception as e:
            logger.exception("Failed to initialize model or FAISS indexes: %s", e)
            # keep agent functional but without model/index
            self.model = None
            self.threat_patterns_index = None
            self.embeddings_index = None

    def _load_cluster_meta(self):
        try:
            if CLUSTER_META_PATH.exists():
                with open(CLUSTER_META_PATH, "r", encoding="utf-8") as f:
                    self.cluster_meta = json.load(f)
            else:
                self.cluster_meta = {}
        except Exception:
            self.cluster_meta = {}

    def _get_threat_patterns(self) -> List[str]:
        """Return list of string threat patterns for the known-threat index."""
        # Use your comprehensive payload lists
        all_threats = []
        
        # Add your SQL injection payloads
        all_threats.extend(self.payloads)
        
       
        # Remove duplicates and limit to reasonable size
        unique_threats = list(set(all_threats))
        return unique_threats[:1000]  # Limit to first 1000 if needed
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
    # -------------------------
    # Public convenience APIs
    # -------------------------
    def is_suspicious(self, text: str) -> bool:
        """Return True if text is detected as suspicious by regex or AI similarity."""
        # 0) Skip safe patterns entirely
        if self.is_safe_pattern(text):
            return False

        # 1) quick regex check
        if self._check_regex_patterns(text):
            return True

        # 2) similarity vs known threat patterns
        sim = self._calculate_threat_similarity(text)
        if sim >= self.threat_threshold:
            return True

        # 3) similarity vs stored embeddings (self-learned)
        stored_sim = self._calculate_stored_similarity(text)
        if stored_sim >= self.stored_threshold:
            return True

        return False

    # -------------------------
    # Core analyze_request flow
    # -------------------------
    def analyze_request(self, request_data: Dict) -> Dict[str, Any]:
        """Analyze a request dictionary and return structured result."""
        user_id = request_data.get("user_context", {}).get("user_id")
        ids = self._extract_ids(request_data)

        # IDOR check (keep existing)
        idor_threats = []
        for found_id in ids:
            if user_id is None:
                continue
            try:
                if int(found_id) != int(user_id):
                    idor_threats.append({
                        "text": f"Unauthorized access attempt to resource ID={found_id}",
                        "type": "IDOR",
                        "detection_method": "idor_check",
                        "confidence": 0.95
                    })
            except Exception:
                continue

        if idor_threats:
            return {
                "blocked": True,
                "error": "IDOR violation detected",
                "threats": idor_threats
            }

        # Extract request texts to analyze
        request_texts = self._extract_request_features(request_data)
        threats_detected: List[Dict] = []

        for text in request_texts:
            if not text or len(text.strip()) < 2:
                continue

            # Decode the text first for better detection
            decoded_text = self._decode_potential_threat(text)
            
            # Check if it's a safe pattern (use decoded text)
            if self.is_safe_pattern(decoded_text):
                continue  # Skip safe patterns entirely

            # 1) Regex check on decoded text
            regex_threats = self._check_regex_patterns(decoded_text)
            if regex_threats:
                # Use original text for display, but decoded for detection
                for threat in regex_threats:
                    threat['text'] = text[:200]  # Keep original for display
                threats_detected.extend(regex_threats)
                
                # Save if it's a real threat
                if SAVE_ON_DETECT and self._is_real_threat(decoded_text):
                    self._save_threat_payload(decoded_text, text)
                
                continue  # If regex caught it, don't proceed to AI

            # 2) Known-threat similarity (use decoded text for better matching)
            sim_score = self._calculate_threat_similarity(decoded_text)
            if sim_score >= self.threat_threshold:
                threats_detected.append({
                    "text": text[:200],  # Display original
                    "type": self._classify_threat_type(decoded_text),  # Classify decoded
                    "detection_method": "ai_similarity_known",
                    "confidence": round(sim_score, 2),
                    "similarity_score": round(sim_score, 2)
                })
                
                # Save if it's a real threat
                if SAVE_ON_DETECT and self._is_real_threat(decoded_text):
                    self._save_threat_payload(decoded_text, text)

            # 3) Stored-embeddings similarity (use decoded text)
            stored_sim = self._calculate_stored_similarity(decoded_text)
            if stored_sim >= self.stored_threshold:
                threats_detected.append({
                    "text": text[:200],  # Display original
                    "type": self._classify_threat_type(decoded_text),  # Classify decoded
                    "detection_method": "ai_similarity_stored",
                    "confidence": round(stored_sim, 2),
                    "similarity_score": round(stored_sim, 2)
                })
                
                # Save if it's a real threat
                if SAVE_ON_DETECT and self._is_real_threat(decoded_text):
                    self._save_threat_payload(decoded_text, text)

        unique_threats = self._deduplicate_threats(threats_detected)

        overall_risk = self._calculate_overall_risk(unique_threats)
        blocked = len(unique_threats) > 0

        return {
            "is_malicious": blocked,
            "blocked": blocked,
            "threats_detected": unique_threats,
            "overall_risk_score": overall_risk,
            "recommendation": self._generate_recommendation(unique_threats)
        }


    def _save_threat_payload(self, decoded_text: str, original_text: str = None):
        """Save threat payload with deduplication checks"""
        try:
            if self.model is not None:
                # Use decoded text for embedding (better representation)
                emb = self.model.encode([decoded_text], convert_to_numpy=True).astype(np.float32)
                
                # Check if this is a duplicate before saving
                if not self._is_duplicate_embedding(emb):
                    # Save the decoded version for better future detection
                    save_suspicious_payload(decoded_text, emb)
                    
                    # Also add to in-memory embeddings_index
                    self._add_to_embeddings_index(emb)
                    
                    logger.debug(f"Saved new threat payload: {decoded_text[:50]}...")
                else:
                    logger.debug(f"Skipped duplicate payload: {decoded_text[:50]}...")
        except Exception as e:
            logger.debug(f"Failed saving threat payload: {e}")


    def _decode_potential_threat(self, text: str) -> str:
        """Decode potential encoded threats (base64, URL, etc.)"""
        import base64
        import urllib.parse
        import html
        
        decoded = text
        
        # Try URL decoding first
        try:
            # Decode multiple times to handle nested encoding
            for _ in range(3):
                old_decoded = decoded
                decoded = urllib.parse.unquote(decoded)
                if decoded == old_decoded:
                    break
        except:
            pass
        
        # Try base64 decoding
        try:
            # Remove padding and whitespace for checking
            clean_text = decoded.replace('\n', '').replace('\r', '').replace(' ', '')
            
            # Check if it looks like base64 (proper length and charset)
            if (len(clean_text) % 4 == 0 and 
                re.match(r'^[A-Za-z0-9+/]+={0,2}$', clean_text) and
                len(clean_text) > 20):  # Reasonable minimum length for base64 payloads
                
                decoded_bytes = base64.b64decode(clean_text)
                # Try to decode as UTF-8, but fall back to latin-1 if it fails
                try:
                    decoded_str = decoded_bytes.decode('utf-8')
                except UnicodeDecodeError:
                    decoded_str = decoded_bytes.decode('latin-1')
                
                # Only use if it decoded to something meaningful
                if len(decoded_str) > 5 and any(c.isalpha() for c in decoded_str):
                    decoded = decoded_str
        except:
            pass
        
        # Try HTML entity decoding
        decoded = html.unescape(decoded)
        
        return decoded


    def _is_real_threat(self, text: str) -> bool:
        """Check if text is actually a threat pattern (not a false positive)"""
        # Check if it's obviously safe
        if self.is_safe_pattern(text):
            return False
        
        # Decode any remaining encodings
        decoded = self._decode_potential_threat(text)
        
        # Check for actual threat patterns in decoded text
        decoded_lower = decoded.lower()
        
        # Threat indicators
        threat_indicators = [
            r'<script[^>]*>',  # Script tags
            r'javascript:',  # JavaScript protocol
            r'on\w+\s*=',  # Event handlers
            r'alert\s*\(',  # Alert calls
            r'SELECT\s+.*\s+FROM',  # SQL SELECT
            r'UNION\s+.*\s+SELECT',  # SQL UNION
            r'INSERT\s+INTO',  # SQL INSERT
            r'UPDATE\s+.*\s+SET',  # SQL UPDATE
            r'DELETE\s+FROM',  # SQL DELETE
            r'DROP\s+TABLE',  # SQL DROP
            r'\.\./',  # Path traversal
            r'\.\.\\',  # Path traversal (Windows)
            r'etc/passwd',  # Path traversal target
            r';ls|;rm|;cat|;whoami',  # Command injection
            r'\|\s*\w+',  # Pipe commands
            r'\$\(',
            r'`[^`]*`',  # Backticks
            r'<\s*(iframe|embed|object)',  # Embedded objects
            r'<\s*svg',  # SVG with scripts
            r'eval\s*\(',  # eval() function
            r'document\.',  # Document object access
            r'window\.',  # Window object access
            r'fetch\s*\(',  # Fetch API
            r'XMLHttpRequest',  # XHR
            r'<\s*form',  # Form tags (potential CSRF)
        ]
        
        for pattern in threat_indicators:
            if re.search(pattern, decoded, re.IGNORECASE):
                return True
        
        # Check for suspicious character sequences
        suspicious_sequences = [
            '--',  # SQL comment
            '/*',  # SQL comment start
            '*/',  # SQL comment end
            '#',  # SQL comment
            '||',  # SQL concatenation
            '&&',  # Command chaining
        ]
        
        for seq in suspicious_sequences:
            if seq in decoded:
                return True
        
        return False


    def _is_duplicate_embedding(self, new_emb: np.ndarray, threshold: float = 0.95) -> bool:
        """Check if embedding is too similar to existing ones"""
        if self.embeddings_index is None or self.embeddings_index.ntotal == 0:
            return False
        
        try:
            # Normalize the new embedding
            new_emb_normalized = new_emb.copy().astype(np.float32)
            faiss.normalize_L2(new_emb_normalized)
            
            # Search for similar embeddings
            k = min(5, self.embeddings_index.ntotal)
            distances, _ = self.embeddings_index.search(new_emb_normalized, k)
            
            # Check if any are too similar
            if distances.size > 0 and distances[0].size > 0:
                max_similarity = float(np.max(distances[0]))
                return max_similarity >= threshold
            
        except Exception as e:
            logger.debug(f"Error checking duplicate embedding: {e}")
        
        return False


    def _add_to_embeddings_index(self, emb: np.ndarray):
        """Safely add embedding to index with deduplication"""
        try:
            vec = emb.copy().astype(np.float32)
            faiss.normalize_L2(vec)
            
            # Check for duplicates before adding
            if not self._is_duplicate_embedding(vec):
                if self.embeddings_index is None:
                    self.embeddings_index = faiss.IndexFlatIP(EMB_DIM)
                self.embeddings_index.add(vec)
        except Exception as e:
            logger.debug(f"Could not add to embeddings_index: {e}")
    # -------------------------
    # Similarity helpers
    # -------------------------
    def _calculate_threat_similarity(self, text: str) -> float:
        """Compute similarity vs known threat patterns (returns 0..1)."""
        if self.model is None or self.threat_patterns_index is None:
            return 0.0
        try:
            emb = self.model.encode([text], convert_to_numpy=True).astype(np.float32)
            faiss.normalize_L2(emb)
            scores, _ = self.threat_patterns_index.search(emb, 1)
            score = float(scores[0][0]) if scores.size > 0 else 0.0
            return score
        except Exception as e:
            logger.debug("Error in threat similarity calc: %s", e)
            return 0.0

    def _calculate_stored_similarity(self, text: str) -> float:
        """Compute similarity vs stored embeddings (self-learned)."""
        if self.model is None or self.embeddings_index is None:
            return 0.0
        try:
            emb = self.model.encode([text], convert_to_numpy=True).astype(np.float32)
            faiss.normalize_L2(emb)
            scores, _ = self.embeddings_index.search(emb, 1)
            score = float(scores[0][0]) if scores.size > 0 else 0.0
            return score
        except Exception as e:
            logger.debug("Error in stored similarity calc: %s", e)
            return 0.0

    # -------------------------
    # Regex, classification, dedupe, scoring
    # -------------------------
    def _check_regex_patterns(self, text: str) -> List[Dict]:
        threats = []
        for threat_type, patterns in self.regex_patterns.items():
            for pattern in patterns:
                if re.search(pattern, text, flags=re.IGNORECASE | re.DOTALL):
                    threats.append({
                        'text': text[:200],
                        'type': threat_type,
                        'detection_method': 'regex',
                        'confidence': 0.95,
                        'pattern': pattern,
                        'matched_text': (re.search(pattern, text, flags=re.IGNORECASE | re.DOTALL).group(0)[:100] if re.search(pattern, text, flags=re.IGNORECASE | re.DOTALL) else "")
                    })
                    break
        return threats

    def _classify_threat_type(self, text: str) -> str:
        tl = text.lower()
        sql_keywords = ['select', 'union', 'drop', 'insert', 'update', 'delete', 'where', '--', '/*']
        if any(k in tl for k in sql_keywords):
            return 'SQL Injection'
        xss_keywords = ['<script', 'javascript:', 'onerror', '<iframe', '<svg']
        if any(k in tl for k in xss_keywords):
            return 'XSS'
        if '../' in text or '..\\' in text or '/etc/' in tl:
            return 'Path Traversal'
        cmd_keywords = [';', '|', '&&', '`', '$(', 'rm ', 'ls ', 'cat ']
        if any(k in tl for k in cmd_keywords):
            return 'Command Injection'
        ssrf_keywords = ['localhost', '127.0.0.1', '169.254', 'file://', '192.168', '10.']
        if any(k in tl for k in ssrf_keywords):
            return 'SSRF'
        return 'Suspicious Pattern'

    def _deduplicate_threats(self, threats: List[Dict]) -> List[Dict]:
        seen = set()
        unique = []
        for t in threats:
            key = (t.get('text', '')[:100], t.get('type', ''), t.get('detection_method', ''))
            if key not in seen:
                seen.add(key)
                unique.append(t)
        return unique

    def _calculate_overall_risk(self, threats: List[Dict]) -> float:
        if not threats:
            return 0.0
        max_conf = max(t.get('confidence', 0.5) for t in threats)
        return round(max_conf * 100, 2)

    def _generate_recommendation(self, threats: List[Dict]) -> str:
        if not threats:
            return "REQUEST_SAFE"
        types = [t['type'] for t in threats]
        if 'SQL Injection' in types:
            return "BLOCK_SQL_INJECTION"
        if 'Command Injection' in types:
            return "BLOCK_COMMAND_INJECTION"
        if 'SSRF' in types:
            return "BLOCK_SSRF"
        if 'XSS' in types:
            return "BLOCK_XSS"
        if 'Path Traversal' in types:
            return "BLOCK_PATH_TRAVERSAL"
        return "BLOCK_SUSPICIOUS"

    # -------------------------
    # Request helpers
    # -------------------------
    def _extract_request_features(self, request_data: Dict) -> List[str]:
        features = []
        if 'path' in request_data:
            features.append(str(request_data['path']))
        qp = request_data.get('query_params', {})
        if isinstance(qp, dict):
            for k, v in qp.items():
                features.append(f"{k}={v}")
                features.append(str(v))
        post = request_data.get('post_data', {})
        if isinstance(post, dict):
            for k, v in post.items():
                features.append(f"{k}={v}")
                features.append(str(v))
        else:
            features.append(str(post))
        headers = request_data.get('headers', {})
        if isinstance(headers, dict):
            for k, v in headers.items():
                lk = k.lower()
                if lk in ['host', 'origin', 'referer', 'cookie', 'user-agent']:
                    continue
                if lk.startswith('x-'):
                    features.append(f"{k}={v}")
        return [str(f) for f in features if f and len(str(f).strip()) > 1]

    def _extract_ids(self, request_data: Dict) -> List[int]:
        ids = []
        for k, v in request_data.get("query_params", {}).items():
            if "id" in k.lower():
                try:
                    if isinstance(v, (list, tuple)):
                        for vv in v:
                            ids.append(int(vv))
                    else:
                        ids.append(int(v))
                except Exception:
                    pass
        path_parts = request_data.get("path", "").split("/")
        for p in path_parts:
            if p.isdigit():
                ids.append(int(p))
        return ids
    



    def debug_similarity(self, text, k=5):
        """Debug method to see similarity against known threat patterns"""
        if self.model is None or self.threat_patterns_index is None:
            return []
        
        embedding = self.model.encode([text]).astype(np.float32)
        faiss.normalize_L2(embedding)
        D, I = self.threat_patterns_index.search(embedding, k=k)
        
        results = []
        for rank, (dist, idx) in enumerate(zip(D[0], I[0]), start=1):
            if 0 <= idx < len(self.known_threats):
                payload_text = self.known_threats[idx]
            else:
                payload_text = "(index out of bounds)"
            results.append({
                "rank": rank,
                "distance": dist,
                "payload": payload_text
            })
        return results
    



    # // for verfication of the faiss index if he is working on all my payloads 
    def get_threat_patterns_count(self):
        """Return the number of threat patterns in the FAISS index"""
        if self.threat_patterns_index is None:
            return 0
        return self.threat_patterns_index.ntotal

    def get_known_threats_sample(self, count=10):
        """Return a sample of known threats for verification"""
        return self.known_threats[:count]

    def verify_faiss_index(self):
        """Verify that FAISS index contains all expected payloads"""
        print(f"FAISS index size: {self.get_threat_patterns_count()}")
        print(f"Known threats count: {len(self.known_threats)}")
        print(f"Stored payloads count: {len(self.payloads)}")
        
        # Check if they match
        if self.get_threat_patterns_count() == len(self.known_threats):
            print("✅ FAISS index matches known threats count")
        else:
            print("❌ FAISS index size doesn't match known threats count")
        
        # Show some samples
        print("\nSample of known threats in FAISS index:")
        for i, threat in enumerate(self.get_known_threats_sample(5)):
            print(f"  {i+1}. {threat[:100]}...")
    def is_safe_pattern(self, text: str) -> bool:
        """Check if text matches safe patterns that should never be blocked or stored"""
        if not text or len(text.strip()) < 2:
            return True
        
        text_lower = text.lower()
        
        # Common safe password values
        safe_passwords = [
            'password', 'password123', 'admin', 'user', 'test', 
            'login', 'auth', 'secret', '123456', 'qwerty', 'letmein',
            'welcome', 'abc123', 'password1', '12345678', '123456789',
            'hello', 'hello123', 'pass', 'pass123', 'guest', 'root',
            'administrator', 'test123', 'testing', 'demo'
        ]
        
        # Check if it's just a safe password
        if text in safe_passwords or text_lower in [p.lower() for p in safe_passwords]:
            return True
        
        # Check for simple key=value patterns (username=admin, password=123)
        if re.match(r'^\w+=\w+$', text) and len(text) < 100:
            key, value = text.split('=', 1)
            if value.lower() in [p.lower() for p in safe_passwords]:
                return True
        
        # Check if it's a common parameter name with simple value
        common_params = ['username', 'password', 'email', 'name', 'first_name', 
                        'last_name', 'phone', 'address', 'city', 'country']
        
        if '=' in text:
            parts = text.split('=', 1)
            if len(parts) == 2:
                key, value = parts
                if key.lower() in common_params and len(value) < 50:
                    # Check if value is simple (alphanumeric, no special chars)
                    if re.match(r'^[a-zA-Z0-9@.\-_]+$', value):
                        return True
        
        # Very simple alphanumeric strings
        if re.match(r'^[a-zA-Z0-9._\-@]+$', text) and len(text) < 50:
            # But NOT if it contains threat keywords
            threat_keywords = ['script', 'select', 'union', 'drop', 'delete', 
                            'insert', 'update', 'alert', 'javascript', 'onload',
                            'onerror', 'onclick', 'iframe', 'object', 'embed']
            for keyword in threat_keywords:
                if keyword in text_lower:
                    return False
            return True
        
        return False


    # for testing 
    def test_safe_patterns(self):
        """Test that safe patterns are not detected as suspicious"""
        safe_examples = [
            "dZNTCQwW0nppgCcIGVwp5FMBqR6quGcMAqlFcg4PaCOL31jCywUNt3f6os3O5gC7",  # Your example
            "password123",
            "user@example.com",
            "normal_username",
            "abc123",
            "hello123"
        ]
        
        print("🔒 Testing safe patterns detection...")
        all_passed = True
        
        for safe_text in safe_examples:
            is_safe = self.is_safe_pattern(safe_text)
            is_suspicious = self.is_suspicious(safe_text)
            
            if is_safe and not is_suspicious:
                print(f"✅ Correctly allowed: {safe_text}")
            else:
                print(f"❌ False positive detected: {safe_text}")
                print(f"   is_safe_pattern(): {is_safe}")
                print(f"   is_suspicious(): {is_suspicious}")
                all_passed = False
        
        # Also test some actual threats to ensure they're still caught
        threat_examples = [
            "SELECT * FROM users",  # SQL injection
            "<script>alert('xss')</script>",  # XSS
            "../../etc/passwd",  # Path traversal
        ]
        
        print("\n🔍 Testing that real threats are still detected...")
        for threat_text in threat_examples:
            is_safe = self.is_safe_pattern(threat_text)
            is_suspicious = self.is_suspicious(threat_text)
            
            if not is_safe and is_suspicious:
                print(f"✅ Correctly blocked: {threat_text}")
            else:
                print(f"❌ False negative: {threat_text}")
                print(f"   is_safe_pattern(): {is_safe}")
                print(f"   is_suspicious(): {is_suspicious}")
                all_passed = False
        
        if all_passed:
            print("\n🎉 All tests passed! Safe patterns are allowed, threats are blocked.")
        else:
            print("\n⚠️  Some tests failed. Review the safe pattern detection.")
        
        return all_passed
    



    # /// affichage joli
    