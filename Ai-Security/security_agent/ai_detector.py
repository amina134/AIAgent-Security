import numpy as np
import faiss
from sentence_transformers import SentenceTransformer
from django.conf import settings
import logging
import json
import re
from typing import Dict, List, Any

logger = logging.getLogger(__name__)

class MiniLMSecurityAgent:
    """
    Agent de sécurité AI avec détection IDOR SIMPLE et EFFICACE
    """
    
    def __init__(self):
        self.model_name = "all-MiniLM-L6-v2"
        self.model = None
        self.threat_patterns_index = None
        self.threat_threshold = 0.65
        
        # Patterns de menaces
        self.known_threats = self._get_threat_patterns()
        
        # Règles regex pour détection
        self.regex_patterns = {
            'SQL Injection': [
                r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|CREATE)\b.*\b(FROM|INTO|TABLE|DATABASE)\b)",
                r"('|\"|`)\s*(OR|AND)\s+['\"`]?[0-9]+['\"`]?\s*=\s*['\"`]?[0-9]+",
                r"(;\s*(DROP|DELETE|UPDATE|INSERT))",
            ],
            'XSS': [
                r"(<script[^>]*>.*</script>)",
                r"(javascript:)", 
                r"(on\w+\s*=\s*[^>]*)",
            ],
            'Path Traversal': [
                r"(\.\./\.\./\.\./)",
                r"(\.\.\\\.\.\\\.\\)",
            ],
            'Command Injection': [
                r"(;\s*(ls|dir|cat|rm|del|mkdir)\s)",
                r"(\|\s*(ls|dir|cat|rm|del))",
            ]
        }
        
        self.initialize_detector()
    
    def _get_threat_patterns(self):
        """Patterns de menaces"""
        return [
            # SQL Injection
            "SELECT * FROM users WHERE username = 'admin' OR '1'='1'",
            "admin' OR 1=1--", 
            "'; DROP TABLE users; --",
            "UNION SELECT username, password FROM users",
            # XSS
            "<script>alert('hello')</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert('XSS')",
            # Path Traversal  
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            # Command Injection
            "; ls -la", 
            "| cat /etc/passwd",
            "&& rm -rf /",
        ]
    
    def initialize_detector(self):
        """Initialise le modèle MiniLM"""
        try:
            logger.info(f"Chargement du modèle {self.model_name}...")
            self.model = SentenceTransformer(self.model_name)
            self._build_threat_index()
            logger.info("Agent de sécurité MiniLM initialisé avec succès")
        except Exception as e:
            logger.error(f"Erreur initialisation agent: {e}")
            raise
    
    def _build_threat_index(self):
        """Construit l'index FAISS"""
        threat_embeddings = self.model.encode(self.known_threats)
        dimension = threat_embeddings.shape[1]
        self.threat_patterns_index = faiss.IndexFlatIP(dimension)
        faiss.normalize_L2(threat_embeddings)
        self.threat_patterns_index.add(threat_embeddings)
    
    def analyze_request(self, request_data: Dict) -> Dict[str, Any]:
        """
        Analyse une requête - DÉTECTION SIMPLE
        """
        threats_detected = []
        
        # 1. Détection des menaces classiques (SQLi, XSS, etc.)
        request_texts = self._extract_request_features(request_data)
        
        for text in request_texts:
            if not text or len(text.strip()) < 2:
                continue
                
            # Vérification regex
            regex_threats = self._check_regex_patterns(text)
            threats_detected.extend(regex_threats)
            
            # Vérification AI similarity
            if not regex_threats:
                ai_threats = self._check_ai_similarity(text)
                threats_detected.extend(ai_threats)
        
        # 2. 🔥 DÉTECTION IDOR SIMPLE - TOUT BLOQUER
        idor_threats = self._detect_idor_simple(request_data)
        threats_detected.extend(idor_threats)
        
        # Dédoublonnage
        unique_threats = self._deduplicate_threats(threats_detected)
        
        return {
            'is_malicious': len(unique_threats) > 0,
            'threats_detected': unique_threats,
            'overall_risk_score': self._calculate_overall_risk(unique_threats),
            'recommendation': self._generate_recommendation(unique_threats)
        }
    
    def _detect_idor_simple(self, request_data: Dict) -> List[Dict]:
        """
        Détection IDOR TRÈS SIMPLE - BLOQUE TOUT CE QUI RESSEMBLE À IDOR
        """
        threats = []
        
        path = request_data.get('path', '')
        query_params = request_data.get('query_params', {})
        post_data = request_data.get('post_data', {})
        
        # 🔥 1. Détection des IDs dans l'URL
        url_id_patterns = [
            r'/users/(\d+)',
            r'/accounts/(\d+)', 
            r'/profile/(\d+)',
            r'/api/users/(\d+)',
            r'/api/accounts/(\d+)',
            r'/clients/(\d+)',
            r'/customers/(\d+)',
        ]
        
        for pattern in url_id_patterns:
            if re.search(pattern, path):
                threats.append({
                    'text': f"IDOR potential in URL: {path}",
                    'type': 'IDOR',
                    'detection_method': 'url_pattern',
                    'confidence': 0.8,
                    'details': {
                        'pattern': pattern,
                        'path': path,
                        'reason': 'Direct object reference in URL path'
                    }
                })
                break  # Un pattern suffit
        
        # 🔥 2. Détection des paramètres sensibles dans GET
        idor_params = ['user_id', 'account_id', 'client_id', 'customer_id', 'id', 'userId', 'accountId']
        
        for param in idor_params:
            if param in query_params:
                threats.append({
                    'text': f"IDOR potential in GET params: {param}={query_params[param]}",
                    'type': 'IDOR',
                    'detection_method': 'query_param', 
                    'confidence': 0.7,
                    'details': {
                        'parameter': param,
                        'value': query_params[param],
                        'reason': 'Sensitive parameter in query string'
                    }
                })
                break
        
        # 🔥 3. Détection des paramètres sensibles dans POST
        if isinstance(post_data, dict):
            for param in idor_params:
                if param in post_data:
                    threats.append({
                        'text': f"IDOR potential in POST data: {param}={post_data[param]}",
                        'type': 'IDOR',
                        'detection_method': 'post_data',
                        'confidence': 0.7,
                        'details': {
                            'parameter': param,
                            'value': post_data[param],
                            'reason': 'Sensitive parameter in POST data'
                        }
                    })
                    break
        
        return threats
    
    def _check_regex_patterns(self, text: str) -> List[Dict]:
        """Vérification regex"""
        threats = []
        for threat_type, patterns in self.regex_patterns.items():
            for pattern in patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    threats.append({
                        'text': text,
                        'type': threat_type,
                        'detection_method': 'regex',
                        'confidence': 0.9,
                        'pattern': pattern
                    })
                    break
        return threats
    
    def _check_ai_similarity(self, text: str) -> List[Dict]:
        """Vérification similarité AI"""
        threats = []
        threat_score = self._calculate_threat_similarity(text)
        if threat_score > self.threat_threshold:
            threat_type = self._classify_threat_type(text)
            threats.append({
                'text': text,
                'type': threat_type,
                'detection_method': 'ai_similarity', 
                'confidence': threat_score,
                'similarity_score': threat_score
            })
        return threats
    
    def _calculate_threat_similarity(self, text: str) -> float:
        """Calcule similarité avec menaces connues"""
        try:
            text_embedding = self.model.encode([text])
            faiss.normalize_L2(text_embedding)
            scores, indices = self.threat_patterns_index.search(text_embedding, 3)
            return float(np.max(scores)) if scores.size > 0 else 0.0
        except Exception as e:
            logger.error(f"Erreur calcul similarité: {e}")
            return 0.0
    
    def _extract_request_features(self, request_data: Dict) -> List[str]:
        """Extrait caractéristiques requête"""
        features = []
        if 'path' in request_data:
            features.append(request_data['path'])
        if 'query_params' in request_data:
            for key, value in request_data['query_params'].items():
                features.append(f"{key}={value}")
        if 'post_data' in request_data:
            if isinstance(request_data['post_data'], dict):
                for key, value in request_data['post_data'].items():
                    features.append(f"{key}={value}")
            else:
                features.append(str(request_data['post_data']))
        return [str(f) for f in features if f and len(str(f).strip()) > 1]
    
    def _classify_threat_type(self, text: str) -> str:
        """Classifie type menace"""
        text_lower = text.lower()
        if any(sql in text_lower for sql in ['select', 'union', 'drop', 'insert']):
            return 'SQL Injection'
        elif any(xss in text_lower for xss in ['<script>', 'javascript:', 'onerror']):
            return 'XSS'
        elif any(trav in text_lower for trav in ['../', '..\\', '/etc/']):
            return 'Path Traversal'
        elif any(cmd in text_lower for cmd in [';', '|', '&&', 'rm ']):
            return 'Command Injection'
        else:
            return 'Suspicious Pattern'
    
    def _deduplicate_threats(self, threats: List[Dict]) -> List[Dict]:
        """Dédoublonne menaces"""
        seen = set()
        unique = []
        for threat in threats:
            key = (threat['text'], threat['type'])
            if key not in seen:
                seen.add(key)
                unique.append(threat)
        return unique
    
    def _calculate_overall_risk(self, threats: List[Dict]) -> float:
        """Calcule score risque global"""
        if not threats:
            return 0.0
        return max(threat.get('confidence', 0.5) for threat in threats)
    
    def _generate_recommendation(self, threats: List[Dict]) -> str:
        """Génère recommandation"""
        if not threats:
            return "REQUEST_SAFE"
        threat_types = [t['type'] for t in threats]
        if 'SQL Injection' in threat_types:
            return "BLOCK_SQL_INJECTION"
        elif 'XSS' in threat_types:
            return "BLOCK_XSS"
        elif 'Command Injection' in threat_types:
            return "BLOCK_COMMAND_INJECTION"
        elif 'Path Traversal' in threat_types:
            return "BLOCK_PATH_TRAVERSAL"
        elif 'IDOR' in threat_types:
            return "BLOCK_IDOR"
        else:
            return "BLOCK_SUSPICIOUS"