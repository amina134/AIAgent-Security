from django.test import TestCase
from security_agent.ai_detector import MiniLMSecurityAgent
import time

class SecurityAgentTests(TestCase):
    
    def setUp(self):
        self.agent = MiniLMSecurityAgent()
        time.sleep(1)
    
    def test_sql_injection_detection(self):
        """Test la détection d'injection SQL"""
        malicious_request = {
            'path': '/api/login',
            'query_params': {'username': "admin' OR '1'='1'"},
            'post_data': {'password': 'any'}
        }
        
        result = self.agent.analyze_request(malicious_request)
        self.assertTrue(result['is_malicious'])
    
    def test_xss_detection(self):
        """Test la détection XSS"""
        malicious_request = {
            'path': '/api/comment',
            'post_data': {'content': "<script>alert('xss')</script>"}
        }
        
        result = self.agent.analyze_request(malicious_request)
        self.assertTrue(result['is_malicious'])
    
    def test_idor_detection_url(self):
        """Test la détection IDOR dans les URLs"""
        malicious_request = {
            'path': '/api/users/12345',
            'query_params': {},
            'post_data': {},
            'client_ip': '192.168.1.100'
        }
        
        result = self.agent.analyze_request(malicious_request)
        print(f"IDOR URL Test Result: {result}")
        self.assertTrue(result['is_malicious'])
    
    def test_idor_detection_params(self):
        """Test la détection IDOR dans les paramètres"""
        malicious_request = {
            'path': '/api/account',
            'query_params': {'user_id': '67890'},
            'post_data': {},
            'client_ip': '192.168.1.100'
        }
        
        result = self.agent.analyze_request(malicious_request)
        print(f"IDOR Params Test Result: {result}")
        self.assertTrue(result['is_malicious'])
    
    def test_idor_detection_post(self):
        """Test la détection IDOR dans les données POST"""
        malicious_request = {
            'path': '/api/update_profile',
            'query_params': {},
            'post_data': {'account_id': '99999', 'name': 'test'},
            'client_ip': '192.168.1.100'
        }
        
        result = self.agent.analyze_request(malicious_request)
        print(f"IDOR POST Test Result: {result}")
        self.assertTrue(result['is_malicious'])
    
    def test_normal_request(self):
        """Test qu'une requête normale n'est pas bloquée"""
        normal_request = {
            'path': '/api/products',
            'query_params': {'page': '1', 'search': 'laptop'},
            'post_data': {'email': 'user@example.com'}
        }
        
        result = self.agent.analyze_request(normal_request)
        self.assertFalse(result['is_malicious'])
    
    def test_command_injection_detection(self):
        """Test la détection de command injection"""
        malicious_request = {
            'path': '/api/execute',
            'post_data': {'command': '; ls -la'}
        }
        
        result = self.agent.analyze_request(malicious_request)
        self.assertTrue(result['is_malicious'])