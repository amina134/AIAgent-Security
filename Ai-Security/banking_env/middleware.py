from django.http import JsonResponse, HttpResponseForbidden
from django.utils.deprecation import MiddlewareMixin
from security_agent.ai_detector import MiniLMSecurityAgent
import json
import logging

logger = logging.getLogger(__name__)

class AISecurityMiddleware(MiddlewareMixin):
    """
    Middleware de sécurité AI pour analyser les requêtes en temps réel
    """
    
    def __init__(self, get_response):
        super().__init__(get_response)
        self.get_response = get_response
        self.security_agent = MiniLMSecurityAgent()
    
    def process_request(self, request):
        """
        Analyse chaque requête entrante avec l'agent AI
        """
        # Exclusion des URLs statiques et admin
        excluded_paths = ['/admin/', '/static/', '/media/']
        if any(request.path.startswith(path) for path in excluded_paths):
            return None
        
        try:
            # Préparation des données de requête pour l'analyse
            request_data = {
                'path': request.path,
                'method': request.method,
                'query_params': dict(request.GET),
                'headers': dict(request.headers),
                'user_agent': request.META.get('HTTP_USER_AGENT', ''),
                'client_ip': self._get_client_ip(request),
                'user_session': self._get_user_session(request)  # ← IMPORTANT: Ajouter la session
            }
            
            # Ajout des données POST pour les requêtes non-GET
            if request.method in ['POST', 'PUT', 'PATCH']:
                try:
                    if request.content_type == 'application/json':
                        request_data['post_data'] = json.loads(request.body)
                    else:
                        request_data['post_data'] = dict(request.POST)
                except:
                    request_data['post_data'] = str(request.body)
            
            # Analyse AI de la requête
            analysis_result = self.security_agent.analyze_request(request_data)
            
            # Log de l'analyse
            logger.info(f"Security Analysis - IP: {request_data['client_ip']} "
                       f"Path: {request.path} Risk: {analysis_result['overall_risk_score']}")
            
            # Décision de blocage
            if analysis_result['is_malicious']:
                return self._block_request(request, analysis_result)
                
        except Exception as e:
            logger.error(f"Erreur dans l'analyse de sécurité: {e}")
        
        return None
    
    def _get_client_ip(self, request):
        """Récupère l'IP réelle du client"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
    
    def _get_user_session(self, request):
        """Récupère la session utilisateur pour l'analyse contextuelle"""
        try:
            if hasattr(request, 'session'):
                return request.session
            elif hasattr(request, 'user') and request.user.is_authenticated:
                return {'_auth_user_id': str(request.user.id)}
            else:
                return None
        except Exception as e:
            logger.error(f"Erreur récupération session: {e}")
            return None
    
    def _block_request(self, request, analysis_result):
        """Bloque la requête malveillante"""
        logger.warning(
            f"Requête bloquée - IP: {self._get_client_ip(request)} "
            f"Path: {request.path} "
            f"Threats: {[t['type'] for t in analysis_result['threats_detected']]}"
        )
        
        return JsonResponse({
            'error': 'Accès refusé',
            'message': 'Activité suspecte détectée par le système de sécurité',
            'threat_type': analysis_result['threats_detected'][0]['type'] if analysis_result['threats_detected'] else 'Unknown',
            'request_id': id(request),
            'security_action': 'BLOCKED'
        }, status=403)