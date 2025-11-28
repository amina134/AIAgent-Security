from django.http import JsonResponse
from django.utils.deprecation import MiddlewareMixin
from security_agent.ai_detector import MiniLMSecurityAgent
import json
import logging
from django.http import HttpResponse
logger = logging.getLogger(__name__)

class AISecurityMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        try:
            self.agent = MiniLMSecurityAgent()
            logger.info("AI Security Agent initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize AI Security Agent: {e}")
            self.agent = None
    
    def __call__(self, request):

        # If AI agent failed to load → let request pass
        if self.agent is None:
            return self.get_response(request)

        try:
            # --------------------------------------------------
            # POST DATA EXTRACTION
            # --------------------------------------------------
            post_data = {}

            if request.method == 'POST':
                if request.POST:
                    post_data = dict(request.POST)
                    for k, v in post_data.items():
                        if isinstance(v, list) and len(v) == 1:
                            post_data[k] = v[0]

                elif request.content_type == 'application/json' and request.body:
                    try:
                        json_data = json.loads(request.body.decode('utf-8'))
                        if isinstance(json_data, dict):
                            post_data = json_data
                    except json.JSONDecodeError:
                        post_data = {'raw_body': request.body.decode('utf-8')}

            # --------------------------------------------------
            # USER CONTEXT
            # --------------------------------------------------
            user_is_authenticated = (
                hasattr(request, 'user') and 
                request.user.is_authenticated
            )

            user_id = request.user.id if user_is_authenticated else None
            print("DEBUG USER ID:", request.user.id if request.user.is_authenticated else None)

            # --------------------------------------------------
            # DATA SENT TO THE AI SECURITY AGENT
            # --------------------------------------------------
            request_data = {
                'path': request.path,
                'method': request.method,
                'query_params': dict(request.GET),
                'post_data': post_data,
                'headers': dict(request.headers),
                'cookies': dict(request.COOKIES),
                'user_context': {
                    'is_authenticated': user_is_authenticated,
                    'user_id': user_id
                },
                
            }

            # --------------------------------------------------
            # RUN ANALYSIS
            # --------------------------------------------------
            analysis_result = self.agent.analyze_request(request_data)

            if analysis_result.get('blocked') or analysis_result.get('is_malicious'):
                logger.warning(f"Blocked malicious request: {analysis_result}")

                return JsonResponse({
                    'error': 'Security violation detected',
                    'blocked': True,
                    'threats': analysis_result.get('threats_detected', []),
                    'risk_score': analysis_result.get('overall_risk_score'),
                }, status=403)

        except Exception as e:
            logger.error(f"AI Middleware error: {e}")
            # Continue request to avoid crashing app

        if self.agent.detect_csrf_attack(request_data):
            return HttpResponse("❌ CSRF Attack Blocked by AI Agent", status=403)
        # SAFE → continue to view
        return self.get_response(request)