from django.http import JsonResponse
from django.utils.deprecation import MiddlewareMixin
from security_agent.ai_detector import MiniLMSecurityAgent
import json
import logging
from django.http import HttpResponse
import html
from django.conf import settings
import os

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

                # Check if client wants HTML response
                accept_header = request.headers.get('Accept', '')
                if 'text/html' in accept_header and not request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    # Return HTML response for browser requests
                    return HttpResponse(self._generate_html_response(analysis_result), content_type='text/html', status=403)
                else:
                    # Return JSON for API requests
                    return JsonResponse({
                        'status': 'blocked',
                        'error': 'Security violation detected',
                        'code': 'SECURITY_VIOLATION',
                        'message': 'Your request has been blocked by our AI security system.',
                        'details': {
                            'threats': analysis_result.get('threats_detected', []),
                            'risk_score': analysis_result.get('overall_risk_score'),
                            'recommendation': analysis_result.get('recommendation', 'BLOCK_SUSPICIOUS'),
                        },
                        'support': {
                            'contact': 'security@yourdomain.com',
                            'reference_id': f"SEC-{hash(request.path + str(user_id))}"[:20]
                        }
                    }, status=403)

        except Exception as e:
            logger.error(f"AI Middleware error: {e}")
            # Continue request to avoid crashing app

        if hasattr(self.agent, 'detect_csrf_attack') and self.agent.detect_csrf_attack(request_data):
            # Check for HTML preference
            accept_header = request.headers.get('Accept', '')
            if 'text/html' in accept_header and not request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return HttpResponse(self._generate_csrf_html_response(), content_type='text/html', status=403)
            else:
                return JsonResponse({
                    'status': 'blocked',
                    'error': 'CSRF Attack Detected',
                    'code': 'CSRF_VIOLATION',
                    'message': 'Potential CSRF attack has been blocked.',
                    'details': {
                        'method': request.method,
                        'path': request.path
                    }
                }, status=403)
        
        # SAFE → continue to view
        return self.get_response(request)

    def _generate_html_response(self, analysis_result):
        """Generate a user-friendly HTML response for browser requests"""
        threats = analysis_result.get('threats_detected', [])
        risk_score = analysis_result.get('overall_risk_score', 0)
        recommendation = analysis_result.get('recommendation', 'BLOCK_SUSPICIOUS')
        
        # Escape HTML in threat data for safety
        threats_limited = threats[:1]
        safe_threats = []
        for threat in threats_limited:
            safe_threat = {}
            for key, value in threat.items():
                if isinstance(value, str):
                    safe_threat[key] = html.escape(value)
                else:
                    safe_threat[key] = value
            safe_threats.append(safe_threat)
        
        # Get static URL for CSS
        css_url = self._get_css_url()
        
        html_content = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Security Alert - Request Blocked</title>
            <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
            <link rel="stylesheet" href="{css_url}">
        </head>
        <body>
            <div class="security-container">
                <div class="security-header">
                    <div class="security-icon">
                        <i class="fas fa-shield-alt"></i>
                    </div>
                    <h1>Security Alert</h1>
                    <p class="subtitle">AI-Powered Threat Detection System</p>
                </div>
                
                <div class="alert-box">
                    <div class="alert-header">
                        <i class="fas fa-exclamation-triangle"></i>
                        <h2>Request Blocked</h2>
                    </div>
                    <p>Our AI security system has detected potential security threats in your request.</p>
                    
                    <div class="risk-meter">
                        <div class="risk-label">
                            <span>Threat Risk Level</span>
                            <span>{risk_score}%</span>
                        </div>
                        <div class="risk-bar">
                            <div class="risk-fill" style="width: {risk_score}%"></div>
                        </div>
                    </div>
                </div>
                
                <div class="threats-section">
                    <div class="section-title">
                        <i class="fas fa-list"></i>
                        <h3>Detected Threats</h3>
                    </div>
                    <div class="threats-list">
        """
        
        # Add threat items
        for i, threat in enumerate(safe_threats, 1):
            threat_type = threat.get('type', 'Unknown')
            confidence = threat.get('confidence', 0) * 100
            method = threat.get('detection_method', 'unknown')
            threat_text = threat.get('text', '')[:200]
            
            # Get appropriate icon for threat type
            icon_class = self._get_threat_icon(threat_type)
            
            html_content += f"""
                        <div class="threat-item">
                            <div class="threat-header">
                                <div class="threat-type">
                                    <i class="{icon_class}"></i>
                                    <span>{threat_type}</span>
                                </div>
                                <span class="confidence-badge">{confidence:.0f}% confidence</span>
                            </div>
                            <div class="threat-method">
                                <i class="fas fa-search"></i>
                                <span>Detected by: {method.replace('_', ' ').title()}</span>
                            </div>
                            <div class="threat-text">
                                {threat_text}
                            </div>
                        </div>
            """
        
        html_content += f"""
                    </div>
                </div>
                
                <div class="recommendation-box">
                    <h3>
                        <i class="fas fa-lightbulb"></i>
                        Security Recommendation
                    </h3>
                    <p>{self._get_recommendation_text(recommendation)}</p>
                    <div class="recommendation-code">Action: {recommendation}</div>
                </div>
                
                
            </div>
            
            <script>
                document.addEventListener('DOMContentLoaded', function() {{
                    // Animate risk meter on load
                    const riskFill = document.querySelector('.risk-fill');
                    riskFill.style.transition = 'width 1s ease-in-out';
                    
                    // Add click to expand threat items
                    const threatItems = document.querySelectorAll('.threat-item');
                    threatItems.forEach(item => {{
                        item.addEventListener('click', function() {{
                            this.classList.toggle('expanded');
                        }});
                    }});
                }});
            </script>
        </body>
        </html>
        """
        
        return html_content
    
    def _generate_csrf_html_response(self):
        """Generate HTML response for CSRF attacks"""
        css_url = self._get_css_url()
        
        return f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>CSRF Protection Alert</title>
            <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
            <link rel="stylesheet" href="{css_url}">
        </head>
        <body>
            <div class="security-container">
                <div class="security-header">
                    <div class="security-icon csrf">
                        <i class="fas fa-user-shield"></i>
                    </div>
                    <h1>CSRF Protection Triggered</h1>
                    <p class="subtitle">Cross-Site Request Forgery Prevention</p>
                </div>
                
                <div class="alert-box warning">
                    <div class="alert-header">
                        <i class="fas fa-exclamation-circle"></i>
                        <h2>Potential CSRF Attack Blocked</h2>
                    </div>
                    <p>Our system detected a potential Cross-Site Request Forgery (CSRF) attempt.</p>
                    
                    <div class="csrf-info">
                        <h3><i class="fas fa-info-circle"></i> What is CSRF?</h3>
                        <p>CSRF is an attack that tricks a user into performing actions they didn't intend on a web application where they're authenticated.</p>
                        
                        <h3><i class="fas fa-shield-alt"></i> Protection Applied</h3>
                        <p>This request was blocked because it appears to be a state-changing operation performed via GET request or without proper CSRF tokens.</p>
                    </div>
                </div>
                
                <div class="recommendation-box">
                    <h3><i class="fas fa-steps"></i> Required Actions</h3>
                    <ol class="steps-list">
                        <li>Ensure you're using POST requests for state-changing operations</li>
                        <li>Include valid CSRF tokens in your requests</li>
                        <li>Verify that your request originates from the same origin</li>
                        <li>Use appropriate headers for API requests</li>
                    </ol>
                </div>
                
               
            </div>
        </body>
        </html>
        """
    
    def _get_css_url(self):
        """Get the CSS URL - handles both development and production"""
        # Try to use staticfiles first
        try:
            from django.contrib.staticfiles.storage import staticfiles_storage
            return staticfiles_storage.url('css/alerts.css')
        except:
            # Fallback to relative path
            return '/static/security/css/simple_alerts.css'
    
    def _get_threat_icon(self, threat_type):
        """Return appropriate icon class for threat type"""
        icons = {
            'SQL Injection': 'fas fa-database',
            'XSS': 'fas fa-code',
            'Command Injection': 'fas fa-terminal',
            'SSRF': 'fas fa-globe',
            'Path Traversal': 'fas fa-folder-tree',
            'IDOR': 'fas fa-user-lock',
            'CSRF': 'fas fa-exchange-alt',
            'Suspicious Pattern': 'fas fa-exclamation-triangle'
        }
        return icons.get(threat_type, 'fas fa-exclamation-circle')
    
    def _get_recommendation_text(self, recommendation):
        """Return human-readable recommendation text"""
        recommendations = {
            'BLOCK_SQL_INJECTION': 'SQL injection patterns detected. Use parameterized queries and input validation.',
            'BLOCK_COMMAND_INJECTION': 'Command injection attempt detected. Avoid system commands with user input.',
            'BLOCK_XSS': 'Cross-site scripting (XSS) patterns detected. Implement output encoding.',
            'BLOCK_PATH_TRAVERSAL': 'Path traversal attempt detected. Validate file paths.',
            'BLOCK_SSRF': 'Server-Side Request Forgery (SSRF) attempt detected. Validate URLs.',
            'BLOCK_SUSPICIOUS': 'Suspicious patterns detected. Review the request.'
        }
        return recommendations.get(recommendation, 'Security issue detected. Review the request.')
    
    def _get_current_timestamp(self):
        """Get current timestamp for display"""
        from datetime import datetime
        return datetime.now().strftime('%Y-%m-%d %H:%M:%S')