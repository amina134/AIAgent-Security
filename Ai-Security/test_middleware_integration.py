import os
import django
import sys
import json

# Configurez le chemin
project_path = os.path.dirname(os.path.abspath(__file__))
sys.path.append(project_path)
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'projet_ds1.settings')

try:
    django.setup()
    print("✅ Django configuré avec succès")
except Exception as e:
    print(f"❌ Erreur configuration Django: {e}")
    sys.exit(1)

from django.test import RequestFactory
from banking_env.middleware import AISecurityMiddleware

def get_response_mock(request):
    """Mock de réponse pour le middleware"""
    from django.http import JsonResponse
    return JsonResponse({'status': 'request_processed', 'message': 'Requête traitée normalement'})

def test_middleware_integration():
    """Test l'intégration complète du middleware"""
    print("🚀 TEST D'INTÉGRATION DU MIDDLEWARE DE SÉCURITÉ")
    print("=" * 60)
    
    factory = RequestFactory()
    middleware = AISecurityMiddleware(get_response_mock)
    
    # Liste des tests
    test_cases = [
        {
            'name': 'SQL Injection dans POST',
            'request': factory.post('/api/login', {
                'username': "admin' OR '1'='1'",
                'password': 'anypassword'
            }),
            'should_block': True,
            'description': "Injection SQL classique dans les données POST"
        },
        {
            'name': 'XSS dans POST',
            'request': factory.post('/api/comment', {
                'content': "<script>alert('xss')</script>",
                'author': 'hacker'
            }),
            'should_block': True,
            'description': "Attaque XSS basique"
        },
        {
            'name': 'Command Injection',
            'request': factory.post('/api/execute', {
                'command': '; rm -rf /',
                'user': 'test'
            }),
            'should_block': True,
            'description': "Injection de commande système"
        },
        {
            'name': 'Path Traversal dans GET',
            'request': factory.get('/api/download?file=../../../etc/passwd'),
            'should_block': True,
            'description': "Path traversal dans les paramètres GET"
        },
        {
            'name': 'Requête GET normale',
            'request': factory.get('/api/products?page=1&search=laptop'),
            'should_block': False,
            'description': "Requête GET normale avec paramètres standards"
        },
        {
            'name': 'Requête POST normale',
            'request': factory.post('/api/login', {
                'username': 'john.doe@example.com',
                'password': 'SecurePassword123'
            }),
            'should_block': False,
            'description': "Requête POST normale avec credentials valides"
        },
        {
            'name': 'Requête avec JSON malveillant',
            'request': factory.post(
                '/api/data',
                data=json.dumps({
                    'query': "SELECT * FROM users WHERE 1=1",
                    'input': "' OR 1=1--"
                }),
                content_type='application/json'
            ),
            'should_block': True,
            'description': "Injection SQL dans un corps JSON"
        }
    ]
    
    results = []
    
    for i, test_case in enumerate(test_cases, 1):
        print(f"\n🔍 Test {i}/{len(test_cases)}: {test_case['name']}")
        print(f"   Description: {test_case['description']}")
        print(f"   URL: {test_case['request'].path}")
        
        try:
            # Exécute le middleware
            response = middleware.process_request(test_case['request'])
            
            if response:
                # Requête bloquée
                print(f"   🔒 RÉSULTAT: BLOQUÉE (Status: {response.status_code})")
                if hasattr(response, 'content'):
                    try:
                        content = json.loads(response.content.decode())
                        print(f"   📄 Message: {content.get('message', 'N/A')}")
                    except:
                        print(f"   📄 Content: {response.content.decode()[:100]}...")
                
                was_blocked = True
            else:
                # Requête autorisée
                print(f"   ✅ RÉSULTAT: AUTORISÉE")
                was_blocked = False
            
            # Vérification du résultat
            if was_blocked == test_case['should_block']:
                status = "✅ SUCCÈS"
                success = True
            else:
                status = "❌ ÉCHEC"
                success = False
                if test_case['should_block']:
                    print(f"   ⚠️  ATTENTION: Cette requête aurait dû être bloquée!")
                else:
                    print(f"   ⚠️  ATTENTION: Faux positif! Cette requête normale a été bloquée!")
            
            print(f"   {status}")
            
            results.append({
                'test': test_case['name'],
                'expected_block': test_case['should_block'],
                'actual_block': was_blocked,
                'success': success,
                'description': test_case['description']
            })
            
        except Exception as e:
            print(f"   💥 ERREUR: {e}")
            results.append({
                'test': test_case['name'],
                'expected_block': test_case['should_block'],
                'actual_block': None,
                'success': False,
                'error': str(e),
                'description': test_case['description']
            })
    
    # Résumé final
    print(f"\n{'='*60}")
    print("📊 RÉSUMÉ DES TESTS D'INTÉGRATION")
    print('='*60)
    
    success_count = sum(1 for r in results if r.get('success', False))
    total_count = len(results)
    
    print(f"Tests réussis: {success_count}/{total_count} ({success_count/total_count*100:.1f}%)")
    
    for result in results:
        status = "✅" if result.get('success', False) else "❌"
        print(f"{status} {result['test']}")
        if not result.get('success', False) and 'error' in result:
            print(f"   Erreur: {result['error']}")
    
    print(f"\n🎯 DÉTAIL DES RÉSULTATS:")
    for result in results:
        status = "BLOQUÉ" if result['actual_block'] else "AUTORISÉ"
        expected = "BLOQUÉ" if result['expected_block'] else "AUTORISÉ"
        print(f"   {result['test']}: {status} (attendu: {expected})")
    
    if success_count == total_count:
        print("\n🎉 TOUS LES TESTS D'INTÉGRATION SONT RÉUSSIS !")
        print("   Votre middleware de sécurité fonctionne parfaitement !")
    else:
        print(f"\n⚠️  {total_count - success_count} test(s) d'intégration ont échoué")

def test_middleware_with_headers():
    """Test le middleware avec différents headers"""
    print(f"\n{'='*60}")
    print("🧪 TEST AVEC HEADERS SPÉCIAUX")
    print('='*60)
    
    factory = RequestFactory()
    middleware = AISecurityMiddleware(get_response_mock)
    
    # Test avec User-Agent suspect
    suspicious_request = factory.post('/api/admin', {
        'username': "admin'--",
        'password': 'test'
    })
    suspicious_request.META['HTTP_USER_AGENT'] = 'sqlmap/1.6#dev'
    
    print("Test avec User-Agent sqlmap (outil de pentest)...")
    response = middleware.process_request(suspicious_request)
    
    if response:
        print("✅ Requête avec User-Agent suspect BLOQUÉE")
    else:
        print("❌ Requête avec User-Agent suspect AUTORISÉE")
    
    # Test avec headers normaux
    normal_request = factory.get('/api/products')
    normal_request.META['HTTP_USER_AGENT'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    
    print("\nTest avec User-Agent normal...")
    response = middleware.process_request(normal_request)
    
    if response:
        print("❌ Faux positif - Requête normale BLOQUÉE")
    else:
        print("✅ Requête normale avec User-Agent standard AUTORISÉE")

if __name__ == '__main__':
    print("🔧 DÉMARRAGE DES TESTS D'INTÉGRATION DU MIDDLEWARE")
    print("Ce test vérifie que le middleware bloque correctement les requêtes malveillantes")
    print("et autorise les requêtes normales sans faux positifs.\n")
    
    # Test principal
    test_middleware_integration()
    
    # Test avec headers
    test_middleware_with_headers()
    
    print(f"\n{'='*60}")
    print("💡 CONSEIL: Si tous les tests passent, votre agent de sécurité")
    print("est prêt pour une démonstration complète avec le serveur Django!")
    print('='*60)