from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json
from .rl_logic.environment import ThreatResponseEnvironment, ResponseActions

# Initialize the RL environment
env = ThreatResponseEnvironment()

@csrf_exempt
def decide_response(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            
            # Map the LLM's threat level to a severity float (0.0 to 1.0)
            risk_map = {"LOW": 0.1, "MEDIUM": 0.4, "HIGH": 0.8, "CRITICAL": 1.0}
            severity = risk_map.get(data.get('risk_level', 'LOW'), 0.2)
            
            # Reset env with current threat state
            state = env.reset() 
            # In a real scenario, the agent would pick an action. 
            # For now, let's simulate the environment's logic for the "best" action.
            
            # Logic: If severity is high, suggest BLOCK_IP
            suggested_action = ResponseActions.BLOCK_IP if severity > 0.7 else ResponseActions.ALERT_ADMIN
            
            # Execute step in environment
            next_state, reward, done, info = env.step(suggested_action)
            
            return JsonResponse({
                "action": info['action_name'],
                "reward_score": reward,
                "system_impact": info['system_load'],
                "status": "Action Recommended"
            })
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=400)

    return JsonResponse({"message": "Send analysis data via POST"}, status=405)