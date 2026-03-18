from apps.response.rl_logic.policy import ResponsePolicy

def main():
    print("Starting ACDAN RL Agent Training...")
    policy = ResponsePolicy(models_path="./data/models")
    
    # Train for 200 episodes
    history = policy.train(episodes=200, batch_size=32)
    
    # Save the model
    policy.save_policy()
    print("Training complete. 'rl_policy.pt' generated.")

if __name__ == "__main__":
    main()