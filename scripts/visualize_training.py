import json
import matplotlib.pyplot as plt
import numpy as np
from pathlib import Path

def plot_training_results(history_path="data/models/rl_training_history.json"):
    # Load data
    with open(history_path, 'r') as f:
        data = json.load(f)

    rewards = data['episode_rewards']
    losses = data['episode_losses']
    episodes = range(1, len(rewards) + 1)

    # Create Figure
    plt.style.use('seaborn-v0_8-darkgrid')
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(10, 8))

    # 1. Plot Rewards (The "Success" Metric)
    ax1.plot(episodes, rewards, color='#2ca02c', label='Total Reward')
    # Add a moving average to show the trend clearly
    window = 10
    if len(rewards) > window:
        avg_rewards = np.convolve(rewards, np.ones(window)/window, mode='valid')
        ax1.plot(range(window, len(rewards) + 1), avg_rewards, color='#d62728', linestyle='--', label='Trend (SMA 10)')
    
    ax1.set_title('RL Agent Reward Progress (Learning Efficiency)', fontsize=14)
    ax1.set_ylabel('Cumulative Reward')
    ax1.legend()

    # 2. Plot Losses (The "Error" Metric)
    ax2.plot(episodes, losses, color='#1f77b4', label='DQN Loss')
    ax2.set_title('Model Convergence (Loss Reduction)', fontsize=14)
    ax2.set_xlabel('Episode Number')
    ax2.set_ylabel('Loss Value')
    ax2.legend()

    plt.tight_layout()
    
    # Save the plot for the report
    output_path = "data/models/training_performance.png"
    plt.savefig(output_path)
    print(f"Graph saved successfully to: {output_path}")

if __name__ == "__main__":
    plot_training_results()