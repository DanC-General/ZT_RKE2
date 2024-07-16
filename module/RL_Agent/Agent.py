import gymnasium as gym 
from enum import Enum
from collections import namedtuple,deque
from itertools import count
import numpy as np 
import random
import torch
import torch.nn as nn
import torch.optim as optim
import torch.nn.functional as F

env = gym.make("")

Transition = namedtuple('Transition,'
                        ('state','action','next_state','reward'))
class ReplayMemory(object): 
    def __init__(self,capacity):
        self.memory = deque([],maxlen=capacity)
    def push(self, *args):
        self.memory.append(Transition(*args))
    def __len__(self): 
        return len(self.memory)
    
class Action(Enum): 
    BENIGN = 0
    MALICIOUS = 1

class DQN(nn.module): 
    def __init__(self,input_dim,output_dim):
        super(DQN, self).__init__()
        self.fc1 = nn.Linear(input_dim,128)
        self.fc2 = nn.Linear(128,128)
        self.fc3 = nn.Linear(128,output_dim)
    
    def forward(self,x): 
        x = torch.relu(self.fc1(x)) 
        x = torch.relu(self.fc2(x))
        x = self.fc3(x)
        return x
    
class DQNAgent: 
    def __init__(self,state_dim,action_dim,lr,gamma,epsilon,epsilon_decay,buffer_size):
        self.state_dim = state_dim
        self.action_dim = action_dim
        self.lr = lr 
        self.gamma = gamma
        self.epsilon = epsilon
        self.epsilon_decay = epsilon_decay
        self.memory = deque(maxlen=buffer_size)
        self.model = DQN(state_dim,action_dim)
        self.optimiser = optim.Adam(self.model.parameters(),lr=lr)
    
    def act(self,state): 
        if np.random.rand() <= self.epsilon:
            return np.random.choice(self.action_dim)
        q_values = self.model(torch.tensor(state, dtype=torch.float32))
        return torch.argmax(q_values).item()

    def remember(self, state, action, reward, next_state, done): 
        self.memory.append((state,action,reward,next_state,done))

    def replay(self,batch_size): 
        if len(self.memory) < batch_size: 
            return 
        minibatch = random.sample(self.memory,batch_size)
        for state,action,reward,next_state,done in minibatch: 
            target = reward
            if not done:   
                target = reward + self.gamma * torch.max(self.model(torch.tensor(next_state,dtype=torch.float32))).item()
            target_f = self.model(torch.tensor(state,dtype=torch.float32)).numpy() 
            target_f[action] = target 
            self.optimiser.zero_grad()
            loss = nn.MSELoss()(torch.tenosr(target_f), self.model(torch.tensor(state,dtype=torch.float32)))
            loss.backward()
            self.optimiser.step()
        if self.epsilon > 0.01:
            self.epsilon *= self.epsilon_decay

state_dim = 18
action_dim = 2
agent = DQNAgent(state_dim, action_dim, lr=0.001,gamma=0.99,epsilon=1.0,epsilon_decay=0.995,buffer_size=1000)
batch_size = 32
num_episodes = 1000
total_rewards = list()
for episode in range(num_episodes): 
    state = env.reset()
    total_reward = 0
    done = False 
    while not done: 
        action = agent.act(state)
        next_state, reward, done, _ = env.step(action) 
        state = next_state
        total_reward += reward 
    total_rewards.append(total_reward)