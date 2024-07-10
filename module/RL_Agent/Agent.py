import gymnasium as gym 
import math
from collections import namedtuple,deque
from itertools import count

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