# pip install -U scikit-fuzzy matplotlib
# https://oleg-dubetcky.medium.com/mastering-fuzzy-logic-in-python-c90463bf1135
import numpy as np
import skfuzzy as fuzz
from skfuzzy import control as ctrl

# Step 1: Define the fuzzy sets for input variables (cost and benefit)
likelihood = ctrl.Antecedent(np.arange(1, 4, 1), 'likelihood')
# Past indication that subject is malicious 
sub_malig = ctrl.Antecedent(np.arange(0.1, 1.1, 0.1), 'sub_malig')
# Chance that current abnormal call is also malicious
sysc_malig = ctrl.Antecedent(np.arange(0.1, 1.1, 0.1), 'sub_malig')

# Membership functions for cost and benefit


likelihood['unlikely'] = fuzz.trimf(likelihood.universe, [0, 0.2, 0.4])
likelihood['plausible'] = fuzz.trimf(likelihood.universe, [0.3, 0.5, 0.7])
likelihood['likely'] = fuzz.trimf(likelihood.universe, [0.6, 0.8, 1])

sub_malig['low'] = fuzz.trimf(sub_malig.universe, [0, 0.2, 0.4])
sub_malig['moderate'] = fuzz.trimf(sub_malig.universe, [0.3, 0.5, 0.7])
sub_malig['high'] = fuzz.trimf(sub_malig.universe, [0.6, 0.8, 1])

sysc_malig['unique'] = fuzz.trimf(sysc_malig.universe, [0, 0.2, 0.4])
sysc_malig['common'] = fuzz.trimf(sysc_malig.universe, [0.3, 0.5, 0.7])
sysc_malig['ubiquitous'] = fuzz.trimf(sysc_malig.universe, [0.6, 0.8, 1])

# TODO change numberical values below 
# Step 2: Define the fuzzy sets for output variable (cost benefit)
subj_trust = ctrl.Consequent(np.arange(0, 11, 1), 'subject_trust')

# Membership functions for subject_trust
subj_trust['low'] = fuzz.trimf(subj_trust.universe, [0, 0, 5])
subj_trust['medium'] = fuzz.trimf(subj_trust.universe, [3, 5, 7])
subj_trust['high'] = fuzz.trimf(subj_trust.universe, [5, 10, 10])

#### MAPPINGS OF FUZZY VARIABLES TO SUBJECT TRUSTS
[[['unlikely|low|unique', 'unlikely|low|common', 'unlikely|low|ubiquitous'],
 ['unlikely|moderate|unique', 'unlikely|moderate|common', 'unlikely|moderate|ubiquitous'],
 ['unlikely|high|unique', 'unlikely|high|common', 'unlikely|high|ubiquitous']],

 [['plausible|low|unique', 'plausible|low|common', 'plausible|low|ubiquitous'],
 ['plausible|moderate|unique', 'plausible|moderate|common', 'plausible|moderate|ubiquitous'],
 ['plausible|high|unique', 'plausible|high|common', 'plausible|high|ubiquitous']],

 [['likely|low|unique', 'likely|low|common', 'likely|low|ubiquitous'],
 ['likely|moderate|unique', 'likely|moderate|common', 'likely|moderate|ubiquitous'],
 ['likely|high|unique', 'likely|high|common', 'likely|high|ubiquitous']]]
#### CORRESPONDING SUBJECT TRUST - low trust is bad, high is good
# all unique syscalls must be assumed to be malicious, so assigned low trust is subject is responsible
trust_list = [[['medium', 'high', 'high'],
 ['medium', 'high', 'high'],
 ['medium', 'medium', 'high']],
 
 [['medium', 'high', 'high'],
 ['medium', 'medium', 'high'],
 ['low', 'medium', 'medium']],
 # Chance they are responsible; proportion of abnormal syscalls ; frequency of executed syscall in other subjects
 [['low', 'medium', 'high'],
 ['low', 'medium', 'medium'],
 ['low', 'low', 'low']]]

# Make rules table
# # Step 3: Define the fuzzy rules from the above table 
rules_list = [[['' for k in range(3)] for j in range(3)] for i in range(3)]
rules = list()
for li,l in enumerate(['unlikely', 'plausible', 'likely']):
    for si,sub in enumerate(['low', 'moderate','high']):
        for syi,sysc in enumerate(['unique','common','ubiquitous']):
            rules_list[li][si][syi] = l + "|" + sub + "|" +sysc + "->" + trust_list[li][si][syi]
            rules.append(ctrl.Rule(likelihood[l] & sub_malig[sub]& sysc_malig[sysc], subj_trust[trust_list[li][si][syi]]))
# print(rules_list)
print(rules)


# # Step 4: Implement the fuzzy inference system

subj_trust_ctrl = ctrl.ControlSystem(rules) 
subj_trust_sim = ctrl.ControlSystemSimulation(subj_trust_ctrl)

# # Step 5: Test the fuzzy logic system with sample inputs
# cost_benefit_sim.input['cost'] = 3  # low cost
# cost_benefit_sim.input['benefit'] = 8  # high benefit
def simulate(likelihood,sub_malig,sysc_malig):
    subj_trust_sim.input('likelihood') = likelihood
    subj_trust_sim.input('sub_malig') = sub_malig
    subj_trust_sim.input('sysc_malig') = sysc_malig
    subj_trust_sim.compute()

# print("Cost Benefit: ", cost_benefit_sim.output['cost_benefit'])