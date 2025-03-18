# CTR Python

A Python library for analyzing security games on attack graphs with both complete and limited defender visibility.

## Installation

```bash
# Install directly from GitHub repository
# 1. create a new venv
# 2. run:
pip install git+https://github.com/wiggly1993/Python_Implementation_ComputersAndSecurity_RoboticsCaseStudies_Cut-The-Rope.git#subdirectory=src/0Day_Library

# Or clone and install from source
git clone https://github.com/wiggly1993/Python_Implementation_ComputersAndSecurity_RoboticsCaseStudies_Cut-The-Rope.git
cd Python_Implementation_ComputersAndSecurity_RoboticsCaseStudies_Cut-The-Rope/src/0Day_Library
pip install -e .
```

## Features

- Analyze existing attack graphs
- Create defender subgraphs with limited visibility
- Analyze security games with various attack/defense rates
- Model attacker movement using different probability distributions
- Generate detailed analysis logs
- Support for both simple and weighted attack graphs
- Visualize attack graphs and defender subgraphs

## Included Attack Graphs

The library includes two primary attack graph models:

### MARA Graph (Experiments 1 & 2)
- Simpler structure with 9 nodes
- Edges have uniform weights
- Used for basic attack path analysis

### MIR100 Graph (Experiments 3 & 4)
- More complex structure with 16 nodes
- Edges have different weights representing varying difficulty levels
- More realistic representation of network vulnerability

## Experiments

### Experiment 1: Basic MARA Graph Analysis
- Uses Poisson distribution for modeling attacker movement
- Default attack rate: 2, default defense rate: 0
- Focus on basic path analysis

```bash
# Run the baseline analysis
python -m ctr_python.experiments.experiment_1
```

### Experiment 2: MARA Graph with Geometric Distribution
- Uses geometric distribution for randomly moving defender
- Default attack rate: 3, default defense rate: 3
- Models defender checks that can interrupt attacker movement

```bash
# Run experiment 2
python -m ctr_python.experiments.experiment_2
```

### Experiment 3: Weighted MIR100 Graph Analysis
- Uses hardness-based approach for edge traversal
- Probability of traversal based on edge weights
- Each edge has a specific difficulty level (weight)

```bash
# Run experiment 3
python -m ctr_python.experiments.experiment_3
```

### Experiment 4: MIR100 Graph with Adaptive Attack Rate
- Calculates attack rate dynamically using geometric mean
- Considers defense rate when calculating movement probabilities
- More sophisticated model of attacker-defender interaction

```bash
# Run experiment 4
python -m ctr_python.experiments.experiment_4
```

## Advanced Options

```bash
# Run with custom attack and defense rates
python -m ctr_python.experiments.experiment_1 --attack_rates 1.5,2.0,2.5 --defense_rates 0,1,2

# Include 0-day exploit analysis (creates n limited subgraphs for the defender and runs analysis on them)
python -m ctr_python.experiments.experiment_1 --run_0day

# Customize subgraph generation (only with --run_0day)
python -m ctr_python.experiments.experiment_1 --run_0day --drop_percentage 0.3 --num_subgraphs 10

# Enable debug mode for additional information
python -m ctr_python.experiments.experiment_1 --debug

# Show graph visualizations for additional sanity checks
python -m ctr_python.experiments.experiment_1 --image_mode
```

These options work for all experiment modules (1-4). Simply replace the experiment number in the command.

## Movement Models

The library implements various movement models for attackers:

1. **Poisson Distribution** (Experiment 1): Models random steps with constant rate
2. **Geometric Distribution** (Experiment 2): Models defender interruptions
3. **Hardness-Based Movement** (Experiment 3): Movement probabilities based on edge weights
4. **Adaptive Geometric Model** (Experiment 4): Combines edge weights with dynamic attack rate

## Output

Results are stored in log files in the current directory:
- `experiment_[n].log`: Baseline analysis for experiment n
- `sub_experiment_[n].log`: Subgraph analysis (when using `--run_0day`)

## Use Cases

- Analyze network security with incomplete defender information
- Compare different movement models for attackers and defenders
- Evaluate the impact of edge weights on attacker success probability
- Determine optimal defense strategies under various scenarios