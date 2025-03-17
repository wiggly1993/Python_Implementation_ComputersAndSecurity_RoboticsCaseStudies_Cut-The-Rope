# CTR Python

A Python library for analyzing security games on attack graphs with both complete and limited defender visibility.

## Installation

```bash
# Install from PyPI
pip install ctr_python

# Or install from source
git clone https://github.com/wiggly1993/Python_Implementation_ComputersAndSecurity_RoboticsCaseStudies_Cut-The-Rope/tree/main/src/0Day_Library/ctr_python
cd ctr_python
pip install -e .
```

## Features

- Analyze existing attack graphs
- Create defender subgraphs with limited visibility
- Analyze security games with various attack/defense rates
- Model attacker movement using Poisson distribution
- Generate detailed analysis logs

## Usage

### Basic Analysis

Run the baseline analysis:

```bash
python -m ctr_python.experiments.experiment_1
```

### Advanced Options

```bash
# Run with custom attack and defense rates
python -m ctr_python.experiments.experiment_1 --attack_rates 1.5,2.0,2.5 --defense_rates 0,1,2

# Include 0-day exploit analysis
python -m ctr_python.experiments.experiment_1 --run_0day

# Customize subgraph generation (only with --run_0day)
python -m ctr_python.experiments.experiment_1 --run_0day --drop_percentage 0.3 --num_subgraphs 10

# Enable debug mode for additional information
python -m ctr_python.experiments.experiment_1 --debug

# Show graph visualizations
python -m ctr_python.experiments.experiment_1 --image_mode
```

## Output

Results are stored in log files in the `logs` directory:
- `experiment_1.log`: Baseline analysis
- `sub_experiment_1.log`: Subgraph analysis (when using `--run_0day`)
