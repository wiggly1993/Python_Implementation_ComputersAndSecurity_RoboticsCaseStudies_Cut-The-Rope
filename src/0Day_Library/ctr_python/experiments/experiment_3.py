"""
Experiment 1: Basic Attack Graph Analysis

This script analyzes security games on attack graphs with both complete and limited
defender visibility. It generates log files with the analysis results.
"""

import os
import logging
import numpy as np
import pathlib
import argparse
from datetime import datetime
from scipy.stats import poisson

from ..graphs.attack_graph_MIR100 import create_mir100_attack_graph
from ..graphs.attack_graph_MIR100 import mir100_set_default_weight
from ..graphs.attack_graph_MIR100 import plot_main_graph

from ..core.create_subgraphs import generate_defender_subgraphs
from ..core.create_subgraphs import visualize_subgraphs

from ..core.ctr_core import main 
from ..core.ctr_core import core_set_default_weight
from ..core.ctr_core import core_set_debug_mode

# Default values - all defaults are defined here and used consistently throughout the code
DEFAULT_WEIGHT_VALUE = 0
RUN_BASELINE_ONLY = True  # Default is to run only baseline 
DEFAULT_DEBUG_MODE = False
DEFAULT_IMAGE_MODE = False
DEFAULT_ATTACK_RATES = [0]
DEFAULT_DEFENSE_RATES = [0]
DEFAULT_NUM_SUBGRAPHS = 100
DEFAULT_DROP_PERCENTAGE = 0.2

def parse_args():
    parser = argparse.ArgumentParser(description='Experiment 1: Attack Graph Analysis')
    
    # Boolean flags
    parser.add_argument('--run_0day', action='store_true', help='Run 0day attack analysis (includes subgraphs)')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    parser.add_argument('--image_mode', action='store_true', help='Enable image mode to show plots')
    
    # List flags
    parser.add_argument('--attack_rates', type=str, help='Comma-separated list of attack rates (e.g., "1,2,3")')
    parser.add_argument('--defense_rates', type=str, help='Comma-separated list of defense rates (e.g., "0,1,2")')
    
    # Integer and float flags
    parser.add_argument('--num_subgraphs', type=int, help='Number of subgraphs to create')
    parser.add_argument('--drop_percentage', type=float, help='Drop percentage for edge removal')
    
    return parser.parse_args()

# Parse command-line arguments
args = parse_args()

# Toggle to control execution mode - now with reversed logic as requested
# Default (True) = standard calculation only, 
# Flag present (False) = includes subgraph analysis
# I know this is sloppy but I can't be bothered :D
RUN_BASELINE_ONLY = not args.run_0day

# Set default weight values for MARA and core modules
mir100_set_default_weight(DEFAULT_WEIGHT_VALUE)
core_set_default_weight(DEFAULT_WEIGHT_VALUE)

# Use command-line args or defaults
debug_mode = args.debug if args.debug is not None else DEFAULT_DEBUG_MODE
core_set_debug_mode(debug_mode)

# Set image mode from args or default
image_mode = args.image_mode if args.image_mode is not None else DEFAULT_IMAGE_MODE

experiment_name = "experiment_3"

######################## Set up logging configuration ########################
################################################################################
def setup_logging():
    """Set up logging with files stored in a dedicated logs directory."""
    logs_dir = pathlib.Path.cwd()
    
    # Define log file paths
    main_log_path = logs_dir / f'{experiment_name}.log'
    subgraph_log_path = logs_dir / f'sub_{experiment_name}.log'
    
    # Remove existing log files if they exist
    if main_log_path.exists():
        main_log_path.unlink()
    
    # Set up main logger
    logger = logging.getLogger()
    handler = logging.FileHandler(main_log_path, mode='w')
    handler.setFormatter(logging.Formatter('%(message)s'))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.info(f'[1] "{main_log_path}"')
    logger.info(f'[1] "{datetime.now().strftime("%a %b %d %H:%M:%S %Y")}"')
    
    # Set up subgraph logger if needed
    subgraph_handler = None
    if not RUN_BASELINE_ONLY:
        if subgraph_log_path.exists():
            subgraph_log_path.unlink()
        subgraph_handler = logging.FileHandler(subgraph_log_path, mode='w')
        subgraph_handler.setFormatter(logging.Formatter('%(message)s'))
    
    return logger, handler, subgraph_handler


######## Define random steps function for attacker movement ###################
################################################################################

def random_steps(route, attack_rate=None, defense_rate=None, graph=None):
    """
    Calculates probabilities for attacker movement along route.
    Returns probability distribution over possible ending nodes.
    """

    # Part 1: Extract hardness values from all edges and append them
    # into one numpy array
    # Calculate hardness values for each edge 
    hardness = []
    for i in range(len(route) - 1):
        start_node = route[i]
        end_node = route[i + 1]
        
        # Initialize variables for max weight loop
        weights = []
        # Collect all weights for max
        for edge in graph[start_node][end_node].values():
            weights.append(edge.get('weight', DEFAULT_WEIGHT_VALUE))
        # Get maximum weight
        max_weight = max(weights) if weights else DEFAULT_WEIGHT_VALUE
        
        # Initialize variables for min weight loop
        min_weights = []
        # Collect all weights for min
        for edge in graph[start_node][end_node].values():
            min_weights.append(edge.get('weight', DEFAULT_WEIGHT_VALUE))
        # Get minimum weight
        min_weight = min(min_weights) if min_weights else DEFAULT_WEIGHT_VALUE
            
        # Convert weights to probabilities
        # We could take max_weight or min_weight here
        # hardness.append(np.exp(-max_weight))

        # Important: We use min_weight here because of the following reason:
        # Since the formula to calculate hardness in R is hardness = exp(-weight)
        # taking the minimum weight will give us the maximum hardness
        # which translates to the path being EASIEST to traverse.
        # Yes hardness of 1 means path is trivial, hardness 0 means path is impossible
        hardness.append(np.exp(-min_weight))

    
    
    hardness = np.array(hardness)

    # print(f'Hardness: {hardness}')

    
    ## Part 2: Based on the extracted hardness values
    ## Calculate Movement Probabilities

    # We calculate two things:
    # 1. Probability of reaching each node (accumulating hardness along the way)
    # Example: if hardness = [0.8, 0.6, 0.4]
    # Then cumprod gives us: [0.8, 0.8*0.6, 0.8*0.6*0.4]
    # Final cumulative_probs = [1.0, 0.8, 0.48, 0.192]
    cumulative_probs = np.concatenate(([1.0], np.cumprod(hardness)))

    # 2. Probability of stopping at each node (based on the next edge's hardness)
    stop_probs = np.concatenate((1 - hardness, [1.0]))

    ## Part 3: Generate Final Distribution
    # Combine reaching and stopping probabilities to get probability of stopping at each node
    # Example calculation with above values:
    # Node0: 1.0 * 0.2 = 0.2    (20% chance of stopping at start)
    # Node1: 0.8 * 0.4 = 0.32   (32% chance of stopping at Node1)
    # Node2: 0.48 * 0.6 = 0.288 (28.8% chance of stopping at Node2)
    # Node3: 0.192 * 1.0 = 0.192 (19.2% chance of reaching final node)
    pdf = cumulative_probs * stop_probs

    # Handle case where probabilities are essentially zero
    if pdf.sum() < 1e-15:
        pdf = np.full_like(pdf, 1e-7)

    # Normalize to ensure probabilities sum to 1
    # print(f"This is the final pdf that is returned in the end: {pdf / pdf.sum()}")
    return pdf / pdf.sum()


################################ run_experiment ################################
################################################################################

def run_experiment(logger=None, main_handler=None, subgraph_handler=None):
    """Run the core analysis with configured parameters."""
    # Create attack graph
    full_attack_graph, node_order = create_mir100_attack_graph(DEFAULT_WEIGHT_VALUE)

    # Parse subgraph parameters from command line or use defaults
    num_subgraphs = args.num_subgraphs if args.num_subgraphs is not None else DEFAULT_NUM_SUBGRAPHS
    drop_percentage = args.drop_percentage if args.drop_percentage is not None else DEFAULT_DROP_PERCENTAGE
    
    # Generate defender subgraphs
    defender_subgraphs_list = generate_defender_subgraphs(
        full_attack_graph, num_subgraphs=num_subgraphs, drop_percentage=drop_percentage
    )

    if image_mode:
        plot_main_graph(full_attack_graph)
        visualize_subgraphs(defender_subgraphs_list, full_attack_graph)
    
    # Parse attack and defense rates from command line or use defaults
    if args.attack_rates is not None:
        attack_rate_list = [float(rate) for rate in args.attack_rates.split(',')]
    else:
        attack_rate_list = DEFAULT_ATTACK_RATES
        
    if args.defense_rates is not None:
        defense_rate_list = [float(rate) for rate in args.defense_rates.split(',')]
    else:
        defense_rate_list = DEFAULT_DEFENSE_RATES
    
    # Use the logger passed in, don't create a new one
    if logger is None:
        logger, main_handler, subgraph_handler = setup_logging()
    
    # Always run baseline analysis with main logger
    print("Running baseline analysis...")
    baseline_result = main(
        full_attack_graph=full_attack_graph,
        defender_subgraphs_list=None,
        attack_rate_list=attack_rate_list,
        defense_rate_list=defense_rate_list,
        random_steps_fn=random_steps,
        run_baseline_only=True
    )
    
    if not RUN_BASELINE_ONLY:
        # Switch to subgraph logger
        for hdlr in logger.handlers[:]:
            logger.removeHandler(hdlr)
        logger.addHandler(subgraph_handler)
        logger.info(f'[1] "{pathlib.Path.cwd() / f"sub_{experiment_name}.log"}"')
        logger.info(f'[1] "{datetime.now().strftime("%a %b %d %H:%M:%S %Y")}"')
        
        print("Running subgraph analysis...")
        subgraph_result = main(
            full_attack_graph=full_attack_graph,
            defender_subgraphs_list=defender_subgraphs_list,
            attack_rate_list=attack_rate_list,
            defense_rate_list=defense_rate_list,
            random_steps_fn=random_steps,
            run_baseline_only=False  
        )
    return baseline_result


# In case I want to print out the results from the .log file in the terminal
def display_results():
    """Display the results from the log file."""
    logs_dir = pathlib.Path.cwd()
    main_log_path = logs_dir / f'{experiment_name}.log'
    
    with open(main_log_path, 'r') as f:
        print(f.read())
    
    # Optionally display subgraph log if it exists
    subgraph_log_path = logs_dir / f'sub_{experiment_name}.log'
    if subgraph_log_path.exists() and not RUN_BASELINE_ONLY:
        print("\n=== SUBGRAPH ANALYSIS RESULTS ===\n")
        with open(subgraph_log_path, 'r') as f:
            print(f.read())


if __name__ == "__main__":
    # Set up logging ONCE
    logger, main_handler, subgraph_handler = setup_logging()
    
    # Pass logger to run_experiment to avoid duplicate setup
    run_experiment(logger, main_handler, subgraph_handler)
    
    # Optional: Display results from the log file 
    # currently it is displayed anyway...
    # display_results()