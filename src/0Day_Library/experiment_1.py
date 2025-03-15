"""
Experiment 1: Basic Attack Graph Analysis

This script analyzes security games on attack graphs with both complete and limited
defender visibility. It generates log files with the analysis results.
"""

import os
import logging
import numpy as np
from datetime import datetime
from scipy.stats import poisson

# Import ctr library components
from attack_graph_MARA import create_mara_attack_graph
from attack_graph_MARA import mara_set_default_weight
from attack_graph_MARA import plot_main_graph

from create_subgraphs import generate_defender_subgraphs
from create_subgraphs import visualize_subgraphs

from ctr_core import main 
from ctr_core import core_set_default_weight
from ctr_core import core_set_debug_mode

# Toggle to control execution mode
# True = standard calculation, False = includes subgraph analysis
RUN_BASELINE_ONLY = True  

# Set default weight values for MARA and core modules
# we are setting it to 0 because of hardness = exp(-w) which gives us
# hardness = 1 (trivial edge) for w = 0 
DEFAULT_WEIGHT_VALUE = 0

mara_set_default_weight(DEFAULT_WEIGHT_VALUE)
core_set_default_weight(DEFAULT_WEIGHT_VALUE)


# Disable or enable debug mode
# Debug mode: shows some information about the edges in the graphs
# and additionally the payoff matrix
debug_mode = False
#set this in the ctr-core module as global variable
core_set_debug_mode(debug_mode)

# Set image mode to True to show plots of the graphs
image_mode = False

# Define experiment name as a variable for easy modification
experiment_name = "experiment_1"

######################## Set up logging configuration ########################
################################################################################
def setup_logging():
    # Set up main logger
    log_path = os.path.join(os.getcwd(), f'{experiment_name}.log')
    if os.path.exists(log_path):
        os.remove(log_path)
    
    logger = logging.getLogger()
    handler = logging.FileHandler(log_path, mode='w')
    handler.setFormatter(logging.Formatter('%(message)s'))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.info(f'[1] "{experiment_name}.log"')
    logger.info(f'[1] "{datetime.now().strftime("%a %b %d %H:%M:%S %Y")}"')
    
    # Set up subgraph logger if needed
    subgraph_handler = None
    if not RUN_BASELINE_ONLY:
        subgraph_log_path = os.path.join(os.getcwd(), f'sub_{experiment_name}.log')
        if os.path.exists(subgraph_log_path):
            os.remove(subgraph_log_path)
        subgraph_handler = logging.FileHandler(subgraph_log_path, mode='w')
        subgraph_handler.setFormatter(logging.Formatter('%(message)s'))
    
    return logger, handler, subgraph_handler


######## Define random steps function for attacker movement ###################
################################################################################
def random_steps(route, attack_rate=None, defense_rate=None, graph=None):
    """
    Calculate probability distribution for random steps using Poisson distribution.
    
    Args:
        route: Attack path
        attack_rate: Lambda parameter for Poisson distribution
        defense_rate: Not used in this implementation
        graph: Attack graph
        
    Returns:
        Array of probabilities for each position in the path
    """
    length = len(route)
    if attack_rate is None:
        attack_rate = 2
    # Get PMF for values 0 to length-1
    pmf = poisson.pmf(np.arange(length), attack_rate)
    # Normalize (though poisson.pmf should already sum to ~1)
    pmf = pmf / pmf.sum()
    return pmf


################################ run_experiment ################################
################################################################################

def run_experiment():
    """Run the core analysis with configured parameters."""
    # Create attack graph
    full_attack_graph, node_order = create_mara_attack_graph(DEFAULT_WEIGHT_VALUE)

    # Generate defender subgraphs
    defender_subgraphs_list = generate_defender_subgraphs(
        full_attack_graph, num_subgraphs=5, drop_percentage=0.2
    )

    if image_mode:
        plot_main_graph(full_attack_graph)
        visualize_subgraphs(defender_subgraphs_list, full_attack_graph)
    
    # Set attack and defense parameters
    attack_rate_list = [2]  
    defense_rate_list = [0]
    
    # Set up logging
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
    
    # If enabled, run subgraph analysis with subgraph logger
    if not RUN_BASELINE_ONLY:
        # Switch to subgraph logger
        for hdlr in logger.handlers[:]:
            logger.removeHandler(hdlr)
        logger.addHandler(subgraph_handler)
        logger.info(f'[1] "sub_{experiment_name}.log"')
        logger.info(f'[1] "{datetime.now().strftime("%a %b %d %H:%M:%S %Y")}"')
        
        print("Running subgraph analysis...")
        main(
            full_attack_graph=full_attack_graph,
            defender_subgraphs_list=defender_subgraphs_list,
            attack_rate_list=attack_rate_list,
            defense_rate_list=defense_rate_list,
            random_steps_fn=random_steps,
            run_baseline_only=False
        )
    
    return baseline_result

def display_results():
    """Display the results from the log file."""
    with open(experiment_name+'.log', 'r') as f:
        print(f.read())

if __name__ == "__main__":
    # Set up logging
    logger, main_handler, subgraph_handler = setup_logging()
    
    # Pass logger to subgraphs module if needed
    # This would require updating the subgraphs module to accept a logger
    
    # Run the experiment
    run_experiment()
    
    # Display results
    display_results()