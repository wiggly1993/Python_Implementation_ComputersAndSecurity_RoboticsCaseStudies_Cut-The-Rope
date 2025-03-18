"""
Core functionality for analyzing and solving security games on attack graphs.

This module provides the core algorithms for:
1. Processing attack graphs
2. Calculating payoff distributions
3. Solving security games using linear programming
"""

import networkx as nx
import numpy as np
from scipy.optimize import linprog
from scipy.stats import norm
from copy import deepcopy
import logging
import os
from datetime import datetime

# Configure logging
logger = logging.getLogger(__name__)
handler = logging.StreamHandler()
formatter = logging.Formatter('%(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)


DEFAULT_WEIGHT_VALUE = 0  # Default fallback value

def core_set_default_weight(value):
    """Set the default weight value for the entire module."""
    global DEFAULT_WEIGHT_VALUE
    DEFAULT_WEIGHT_VALUE = value
    #print(f"Default weight value set to: {DEFAULT_WEIGHT_VALUE}")

DEBUG_MODE = False  # Global debug flag

def core_set_debug_mode(enabled=False):
    """Toggle debug output on or off."""
    global DEBUG_MODE
    DEBUG_MODE = enabled



def find_and_add_entry_node(graph):
    """
    Add a virtual entry node to a graph connecting to all root nodes.
    
    Args:
        graph: NetworkX graph to process
        
    Returns:
        Tuple of (entry_node, modified_graph, original_roots)
    """
    # First identify the original root nodes
    original_roots = [n for n, deg in graph.in_degree() if deg == 0]
    
    if len(original_roots) > 1:
        # add virtual entry node
        entry = 0  # virtual entry node
        graph.add_node(entry)
        for r in original_roots:
            graph.add_edge(entry, r, weight=DEFAULT_WEIGHT_VALUE)
        return entry, graph, original_roots
    else:
        # Only one root, use it as entry
        entry = original_roots[0]
        return entry, graph, original_roots

def merge_targets_with_multi_edges(orig_graph):
    """
    Merges all target nodes into a single virtual target node.
    
    Preserves parallel edges and their weights from the original graph.
    
    Args:
        orig_graph: Original NetworkX graph
        
    Returns:
        Modified graph with merged target nodes
    """
    # Find target nodes (nodes with no outgoing edges)
    targets = [n for n, out_degree in orig_graph.out_degree() if out_degree == 0]
    
    # Return original graph if 0 or 1 target
    if len(targets) <= 1:
        return orig_graph

    # Create merged label for virtual target
    merged_label = "c(" + ",".join(str(t) for t in targets) + ")"

    # Create new MultiDiGraph
    newG = nx.MultiDiGraph()

    # Add all non-target nodes
    non_targets = [n for n in orig_graph.nodes() if n not in targets]
    for node in non_targets:
        newG.add_node(node)
        
    # Add the virtual target node
    newG.add_node(merged_label)
    
    # Track edges to target nodes
    pred_target_edges = {}

    # Collect all edges going to target nodes
    for u, v, data in orig_graph.edges(data=True):
        if v in targets:
            if u not in pred_target_edges:
                pred_target_edges[u] = []
            weight = data.get('weight', DEFAULT_WEIGHT_VALUE)
            pred_target_edges[u].append((weight, v))

    # Create edges to virtual target preserving parallel edges
    for u, edges in pred_target_edges.items():
        weight_counts = {}
        for weight, _ in edges:
            weight_counts[weight] = weight_counts.get(weight, 0) + 1

        for weight, count in weight_counts.items():
            for _ in range(count):
                newG.add_edge(u, merged_label, weight=weight)
    
    # Copy over all other edges
    for u, v, data in orig_graph.edges(data=True):
        if v not in targets and u not in targets:
            newG.add_edge(u, v, **data)

    return newG

def generate_game_elements(graph, entry_node, original_roots):
    """
    Set up all elements needed for security game after preprocessing the graph.
    
    Args:
        graph: Preprocessed attack graph
        entry_node: The virtual entry node
        original_roots: List of original root nodes
        
    Returns:
        Tuple containing:
        (routes, V, as1, as2, target_list, node_order, adv_list, theta, m)
    """
    # Find target node
    target_list = [n for n, d in graph.out_degree() if d == 0]
    if len(target_list) != 1:
        logger.warning(f"Expected exactly one target node after contraction. Found: {target_list}")
    
    # Get all possible attack routes
    raw_routes = list(nx.all_simple_paths(graph, entry_node, target_list[0]))

    # Remove duplicate paths
    consolidated_routes = []
    seen_paths = set()

    for path in raw_routes:
        path_key = tuple(path)
        if path_key not in seen_paths:
            seen_paths.add(path_key)
            consolidated_routes.append(list(path))

    routes = consolidated_routes

    # Get all unique nodes appearing in any route
    V = sorted(set(node for path in routes for node in path), key=str)

    # Get nodes in topological order
    topo_all = list(nx.topological_sort(graph))
    node_order = [n for n in topo_all if n in V]
    
    # Create list of defender check locations (excluding entry, target, roots)
    excluded = {entry_node} | set(target_list) | set(original_roots)
    as1 = [n for n in V if n not in excluded]

    # Set up attack paths
    as2 = routes

    # Create list of possible attacker locations (excluding entry and target)
    excluded_nodes = set([entry_node]) | set(target_list)
    adv_list = [n for n in V if n not in excluded_nodes]
    
    if len(adv_list) == 0:
        logger.warning("No adversary intermediate locations found. Check graph structure.")

    # Calculate initial probabilities for attacker locations
    theta = {loc: 1/len(adv_list) for loc in adv_list} if adv_list else {}
    
    # Count total number of attack paths
    m = len(routes)
    
    return routes, V, as1, as2, target_list, node_order, adv_list, theta, m

def lossDistribution(U):
    """
    Creates standardized format for probability distribution.
    
    Args:
        U: Array of normalized probabilities
        
    Returns:
        Dictionary with distribution attributes
    """
    return {
        'dpdf': U,  
        'support': np.arange(1, len(U) + 1),
        'cdf': np.cumsum(U),
        'tail': 1 - np.cumsum(U) + U,
        'range': [1, len(U)]
    }

def calculate_payoff_distribution(graph, as1, as2, V, adv_list, theta, random_steps_fn, 
                                 attack_rate, defense_rate, node_order):
    """
    Calculate probability distributions for each check location & attack path pair.
    
    Args:
        graph: Attack graph
        as1: List of defender check locations
        as2: List of attack paths
        V: List of all nodes in any path
        adv_list: List of possible attacker positions
        theta: Dictionary of starting position probabilities
        random_steps_fn: Function to calculate random walk probabilities
        attack_rate: Attacker movement rate parameter
        defense_rate: Defender check rate parameter
        node_order: Topological ordering of nodes
        
    Returns:
        List of probability distributions for each check+path pair
    """
    payoffs = []

    for check in as1:
        for path in as2:
            U = np.zeros(len(V))

            for avatar in adv_list:
                L = np.zeros(len(V))

                if avatar in path:
                    # Extract relevant portion of path from avatar position
                    start_idx = path.index(avatar)
                    route = path[start_idx:]
                    
                    # Get raw movement probabilities
                    pdf_d = random_steps_fn(route, attack_rate, defense_rate, graph)

                    # Adjust based on defender's check point
                    if check in route:
                        check_idx = route.index(check)
                        # Add 1 to include the check point
                        cutPoint = check_idx + 1
                    else:
                        cutPoint = len(route)

                    # Take probabilities up to check point and renormalize
                    pdf_subset = pdf_d[:cutPoint]
                    if np.sum(pdf_subset) < 1e-15:
                        payoffDistr = np.zeros(cutPoint)
                        payoffDistr[-1] = 1.0
                    else:
                        payoffDistr = pdf_subset / np.sum(pdf_subset)
                    
                    # Map probabilities to node indices in V
                    route_subset = route[:cutPoint]
                    for idx_node, node in enumerate(route_subset):
                        L[V.index(node)] = payoffDistr[idx_node]

                else:
                    # If avatar not on path, it stays at current position
                    L[V.index(avatar)] = 1.0

                # Weight by probability of starting at this position
                U += theta[avatar] * L

            # Normalize and handle edge cases
            U_sum = np.sum(U)
            if U_sum < 1e-15:
                U = np.full_like(U, 1e-7)
            else:
                # normalize and prevent 0 probabilities
                U = U/U_sum
                U = np.where(U < 1e-7, 1e-7, U)
            
            # Reorder according to topological sort
            node_positions = [V.index(n) for n in node_order]
            U = U[node_positions]

            # Create final distribution
            ld = lossDistribution(U)
            payoffs.append(ld)

    return payoffs

def solve_game(payoffs, as1, as2):
    """
    Solve zero-sum security game using linear programming.
    
    Args:
        payoffs: List of payoff distributions
        as1: List of defender check locations
        as2: List of attack paths
        
    Returns:
        Dictionary containing equilibrium strategies and values
    """
    n = len(as1)
    m = len(as2)
    
    # Create payoff matrix
    payoff_matrix = np.zeros((n, m))
    for i in range(n):
        for j in range(m):
            idx = i*m + j
            ld = payoffs[idx]
            payoff_matrix[i, j] = ld['dpdf'][-1]

    # Log payoff matrix
    if DEBUG_MODE:
        logger.info("\n=== Final Payoff Matrix ===")
        logger.info(f"Matrix dimensions: {n} x {m}\n")
        logger.info("Payoff Matrix (probability of reaching target):")
        for i in range(n):
            row_str = f"Row {i+1:2d}:"
            for j in range(m):
                row_str += f" {payoff_matrix[i,j]:8.6f}"
            logger.info(row_str)
    
    ### Defender's optimization
    c = np.zeros(n+1)
    c[0] = 1.0
    
    A_ub = np.zeros((m, n+1))
    b_ub = np.zeros(m)
    for j in range(m):
        A_ub[j,0] = -1.0
        for i in range(n):
            A_ub[j,i+1] = payoff_matrix[i,j]
            
    A_eq = np.zeros((1, n+1))
    A_eq[0,1:] = 1.0
    b_eq = np.array([1.0])
    
    bounds = [(0,None)]*(n+1)
    
    v_defender = None
    v_attacker = None
    
    # Solve LP for defender
    res = linprog(c, A_ub=A_ub, b_ub=b_ub, A_eq=A_eq, b_eq=b_eq, bounds=bounds)
    
    if res.success:
        v_defender = res.x[0]
        x_def = res.x[1:]
        
        ### Attacker's optimization
        c_att = np.zeros(m+1)
        c_att[0] = -1.0
        
        A_ub_att = np.zeros((n, m+1))
        b_ub_att = np.zeros(n)
        for i in range(n):
            A_ub_att[i,0] = 1.0
            for j in range(m):
                A_ub_att[i,j+1] = -payoff_matrix[i,j]
                
        A_eq_att = np.zeros((1, m+1))
        A_eq_att[0,1:] = 1.0
        b_eq_att = np.array([1.0])
        
        bounds_att = [(0,None)]*(m+1)

        # Solve LP for attacker
        res_att = linprog(c_att, A_ub=A_ub_att, b_ub=b_ub_att, 
                         A_eq=A_eq_att, b_eq=b_eq_att, bounds=bounds_att)
        
        if res_att.success:
            y_att = res_att.x[1:]
            v_attacker = res_att.x[0]
            
            # Check if values match
            if abs(v_defender - v_attacker) > 1e-5:
                logger.warning("\nWarning: Defender and attacker values don't match!")
                logger.warning(f"Defender value: {v_defender:.6f}")
                logger.warning(f"Attacker value: {v_attacker:.6f}")
            
            return {
                'optimal_defense': dict(zip(as1, x_def)),
                'attacker_strategy': y_att,
                'defender_success': v_defender,
                'attacker_success': v_attacker
            }
    
    logger.warning("LP optimization failed")
    return None

def print_debug_info(graph, stage=""):
    """
    Print debug information about a graph.
    
    Args:
        graph: NetworkX graph to examine
        stage: Label for this debug stage
    """

    if not DEBUG_MODE: 
        return

    logger.info(f"\n{stage}:")
    logger.info(f"Nodes: {list(graph.nodes())}")
    logger.info("Total list of Edges with their weights:")
    if isinstance(graph, nx.MultiDiGraph):
        # For MultiDiGraph, handle multiple edges between same nodes
        for u, v, key, data in graph.edges(data=True, keys=True):
            weight = data.get('weight', DEFAULT_WEIGHT_VALUE)
            logger.info(f"{u} -> {v} (key={key}) : {weight}")
    else:
        # For regular DiGraph
        for u, v, data in graph.edges(data=True):
            weight = data.get('weight', DEFAULT_WEIGHT_VALUE)
            logger.info(f"{u} -> {v} : {weight}")



def run_game(attacker_graph, defender_graph=None, attack_rate_list=None, dropped=None, 
             defense_rate_list=None, random_steps_fn=None):
    """
    Run security game analysis on attack graphs.
    
    Args:
        attacker_graph: Graph from attacker's perspective
        defender_graph: Graph from defender's perspective (default: same as attacker)
        attack_rate_list: List of attacker movement rates to analyze
        dropped: List of nodes dropped from defender's view
        defense_rate_list: List of defender check rates to analyze
        random_steps_fn: Function to calculate random walk probabilities
        
    Returns:
        Final equilibrium results
    """
    # For backward compatibility and initial testing
    if defender_graph is None:
        defender_graph = attacker_graph
    
    final_eq = None

    # Process attacker graph
    print_debug_info(attacker_graph, "This is the Attacker Graph")
    atk_virtual_entry_node, attacker_graph, atk_original_roots = find_and_add_entry_node(attacker_graph)
    attacker_graph = merge_targets_with_multi_edges(attacker_graph) 
    print_debug_info(attacker_graph, "After merging targets of attack graph")

    # Calculate attacker elements
    _, V, _, as2, target_list, node_order, adv_list, theta, m = generate_game_elements(
        attacker_graph, atk_virtual_entry_node, atk_original_roots)

    # Process defender graph
    print_debug_info(defender_graph, "This is the Defender Graph")
    def_virtual_entry_node, defender_graph, def_original_roots = find_and_add_entry_node(defender_graph)
    defender_graph = merge_targets_with_multi_edges(defender_graph) 
    print_debug_info(defender_graph, "After merging targets of the Defender Graph")

    # Calculate defender elements
    _, _, as1, _, _, _, _, _, _ = generate_game_elements(defender_graph, def_virtual_entry_node, def_original_roots)

    # Debug information
    if dropped:
        logger.info(f"\nDropped nodes are: {dropped}")
    # debug_paths(as1, as2)
    
    # Set default rate lists if not provided
    if not defense_rate_list:
        defense_rate_list = [0]
    if not attack_rate_list:
        attack_rate_list = [0]
    
    # Run analysis for each combination of rates
    for defenseRate in defense_rate_list:
        for attackRate in attack_rate_list:
            logger.info("\n++++++++++++++++++++++++++++++++")
            logger.info(f"\nThe virtual target nodeID is {target_list[0]}\n")
            logger.info(f"attack rate =  {attackRate} , defense rate =  {defenseRate} \n")
            logger.info("\tequilibrium for multiobjective security game (MOSG)\n")
            
            # Calculate payoffs
            payoffs = calculate_payoff_distribution(
                attacker_graph, as1, as2, V, adv_list, theta, 
                random_steps_fn,
                attackRate, defenseRate, node_order
            )
            
            # Solve the game
            eq = solve_game(payoffs, as1, as2)
            if eq is not None:
                final_eq = eq  
                logger.info("optimal defense strategy:")
                logger.info("         prob.")
                for node, prob in sorted(eq['optimal_defense'].items(), key=lambda x: str(x[0])):
                    logger.info(f"{node} {prob:.6e}")
                
                logger.info("\nworst case attack strategies per goal:")
                logger.info("          1")
                if 'attacker_strategy' in eq:
                    for idx, prob in enumerate(eq['attacker_strategy'], 1):
                        logger.info(f"{idx} {prob:.7f}")
                logger.info(f"[1] {eq['attacker_success']:.3f}")
                
                logger.info(f"\nDefender can keep attacker success below: {eq['defender_success']:.3f}")
                logger.info(f"Attacker can guarantee success probability of: {eq['attacker_success']:.3f}")

    return final_eq

def main(full_attack_graph, defender_subgraphs_list=None, attack_rate_list=None, 
         defense_rate_list=None, random_steps_fn=None, run_baseline_only=False):
    """
    Main entry point for running security game analysis.
    
    Args:
        full_attack_graph: Complete attack graph
        defender_subgraphs_list: List of (subgraph, dropped_nodes) tuples
        attack_rate_list: List of attacker movement rates to analyze
        defense_rate_list: List of defender check rates to analyze
        random_steps_fn: Function to calculate random walk probabilities
        run_baseline_only: Whether to only run baseline analysis
        
    Returns:
        Baseline results and optional subgraph analysis results
    """
    # First run with full graph
    logger.info("\n\n")
    logger.info("="*80)
    logger.info("BASELINE RUN: BOTH ATTACKER AND DEFENDER HAVE FULL GRAPH KNOWLEDGE")
    logger.info("="*80)
    logger.info("\n")
    
    # Run the baseline
    logger.info("Starting baseline graph calculation")
    baseline_result = run_game(
        attacker_graph=full_attack_graph, 
        defender_graph=full_attack_graph, 
        attack_rate_list=attack_rate_list, 
        defense_rate_list=defense_rate_list, 
        random_steps_fn=random_steps_fn
    )
    
    # If not running baseline only and we have subgraphs, run subgraph analysis
    if not run_baseline_only and defender_subgraphs_list:
        logger.info("\n")
        logger.info("="*80)
        logger.info(f"STARTING SUBGRAPH ANALYSIS WITH {len(defender_subgraphs_list)} DEFENDER SUBGRAPHS")
        logger.info("="*80)
        logger.info("\n")
        
        # List to store attacker success values
        attacker_success_values = []
        
        # Run the subgraph analysis
        for i, (defender_subgraph, dropped_nodes) in enumerate(defender_subgraphs_list):
            logger.info("\n")
            logger.info("-"*60)
            logger.info(f"SUBGRAPH RUN #{i+1}: DEFENDER HAS LIMITED NETWORK VISIBILITY")
            logger.info(f"Nodes {', '.join(map(str, dropped_nodes))} were dropped from this graph")
            logger.info("-"*60)
            logger.info("\n")
            
            # Prepare the graph
            defender_subgraph_current = deepcopy(defender_subgraph)
            
            result = run_game(
                attacker_graph=full_attack_graph, 
                defender_graph=defender_subgraph_current, 
                dropped=dropped_nodes,
                attack_rate_list=attack_rate_list, 
                defense_rate_list=defense_rate_list, 
                random_steps_fn=random_steps_fn
            )
            
            # Store attacker success value if available
            if result and 'attacker_success' in result:
                attacker_success_values.append(result['attacker_success'])
        
        # Calculate and log the average
        if attacker_success_values:
            avg_attacker_success = sum(attacker_success_values) / len(attacker_success_values)
            
            logger.info("\n\n")
            logger.info("="*80)
            logger.info("SUBGRAPH ANALYSIS SUMMARY")
            logger.info("="*80)
            logger.info(f"Number of subgraphs analyzed: {len(attacker_success_values)}")
            logger.info(f"Baseline attacker success: {baseline_result['attacker_success']:.3f}")
            logger.info(f"Average attacker success across subgraphs: {avg_attacker_success:.3f}")
            logger.info(f"Difference from baseline: {'+' if avg_attacker_success - baseline_result['attacker_success'] > 0 else ''}{avg_attacker_success - baseline_result['attacker_success']:.3f}")
            logger.info("="*80)
            
            return baseline_result, attacker_success_values, avg_attacker_success
    
    return baseline_result


if __name__ == "__main__":
    pass


# if __name__ == "__main__":
#     # Import necessary modules
#     from attack_graph_MARA import create_mara_attack_graph
#     from create_subgraphs import generate_defender_subgraphs
#     from scipy.stats import poisson
#     import numpy as np
    
#     # Define random_steps function
#     def random_steps(route, attack_rate=None, defense_rate=None, graph=None):
#         length = len(route)
#         if attack_rate is None:
#             attack_rate = 2
#         # Get PMF for values 0 to length-1
#         pmf = poisson.pmf(np.arange(length), attack_rate)
#         # Normalize (though poisson.pmf should already sum to ~1)
#         pmf = pmf / pmf.sum()
#         return pmf
    
#     # Set up parameters
#     attack_rate_list = [2]  
#     defense_rate_list = [0]
    
#     # Create attack graph
#     full_attack_graph, node_order = create_mara_attack_graph()
#     print(f"Created attack graph with {len(full_attack_graph.nodes())} nodes")
    
#     # Generate subgraphs
#     defender_subgraphs_list = generate_defender_subgraphs(full_attack_graph, num_subgraphs=2, drop_percentage=0.2)
#     print(f"Generated {len(defender_subgraphs_list)} defender subgraphs")
    
#     # Run main analysis
#     results = main(
#         full_attack_graph=full_attack_graph,
#         defender_subgraphs_list=defender_subgraphs_list,
#         attack_rate_list=attack_rate_list,
#         defense_rate_list=defense_rate_list,
#         random_steps_fn=random_steps,
#         run_baseline_only=False
#     )
    
#     print("Analysis complete!")