"""
Functions for creating and manipulating network attack subgraphs.

This module provides functionality to create defender subgraphs by randomly
removing nodes from a complete attack graph, simulating limited visibility
for defenders.
"""

import random
import networkx as nx
from copy import deepcopy
import matplotlib.pyplot as plt

def clean_subgraph(sub_graph, original_graph):
    """
    Removes nodes that have no path to any legitimate target node.
    
    Args:
        graph: The subgraph with randomly dropped nodes
        original_graph: The original complete graph
    """
    # Create a working copy
    cleaned_graph = sub_graph.copy()
    
    # STEP 1: Identify LEGITIMATE target nodes from ORIGINAL graph
    original_targets = [n for n, d in original_graph.out_degree() if d == 0]
    #print(f"Original legitimate targets: {original_targets}")
    
    # STEP 2: Find which of these legitimate targets are still in our subgraph
    existing_targets = [t for t in original_targets if t in cleaned_graph]
    #print(f"Remaining legitimate targets in subgraph: {existing_targets}")
    
    if not existing_targets:
        print("Warning: No legitimate targets remain in subgraph!")
        return cleaned_graph
    
    # STEP 3: Find nodes that can reach any of the legitimate targets
    reachable_nodes = set()
    
    for node in cleaned_graph.nodes():
        # If node is a target, it's reachable
        if node in existing_targets:
            reachable_nodes.add(node)
            continue
            
        # Check if node can reach any legitimate target
        for target in existing_targets:
            try:
                if nx.has_path(cleaned_graph, node, target):
                    reachable_nodes.add(node)
                    break
            except nx.NetworkXNoPath:
                continue
    
    # STEP 4: Remove unreachable nodes
    nodes_to_remove = set(cleaned_graph.nodes()) - reachable_nodes
    #print(f"Removing {len(nodes_to_remove)} unreachable nodes: {nodes_to_remove}")
    
    for node in nodes_to_remove:
        cleaned_graph.remove_node(node)
    
    return cleaned_graph



def create_defender_subgraph(graph, drop_percentage=0.2):
    """
    Creates a subgraph for the defender by removing a percentage of non-target nodes.
    
    Assumptions:
    - Target nodes CANNOT be dropped (defender is aware of all critical assets)
    - Entry nodes CAN be dropped (defender might not know all entry points)
    - Intermediate nodes CAN be dropped
    
    Args:
        graph: NetworkX graph
        drop_percentage: Percentage of non-target nodes to drop (default: 0.2)
        
    Returns:
        Tuple of (NetworkX subgraph, list of dropped nodes)
    """
    
    # Make a deep copy to avoid modifying the original
    sub_graph = deepcopy(graph)

    #print(f"++++++++++++++++++++++++++++++++++++++++")
    #print(f"Start dropping & cleanup for the next subgraph here")
    # Identify target nodes (nodes with no outgoing edges)
    target_nodes = []
    for n, d in sub_graph.out_degree():
        if d == 0:
            target_nodes.append(n)
    
    #print(f"Identified {len(target_nodes)} target nodes: {target_nodes}")
    
    # Create list of non-target nodes that can be dropped
    droppable_nodes = []
    for n in sub_graph.nodes():
        if n not in target_nodes:
            droppable_nodes.append(n)
    
    # Calculate how many nodes to drop
    num_to_drop = max(1, int(len(droppable_nodes) * drop_percentage))
    
    # Randomly select nodes to drop
    dropped_nodes = random.sample(droppable_nodes, num_to_drop)
    #print(f"Dropping {len(dropped_nodes)} nodes: {dropped_nodes}")
    
    # Remove selected nodes
    sub_graph.remove_nodes_from(dropped_nodes)
    
    #print(f"Original graph had {len(graph.nodes())} nodes, subgraph has {len(sub_graph.nodes())} nodes")

    # Now let's clean the subgraph from any dead branches
    sub_graph = clean_subgraph(sub_graph, graph)
    
    # Return both the subgraph and the list of dropped nodes
    return (sub_graph, dropped_nodes)



def generate_defender_subgraphs(attack_graph, num_subgraphs=100, drop_percentage=0.2):
    """
    Generate multiple defender subgraphs from a full attack graph.
    
    Args:
        attack_graph: Original full attack graph
        num_subgraphs: Number of subgraphs to generate (default: 100)
        drop_percentage: Percentage of nodes to drop in each subgraph (default: 0.2)
        
    Returns:
        List of (subgraph, dropped_nodes) tuples
    """
    # Create a deep copy of the attack graph to work with
    full_graph = deepcopy(attack_graph)
    
    # Generate the requested number of subgraphs
    return [create_defender_subgraph(full_graph, drop_percentage) 
            for _ in range(num_subgraphs)]


def visualize_subgraphs(subgraph_list, original_graph=None):
    """
    Visualizes the last 3 defender's subgraphs side by side.
    """

    # Take only the last 3 graphs
    graphs_to_show = subgraph_list[-3:] if len(subgraph_list) >= 3 else subgraph_list
    num_graphs = len(graphs_to_show)
    
    # Create subplot figure
    fig, axes = plt.subplots(1, num_graphs, figsize=(6*num_graphs, 6))
    
    # Handle case when only one graph (axes not array)
    if num_graphs == 1:
        axes = [axes]
    
    # Identify original target nodes from the original graph
    orig_graph = original_graph if original_graph else subgraph_list[0][0]
    original_target_nodes = [n for n, d in orig_graph.out_degree() if d == 0]
    
    for i, (subgraph, dropped_nodes) in enumerate(graphs_to_show):
        # Calculate cleaned up nodes (nodes that were removed during the clean_subgraph process)
        # These are nodes that were in the subgraph after dropping but removed during cleaning
        # We need to infer this from the original graph and the current subgraph
        
        # First get all nodes from original graph
        all_original_nodes = set(orig_graph.nodes())
        # Then get the dropped nodes (from the function output)
        dropped_node_set = set(dropped_nodes)
        # Get current subgraph nodes
        current_nodes = set(subgraph.nodes())
        
        # Cleaned up nodes = nodes that should be in subgraph after dropping but aren't
        # i.e., (all original nodes - dropped nodes) - current nodes
        expected_nodes = all_original_nodes - dropped_node_set
        cleaned_up_nodes = expected_nodes - current_nodes
        
        # Identify entry nodes in subgraph (excluding original target nodes)
        entry_nodes = [n for n, d in subgraph.in_degree() if d == 0 and n not in original_target_nodes]
        
        # Use spring layout
        pos = nx.spring_layout(subgraph, k=1, iterations=50, seed=42)
        
        # Draw edges with arrows
        nx.draw_networkx_edges(subgraph, pos, 
                              edge_color='gray',
                              arrows=True,
                              arrowsize=15,
                              width=1.5,
                              ax=axes[i])
        
        # Create color map for nodes - targets are ALWAYS red regardless of connectivity
        node_colors = []
        for node in subgraph.nodes():
            if node in original_target_nodes:
                node_colors.append('lightcoral')  # Target nodes always red
            elif node in entry_nodes:
                node_colors.append('lightgreen')  # Entry nodes (non-targets) green
            else:
                node_colors.append('lightblue')   # Regular nodes blue
        
        # Draw nodes
        nx.draw_networkx_nodes(subgraph, pos,
                              node_color=node_colors,
                              node_size=500,
                              edgecolors='darkblue',
                              linewidths=1.5,
                              ax=axes[i])
        
        # Create and draw labels
        labels = {node: str(node) for node in subgraph.nodes()}
        nx.draw_networkx_labels(subgraph, pos,
                               labels,
                               font_size=10,
                               font_weight='bold',
                               ax=axes[i])
        
        # Update title to include information about dropped nodes and cleaned up nodes
        axes[i].set_title(f"Defender's Subgraph {i+1}\nDropped: {dropped_nodes}\nCleaned up: {sorted(list(cleaned_up_nodes))}", 
                          fontsize=12, fontweight='bold')
        axes[i].axis('off')
    
    plt.tight_layout()
    plt.show()