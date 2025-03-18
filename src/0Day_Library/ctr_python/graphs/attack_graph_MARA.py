"""
This module provides the MARA attack graph for security analysis.
"""

import networkx as nx  # type: ignore
import matplotlib.pyplot as plt  # type: ignore
import numpy as np  # type: ignore

DEFAULT_WEIGHT_VALUE = 0  # Default fallback value

def mara_set_default_weight(value):
    """Set the default weight value for the entire module."""
    global DEFAULT_WEIGHT_VALUE
    DEFAULT_WEIGHT_VALUE = value
    #print(f"Default weight value in MARA is set to: {DEFAULT_WEIGHT_VALUE}")


def create_mara_attack_graph(DEFAULT_WEIGHT_VALUE=DEFAULT_WEIGHT_VALUE):
    """
    Create a directed graph based on the MARA structure.
    
    Returns:
        Tuple containing:
            - nx.DiGraph: The created attack graph
            - List[int]: Nodes in topological order
    """
    # Create a directed graph
    graph = nx.DiGraph()
    
    # Define edges exactly as they were in the R implementation
    edges = [
        (1, 2),                  # 1 -> 2
        (2, 3), (2, 4), (2, 5),  # 2 -> 3,4,5 
        (3, 6), (4, 6),          # 3,4 -> 6
        (5, 7), (7, 8), (8, 9)   # 5 -> 7 -> 8 -> 9
    ]
    graph.add_edges_from(edges)
    
    # Set default weight value for all edges
    nx.set_edge_attributes(graph, DEFAULT_WEIGHT_VALUE, 'weight')
    
    # Compute topological order of nodes
    node_order = list(nx.topological_sort(graph))
    
    return graph, node_order


# # Create the graph and node order (for backward compatibility)
# attack_graph, node_order = create_mara_attack_graph()
# print("Successfully created MARA attack graph.")



def plot_main_graph(attack_graph):
    # Use hierarchical layout with adjusted parameters
    pos = nx.spring_layout(attack_graph, k=1, iterations=50, seed=42)

    # Manual adjustment to separate nodes 3 and 4
    pos[3] = pos[3] + np.array([0.1, 0.1])  # Move node 3 up and right
    pos[4] = pos[4] + np.array([-0.1, -0.1])  # Move node 4 down and left

    plt.figure(figsize=(10, 6))

    # Draw edges with arrows
    nx.draw_networkx_edges(attack_graph, pos, 
                        edge_color='gray',
                        arrows=True,
                        arrowsize=20,
                        width=2)

    # Create color map for nodes
    node_colors = ['lightblue'] * len(attack_graph)  # Default color
    node_colors[0] = 'lightgreen'  # Node 1
    node_colors[5] = 'lightcoral'  # Node 6 
    node_colors[8] = 'lightcoral'  # Node 9
    node_colors[4] = 'lightblue'      # Node 5

    # Draw nodes
    nx.draw_networkx_nodes(attack_graph, pos,
                        node_color=node_colors,
                        node_size=700,
                        edgecolors='darkblue',
                        linewidths=2)

    # Create two separate label dictionaries - using actual node numbers
    #white_labels = {5: '5'}  # Only purple node gets white label
    black_labels = {1: '1', 2: '2', 3: '3', 4: '4',5: '5', 6: '6', 7: '7', 8: '8', 9: '9'}

    # Draw labels separately
    nx.draw_networkx_labels(attack_graph, pos,
                        font_size=12,
                        font_weight='bold',
                        font_color='white')

    nx.draw_networkx_labels(attack_graph, pos,
                        black_labels,
                        font_size=12,
                        font_weight='bold')

    plt.title("Basic Attack Graph \n with no Exploit Data", pad=20, fontsize=14, fontweight='bold')
    plt.axis('off')
    plt.tight_layout()
    plt.show()