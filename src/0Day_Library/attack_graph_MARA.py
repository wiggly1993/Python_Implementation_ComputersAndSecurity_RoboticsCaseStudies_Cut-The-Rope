"""
This module provides the MARA attack graph for security analysis.
"""

import networkx as nx  # type: ignore
import matplotlib.pyplot as plt  # type: ignore

DEFAULT_WEIGHT_VALUE = 0  # Default fallback value

def mara_set_default_weight(value):
    """Set the default weight value for the entire module."""
    global DEFAULT_WEIGHT_VALUE
    DEFAULT_WEIGHT_VALUE = value
    print(f"Default weight value in MARA is set to: {DEFAULT_WEIGHT_VALUE}")


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
    
    # Define edges according to the original R code's structure
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