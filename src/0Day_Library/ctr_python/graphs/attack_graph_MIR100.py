"""
This module provides the MIR100 attack graph for security analysis.
"""

import networkx as nx  # type: ignore
import matplotlib.pyplot as plt  # type: ignore
import numpy as np  # type: ignore

DEFAULT_WEIGHT_VALUE = 0  # Default fallback value

def mir100_set_default_weight(value):
    """Set the default weight value for the entire module."""
    global DEFAULT_WEIGHT_VALUE
    DEFAULT_WEIGHT_VALUE = value
    #print(f"Default weight value in MIR100 is set to: {DEFAULT_WEIGHT_VALUE}")

def create_base_graph():
    """
    Create the base directed graph with edges (no probabilities yet).
    """
    G = nx.DiGraph()
    
    edges = [
        (1, 5), (5, 15), (15, 12), (11, 13), (15, 13),
        (3, 6), (3, 8), (6, 8), (4, 7), (2, 9),
        (2, 10), (8, 10), (7, 10), (2, 11), (10, 15),
        (8, 14), (9, 14), (11, 14), (7, 14), (11, 16),
        (7, 16), (2, 16), (8, 16), (15, 16)
    ]
    
    G.add_edges_from(edges)
    return G

def add_edge_probabilities(G):
    """
    Add 'prob' attribute to edges, matching the exact R internal ordering.
    """
    # The edges in R's internal order, based on the debug output
    edges_in_order = [
        (1, 5),   # Edge 1
        (5, 15),  # Edge 2
        (15, 12), # Edge 3
        (15, 13), # Edge 4
        (15, 16), # Edge 5
        (11, 13), # Edge 6
        (11, 14), # Edge 7
        (11, 16), # Edge 8
        (3, 6),   # Edge 9
        (3, 8),   # Edge 10
        (6, 8),   # Edge 11
        (8, 10),  # Edge 12
        (8, 14),  # Edge 13
        (8, 16),  # Edge 14
        (4, 7),   # Edge 15
        (7, 10),  # Edge 16
        (7, 14),  # Edge 17
        (7, 16),  # Edge 18
        (2, 11),  # Edge 19
        (2, 9),   # Edge 20
        (2, 10),  # Edge 21
        (2, 16),  # Edge 22
        (9, 14),  # Edge 23
        (10, 15)  # Edge 24
    ]
    
    # Probabilities in R's order, based on the debug output
    edge_probs = [
        0.111265,   # 1->5
        0.111265,   # 5->15
        0.472876,   # 15->12
        0.472876,   # 15->13
        0.472876,   # 15->16
        0.344921,   # 11->13
        0.472876,   # 11->14
        1.000000,   # 11->16
        0.344921,   # 3->6
        0.472876,   # 3->8
        1.000000,   # 6->8
        1.000000,   # 8->10
        1.000000,   # 8->14
        0.472876,   # 8->16
        0.472876,   # 4->7
        0.472876,   # 7->10
        0.472876,   # 7->14
        0.472876,   # 7->16
        0.472876,   # 2->11
        0.472876,   # 2->9
        0.344921,   # 2->10
        0.344921,   # 2->16
        0.344921,   # 9->14
        1.000000    # 10->15
    ]
    
    # Now I explicitly assign each probability in R's order
    for (u, v), p in zip(edges_in_order, edge_probs):
        if G.has_edge(u, v):
            G[u][v]['prob'] = p
        else:
            raise ValueError(f"Edge ({u}->{v}) not found in the graph. Check definitions!")
    
    return G

def add_edge_weights(G):
    """
    'weight' = -log(prob), same as the R code (with potential -0.0 -> 0.0 cleanup).
    """
    for u, v in G.edges():
        p = G[u][v]['prob']
        w = -np.log(p)
        if abs(w) < 1e-14:
            w = 0.0
        G[u][v]['weight'] = w

    return G

def create_mir100_attack_graph(DEFAULT_WEIGHT_VALUE=DEFAULT_WEIGHT_VALUE):
    """
    Create the MIR100 attack graph with probabilities and weights.
    
    Returns:
        Tuple containing:
            - nx.DiGraph: The created attack graph
            - List[int]: Nodes in topological order
    """
    G = create_base_graph()
    G = add_edge_probabilities(G)
    G = add_edge_weights(G)
    
    # Compute topological order of nodes
    node_order = list(nx.topological_sort(G))
    
    return G, node_order

def plot_main_graph(attack_graph):
    """
    Visualizes the MIR100 attack graph.
    """
    # Create subplot figure
    fig, ax = plt.subplots(figsize=(12, 10))
    
    # Identify original target nodes (nodes with no outgoing edges)
    original_target_nodes = [n for n, d in attack_graph.out_degree() if d == 0]
    
    # Identify entry nodes (nodes with no incoming edges)
    entry_nodes = [n for n, d in attack_graph.in_degree() if d == 0 and n not in original_target_nodes]
    
    # Use spring layout
    pos = nx.spring_layout(attack_graph, k=1, iterations=50, seed=42)
    
    # Draw edges with arrows
    nx.draw_networkx_edges(attack_graph, pos, 
                          edge_color='gray',
                          arrows=True,
                          arrowsize=15,
                          width=1.5,
                          ax=ax)
    
    # Create color map for nodes
    node_colors = []
    for node in attack_graph.nodes():
        if node in original_target_nodes:
            node_colors.append('lightcoral')  # Target nodes always red
        elif node in entry_nodes:
            node_colors.append('lightgreen')  # Entry nodes (non-targets) green
        else:
            node_colors.append('lightblue')   # Regular nodes blue
    
    # Draw nodes
    nx.draw_networkx_nodes(attack_graph, pos,
                          node_color=node_colors,
                          node_size=500,
                          edgecolors='darkblue',
                          linewidths=1.5,
                          ax=ax)
    
    # Create and draw labels
    labels = {node: str(node) for node in attack_graph.nodes()}
    nx.draw_networkx_labels(attack_graph, pos,
                           labels,
                           font_size=10,
                           font_weight='bold',
                           ax=ax)
    
    # Set title
    ax.set_title("MIR100 Attack Graph", fontsize=12, fontweight='bold')
    ax.axis('off')
    
    plt.tight_layout()
    plt.show()

# Create the graph and node order (for backward compatibility)
# attack_graph, node_order = create_mir100_attack_graph()
# print("Successfully created MIR100 attack graph.")