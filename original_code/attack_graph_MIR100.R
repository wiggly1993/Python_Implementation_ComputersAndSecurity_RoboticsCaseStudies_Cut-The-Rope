library(igraph)

attack_graph <- graph_from_literal(
  1 -+ 5 ,
  5 -+ 15 ,
  15 -+ 12,
  11-+ 13,
  15 -+ 13,
  3 -+ 6,
  3 -+ 8,
  6 -+ 8,
  4-+ 7,
  2-+9,
  2-+10,
  8-+10,
  7-+10,
  2-+11 ,
  10-+15,
  8-+14,
  9-+14,
  11-+14,
  7-+14,
  11-+16,
  7-+16,
  2 -+16,
  8-+16,
  15 -+ 16
)

# hardness of compromising nodes
# assign a hardness value (= probability) to reach node
edgeProbs <- c(0.111265, 0.111265, 0.47287625, 0.47287625, 0.47287625,  0.3449215, 0.47287625, 1, 0.3449215, 0.47287625, 1, 1, 1, 0.47287625, 0.47287625, 0.47287625, 0.47287625, 0.47287625, 0.47287625, 0.47287625, 0.3449215,0.3449215, 0.3449215, 1)


# we add the success probability per Exploit (p_e) directly as the vertex property
# "edge_probabilities" here. It is understood 
# as the probability to master the particular exploit
# i.e., succeed at this point of the attack
attack_graph <- set_edge_attr(attack_graph,
                              name = "edge_probabilities",
                              index = E(attack_graph),
                              value = edgeProbs)

# edge probabilities defined such that the most probably exploitable route = the shortest path
attack_graph <- set_edge_attr(attack_graph,
                              name = "weight",
                              index = E(attack_graph),
                              value = -log(edgeProbs))

node_order <- as_ids(topo_sort(attack_graph))  # determine the node order from a topological sort

