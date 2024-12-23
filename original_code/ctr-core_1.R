library(HyRiM)

# Debug function to print edge information
print_edge_info <- function(graph) {
  edges <- as_edgelist(graph)
  weights <- E(graph)$weight
  probs <- E(graph)$probability
  
  for (i in 1:nrow(edges)) {
    prob_str <- if(!is.null(probs)) sprintf("prob=%f", probs[i]) else "prob=N/A"
    weight_str <- if(!is.null(weights)) sprintf("weight=%f", weights[i]) else "weight=N/A"
    cat(sprintf("DEBUG:     %s -> %s | %s, %s\n", 
                edges[i,1], edges[i,2], prob_str, weight_str))
  }
}

# # Print initial debug information
# cat("DEBUG: Starting graph processing...\n")
# cat("DEBUG: Original graph info (before processing):\n")
# cat(sprintf("DEBUG:   Number of nodes: %d\n", gorder(attack_graph)))
# cat(sprintf("DEBUG:   Number of edges: %d\n", gsize(attack_graph)))
# cat("DEBUG:   Edges (u -> v: probabilities, weight):\n")
# print_edge_info(attack_graph)

# Find roots
roots <- V(attack_graph)[degree(attack_graph, mode="in")==0] %>% as_ids
k <- length(roots)

if (k > 1) {
  entry <- "attacker_entry_node"
  attack_graph <- add_vertices(attack_graph, 1, name = entry)
  
  edgelist <- rep(entry, times=2*k)
  edgelist[2*(1:k)] <- roots
  
  attack_graph <- add_edges(attack_graph, edgelist)
  attack_graph <- set_edge_attr(
    attack_graph,
    name = "weight",
    index = get.edge.ids(attack_graph, edgelist),
    value = 1
  )
} else {
  entry <- roots[1]
}

# Process targets
target_list <- V(attack_graph)[degree(attack_graph, mode="out")==0] %>% as_ids
vertexNo <- matrix(0, nrow = 1, ncol = gorder(attack_graph))
colnames(vertexNo) <- get.vertex.attribute(attack_graph, "name")
jointVertex <- gorder(attack_graph) - length(target_list) + 1
vertexNo[, target_list] <- jointVertex
vertexNo[vertexNo == 0] <- 1:(jointVertex - 1)
attack_graph <- contract.vertices(attack_graph, mapping = vertexNo)

# # Print processed graph debug information
# cat("DEBUG: Processed graph info (after process_graph):\n")
# cat(sprintf("DEBUG:   Number of nodes: %d\n", gorder(attack_graph)))
# cat(sprintf("DEBUG:   Number of edges: %d\n", gsize(attack_graph)))
# cat(sprintf("DEBUG:   Original roots: [%s]\n", paste(roots, collapse=", ")))
# cat(sprintf("DEBUG:   Virtual entry node (if any): %s\n", if(k > 1) entry else "None"))
# cat("DEBUG:   Virtual target node (if any): virtual_target_node\n")
# cat("DEBUG:   Final edges (u -> v: probabilities, weight):\n")
# print_edge_info(attack_graph)

# Continue with the rest of the processing
node_order <- as_ids(topo_sort(attack_graph))
target_list <- V(attack_graph)[degree(attack_graph, mode="out")==0] %>% as_ids
routes <- lapply(all_simple_paths(attack_graph, from=entry, to=target_list), as_ids)
V <- unique(unlist(routes))
node_order <- intersect(node_order, V)

if (!exists("as1")) {
  as1 <- setdiff(V, c("attacker_entry_node", roots, target_list))
}

as2 <- routes
m <- length(as2)
n <- length(as1)
advList <- setdiff(V, c(entry, target_list))
Theta <- rep(1/n, times = length(advList))
names(Theta) <- advList

# cat("DEBUG: Finished graph processing.\n")

# # Convert the edge data to a proper data frame with consistent types
# final_edges_r <- as_data_frame(attack_graph, what="edges")

# # Convert 'from' and 'to' columns to character type before sorting
# final_edges_r$from <- as.character(final_edges_r$from)
# final_edges_r$to <- as.character(final_edges_r$to)

# # Now sort
# final_edges_r <- final_edges_r[order(final_edges_r$from, final_edges_r$to), ]
# cat("Final edges analysed!\n")
# print(final_edges_r)


# avoid the loops being skipped if the experiments do not define attack or defense rates to try
if (!exists("defenseRateList")) { defenseRateList <- 0 }
if (!exists("attackRateList")) { attackRateList <- 0 }

for(defenseRate in defenseRateList){
  for(attackRate in attackRateList) {
    cat("\n++++++++++++++++++++++++++++++++\nattack rate = ", attackRate, ", defense rate = ", defenseRate, "\n")
    payoffsList <- NULL  # to collect all payoffs for the multi-criteria game
    
    # this loop will only take a single iteration (we have only one target in the current version; multiple targets are "theoretically possible", and up to future work/studies)    
    for(target in target_list) {  # each target is its own goal for the defender to optimize against all adversary avatars
     
      payoffMatrix <- list() # to take up the utility distributions
      for(i in as1) { # run over all spots to inspect
        for(path in as2) { # run over all attack paths
          U <- rep(0, length(V))
          names(U) <- V
          
          for(avatar in advList) {
            
            L <- rep(0, length(V))
            names(L) <- V   # for indexing by node ID
            # adversary moves only if it is on this path
            if (avatar %in% path) {
              route <- path[which(path == avatar):length(path)]
              
              # let the adv. take a random number of steps
              pdfD <- randomSteps(route, attackRate, defenseRate)
              
              # correction over the past (2019) version of the code to avoid the cutpoint returning as -1
              cutPoint <- min(which(route == i), length(route)) 
              
              # truncate the distribution; there is the special case of the avatar
              # able to take the first step with probability 100%, but the defender
              # blocking just at this point. In that case, the adversary would not move
              # move as far as it can, and stop at the cutpoint
              if (sum(pdfD[1:cutPoint]) == 0) {
                payoffDistr <- rep(0, cutPoint)
                payoffDistr[cutPoint] <- 1  # adversary moves exactly to the cutpoint
              } else {
                # adversary moves at random
                payoffDistr <- pdfD[1:cutPoint]/sum(pdfD[1:cutPoint])
              }
              
              L[route[1:cutPoint]] <- payoffDistr
            }
            else { # otherwise, the adversary doesn't move
              # note that this bit of code expresses that the full mass is here at the starting location 
              # of the avatar, implying that there is zero mass on any of the goals
              # => this is consistent with the situation that the attack 'does not happen' over this route at all
              L[avatar] <- 1  
              # Remark: without the above line, the losses would come up with empty categories (which the solver cannot handle)
            }
            # update the mix over all adversarial avatars
            U <- U + Theta[avatar] * L
          }
          # construct the loss distribution
          U <- U / sum(U)  # avoid warnings (by lossDistribution) to not have normalized yet
          
          # re-order according to shortest distances to make the tail masses = the probabilities
          # to hit (one of) the target(s)
          # the variable "node_order" is supplied externally
          U <- U[node_order]
          
          # fix zero-probability categories, if a path does not put mass there
          # since the adversary does not arrive at this (particular) goal.
          # this is just to avoid the later solver to throw an exception, 
          # and we will keep the "noise" below the tolerance threshold (1e-5); see below
          U[U == 0] <- 1e-7
          
          ld <- lossDistribution(U, discrete=TRUE, dataType="pdf", supp=c(1,length(V)), smoothing="always", bw = 0.2)
          payoffMatrix <- append(payoffMatrix, list(ld))
        } #loop over all attack paths
      } #loop over all spot check locations
      
      payoffsList <- append(payoffsList, payoffMatrix)
    }   #loop over all target nodes (if there is more than one; not yet implemented/studied)
    # construct and solve the game
    
    G <- mosg(n, m, goals = length(target_list), 
              losses = payoffsList, byrow = TRUE, 
              defensesDescr = (as1 %>% as.character))
    eq <- mgss(G, tol=1e-5)  # compute a multi-goal security strategy
    print(eq)      # printout the equilibrium (optimal defense)
    # print out the assurance, i.e., optimal likelihood to hit the goal
    # by the node ordering, the target is the *last* entry in the optimally assured loss distribution
    # (i.e., the highest category of damage)
    loc <- eq$assurances$`1`$dpdf
    print(round(loc[length(loc)], digits=3))
    
  } # loop over all attack rates
} # loop over all defense rates
