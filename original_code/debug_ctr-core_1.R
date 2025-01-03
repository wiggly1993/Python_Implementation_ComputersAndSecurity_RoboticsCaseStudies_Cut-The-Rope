# adapted version of original cut the rope: condense all targets (if there are more than one)
# into a single target node, and play "cut the rope" without change (except for bugfixes as annotated below)
library(HyRiM)

# read the attack graph of interest to create the variables
# routes: a list of attack paths 
# target: the final node in the attack graph
########################  Debug Methods  ########################################
debug_payoff_calc <- function(i, path, avatar, U, L, theta) {
  cat("\n=== Payoff Calculation Debug ===\n")
  cat("Check location:", i, "\n")
  cat("Path:", paste(path, collapse=" -> "), "\n")
  cat("Avatar:", avatar, "\n")
  cat("Initial U vector:", paste(U, collapse=", "), "\n")
  
  if (avatar %in% path) {
    route <- path[which(path == avatar):length(path)]
    cat("Route from avatar:", paste(route, collapse=" -> "), "\n")
    
    pdfD <- randomSteps(route)
    cat("PDF from randomSteps:", paste(pdfD, collapse=", "), "\n")
    
    cutPoint <- min(which(route == i), length(route))
    cat("Cut point:", cutPoint, "\n")
    
    payoffDistr <- pdfD[1:cutPoint]/sum(pdfD[1:cutPoint])
    cat("Normalized payoff distribution:", paste(payoffDistr, collapse=", "), "\n")
    
    cat("Final L vector:", paste(L, collapse=", "), "\n")
  }
  
  cat("Theta[avatar]:", theta[avatar], "\n")
  cat("Updated U vector:", paste(U, collapse=", "), "\n")
}



################################################################################
roots <- V(attack_graph)[degree(attack_graph, mode="in")==0] %>% as_ids
k <- length(roots)

if (k > 1) {
  entry <- "attacker_entry_node"
  attack_graph <- add_vertices(attack_graph, 1, name = entry)
  edgelist <- rep(entry, times=2*k)
  edgelist[2*(1:k)] <- roots
  attack_graph <- add_edges(attack_graph, edgelist)
  attack_graph <- set_edge_attr(attack_graph,
                                name = "weight",
                                index = get.edge.ids(attack_graph, edgelist),
                                value = 1)
} else {
  entry <- roots[1]
}

# Debug print before merging targets
cat("\nBefore merging targets:\n")
cat("Nodes:", V(attack_graph)$name, "\n")
cat("Edges with weights:\n")
E(attack_graph)$weight <- ifelse(is.na(E(attack_graph)$weight), 1, E(attack_graph)$weight)
for(e in E(attack_graph)) {
    cat(ends(attack_graph, e)[1], "->", ends(attack_graph, e)[2], ":", 
        E(attack_graph)$weight[e], "\n")
}

# Debug target identification
target_list <- V(attack_graph)[degree(attack_graph, mode="out")==0] %>% as_ids
cat("\nTARGET IDENTIFICATION:\n")
cat("Found target nodes:", paste(target_list, collapse=", "), "\n")
cat("Number of targets:", length(target_list), "\n")

# Debug edge structure before contraction
cat("\nEDGE STRUCTURE BEFORE CONTRACTION:\n")
cat("Edges to target nodes:\n")
for(target in target_list) {
    incident_edges <- incident(attack_graph, target, mode="in")
    cat("\nTarget", target, "incoming edges:\n")
    for(e in incident_edges) {
        from_vertex <- ends(attack_graph, e)[1]
        cat("From:", from_vertex, "Weight:", E(attack_graph)$weight[e], "\n")
    }
}

# Create mapping and perform contraction
vertexNo <- matrix(0, nrow = 1, ncol = gorder(attack_graph))
colnames(vertexNo) <- get.vertex.attribute(attack_graph, "name")
jointVertex <- gorder(attack_graph) - length(target_list) + 1
vertexNo[,target_list] <- jointVertex
vertexNo[vertexNo == 0] <- 1:(jointVertex - 1)

cat("\nPERFORMING CONTRACTION:\n")
cat("Using contract.vertices with mapping:\n")
print(vertexNo)
attack_graph <- contract.vertices(attack_graph, mapping = vertexNo)

# Debug final structure and parallel edges
cat("\nFINAL GRAPH STRUCTURE:\n")
cat("Node count:", gorder(attack_graph), "\n")
cat("Edge count:", gsize(attack_graph), "\n")

# Analyze parallel edges
edge_df <- data.frame(
    from = ends(attack_graph, E(attack_graph))[,1],
    to = ends(attack_graph, E(attack_graph))[,2],
    weight = E(attack_graph)$weight
)

cat("\nPARALLEL EDGE ANALYSIS:\n")
for(pair in unique(paste(edge_df$from, "->", edge_df$to))) {
    subset <- edge_df[paste(edge_df$from, "->", edge_df$to) == pair,]
    if(nrow(subset) > 1) {
        cat("\nParallel edges for", pair, ":\n")
        cat("Count:", nrow(subset), "\n")
        cat("Weights:", paste(subset$weight, collapse=", "), "\n")
    }
}



#########
# Debug print after merging
cat("\n AFTER merging targets:\n")
cat("Node count:", gorder(attack_graph), "\n")
cat("Edge count:", gsize(attack_graph), "\n\n")

cat("Edge structure after merging:\n")
for(i in seq_along(E(attack_graph))) {
    cat("Edge", i, ":", paste(ends(attack_graph, E(attack_graph)[i]), collapse=", "),
        "weight:", E(attack_graph)$weight[i], "\n")
}

################################################################################
node_order <- as_ids(topo_sort(attack_graph))
target_list <- V(attack_graph)[degree(attack_graph, mode="out")==0] %>% as_ids
routes <- lapply(all_simple_paths(attack_graph, from=entry, to=target_list), as_ids)

# debug_edge_weights(attack_graph, routes)

V <- unique(unlist(routes))
node_order <- intersect(node_order, V)

if (!exists("as1")) {
  as1 <- setdiff(V, c("attacker_entry_node", roots, target_list))
}
as2 <- routes
m <- length(as2)
n <- length(as1)
advList <- setdiff(V, c(entry, target_list))
#Theta <- rep(1/n, times = length(advList))
# New crazy version
Theta <- rep(1/length(advList), times = length(advList))
names(Theta) <- advList




############

if (!exists("defenseRateList")) { defenseRateList <- 0 }
if (!exists("attackRateList")) { attackRateList <- 0 }

for(defenseRate in defenseRateList) {
  for(attackRate in attackRateList) {
    #cat("\n++++++++++++++++++++++++++++++++\nattack rate = ", attackRate, 
    #    ", defense rate = ", defenseRate, "\n")
    payoffsList <- NULL


    # Add debug statements here
    cat("\n=== Debug: Strategy Mappings ===\n")
    cat("Defender strategies (as1):", paste(as1, collapse=", "), "\n")
    cat("Attacker paths (as2):\n")
    for(idx in seq_along(as2)) {
        cat("Path", idx-1, ":", paste(as2[[idx]], collapse="->"), "\n")
    }
    
    for(target in target_list) {
      payoffMatrix <- list()
      
      for(i in as1) {
        for(path in as2) {
          
          # Initialize U to zero for this (i, path) pair
          U <- rep(0, length(V))
          names(U) <- V
          
          #cat("\n--- Starting payoff calc for check =", i,
          #    ", path =", paste(path, collapse="->"), "---\n")
          
          # Loop over all possible attacker starts (avatars)
          for(avatar in advList) {
            L <- rep(0, length(V))
            names(L) <- V
            
            # If avatar is on this path, compute sub-route distribution
            if (avatar %in% path) {
              start_idx <- which(path == avatar)
              route <- path[start_idx:length(path)]
              
              #cat("\nProcessing avatar", avatar, ":\n")
              #cat("Route from avatar:", paste(route, collapse="->"), "\n")
              
              pdfD <- randomSteps(route, attackRate, defenseRate)
              #cat("PDF for entire route:", paste(pdfD, collapse=", "), "\n")
              
              # Identify cut point if defender checks i along that route
              if (i %in% route) {
                cutPoint <- min(which(route == i), length(route))
              } else {
                cutPoint <- length(route)
              }
              #cat("Cut point:", cutPoint, "\n")
              
              pdf_subset <- pdfD[1:cutPoint]
              #cat("PDF subset:", paste(pdf_subset, collapse=", "), "\n")
              
              if (sum(pdf_subset) < 1e-15) {
                payoffDistr <- rep(0, cutPoint)
                payoffDistr[cutPoint] <- 1
              } else {
                payoffDistr <- pdf_subset / sum(pdf_subset)
              }
              #cat("Payoff distribution:", paste(payoffDistr, collapse=", "), "\n")
              
              route_subset <- route[1:cutPoint]
              L[route_subset] <- payoffDistr
              
              #cat("Route subset:", paste(route_subset, collapse="->"), "\n")
              #cat("L distribution for this avatar (BEFORE weighting by Theta):\n")
              #for(idx_l in seq_along(L)) {
              #  if(abs(L[idx_l]) > 1e-15) {
              #    cat("  Node", names(L)[idx_l], ":", L[idx_l], "\n")
              #  }
              #}
              
            } else {
              # If avatar not on path, stays at its location (prob=1)
              L[avatar] <- 1
              #cat("\nProcessing avatar", avatar, "(not in path):\n")
              #cat("L[", avatar, "] = 1.0\n")
            }
            
            #cat("\nTheta[", avatar, "] =", Theta[avatar], "\n")
            U <- U + Theta[avatar] * L
            #cat("Current U after adding this avatar's contribution:\n")
            #for(idx_u in seq_along(U)) {
            #  if(abs(U[idx_u]) > 1e-10) {
            #    cat("  Node", names(U)[idx_u], ":", U[idx_u], "\n")
            #  }
            #}
          }
          
          #cat("\n--- Aggregated U for check =", i, 
          #    ", path =", paste(path, collapse="->"),
          #    " (BEFORE normalization) ---\n")
          #for(idx_u in seq_along(U)) {
          #  if(abs(U[idx_u]) > 1e-10) {
          #    cat("  Node", names(U)[idx_u], ":", U[idx_u], "\n")
          #  }
          #}
          
          # Normalize U
          if(sum(U) < 1e-15) {
            U <- rep(1e-7, length(U))
          } else {
            U <- U / sum(U)
            # clip extremely small values
            U[U < 1e-7] <- 1e-7
          }
          U <- U[node_order]
          
          # cat("\n--- Normalized U for check =", i,
          #     ", path =", paste(path, collapse="->"), "---\n")
          # for(idx_u2 in seq_along(U)) {
          #   if(abs(U[idx_u2]) > 1e-10) {
          #     cat("  Node", names(U)[idx_u2], ":", U[idx_u2], "\n")
          #   }
          # }
          
          # Create final distribution object for this (i, path)
          # cat("Pre-lossDistribution U for check=", i, 
          # ", path=", paste(path, collapse="->"), 
          # ":", paste(U, collapse=", "), "\n")

          ld <- lossDistribution(
            U, discrete=TRUE, dataType="pdf",
            supp=c(1,length(V)), smoothing="always", bw=0.2
          )
          payoffMatrix <- append(payoffMatrix, list(ld))

        }
      }
      payoffsList <- append(payoffsList, payoffMatrix)
    }
    
    # NEW DEBUG CODE: Print payoff matrix before MOSG construction
    cat("\n=== Debug: Final Payoff Matrix ===\n")
    matrix_rows <- length(as1)
    matrix_cols <- length(as2)
    cat("Matrix dimensions:", matrix_rows, "x", matrix_cols, "\n\n")
    
    # Create a matrix to store the values we care about
    debug_matrix <- matrix(0, nrow=matrix_rows, ncol=matrix_cols)
    
    # Fill the matrix with the final probabilities (last value of dpdf for each distribution)
    for(i in 1:matrix_rows) {
        for(j in 1:matrix_cols) {
            idx <- (i-1)*matrix_cols + j
            debug_matrix[i,j] <- payoffsList[[idx]]$dpdf[length(V)]
        }
    }
    
    # Print the matrix in a readable format
    cat("Payoff Matrix (probability of reaching target):\n")
    for(i in 1:matrix_rows) {
        cat(sprintf("Row %2d:", i))
        for(j in 1:matrix_cols) {
            cat(sprintf(" %8.6f", debug_matrix[i,j]))
        }
        cat("\n")
    }
    
    cat("\n=== End Debug: Final Payoff Matrix ===\n")

    # Construct and solve the MOSG
    G <- mosg(n, m, goals = length(target_list),
              losses = payoffsList, byrow = TRUE,
              defensesDescr = (as1 %>% as.character))
    eq <- mgss(G, tol=1e-5)
    print(eq)    # Let R handle the printing of the equilibrium
    
    loc <- eq$assurances$`1`$dpdf
    print(round(loc[length(loc)], digits=3))
  }
}
