# adapted version of original cut the rope: condense all targets (if there are more than one)
# into a single target node, and play "cut the rope" without change (except for bugfixes as annotated below)
library(HyRiM)

# read the attack graph of interest to create the variables
# routes: a list of attack paths 
# target: the final node in the attack graph

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

# # Debug print before merging targets
# cat("\nBefore merging targets:\n")
# cat("Nodes:", V(attack_graph)$name, "\n")
# cat("Edges with weights:\n")
# E(attack_graph)$weight <- ifelse(is.na(E(attack_graph)$weight), 1, E(attack_graph)$weight)
# for(e in E(attack_graph)) {
#     cat(ends(attack_graph, e)[1], "->", ends(attack_graph, e)[2], ":", 
#         E(attack_graph)$weight[e], "\n")
# }

################################################################################
target_list <- V(attack_graph)[degree(attack_graph, mode="out")==0] %>% as_ids
vertexNo <- matrix(0, nrow = 1, ncol = gorder(attack_graph))
colnames(vertexNo) <- get.vertex.attribute(attack_graph, "name")
jointVertex <- gorder(attack_graph) - length(target_list) + 1
vertexNo[,target_list] <- jointVertex
vertexNo[vertexNo == 0] <- 1:(jointVertex - 1)

# # Debug print vertexNo mapping
# cat("\nANALYSIS of R STARTS NOW:\n")
# cat("\nVertexNo mapping:\n")
# print(vertexNo)

attack_graph <- contract.vertices(attack_graph, mapping = vertexNo)

# # Debug print after merging
# cat("\n AFTER merging targets:\n")
# cat("Node count:", gorder(attack_graph), "\n")
# cat("Edge count:", gsize(attack_graph), "\n\n")

# cat("Edge structure after merging:\n")
# for(i in seq_along(E(attack_graph))) {
#     cat("Edge", i, ":", paste(ends(attack_graph, E(attack_graph)[i]), collapse=", "),
#         "weight:", E(attack_graph)$weight[i], "\n")
# }

################################################################################
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

# # Debug prints for game elements
# cat("\nGame Elements Analysis:\n")
# cat("V (All nodes in game):", V, "\n")
# cat("adv_list (Possible attacker starting points):", advList, "\n")
# cat("theta (Probability distribution over starting points):\n")
# for(i in seq_along(advList)) {
#     cat(advList[i], ":", Theta[i], "\n")
# }

# cat("\nPath Analysis:\n")
# cat("Attack paths (as2):\n")
# for(i in seq_along(as2)) {
#     cat("Path", i-1, ":", paste(as2[[i]], collapse=", "), "\n")
# }

if (!exists("defenseRateList")) { defenseRateList <- 0 }
if (!exists("attackRateList")) { attackRateList <- 0 }

for(defenseRate in defenseRateList){
  for(attackRate in attackRateList) {
    cat("\n++++++++++++++++++++++++++++++++\nattack rate = ", attackRate, ", defense rate = ", defenseRate, "\n")
    payoffsList <- NULL
    
    for(target in target_list) {
      payoffMatrix <- list()
      for(i in as1) {
        for(path in as2) {
          U <- rep(0, length(V))
          names(U) <- V
          
          for(avatar in advList) {
            L <- rep(0, length(V))
            names(L) <- V
            
            if (avatar %in% path) {
              route <- path[which(path == avatar):length(path)]
              pdfD <- randomSteps(route, attackRate, defenseRate)
              
              # Debug prints for path processing
              #cat("\nProcessing Path for spot check location", i, "\n")
              #cat("Route:", paste(route, collapse=", "), "\n")
              
              cutPoint <- min(which(route == i), length(route))
              #cat("Cut point:", cutPoint, "\n")
              
              if (sum(pdfD[1:cutPoint]) == 0) {
                payoffDistr <- rep(0, cutPoint)
                payoffDistr[cutPoint] <- 1
              } else {
                payoffDistr <- pdfD[1:cutPoint]/sum(pdfD[1:cutPoint])
              }
              
              #cat("PDF up to cut:", paste(pdfD[1:cutPoint], collapse=", "), "\n")
              #cat("Normalized payoff distribution:", paste(payoffDistr, collapse=", "), "\n")
              
              L[route[1:cutPoint]] <- payoffDistr
            } else {
              L[avatar] <- 1
            }
            U <- U + Theta[avatar] * L
          }
          U <- U / sum(U)
          U <- U[node_order]
          U[U == 0] <- 1e-7
          ld <- lossDistribution(U, discrete=TRUE, dataType="pdf", supp=c(1,length(V)), smoothing="always", bw = 0.2)
          payoffMatrix <- append(payoffMatrix, list(ld))
        }
      }
      payoffsList <- append(payoffsList, payoffMatrix)
    }
    
    G <- mosg(n, m, goals = length(target_list), 
              losses = payoffsList, byrow = TRUE, 
              defensesDescr = (as1 %>% as.character))
    eq <- mgss(G, tol=1e-5)
    print(eq)
    
    loc <- eq$assurances$`1`$dpdf
    print(round(loc[length(loc)], digits=3))
  }
}