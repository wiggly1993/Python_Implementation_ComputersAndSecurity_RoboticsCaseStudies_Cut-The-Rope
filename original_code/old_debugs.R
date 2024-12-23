names(Theta) <- advList

# # Debug output for key vectors
# cat("\n=== Debug Output for Key Vectors ===\n")

# # 1. Print all routes
# cat("\nROUTES (all attack paths):\n")
# for (i in seq_along(routes)) {
#     cat(sprintf("Route %d: %s\n", i, paste(routes[[i]], collapse=" -> ")))
# }

# # 2. Print V vector
# cat("\nV vector (all nodes):\n")
# cat(paste(V, collapse=", "), "\n")

# # 3. Print advList vector
# cat("\nadvList vector (possible attacker locations):\n")
# cat(paste(advList, collapse=", "), "\n")

# # 4. Print as1 vector
# cat("\nas1 vector (defender check locations):\n")
# cat(paste(as1, collapse=", "), "\n")

# # Print comparison summary
# cat("\n=== Vector Comparison ===\n")
# cat("Total elements in each vector:\n")
# cat("Routes:", length(routes), "\n")
# cat("V:", length(V), "\n")
# cat("advList:", length(advList), "\n")
# cat("as1:", length(as1), "\n")

# # Add this after the line: names(Theta) <- advList
# cat("\n=== Debug Output from R Implementation ===\n")
# cat("\n n is the list of nodes the defender can check. Total value of n is ", n, "\n")
# cat("\nGame Elements Analysis:\n")
# cat("----------------------\n")
# cat("Total number of nodes in V:", length(V), "\n")
# cat("Total number of potential attack paths:", length(routes), "\n")
# cat("Total number of adversary locations:", length(advList), "\n")

# cat("\nV (All nodes in game):", paste(sort(as.numeric(V)), collapse=", "), "\n")
# cat("adv_list (Possible attacker starting points):", paste(sort(as.numeric(advList)), collapse=", "), "\n")

# cat("\nTheta Analysis:\n")
# cat("Number of theta entries:", length(Theta), "\n")
# cat(sprintf("Sum of theta probabilities: %.6f\n", sum(Theta)))  # Should be 1.0
# cat("\nTheta distribution:\n")
# for (node in sort(as.numeric(names(Theta)))) {
#     cat(sprintf("Node %s: %.6f\n", node, Theta[as.character(node)]))
# }

# cat("\nDetailed Path Analysis:\n")
# cat("---------------------\n")
# for (i in seq_along(routes)) {
#     cat(sprintf("\nPath %d:\n", i))
#     cat("Full path:", paste(routes[[i]], collapse=", "), "\n")
#     cat("Length:", length(routes[[i]]), "\n")
#     cat("Intermediate nodes:", paste(intersect(routes[[i]], advList), collapse=", "), "\n")
# }

# cat("\nVerification Checks:\n")
# cat("-------------------\n")
# cat("1. All adv_list nodes in V?", all(advList %in% V), "\n")
# cat("2. Any duplicates in adv_list?", length(advList) != length(unique(advList)), "\n")
# cat("3. Number of nodes with theta values:", length(Theta), "\n")
# cat("4. Nodes in adv_list but not in theta:", paste(setdiff(advList, names(Theta)), collapse=", "), "\n")
# cat("5. Nodes in theta but not in adv_list:", paste(setdiff(names(Theta), advList), collapse=", "), "\n")
# cat("============================================\n\n")



# ENDS HERE



debug_edge_weights <- function(attack_graph, routes) {
  cat("\n=== Edge Weights Analysis ===\n")
  
  for(path_idx in seq_along(routes)) {
    path <- routes[[path_idx]]
    cat(sprintf("\nPath %d: %s\n", path_idx, paste(path, collapse=" -> ")))
    cat("Edge weights along path:\n")
    
    for(i in 1:(length(path)-1)) {
      source <- path[i]
      target <- path[i+1]
      
      # Get edge ID
      edge_id <- get.edge.ids(attack_graph, c(source, target))
      
      # Get edge attributes
      weight <- E(attack_graph)$weight[edge_id]
      prob <- E(attack_graph)$edge_probabilities[edge_id]
      
      cat(sprintf("  %s -> %s:\n", source, target))
      cat(sprintf("    Weight: %s\n", ifelse(is.na(weight), "1.0", weight)))
      cat(sprintf("    Edge Probability: %s\n", ifelse(is.na(prob), "NA", prob)))
      
      # Get all edge attributes
      all_attrs <- edge_attr(attack_graph, index=edge_id)
      cat("    All edge attributes:", toString(all_attrs), "\n")
    }
  }
}