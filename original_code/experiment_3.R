# experiment 3:
# conducted: 2022-01-24
# setup:
# - adversary: moves at Poisson rate
# - defender: periodic 
# - attack graph: MIR100

rm(list = ls())  # clean up the workspace to avoid side-effects

outputLogFile <- "experiment_3.log"

con <- file(outputLogFile)
sink(con, append=TRUE)
sink(con, append=TRUE, type="message")
print(outputLogFile)
print(date())

source(file = "attack_graph_MIR100.R")

# steps determined by hardness to exploit
randomSteps <- function(route, attackRate = NULL, defenseRate = NULL) {
  #cat("\n=== Debug: randomSteps function ===\n")
  #cat("Input route:", paste(route, collapse="->"), "\n")
  
  # Get edge probabilities
  edges <- E(attack_graph, path=route)
  #cat("\nEdges found:\n")
  #print(edges)  # Simply print the edges object directly
  
  hardness <- edge_attr(attack_graph, "edge_probabilities", edges)
  #cat("\nRaw hardness values:", paste(hardness, collapse=", "), "\n")
  
  # Handle NA values
  hardness[is.na(hardness)] <- 1
  #cat("Hardness after NA handling:", paste(hardness, collapse=", "), "\n")
  
  # Calculate PDF components
  stop_probs <- c(1 - hardness, 1)
  cum_probs <- c(1, cumprod(hardness))
  
  #cat("\nStop probabilities:", paste(stop_probs, collapse=", "), "\n")
  #cat("Cumulative probabilities:", paste(cum_probs, collapse=", "), "\n")
  
  # Calculate final PDF
  pdfD <- stop_probs * cum_probs
  #cat("PDF before normalization:", paste(pdfD, collapse=", "), "\n")
  
  pdfD <- pdfD / sum(pdfD)
  #cat("Final normalized PDF:", paste(pdfD, collapse=", "), "\n")
  #cat("=== End randomSteps debug ===\n\n")
  
  return(pdfD)
}


# THIS WAS CHANGED
source("debug_ctr-core_1.R")

sink()
file.show(outputLogFile)
