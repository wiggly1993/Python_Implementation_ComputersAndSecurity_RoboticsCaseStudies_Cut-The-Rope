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
  # Only debug first 2 paths
  debug_path <- FALSE
  if(length(route) > 0 && route[1] == "1") {  # Check for string "1" instead of integer
    debug_path <- TRUE
    cat("[DEBUG-R] ==========================================\n")
    cat(sprintf("[DEBUG-R] Analyzing path: %s\n", paste(route, collapse=",")))
  }
  
  hardness <- edge_attr(attack_graph, "edge_probabilities", E(attack_graph, path=route))
  
  if(debug_path) {
    cat("[DEBUG-R] Edge probabilities:\n")
    for(i in 1:(length(route)-1)) {
      cat(sprintf("[DEBUG-R] Edge %s->%s: prob=%f\n", 
          as.character(route[i]), 
          as.character(route[i+1]), 
          hardness[i]))
    }
    cat(sprintf("[DEBUG-R] Hardness array: %s\n", paste(hardness, collapse=",")))
  }
  
  hardness[is.na(hardness)] <- 1 # fix missing hardness values
  
  # Calculate probability distribution
  pdfD <- c(1 - hardness, 1) * c(1, cumprod(hardness))
  
  if(debug_path) {
    cat(sprintf("[DEBUG-R] PDF before normalization: %s\n", paste(pdfD, collapse=",")))
    pdfD <- pdfD / sum(pdfD)
    cat(sprintf("[DEBUG-R] PDF after normalization: %s\n", paste(pdfD, collapse=",")))
    cat("[DEBUG-R] ==========================================\n\n")
  } else {
    pdfD <- pdfD / sum(pdfD)
  }
  
  return(pdfD)
}

source("ctr-core_1.R")

sink()
file.show(outputLogFile)