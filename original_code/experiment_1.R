# experiment 1:
# conducted: 2022-01-24
# setup:
# - adversary: moves at Poisson rate
# - defender: periodic 
# - attack graph: MARA

# Similar to restarting a kernel in python
rm(list = ls())  

# This part makes sure that everything we will print later on will not go
# into the console but instead go directly into the .log file
outputLogFile <- "experiment_1.log"
con <- file(outputLogFile)
sink(con, append=TRUE)
sink(con, append=TRUE, type="message")

# Thus this will be printed directly into the log file.
print(outputLogFile)
print(date())

# similar to import attack_graph.MARA.R
source(file = "attack_graph_MARA.R")

attackRateList <- 2  # parameter lambda

# defines a new function called poisson
randomSteps <- function(route, attackRate = NULL, defenseRate = NULL) {
  # the value of "attackRate" comes from an external loop
  pdfD <- dpois(x=0:(length(route)-1), lambda = attackRate)
  pdfD <- pdfD / sum(pdfD)
  return(pdfD)
}

source("ctr-core_1.R")

sink()
file.show(outputLogFile)
