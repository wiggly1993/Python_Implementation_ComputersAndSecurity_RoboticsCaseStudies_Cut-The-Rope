# adapted version of original cut the rope: condense all targets (if there are more than one)
# into a single target node, and play "cut the rope" without change (except for bugfixes as annotated below)
library(HyRiM)

# read the attack graph of interest to create the variables
# routes: a list of attack paths
# target: the final node in the attack graph

################################################################################
# externally supplied (i.e., elsewhere defined) variables
# these are defined as part of the individual experiments:
# + node_order: ordering of nodes (can be a topological order or any other)
# + randomSteps: a function taking a route for the adversary, and returning a 
#   probability mass function giving the likelihoods of how far the attacker may have come on the route
# + attackRateList: list of attack rates to iterate over, whose values are used by "randomSteps"
# + defenseRateList: list of defense rates (also used internally by "randomSteps" if this uses a geometric distribution)



# This section revoles around adding a new starting virtual node to the graph
# [1,2,3,4,5]
# ["attacker_entry_node", 1,2,3,4,5]
################################################################################

# This finds the starting nodes that have no edges pointing to them
# stores these nodes in the variable "roots"
roots <- V(attack_graph)[degree(attack_graph, mode="in")==0] %>% as_ids
# the number of starting nodes
k <- length(roots)


if (k > 1) {
  # add a virtual starting point
  entry <- "attacker_entry_node"  # the virtual node
  # add the virtual node to the graph
  attack_graph <- add_vertices(attack_graph, 1, name = entry)

  # create a list that repeats entry node k*2 times 
  # [entry, entry, entry] (for k=3)
  edgelist <- rep(entry, times=2*k)
  # add roots to the list but in the odd positions
  # [entry, root1, entry, root2, entry, root3]
  edgelist[2*(1:k)] <- roots

  # add edges from entry nade to all starting nodes
  attack_graph <- add_edges(attack_graph, edgelist)
  # give all the new edges from virtual to roots a weight of 1
  attack_graph <- set_edge_attr(attack_graph,
                                name = "weight",
                                index = get.edge.ids(attack_graph, edgelist),
                                value = 1)   # the virtual start is no obstacle towards the real entry point
} else {
  entry <- roots[1]
}

################################################################################


# In this section we alter the graph structure from [1,2,3,4,5,6,7,8,9,10]
# to something that contains only a single target node [1,2,3,4,5,6,7,8] <- 8 is the target here
################################################################################
# create a list of target nodes
target_list <- V(attack_graph)[degree(attack_graph, mode="out")==0] %>% as_ids

# create a list of 0s with the length of the number of nodes in the graph
# [0, 0, 0, ...]
vertexNo <- matrix(0, nrow = 1, ncol = gorder(attack_graph))

# create a "matrix" that adds the labels for the nodes for each columns
#  A  B  C
# [0, 0, 0]
# Here the matrix still is (1,3), these labels appear to be living outside
colnames(vertexNo) <- get.vertex.attribute(attack_graph, "name")

# all nodes (10) - target nodes (3) + 1 = 8
jointVertex <- gorder(attack_graph) - length(target_list) + 1

# The value jointVertex was the number of all nodes - target nodes + 1
# And this value will be inserted into VertexNo [0, 0, 0, ..]
# But only at the locations of the targets nodes 
# So we could have something like [0, 0, 8, 0, 8, 0, 8]
vertexNo[,target_list] <- jointVertex

# finds the 0s in vertexNo and replaces them with the numbers 1 to jointVertex - 1 # nolint
# before: [0, 0, 8, 0, 8, 0, 8]
# after: [1, 2, 8, 3, 8, 4, 8]
vertexNo[vertexNo == 0] <- 1:(jointVertex - 1)

#This line actually changes the graph
# It merges all the nodes that were labeled with the same number (here 8) into one single node (virtual target)
# all nodes that had unique labels remain as they were
attack_graph <- contract.vertices(attack_graph, mapping = vertexNo)


# Everything we did in this section was to start with the given attack graph
# [1,2,3,4,5,6,7,8,9,10] <- with 2,4,6 as target nodes
# and create a new graph out of that combines these target nodes at the end
# [1,2,3,4,5,6,7,8] <- with 8 as the new (virtual) target node
################################################################################


# (Prob Models): Topological sort of all the nodes in the reduced Graph nodes
# node_order = [1,3,2,5,7,4,6,8]
# only add nodes whose parents already have been addded
node_order <- as_ids(topo_sort(attack_graph))  

# Gives us a new target list with ideally only one target node: [8] for our case
target_list <- V(attack_graph)[degree(attack_graph, mode="out")==0] %>% as_ids
################################################################################


################################################################################

# this creates a list of all possible paths from the entry node to the target node
# [[1,2,8], [1,3,4,8], [1,5,6,7,8]]
routes <- lapply(all_simple_paths(attack_graph, from=entry, to=target_list), as_ids)

# get all nodes from all routes (potential attacker starting points)
# Before: routes = [[1,2,8], [1,3,4,8], [1,2,8]]
# After: V = [1,2,3,4,8] (unique nodes across all paths)
V <- unique(unlist(routes)) 

# we want a list of V that is sorted topologically
# to achieve this we use intersect to only keep the nodes that are in node_order
# node_order = [1,3,2,4,8]
node_order <- intersect(node_order, 
                        V) 


# as1 is supposed to be a list of nodes the defender can act on
# so what this line does is to take V and remove the virtual entry, the root nodes and the target node(s)
# If V = [1,2,3,4,5,6,7,8] where:
# attacker_entry_node = 1
# roots = [2]
# target_list = [8]
# Then as1 = [3,4,5,6,7] (places where defender can act)
if (!exists("as1")) {
  as1 <- setdiff(V, c("attacker_entry_node", roots, target_list))
}

# This defines the attackers action space
# But instead of giving him individual nodes, we give him the routes
# routes = [[1,2,8], [1,3,4,8], [1,2,8]]
as2 <- routes

# number of different attack routes the attacker has
m <- length(as2)
# number of different individual nodes the defender can act on
n <- length(as1)


# This creates a list of all possible nodes where the attacker could start but we are excluding
# the entry node and target node(s)
# V = [1,2,3,4,8]
# advList = [2,3,4]
advList <- setdiff(V, c(entry, target_list))  

# This creates a list where each adversary location is given equal probability (1/n). 
# This represents the defender's uncertainty about where the attacker might be
Theta <- rep(1/n, times = length(advList))

# Create dictionary mapping locations to their probabilities
# Before: advList = [2,3,4,5,6,7]
#         Theta = [1/5, 1/5, 1/5, 1/5, 1/5, 1/5]
# After: Theta = {2: 0.2, 3: 0.2, 4: 0.2, 5: 0.2, 6: 0.2, 7: 0.2}
names(Theta) <- advList

# experiment_1.R does only define attackRateList = 2 but no value for defenserate
# Important note: in this specific code we have here, even if defenderate is defined, 
# it will not have any impact on the code we have here.
# I assume that is bec we are in the "First movement" framework where the defender
# checks are at fixed time intervals
if (!exists("defenseRateList")) { defenseRateList <- 0 }
if (!exists("attackRateList")) { attackRateList <- 0 }

for(defenseRate in defenseRateList){
  for(attackRate in attackRateList) {
    # print out the current attack and defense rates
    cat("\n++++++++++++++++++++++++++++++++\nattack rate = ", attackRate, ", defense rate = ", defenseRate, "\n")
    
    # creates an empty None object that will store the payoff matrices later.
    payoffsList <- NULL  
    
    # in theory we could loop for all target nodes, but we have only one here since we merged them
    for(target in target_list) {  
     
      # create empty list 
      payoffMatrix <- list() 

      # This loop runs over all nodes that the defender can inspect
      for(i in as1) { 
        # So for ONE node now we loop over all possible attack paths for the attacker
        # routes = [[1,2,8], [1,3,4,8], [1,2,8]]
        for(path in as2) { 
          # Creates list of zeros with length of V
          # Remember V = [1,2,3,4,8] (UNIQUE nodes across all attack paths)
          # U = [0, 0, 0, 0, 0]
          U <- rep(0, length(V))

          # creates a dictionary 
          # U = {1:0, 2:0, 3:0, 4:0, 8:0}
          names(U) <- V
          
          # we do this for one specific node and for one specific path (iterate)
          # now we iterate over all possible attacker start locations
          # V = [1,2,3,4,8] (UNIQUE nodes across all attack paths)
          # advList = [2,3,4] (Potential starting points of attacker)


          for(avatar in advList) {
            
            # Creates another list of zeros with length of V
            L <- rep(0, length(V))

            # Creates another dictionary
            # L = {1:0, 2:0, 3:0, 4:0, 8:0}
            names(L) <- V

            # since it is totally possible that "avatar" is not in the current path
            if (avatar %in% path) {

              # this creates only the "leftover" path from the current avatar location
              # path = [1,2,4,8]
              # avatar = 2
              # route = [2,4,8]
              route <- path[which(path == avatar):length(path)]
              
              # This gives us the poisson distr. for how many steps the attacker will take
              # pdfD = [0.15, 0.30, 0.30, 0.20, 0.05] 
              pdfD <- randomSteps(route, attackRate, defenseRate)
               
              # this case handles a situation where 
              # as1 (set of nodes defender can act on) could in theory not be contained in the 
              # path (route) we are looking at, This would return -1 which would be problematic
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

