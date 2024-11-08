# tryCatch({
#     library(HyRiM)
#     library(Rglpk)
#     print("Packages loaded successfully")
# }, error = function(e) {
#     print(paste("Error:", e$message))
# })

# print("hello world")


# Create a vector of numbers
x <- c(1, 2, 3, 4, 5)
y <- x^2

# Print some basic statistics
print("Basic Statistics:")
print(paste("Mean of x:", mean(x)))
print(paste("Sum of x:", sum(x)))

# Create a simple plot
plot(x, y, 
     type = "o",
     col = "blue",
     main = "Simple Test Plot",
     xlab = "X values",
     ylab = "Y values (X squared)")