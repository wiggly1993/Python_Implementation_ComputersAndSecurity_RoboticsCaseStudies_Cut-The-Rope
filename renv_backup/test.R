tryCatch({
    library(HyRiM)
    library(Rglpk)
    print("Packages loaded successfully")
}, error = function(e) {
    print(paste("Error:", e$message))
})