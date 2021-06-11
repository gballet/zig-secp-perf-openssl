load package statistics
M = load("zig.csv")
sec = M(M(:,1) == 1, 2)
ed = M(M(:,1) == 2, 2)
boxplot({sec,ed})
set(gca (), "xtick", [1 2], "xticklabel", {"secp256k1", "ed25519"})
ylabel("ns")
