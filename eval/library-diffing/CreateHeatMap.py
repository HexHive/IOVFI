import numpy as np
import matplotlib
import matplotlib.pyplot as plt

versions = ["1.2.7", "1.2.7.1", "1.2.7.2", "1.2.7.3",	"1.2.8", "1.2.9",
              "1.2.10", "1.2.11"]
reverse_versions = ["1.2.7", "1.2.7.1", "1.2.7.2", "1.2.7.3",	"1.2.8", "1.2.9",
                    "1.2.10", "1.2.11"]
reverse_versions.reverse()

diffs = np.array([[0.09090909091, 0.09917355372, 0.09917355372,
                     0.09917355372, 0.09917355372, 0.04132231405,
                     0.03305785124, 0],
                    [0.1092436975, 0.1176470588, 0.1176470588, 0.1176470588,
                     0.1176470588, 0.05042016807, 0, 0.05042016807],
                    [0.1333333333, 0.15, 0.15, 0.1666666667,
                     0.1583333333, 0, 0.09166666667, 0.09166666667],
                    [0.04587155963, 0.04587155963, 0.04587155963,
                     0.03669724771, 0, 0.2293577982, 0.2293577982,
                     0.2293577982],
                    [0.06306306306, 0.06306306306, 0.06306306306, 0,
                     0.06306306306, 0.2072072072, 0.1981981982, 0.1981981982],
                    [0.06422018349, 0.04587155963, 0, 0.06422018349,
                     0.05504587156, 0.2201834862, 0.2018348624, 0.2018348624],
                    [0.07272727273, 0, 0.07272727273, 0.07272727273,
                     0.07272727273, 0.2545454545, 0.2454545455, 0.2454545455],
                    [0, 0.08411214953, 0.1028037383, 0.1214953271,
                     0.1028037383, 0.2429906542, 0.2523364486, 0.261682243]])

git_diffs = np.array([
    ["", "", "", "", "", "", "", "(0, 0)"],
    ["", "", "", "", "", "", "(0, 0)", "(25, 31)"],
    ["", "", "", "", "", "(0, 0)", "(50, 44)", "(72, 60)"],
    ["", "", "", "", "(0, 0)", "(1644, 1007)", "(1657, 1014)", "(1663, 1014)"],
    ["", "", "", "(0, 0)", "(97, 25)", "(1729, 1020)", "(1742, 1027)",
     "(1748, 1027)"],
    ["", "", "(0, 0)", "(9, 9)", "(97, 25)", "(1729, 1020)", "(1742, 1027)",
     "(1748, 1027)"],
    ["", "(0, 0)", "(17, 16)", "(17, 16)", "(105, 32)", "(1735, 1025)",
     "(1748, 1032)", "(1754, 1032)"],
    ["(0, 0)", "(358, 218)", "(360, 219)", "(360, 219)", "(445, 232)",
     "(2041, 1191)", "(2050, 1194)", "(2056, 1194)"],
])


fig, ax = plt.subplots()
im = ax.imshow(diffs)

cbar = ax.figure.colorbar(im, ax=ax)
cbar.ax.set_ylabel("Percent difference", rotation=-90, va="bottom")

# We want to show all ticks...
ax.set_xticks(np.arange(len(versions)))
ax.set_yticks(np.arange(len(versions)))
# ... and label them with the respective list entries
ax.set_xticklabels(versions)
ax.set_yticklabels(reverse_versions)

# Rotate the tick labels and set their alignment.
plt.setp(ax.get_xticklabels(), rotation=45, ha="right",
         rotation_mode="anchor")

# Loop over data dimensions and create text annotations.
for i in range(len(versions)):
    for j in range(len(versions)):
        text = ax.text(j, i, git_diffs[i, j],
                       ha="center", va="center", color="r")

ax.set_title("Measured semantic differences")
fig.tight_layout()
fig.set_size_inches(11, 10)
plt.savefig('difference.pdf', bbox_inches='tight')