"""Export scientific figures for the local MPC-Aion learning-process audit."""
import argparse
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np


def export(directory):
    body=json.loads((directory/"results.json").read_text())
    baseline,filtered=body["cases"]
    mode=body["manifest"]["config"].get("threshold_mode","dynamic")
    boundary_label="Static threshold" if mode=="static" else "Current dynamic filter"
    blue,red="#2374ab","#c43c39"
    fig,axes=plt.subplots(2,2,figsize=(12,8),layout="constrained")
    for case,color,label in ((baseline,blue,"Quantized, no filter"),(filtered,red,boundary_label)):
        axes[0,0].plot([r["round"] for r in case["history"]],
            [100*r["accuracy"] for r in case["history"]],marker="o",color=color,label=label)
    if mode=="dynamic":
        axes[0,0].axvline(6,color="#777",ls=":",lw=1)
    axes[0,0].set(title="Honest non-IID learning",xlabel="Round",ylabel="Test accuracy (%)",ylim=(0,100))
    axes[0,0].legend(fontsize=9)
    rounds=[r["round"] for r in filtered["history"][1:]]
    axes[0,1].plot(rounds,[r["squared_norms_real"][1] for r in baseline["history"][1:]],
        color=blue,ls="--",label="Client 1, no filter")
    axes[0,1].plot(rounds,[r["squared_norms_real"][1] for r in filtered["history"][1:]],
        color=red,marker="o",label="Client 1, static path" if mode=="static" else "Client 1, dynamic path")
    axes[0,1].plot(rounds,[r["threshold_squared_real"] for r in filtered["history"][1:]],
        color="#333",lw=2,label="Acceptance boundary T / S²")
    axes[0,1].set(title="Client 1 norm and fixed threshold" if mode=="static" else "Client 1 is repeatedly excluded",xlabel="Round",ylabel="Squared L2 in real units")
    axes[0,1].legend(fontsize=9)
    accepted=np.asarray([[int(i in r["accepted_clients"]) for r in filtered["history"][1:]] for i in range(4)])
    axes[1,0].imshow(accepted,cmap="RdYlGn",vmin=0,vmax=1,aspect="auto")
    for i in range(4):
        for j in range(len(rounds)):
            axes[1,0].text(j,i,"Pass" if accepted[i,j] else "Drop",ha="center",va="center",fontsize=8)
    axes[1,0].set(title="All four clients are honest",xlabel="Round",xticks=range(len(rounds)),xticklabels=rounds,
        yticks=range(4),yticklabels=["C0: classes 0,1,2","C1: classes 2,3,4","C2: classes 5,6,7","C3: classes 7,8,9"])
    x=np.arange(10)
    axes[1,1].bar(x-.2,100*np.asarray(baseline["history"][-1]["per_class_accuracy"]),width=.4,color=blue,label="No filter")
    axes[1,1].bar(x+.2,100*np.asarray(filtered["history"][-1]["per_class_accuracy"]),width=.4,color=red,label=boundary_label)
    axes[1,1].set(title=f"Final class accuracy at round {body['manifest']['config']['rounds']}",xlabel="Class",ylabel="Accuracy (%)",xticks=x,ylim=(0,105))
    axes[1,1].legend(fontsize=9)
    for ax in (axes[0,0],axes[0,1],axes[1,1]): ax.grid(axis="y",alpha=.2)
    fig.suptitle("FMNIST / LeNet5 / 4 honest clients / seed 42\nPlaintext MPC-function reference; no native MPC execution",fontsize=13)
    for suffix in ("png","svg"):
        fig.savefig(directory/f"learning-process.{suffix}",dpi=160)
    plt.close(fig)


if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory",type=Path,required=True)
    args=parser.parse_args()
    export(args.directory)
