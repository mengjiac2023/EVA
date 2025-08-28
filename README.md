# EVA

EVA is a system built for privacy-preserving federated learning, where individual training weights are aggregated using secure aggregation. 

WARNING: This is an academic proof-of-concept prototype and is not production-ready.

## Overview
We integrate our code into [ABIDES](https://github.com/jpmorganchase/abides-jpmc-public), an open-source highfidelity simulator designed for AI research in financial markets (e.g., stock exchanges). 
The simulator supports tens of thousands of clients interacting with a server to facilitate transactions (and in our case to compute sums). 
It also supports configurable pairwise network latencies.

EVA protocol works by steps (i.e., round trips). 
A step includes waiting and processing messages. 
See more details in our paper.
## Pure Summation
### EVA
EVA supports batches of clients with size power of 2, starting from 128,
e.g., 128, 256, 512.

Example command:
```
python abides.py -c eva -n 128
```
### Flamingo
And for Flamingo, similar instructions can be run after entering into corresponding folder, that is, flamingo or FedAvg.

Example command:
```
python abides.py -c flamingo -n 256
```

##  ML Application
Our program has multiple configs.
```
-c [protocol name] 
-n [number of clients (power of 2)]
```
The machine learning model we use in this repository is a multi-layer perceptron classifier (`MLPClassfier` in `sklearn`) that can pull a variety of different datasets from the [pmlb website](https://epistasislab.github.io/pmlb/index.html). Users might wish to implement more complex models themselves.

Beyond the aforementioned configs, we provide machine learning training configs below.
```
-t [dataset name]
-s [random seed (optional)]
-e [input vector length]
-x [float-as-int encoding constant (optional)]
-y [float-as-int multiplier (optional)]
```

Example command: 
```
python abides.py -c eva -n 128 -i 5 -p 1 -t mnist 
```
### EVA
EVA supports batches of clients with size power of 2, starting from 128,
e.g., 128, 256, 512.

Example command:
```
python abides.py -c eva -n 128
```
### Flamingo and FedAvg
And for Flamingo and FedAvg, similar instructions can be run after entering into corresponding folder, that is, flamingo or FedAvg.

Example commands:
```
python abides.py -c flamingo -n 256
```
```
python abides.py -c fedavg -n 128
```

## Acknowledgement
We thank authors of [Flamingo](https://ieeexplore.ieee.org/stamp/stamp.jsp?tp=&arnumber=10179434) for providing an example template of ABIDES framework.

