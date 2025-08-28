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

## EVA ( Pure Summation ) 


Our program has multiple configs.
```
-c [protocol name] 
-n [number of clients (power of 2)]
```
EVA supports batches of clients with size power of 2, starting from 128,
e.g., 128, 256, 512.

Example command:
```
python abides.py -c eva -n 128
```

## Acknowledgement
We thank authors of [Flamingo](https://ieeexplore.ieee.org/stamp/stamp.jsp?tp=&arnumber=10179434) for providing an example template of ABIDES framework.

