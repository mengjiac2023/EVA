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

## Set Up
Create an environment with python 3.9.12 and then activate it:
```bash
conda create --name evaEnv python=3.9.12
conda activate evaEnv
```
Use pip to install required packages:
```bash
pip install -r requirements.txt
```

## Pure Summation
The code for this task is located in the **SumTask** folder.

Our program supports multiple configurations with the following options:

- `-c [protocol name]` : protocol to use (e.g., `eva`, `flamingo`)  
- `-n [number of clients]` : must be a power of 2  
- `-i [number of iterations]` : number of iterations  
- `-p [parallel or not]` : set `1` for parallel, `0` for sequential  
- `-o [neighborhood size]` : multiplicative factor of `2logn`  

EVA supports batches of clients with size power of 2, starting from 128,
e.g., 128, 256, 512.

**Examples:**

For **EVA**, run:
```bash
python abides.py -c eva -n 128 -i 1
```
For **Flamingo**, run
```bash
python abides.py -c flamingo -n 128 -i 1
```


##  Machine Learning Applications
We provide three protocols: **EVA**, **Flamingo**, and **FedAvg**, located in the `eva`, `flamingo`, and `fedavg` folders respectively.
Each protocol supports the following parameters:
- `-t [dataset name]` : training dataset  
- `-c [protocol name]` : protocol to use (e.g., `eva`, `flamingo`)  
- `-n [number of clients]` : must be a power of 2  
- `-i [number of iterations]` : number of iterations  
- `-p [parallel or not]` : set `1` for parallel, `0` for sequential  
- `-o [neighborhood size]` : multiplicative factor of `2logn`

**Examples (using MNIST):**

For **EVA**, enter the `EVA` folder and run:
```bash
python abides.py -c eva -t mnist -n 128 -i 3
```
For Flamingo, enter the `Flamingo` folder and run:
```bash
python abides.py -c flamingo -t mnist -n 128 -i 3
```
For FedAvg, enter the `FedAvg` folder and run:
```bash
python abides.py -c fedavg -t mnist -n 128 -i 3
```
## Acknowledgement
We thank authors of [Flamingo](https://github.com/eniac/flamingo) for providing an example template of ABIDES framework.

