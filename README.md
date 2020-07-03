# cryptanalysisSHMWW
Cryptanalysis of Song *et al.* code-based signature scheme, publishesd in [Theoretical Computer Science](https://doi.org/10.1016/j.tcs.2020.05.011)

This repository hosts:
1. a (raw) sage implementation of the code-based signature scheme proposed by Song, Huang, Mu, Wu, and Wang [Theoretical Computer Science](https://doi.org/10.1016/j.tcs.2020.05.011) (file `SHMWW.sage`),
1. a cryptanalysis implementation that recovers the secret key from a few hundreds of signatures (file `SHMWW_cryptanalysis.sage`). 

## Generating an instance and signatures

Song *et al.* proposed two sets of parameters: PARA-1 and PARA-2 respectively targeting 80 and 128 bits of classical security (see Table 1 of [SHMWW]).

To generate an instance of PARA-X along with N signatures for that instance:
1. Modify line 4 of `SHMWW.sage` into `__PARAMETER_SET__ = X`
1. Modify line 5 of `SHMWW.sage` into `__NUMBER_OF_SIGS__ = N`
1. Run `sage`
1. Load and run the script: `%runfile SHMWW.sage`

This script generates three files:
1. `PARA-Xpk` that contains the public key under the form
```
[
[ first line of H ]
[       ...       ]
[ last line of H  ]
]
[
[ first line of S ]
[       ...       ]
[ last line of S  ]
]
```
2. `PARA-Xsk` that contains the secret key under the form
```
[
[ first line of E ]
[       ...       ]
[ last line of E  ]
]
```
3. `PARA-Xsig` that contains N signatures under the form
```
[ vector z of length n  ]
[ vector c of length k' ]
[ commitment vector of length n-k ]
```

For cryptanalytic purposes, the use of a weight restricted hash (WRH) function is not mandatory. Instead, we generate the challenge as a vector c of same lenght (h') and weight (w_1) as the output of the WRH function described in [SHMWW].

Verbose mode can be turned off by setting `__VERBOSE__ = 0` on line 8 of `SHMWW.sage`. Manual configuration on the fly can be turned on by setting `__MANUAL_SETUP__ = 1` on line 7 of `SHMWW.sage`.

## Running the cryptanalysis

To run the cryptanalysis:
1. set the instance (1 or 2), number of signatures, and filename in lines 5, 6, and 7 of `SHMWW_cryptanalysis.sage`
1. run sage
1. load and run the cryptanlysis script: `%runfile SHMWW_cryptanalysis.sage`

The scripts reads `pk` and the signatures, prints the number of lines of `sk` recovered and when done, compares the recovered secret key to the original one.

Depending on the instance, the number of signatures available and your machine, the scripts may take more than 30 minutes to complete.

## Technical details and reference

The technical details about the cryptanalysis will be soon provided in a complete paper.

[SHMWW] Song, Y., Huang, X., Mu, Y., Wu, W., & Wang, H. (2020). *A code-based signature scheme from the Lyubashevsky framework*. Theoretical Computer Science.
