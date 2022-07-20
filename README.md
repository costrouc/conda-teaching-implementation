# Conda teaching implementation

In the following repository there is an implementation of Conda. While
working with Conda and
[conda-store](https://github.com/quansight/conda-store) I have to ask
core [Conda](https://conda.io/) and
[Conda-Forge](https://conda-forge.org/) developers many questions. I
thought it would be nice to write a reference implementation with the
core goal of teaching the inner workings of Conda. With this goal in
mind the following principles were followed:

 - only uses the python `stdlib`
 - understandability is key
 - correctness is important
 - performance is not important
