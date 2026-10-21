## A goal without a process: swarming closed source solana programs

[swarm of birds doing something beautiful and complex, guided by simple rules](./swarm.png)

Reverse engineering is solved, or so they say.

This (seemigly nerdy and niche) statement should be considered carefully: reverse engineering is essentially the art of pure understanding and simplyfing.

LLMs are particulary suited to this kind of problem by nature: any kind of program is fully clear, syntantically, to a computer, and yet, its semantics come from thin and distant connections, all downstream of external inputs down to effects, all somehow cross correlated and intertwined.

A good reverse engineer manually spreads that initial context, easily observed by just executing the program and by understand its goal, into the internal structures (the processes) of the system: one might ultimately realize that the system's goal is subverted by certain inputs, or the actual processes themselves might be of inspiration for a transplant for other programs.

LLMs can automatically build an internal representation of those connections to the function of the program, they can experiement with hundreds of parallel inputs, and with those augmented static and dynamic capabilities, any model will be able to tell you everything about how something works given a binary as of now.

If roughly "knowing what is does" is the definition of reverse engineering, then yes, we can call the problem solved and all go home.

I dare to say that with more powerful tools, we should be more ambicious than that.
One rigorous, yet seldom explored, definition of truly reverse engineering something is "recompilation": fully recovering the source code and compiling an identical binary (with the right toolchains).


So, is that reverse engineering solved?

## Calling all agents

https://huggingface.co/blog/MatthewReingold/n64-decomp-dev-blog

n64decomp/007
doldecomp/melee


https://arxiv.org/pdf/2605.29059




