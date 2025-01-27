# Arxan-Unmutate
IDAPython script to unmutate common arxan mutations on x86-64 protected games

This is being uploaded for educational purposes only.

I probably missed a few mutations, if there's any you find that this script doesnt account for, just create an issue with an example of the mutation and what it simplifies to. This was made by analyzing Call of Duty builds, so it'll work best for that game.

# TODO
- Break out of script gracefully after initial analysis if DO_PATCH is disabled
- Account for weird edge cases like interrupts
- Maybe add setting to allow users to trust IDA if it says a function is no-return (edge case)
