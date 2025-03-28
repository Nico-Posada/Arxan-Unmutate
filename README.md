# Arxan-Unmutate
IDAPython script to unmutate common arxan mutations on x86-64 protected games

This is being uploaded for educational purposes only.

I probably missed a few mutations, if there's any you find that this script doesnt account for, just create an issue with an example of the mutation and what it simplifies to. This was made by analyzing Call of Duty builds, so it'll work best for that game.

# NOTE
- This was made using IDA9.0's IDAPython API, this script may not work on older versions of the API (open an issue if there's any problems with that)
- I use a fair amount of typing utility here which may not be compatible on older versions of Python. I'll probably remove all that later on since a lot of people are too lazy to update python versions (3.13 is out guys)

# TODO
- Maybe add setting to allow users to trust IDA if it says a function is no-return (edge case)
- Minimal GUI to set start address and other settings
