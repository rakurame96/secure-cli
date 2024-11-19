with open("largefile.txt", "w") as f:
    # f.write("A" * 1073741824)  # 1GB file with repeated 'A' characters
    f.write("A" * 1073700)  # 1GB file with repeated 'A' characters
