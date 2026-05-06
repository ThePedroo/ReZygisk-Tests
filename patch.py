original = "CC_ARCH = $(CC) --target=$(TARGET_$(ARCH)) --sysroot=$(SYSROOT)"
new = "CC_ARCH = $(CC) --target=$(TARGET_$(ARCH))"

files = [
    "loader/src/external/csoloader/Makefile",
    "loader/src/external/plti/Makefile"
]

for file in files:
    with open(file, "r") as f:
        content = f.read()
    
    content = content.replace(original, new)
    
    with open(file, "w") as f:
        f.write(content)