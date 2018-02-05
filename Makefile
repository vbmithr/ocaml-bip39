all:
	jbuilder build @install @runtest-bip39
.PHONY: clean
clean:
	rm -rf _build
