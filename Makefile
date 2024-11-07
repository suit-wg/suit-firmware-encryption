DOCUMENT=draft-ietf-suit-firmware-encryption

.PHONY: all
all: $(DOCUMENT).xml

$(DOCUMENT).xml: $(DOCUMENT).md
	kdrfc -ht3 $<

.PHONY: clean
clean:
	$(RM) $(DOCUMENT).xml $(DOCUMENT).html $(DOCUMENT).txt
