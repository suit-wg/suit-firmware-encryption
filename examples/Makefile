SUIT_ENCRYPTION_INFO := \
	suit-encryption-info-aes-kw-aes-gcm.cose \
	suit-encryption-info-es-ecdh-aes-gcm.cose \
	suit-encryption-info-aes-kw-aes-cbc.cose \
	suit-encryption-info-es-ecdh-aes-cbc.cose \
	suit-encryption-info-aes-kw-aes-ctr.cose \
	suit-encryption-info-es-ecdh-aes-ctr.cose

SUIT_MANIFEST_WITH_ENCRYPTED_PAYLOAD := \
	suit-manifest-aes-kw.suit \
	suit-manifest-aes-kw-content.suit \
	suit-manifest-es-ecdh-content.suit \
	suit-manifest-es-ecdh-dependency.suit

.PHONY: all
all: $(SUIT_ENCRYPTION_INFO) $(SUIT_MANIFEST_WITH_ENCRYPTED_PAYLOAD)

%.cose: %.diag
	diag2cbor.rb $< > $@

%.suit: %.diag.signed
	diag2cbor.rb $< > $@

%.hex.cose: %.hex
	pretty2cbor.rb $< > $@

.PHONY: cddl
cddl: draft-ietf-suit-firmware-encryption.cddl draft-ietf-suit-manifest.cddl

draft-ietf-suit-firmware-encryption.cddl: ../draft-ietf-suit-firmware-encryption.cddl rfc-9052.cddl
	cat $^ > $@

draft-ietf-suit-manifest.cddl: draft-ietf-suit-firmware-encryption.cddl
	curl https://raw.githubusercontent.com/suit-wg/manifest-spec/master/draft-ietf-suit-manifest.cddl -o $@
	cat draft-ietf-suit-firmware-encryption.cddl >> $@

rfc-9052.cddl: rfc-9052.xml
	sed -n -e '/<sourcecode type="CDDL"/,/<\/sourcecode/ p' $< | sed -e '/<sourcecode type="CDDL"/ d' -e '/<\/sourcecode/ d' -e '/<\/section>/,/<figure title=""/ d' -e 's/\&gt;/>/g' > $@

rfc-9052.xml:
	curl https://raw.githubusercontent.com/cose-wg/cose-rfc8152bis/master/draft-ietf-cose-rfc8152bis-struct.xml -o $@

.PHONY: validate
validate: all cddl validate_binary_match
	cddl draft-ietf-suit-firmware-encryption.cddl validate suit-encryption-info-aes-kw.cose
	cddl draft-ietf-suit-firmware-encryption.cddl validate suit-encryption-info-es-ecdh.cose
	cddl draft-ietf-suit-manifest.cddl validate suit-manifest-aes-kw.suit

define CheckMatch
	diff $(1) $(1:.cose=.hex.cose)

endef

.PHONY: validate_binary_match
validate_binary_match: $(SUIT_ENCRYPTION_INFO) $(SUIT_ENCRYPTION_INFO:.cose=.hex.cose)
	$(foreach s,$(SUIT_ENCRYPTION_INFO),$(call CheckMatch,$(s)))

.PHONY: clean
clean:
	$(RM) *.cose *.suit *.xml *.cddl
