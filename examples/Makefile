SUIT_ENCRYPTION_INFO := suit-encryption-info-aes-kw.cose suit-encryption-info-es-ecdh.cose
SUIT_MANIFEST_WITH_ENCRYPTED_PAYLOAD := suit-manifest-aes-kw.suit suit-manifest-aes-kw-content.suit suit-manifest-es-ecdh-content.suit suit-manifest-es-ecdh-dependency.suit
KDF_CONTEXT := a128kw_kdf_context.cbor
CDDL := draft-ietf-suit-firmware-encryption.cddl draft-ietf-suit-manifest.cddl draft-ietf-suit-firmware-encryption-kdf-context.cddl

.PHONY: all
all: $(SUIT_ENCRYPTION_INFO) $(SUIT_ENCRYPTION_INFO:.cose=.hex) $(SUIT_MANIFEST_WITH_ENCRYPTED_PAYLOAD) $(KDF_CONTEXT)

%.cose: %.diag
	diag2cbor.rb $< > $@

%.hex: %.cose
	xxd -p -u -c 30 $< > $@

%.cbor: %.diag
	diag2cbor.rb $< > $@

%.suit: %.diag.signed
	diag2cbor.rb $< > $@

.PHONY: cddl
cddl: $(CDDL)

draft-ietf-suit-firmware-encryption.cddl: ../draft-ietf-suit-firmware-encryption.cddl rfc-9052.cddl
	cat $^ > $@

draft-ietf-suit-trust-domains.cddl:
	curl --retry 3 https://raw.githubusercontent.com/suit-wg/suit-multiple-trust-domains/main/draft-ietf-suit-trust-domains.cddl -o $@

draft-ietf-suit-manifest.cddl: draft-ietf-suit-firmware-encryption.cddl draft-ietf-suit-trust-domains.cddl
	curl --retry 3 https://raw.githubusercontent.com/suit-wg/manifest-spec/master/draft-ietf-suit-manifest.cddl -o $@
	cat draft-ietf-suit-firmware-encryption.cddl >> $@
	cat draft-ietf-suit-trust-domains.cddl >> $@

rfc-9052.cddl: rfc-9052.xml
	sed -n -e '/<sourcecode type="CDDL"/,/<\/sourcecode/ p' $< | sed -e '/<sourcecode type="CDDL"/ d' -e '/<\/sourcecode/ d' -e '/<\/section>/,/<figure title=""/ d' -e 's/\&gt;/>/g' > $@

rfc-9052.xml:
	curl --retry 3 https://raw.githubusercontent.com/cose-wg/cose-rfc8152bis/master/draft-ietf-cose-rfc8152bis-struct.xml -o $@

draft-ietf-suit-firmware-encryption-kdf-context.cddl: draft-ietf-suit-firmware-encryption.cddl
	cat ../$@ $^ > $@

.PHONY: validate
validate: all cddl
	cddl draft-ietf-suit-firmware-encryption.cddl validate suit-encryption-info-aes-kw.cose
	cddl draft-ietf-suit-firmware-encryption.cddl validate suit-encryption-info-es-ecdh.cose
	cddl draft-ietf-suit-manifest.cddl validate suit-manifest-aes-kw.suit
	cddl draft-ietf-suit-manifest.cddl validate suit-manifest-aes-kw-content.suit
	cddl draft-ietf-suit-manifest.cddl validate suit-manifest-es-ecdh-content.suit
	cddl draft-ietf-suit-manifest.cddl validate suit-manifest-es-ecdh-dependency.suit
	cddl draft-ietf-suit-firmware-encryption-kdf-context.cddl validate a128kw_kdf_context.cbor
	python3 ./validate_aeskw_suit_encryption_info.py
	python3 ./validate_esdh_suit_encryption_info.py

.PHONY: clean
clean:
	$(RM) *.cose *.suit *.xml *.cddl
