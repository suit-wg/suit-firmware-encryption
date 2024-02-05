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

KDF_CONTEXT := a128kw_kdf_context.cbor

CDDL := \
	draft-ietf-suit-firmware-encryption.cddl \
	aeskw.cddl \
	esdh_aeskw.cddl \
	draft-ietf-suit-manifest.cddl

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

%.hex.cose: %.hex
	pretty2cbor.rb $< > $@

.PHONY: cddl
cddl: $(CDDL)

draft-ietf-suit-firmware-encryption.cddl: ../draft-ietf-suit-firmware-encryption.cddl rfc-9052.cddl
	cat $^ > $@

aeskw.cddl: ../cddls/aeskw.cddl rfc-9052.cddl
	cat $^ > $@

esdh_aeskw.cddl: ../cddls/esdh_aeskw.cddl rfc-9052.cddl
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

.PHONY: validate
validate: all cddl validate_binary_match validate_cddl_match validate_decrypted_plaintext

define CheckMatch
	diff $(1) $(1:.cose=.hex.cose)

endef

.PHONY: validate_binary_match
validate_binary_match: $(SUIT_ENCRYPTION_INFO) $(SUIT_ENCRYPTION_INFO:.cose=.hex.cose)
	$(foreach s,$(SUIT_ENCRYPTION_INFO),$(call CheckMatch,$(s)))
	@echo [SUCCESS] Each binaries from diag matches to one from hex

.PHONY: validate_cddl_match
validate_cddl_match: all cddl
	RUBYOPT="-W0" cddl draft-ietf-suit-firmware-encryption.cddl validate suit-encryption-info-aes-kw-aes-gcm.cose
	RUBYOPT="-W0" cddl aeskw.cddl validate suit-encryption-info-aes-kw-aes-gcm.cose
	RUBYOPT="-W0" cddl draft-ietf-suit-firmware-encryption.cddl validate suit-encryption-info-es-ecdh-aes-gcm.cose
	RUBYOPT="-W0" cddl esdh_aeskw.cddl validate suit-encryption-info-es-ecdh-aes-gcm.cose
	RUBYOPT="-W0" cddl draft-ietf-suit-firmware-encryption.cddl validate suit-encryption-info-aes-kw-aes-cbc.cose
	RUBYOPT="-W0" cddl aeskw.cddl validate suit-encryption-info-aes-kw-aes-cbc.cose
	RUBYOPT="-W0" cddl draft-ietf-suit-firmware-encryption.cddl validate suit-encryption-info-es-ecdh-aes-cbc.cose
	RUBYOPT="-W0" cddl esdh_aeskw.cddl validate suit-encryption-info-es-ecdh-aes-cbc.cose
	RUBYOPT="-W0" cddl draft-ietf-suit-firmware-encryption.cddl validate suit-encryption-info-aes-kw-aes-ctr.cose
	RUBYOPT="-W0" cddl aeskw.cddl validate suit-encryption-info-aes-kw-aes-ctr.cose
	RUBYOPT="-W0" cddl draft-ietf-suit-firmware-encryption.cddl validate suit-encryption-info-es-ecdh-aes-ctr.cose
	RUBYOPT="-W0" cddl esdh_aeskw.cddl validate suit-encryption-info-es-ecdh-aes-ctr.cose
	@echo [SUCCESS] Each SUIT_Encryption_Info matches to its CDDL
	RUBYOPT="-W0" cddl draft-ietf-suit-manifest.cddl validate suit-manifest-aes-kw.suit
	RUBYOPT="-W0" cddl draft-ietf-suit-manifest.cddl validate suit-manifest-aes-kw-content.suit
	RUBYOPT="-W0" cddl draft-ietf-suit-manifest.cddl validate suit-manifest-es-ecdh-content.suit
	RUBYOPT="-W0" cddl draft-ietf-suit-manifest.cddl validate suit-manifest-es-ecdh-dependency.suit
	@echo [SUCCESS] Each SUIT Manifest with Encrypted Payloads matches to its CDDL
	RUBYOPT="-W0" cddl ../cddls/kdf-context.cddl validate a128kw_kdf_context.cbor
	@echo [SUCCESS] KDF Context matches to its CDDL

.PHONY: validate_decrypted_plaintext
validate_decrypted_plaintext:
	python3 ./validate_aeskw_suit_encryption_info.py
	python3 ./validate_esdh_suit_encryption_info.py
	@echo [SUCCESS] The expected plaintext firmware can be decrypted

.PHONY: clean
clean:
	$(RM) *.cose *.suit *.xml *.cddl
