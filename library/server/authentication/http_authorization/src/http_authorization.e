note
	description : "[
			Object representing Authorization http header
		]"
	date: "$Date$"
	revision: "$Revision$"
	EIS: "name=RFC2617 HTTP Authentication: Basic and Digest Access Authentication", "protocol=URI", "src=http://tools.ietf.org/html/rfc2617"
	EIS: "name=Wikipedia Basic Access Authentication", "protocol=URI", "src=http://en.wikipedia.org/wiki/Basic_access_authentication"
	EIS: "name=Wikipedia Digest Access Authentication", "protocol=URI", "src=http://en.wikipedia.org/wiki/Digest_access_authentication"

class
	HTTP_AUTHORIZATION

inherit
	REFACTORING_HELPER

	DEBUG_OUTPUT

create
	make,
	make_basic_auth,
	make_custom_auth

feature -- Initialization

	make (a_http_authorization: READABLE_STRING_8)
			-- Initialize `Current'.
			-- Parse authorization header.
		local
			i: INTEGER
			t, s: STRING_8
			u,p: READABLE_STRING_32
			utf: UTF_CONVERTER
			empty_string_8: STRING_8
		do
			create empty_string_8.make_empty

			password := Void

			create http_authorization.make_from_string (a_http_authorization)
			create t.make_empty
			type := t

			if not a_http_authorization.is_empty then
				i := 1
				if a_http_authorization[i] = ' ' then
					i := i + 1
				end
				i := a_http_authorization.index_of (' ', i)
				if i > 0 then
					t.append (a_http_authorization.substring (1, i - 1))
					t.right_adjust; t.left_adjust

					if t.same_string (Basic_auth_type) then
						type := Basic_auth_type
						s := (create {BASE64}).decoded_string (a_http_authorization.substring (i + 1, a_http_authorization.count))
						i := s.index_of (':', 1) --| Let's assume ':' is forbidden in login ...
						if i > 0 then
							u := utf.utf_8_string_8_to_string_32 (s.substring (1, i - 1)) -- UTF_8 decoding to support unicode username
							p := utf.utf_8_string_8_to_string_32 (s.substring (i + 1, s.count)) -- UTF_8 decoding to support unicode password
							login := u
							password := p
							check
								(create {HTTP_AUTHORIZATION}.make_custom_auth (u, p, t)).http_authorization ~ http_authorization
							end
						end
					elseif
						t.same_string (Digest_auth_type)
					then
						type := Digest_auth_type

						-- Try to parse the fields, and set them to the epmty string if they didn't match our expectations.
						-- If fields are not present in the header, leave them unattached (i.e., Void).

						-- Parse response
						response_value := get_header_value_by_key (a_http_authorization, "response")
						if
							attached response_value as attached_response_value and then
							attached_response_value.count /= 34
						then
							-- Response is not valid, set it to empty string.
							response_value := empty_string_8
							is_bad_request := True
						end
						response_value := unquote_string (response_value)
						if
							not attached response_value as attached_response_value or else attached_response_value.is_empty
						then
							is_bad_request := True
						end

						-- Parse login
						login := get_header_value_by_key (a_http_authorization, "username")
						login := unquote_string (login)

						-- Parse realm
						-- XXX Add further tests for validity of realm value.
						realm_value := get_header_value_by_key (a_http_authorization, "realm")
						realm_value := unquote_string (realm_value)

						-- Parse nonce
						nonce_value := get_header_value_by_key (a_http_authorization, "nonce")
						nonce_value := unquote_string (nonce_value)

						-- Parse uri
						uri_value := get_header_value_by_key (a_http_authorization, "uri")
						uri_value := unquote_string (uri_value)

						-- Parse qop
						qop_value := get_header_value_by_key (a_http_authorization, "qop")
						if
							attached qop_value as attached_qop_value and then
							not attached_qop_value.is_equal ("auth")
						then
							-- If the qop field is present, it has to be auth.
							-- Other quality of protection is not supported so far.
							qop_value := empty_string_8
							is_bad_request := True
						end

						-- Parse algorithm
						algorithm_value := get_header_value_by_key (a_http_authorization, "algorithm")
						check
							is_MD5: not attached algorithm_value as attached_algorithm_value or else (attached_algorithm_value.is_empty or attached_algorithm_value.is_case_insensitive_equal ("MD5"))
						end
						if
							attached algorithm_value as attached_algorithm_value and then
							not attached_algorithm_value.is_equal ("MD5")
						then
							-- If the algorithm field is present, it has to be MD5.
							algorithm_value := empty_string_8
							is_bad_request := True
						end

						-- Parse nc
						nc_value := get_header_value_by_key (a_http_authorization, "nc")
						if
							attached nc_value as attached_nc_value and then
							attached_nc_value.count /= 8
						then
							-- If the nc field is present, it has to have length 8.
							nc_value := empty_string_8
							is_bad_request := True
						end

						-- Parse cnonce
						cnonce_value := get_header_value_by_key (a_http_authorization, "cnonce")
						cnonce_value := unquote_string (cnonce_value)

						-- Parse opaque
						opaque_value := get_header_value_by_key (a_http_authorization, "opaque")
						opaque_value := unquote_string (opaque_value)


						-- Check that all mandatory fields are actually attached.
						if
							not attached login or
							not attached realm_value or
							not attached nonce_value or
							not attached uri_value or
							not attached response_value
						then
							is_bad_request := True
						end
					else
						-- We don't know authentication method.
						is_bad_request := True
					end
				else
					-- Bad format.
					is_bad_request := True
				end
			end
		ensure
			a_http_authorization /= Void implies http_authorization /= Void
		end

	make_basic_auth (u: READABLE_STRING_32; p: READABLE_STRING_32)
			-- Create a Basic authentication.
		do
			io.putstring ("HTTP_AUTHORIZATION.make_basic_auth()%N")

			make_custom_auth (u, p, Basic_auth_type)
		end

	make_custom_auth (u: READABLE_STRING_32; p: READABLE_STRING_32; a_type: READABLE_STRING_8)
			-- Create a custom `a_type' authentication.
			-- This does not yet support digest authentication.
			-- Should I do this?
		require
			a_type_accepted: a_type.is_case_insensitive_equal (Basic_auth_type)
							or a_type.is_case_insensitive_equal (Digest_auth_type)
		local
			t: STRING_8
			utf: UTF_CONVERTER
		do
			io.putstring ("HTTP_AUTHORIZATION.make_custom_auth()%N")

			login := u
			password := p
			create t.make_from_string (a_type)
			t.left_adjust; t.right_adjust
			type := t
			if t.is_case_insensitive_equal (Basic_auth_type) then
				type := Basic_auth_type
				create http_authorization.make_from_string ("Basic " + (create {BASE64}).encoded_string (utf.string_32_to_utf_8_string_8 (u + {STRING_32} ":" + p)))
			elseif t.is_case_insensitive_equal (Digest_auth_type) then
				type := Digest_auth_type
				to_implement ("HTTP Authorization %""+ t +"%", not yet implemented")
				create http_authorization.make_from_string (t + " ...NOT IMPLEMENTED")
			else
				to_implement ("HTTP Authorization %""+ t +"%", not yet implemented")
				create http_authorization.make_from_string ("Digest ...NOT IMPLEMENTED")
			end
		end

feature -- Access

	http_authorization: IMMUTABLE_STRING_8

	-- We always have a type.
	type: READABLE_STRING_8

	login: detachable READABLE_STRING_8

	password: detachable READABLE_STRING_8

	realm_value: detachable READABLE_STRING_8

	nonce_value: detachable READABLE_STRING_8

	nc_value: detachable READABLE_STRING_8

	cnonce_value: detachable READABLE_STRING_8

	qop_value: detachable READABLE_STRING_8

	response_value: detachable READABLE_STRING_8

	opaque_value: detachable READABLE_STRING_8

	uri_value: detachable READABLE_STRING_8

	algorithm_value: detachable READABLE_STRING_8

feature -- Status report

	is_basic: BOOLEAN
			-- Is Basic authorization?
		do
			Result := type.is_case_insensitive_equal (Basic_auth_type)
		end

	is_digest: BOOLEAN
			-- Is Digest authorization?
		do
			Result := type.is_case_insensitive_equal (Digest_auth_type)
		end

	is_authorized_digest(server_username: READABLE_STRING_8; server_password: READABLE_STRING_8; server_realm: READABLE_STRING_8;
				server_nonce_list: ARRAYED_LIST[STRING_8]; server_method: READABLE_STRING_8; server_uri: READABLE_STRING_8;
				server_algorithm: detachable READABLE_STRING_8; server_qop: detachable READABLE_STRING_8): BOOLEAN
			-- Validates digest authentication.
			--
			-- Here we need the values which the server has sent in the WWW-Authenticate header.
			--
			-- TODO `server_nonce_list' should also contain latest nonce-count values from client.
			-- TODO uri may be changed by proxies. Which uri should we take, the one from the request or the one from the authorization-header?
			-- TODO This method could be modified s.t. it does not take the cleartext password as an argument.
			-- TODO Be more flexible: Do not only support auth, MD5 etc.			
		require
			-- FIXME Is this necessary, or does Eiffel guarantee that this is attached?
			server_arguments_attached:
				attached server_password and
				attached server_username and
				attached server_realm and
				attached server_method and
				attached server_uri and
				attached server_nonce_list
			is_digest: is_digest
		local
			HA1: STRING_8
			HA2: STRING_8
			response_expected: STRING_8
			nonce_found: BOOLEAN
		do
			if
				attached realm_value as attached_realm_value and
				attached response_value as attached_response_value and
				attached nonce_value as attached_nonce_value
			then
				-- Check whether we know the nonce from the Authorization-header.
				-- XXX The following could be optimized, for example move to other position, start at end etc.
				-- XXX We could also make use of 'across' for better readability.
				from
					server_nonce_list.start
				until
					server_nonce_list.exhausted
				loop
					nonce_found := nonce_found or server_nonce_list.item.is_case_insensitive_equal (attached_nonce_value)
					server_nonce_list.forth
				end

				if
					server_nonce_list.last.is_case_insensitive_equal (attached_nonce_value)
				then
					-- The nonce is the one we expected.
					HA1 := compute_hash_a1 (server_username, server_realm, server_password, server_algorithm, attached_nonce_value)

					HA2 := compute_hash_a2 (server_method, server_uri, server_algorithm, server_qop, false)

					response_expected := compute_expected_response (HA1, HA2, attached_nonce_value, server_qop, server_algorithm, nc_value, cnonce_value)

					Result := response_expected.is_equal (attached_response_value)

--					if not Result then
--						io.putstring ("Expected response: " + response_expected + "%N")
--						io.putstring ("Actual response: " + attached_response_value + "%N")
--					else
--						io.putstring ("Expected and actual response: " + response_expected + "%N")
--					end
				elseif
					nonce_found
				then
					-- The nonce is not the one we expected.
					-- Maybe it is in the list of nonces from the client.
					-- Then, the nonce could just be stale, and the user agent doesn't have to prompt for the credentials again.
					-- The result is false anyway.

					HA1 := compute_hash_a1 (server_username, server_realm, server_password, server_algorithm, attached_nonce_value)

					HA2 := compute_hash_a2 (server_method, server_uri, server_algorithm, server_qop, false)

					response_expected := compute_expected_response (HA1, HA2, attached_nonce_value, server_qop, server_algorithm, nc_value, cnonce_value)

					stale := response_expected.is_equal (attached_response_value)

					io.putstring ("Nonce is not the expected one. Stale: " + stale.out + "%N")
				else
					io.putstring ("We don't know this nonce:%N   " + attached_nonce_value + ".%N")
					io.putstring ("We only know those:%N")

					from
						server_nonce_list.start
					until
						server_nonce_list.exhausted
					loop
						io.putstring ("   " + server_nonce_list.item + ".%N")
						server_nonce_list.forth
					end
				end
			else
				io.putstring ("Could not compute expected response since something was not attached.")
			end
		end

	is_quoted (s: STRING_32): BOOLEAN
		-- Returns type iff `s' begins and ends with a quote sign.
		do
			-- Also test that lenght is greater than one, otherwise the string could consist of just one quote sign.
			Result := s.starts_with ("%"") and s.ends_with ("%"") and (s.count >= 2)
		end

	debug_output: STRING_32
			-- String that should be displayed in debugger to represent `Current'.
		do
			create Result.make_empty
			Result.append (type)
			Result.append (" ")
			if attached login as l_login then
				Result.append ("login=[")
				Result.append (l_login)
				Result.append ("] ")
			end
			if attached password as l_password then
				Result.append ("password=[")
				Result.append (l_password)
				Result.append ("] ")
			end
		end

	is_bad_request: BOOLEAN
			-- If a directive or its value is improper, or required directives are missing,
			-- the proper response is 400 Bad Request.
			--
			-- TODO Make more/extensive use of this.

	stale: BOOLEAN
			-- True iff authorization was stale.

feature -- Digest computation

	compute_hash_A1 (server_username: READABLE_STRING_8; server_realm: READABLE_STRING_8; server_password: READABLE_STRING_8; server_algorithm: detachable READABLE_STRING_8; server_nonce: READABLE_STRING_8): STRING_8
			-- Compute H(A1).
		require
			is_digest: is_digest
		local
			hash: MD5
			A1: READABLE_STRING_8
		do
			create hash.make

			A1 := server_username + ":" + server_realm + ":" + server_password

			hash.update_from_string (A1);

			Result := hash.digest_as_string

			Result.to_lower

--			io.putstring ("Computed HA1: " + Result + "%N")
		end

	compute_hash_A2 (server_method: READABLE_STRING_8; server_uri: READABLE_STRING_8; server_algorithm: detachable READABLE_STRING_8; server_qop: detachable READABLE_STRING_8; for_auth_info: BOOLEAN): STRING_8
			-- Compute H(A2)
			-- `for_auth_info' MUST be set to True iff  we compute the hash for the Authentication-Info header.
		local
			hash: MD5
			A2: READABLE_STRING_8
		do
			-- Special treatment of Authentication-Info header.
			if for_auth_info then
				A2 := ":" + server_uri
			else
				A2 := server_method + ":" + server_uri
			end

			create hash.make

			hash.update_from_string (A2)

			Result := hash.digest_as_string

			Result.to_lower

--			io.putstring ("Computed HA2: " + Result + "%N")
		end

	compute_expected_response(ha1: READABLE_STRING_8; ha2: READABLE_STRING_8; server_nonce: READABLE_STRING_8; server_qop: detachable READABLE_STRING_8; server_algorithm: detachable READABLE_STRING_8; a_nc: detachable READABLE_STRING_8; a_cnonce: detachable READABLE_STRING_8) : STRING_8
			-- Computes UNQUOTED expected response.
		local
			hash: MD5
			unhashed_response: READABLE_STRING_8
		do
			create Result.make_empty

			if
				attached server_qop as attached_server_qop
			then
				if
					attached a_nc as attached_nc_value and
					attached a_cnonce as attached_cnonce_value
				then

					-- Standard (for digest) computation of response.

					create hash.make

					unhashed_response := ha1 + ":" + server_nonce + ":" + attached_nc_value + ":" + attached_cnonce_value + ":" + attached_server_qop + ":" + ha2

--						io.put_string ("Expected unhashed response: " + unhashed_response)
--						io.new_line

					hash.update_from_string (unhashed_response)

					Result := hash.digest_as_string

					Result.to_lower

--						io.put_string ("Expected unquoted response: " + Result)
--						io.new_line
				else
					-- TODO Throw an exception. This should be excluded by invariant.
					io.putstring ("ERROR: This should not happen!%N")
				end
			else
				-- qop directive is not present.
				-- Use construction for backwards compatibility with RFC 2069

				io.put_string ("RFC 2069 mode.")
				io.new_line

				create hash.make

				unhashed_response := ha1 + ":" + server_nonce + ":" + ha2

				hash.update_from_string (unhashed_response)

				Result := hash.digest_as_string

				Result.to_lower
			end
		end

feature -- Access

	get_header_value_by_key(h: READABLE_STRING_8; k: STRING_8): detachable READABLE_STRING_8
			-- From header `h', get value associated with key `k'.
			-- Returns Void if `h' does not contain such a value.
		local
			i,j: INTEGER
			result_string: STRING
		do
			-- We assume that each key-value pair begins with a space and ends with '='.
			-- FIXME This assumption may not be justified.
			-- TODO Does there already exists a parsing method for such headers?
			i := h.substring_index (" " + k + "=", 1)

			if i = 0 then
				Result := Void

				io.putstring ("Parsed " + k +": Void%N")
			else
				i := h.index_of ('=', i)

				j :=  h.index_of (',', i + 1)

				-- Special treatment of last pair, since it is not terminated by a coma.
				if j = 0 and i > 0 then
					j := h.count + 1
				end

				check
					-- FIXME
					not(i+1 > j-1 or i = 0 or j = 0)
				end

				Result := h.substring (i+1, j-1)

--				io.putstring ("Parsed " + k +": " + Result + "%N")
			end
		ensure
			key_not_present: not h.has_substring (k) implies result = Void
			key_present: h.has_substring (k) implies result /= Void
		end

	unquote_string(s: detachable READABLE_STRING_8): detachable STRING_8
			-- Returns string without quotes.
			-- If `s' attached but not quoted, returns empty string.
			-- Otherwise, returns Void.
		local
			i, j: INTEGER
			rs: STRING_32
		do
			if
				attached s as attached_s
			then
				create rs.make_from_string (attached_s)

				rs.left_adjust
				rs.right_adjust

				i := rs.index_of ('"', 1)
				j := rs.index_of ('"', i+1)

				if i+1 > j-1 or i = 0 or j = 0 then
					io.putstring ("Not able to unquote string: " + attached_s + "%N")
					create Result.make_empty
--					is_bad_request := True
				else
					Result := rs.substring (i+1, j-1)
				end
			else
--				io.putstring ("Not able to unquote string: Void%N")
			end
		ensure
			unquoted: (attached s as attached_s and then is_quoted (attached_s)) implies not is_quoted (attached_s)
		end

feature -- Constants

	Basic_auth_type: STRING_8 = "Basic"
	Digest_auth_type: STRING_8 = "Digest"

invariant
	type_valid: is_digest or is_basic or is_bad_request

	digest_values_attached: (is_digest implies
		attached response_value as attached_response_value and then not attached_response_value.is_empty and
		attached login and
		attached realm_value and
		attached nonce_value and
		attached uri_value)
		or is_bad_request

	digest_requirements:
		((attached qop_value as attached_qop_value and then not attached_qop_value.is_empty) implies
			attached cnonce_value as attached_cnonce_value and
			attached nc_value as attached_nc_value
		)
		and
		((not attached qop_value as attached_qop_value or else attached_qop_value.is_empty) implies
			(not attached cnonce_value as attached_cnonce_value or else attached_cnonce_value.is_empty) and
			(not attached nc_value as attached_nc_value or else attached_nc_value.is_empty)
		)
		or
		is_bad_request

	nc_value_length: attached nc_value as attached_nc_value and then attached_nc_value.count /= 8 implies is_bad_request

	supported_qop: attached qop_value as attached_qop_value implies (attached_qop_value.is_empty and is_bad_request) or attached_qop_value.is_case_insensitive_equal ("auth")

	supported_algorithm: attached algorithm_value as attached_algorithm_value implies (attached_algorithm_value.is_empty and is_bad_request) or attached_algorithm_value.is_case_insensitive_equal ("MD5")
end
