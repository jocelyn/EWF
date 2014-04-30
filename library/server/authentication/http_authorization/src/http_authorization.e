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

	make (a_http_authorization: detachable READABLE_STRING_8)
			-- Initialize `Current'.
			-- Parse authorization header.
			--
			-- TODO What should we do if
			-- 		argument is void
			--		empty
			--		neither a Basic nor a Digest authorization
			--		not a VALID Basic or Digest authorization (i.e., starts with "Basic" or "Digest", but does not have proper format)?
		local
			i, j: INTEGER
			t, s: STRING_8
			u,p: READABLE_STRING_32
			utf: UTF_CONVERTER
			l_md5: MD5
		do
			password := Void

			-- Default also if neither Basic nor Digest. (TODO Check this. Is this ok?)
			if a_http_authorization = Void then
					-- Default: Basic
				type := basic_auth_type
				http_authorization := Void
			else
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
						elseif t.same_string (Digest_auth_type) then
							type := Digest_auth_type

							-- XXX Why do we know here that a_http_authorization is attached?
							-- XXX Find out difference between being void and being attached, lear more about void safety etc.


							-- Parse response
							response_value := get_header_value_by_key (a_http_authorization, "response")

							if
								attached response_value as attached_response_value and then
								(
									not (attached_response_value.count = 34) or
									not attached_response_value.item (1).is_equal ('"') or
									not attached_response_value.item (attached_response_value.count).is_equal ('"')
									-- TODO Make sure that it is in hex format.
								)

							then
								-- Response is not valid, set it to void.
								response_value := Void
							end

							-- Parse login
							login := get_header_value_by_key (a_http_authorization, "username")
							login := set_void_if_unquoted (login)

							-- Parse realm
							-- XXX Add further tests for validity of realm value.
							realm_value := get_header_value_by_key (a_http_authorization, "realm")
							realm_value := set_void_if_unquoted (realm_value)

							-- Parse nonce
							nonce_value := get_header_value_by_key (a_http_authorization, "nonce")
							nonce_value := set_void_if_unquoted (nonce_value)

							-- Parse uri
							uri_value := get_header_value_by_key (a_http_authorization, "uri")

							-- Parse qop
							qop_value := get_header_value_by_key (a_http_authorization, "qop")
							if
								attached qop_value as attached_qop_value and then
								-- Note: Here, auth and auth-int are not quoted any more!
								not (attached_qop_value.is_equal ("auth") or attached_qop_value.is_equal ("auth-int"))
							then
								qop_value := Void
							end

							-- TODO Parse algorithm
							algorithm_value := get_header_value_by_key (a_http_authorization, "algorithm")
							-- TODO Check that it is one of the algorithms supplied in the WWW_Authenticate response header.

							-- TODO Parse nc
							nc_value := get_header_value_by_key (a_http_authorization, "nc")
							-- TODO Make sure that it is in hex format.
							-- Make sure it has length 8.

							-- TODO Parse cnonce
							cnonce_value := get_header_value_by_key (a_http_authorization, "cnonce")

							-- TODO Parse opaque
							opaque_value := get_header_value_by_key (a_http_authorization, "opaque")
							-- TODO Check that it is the opaque supplied in the WWW_Authenticate response header.
							-- Also handle case where WWW_Authenticate did'n supply an opaque value.
						end
					end
				end
			end
		ensure
			a_http_authorization /= Void implies http_authorization /= Void
--			a_http_authorization.has_substring ("Basic") or a_http_authorization.has_substring ("basic") or a_http_authorization.has_substring ("Digest") or a_http_authorization.has_substring ("digest")
--			a_http_authorization.has_substring ("Basic") or a_http_authorization.has_substring ("basic") or a_http_authorization.has_substring ("Digest") or a_http_authorization.has_substring ("digest")
--			type.is_case_insensitive_equal (basic_auth_type) or type.is_case_insensitive_equal (digest_auth_type)
--			(a_http_authorization.has_substring ("Basic") or a_http_authorization.has_substring ("basic")) implies type.is_case_insensitive_equal (basic_auth_type)
--			(a_http_authorization.has_substring ("Digest") or a_http_authorization.has_substring ("digest")) implies type.is_case_insensitive_equal (digest_auth_type)

		end

	make_basic_auth (u: READABLE_STRING_32; p: READABLE_STRING_32)
			-- Create a Basic authentication.
		do
			io.putstring ("HTTP_AUTHORIZATION.make_basic_auth()%N")

			make_custom_auth (u, p, Basic_auth_type)
		end

	make_custom_auth (u: READABLE_STRING_32; p: READABLE_STRING_32; a_type: READABLE_STRING_8)
			-- Create a custom `a_type' authentication.
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

	http_authorization: detachable IMMUTABLE_STRING_8

	type: READABLE_STRING_8

	-- Deprecated. Rename into `username'.
	login: detachable READABLE_STRING_32

	password: detachable READABLE_STRING_32

	realm_value: detachable READABLE_STRING_32

	nonce_value: detachable READABLE_STRING_32

	nc_value: detachable READABLE_STRING_32

	cnonce_value: detachable READABLE_STRING_32

	qop_value: detachable READABLE_STRING_32

	response_value: detachable READABLE_STRING_32

	opaque_value: detachable READABLE_STRING_32

	uri_value: detachable READABLE_STRING_32

	algorithm_value: detachable READABLE_STRING_32

feature -- Status report

	is_basic: BOOLEAN
			-- Is Basic authorization?
		do
			Result := type.is_case_insensitive_equal (Basic_auth_type)
		end

	is_digest: BOOLEAN
			-- Is Basic authorization?
		do
			Result := type.is_case_insensitive_equal (Digest_auth_type)
		end

	error_occurred: BOOLEAN
			-- True, if there was a syntactical error in the digest-response.
			-- If a directive or its value is improper, or required directives are missing,
			-- the proper response is 400 Bad Request.

	is_authorized(valid_credentials: STRING_TABLE [READABLE_STRING_32]; m: READABLE_STRING_8; u: READABLE_STRING_8): BOOLEAN
			-- Check authorization.
			-- `m': Method
			-- `u': Uri			
			--
			-- TODO Add arguments for the fields we supplied in the WWW-Authenticate header.
			-- This must be done s.t. we can check whether the values received in this http-authorization are correct.
			-- For example: If the http-authorization is a digest authorization, then the nonce contained in it
			-- must be the same as the one we supplied in the corresponding WWW-Authenticate header.
			--
			-- TODO For digest, take into account: stale, nonce-count etc.
			-- TODO Maybe give other parameter, for example: req
		require
			attached login
		local
			HA1: STRING_8
			HA2: STRING_8
			response_expected: STRING_8
		do
			if 	type.is_case_insensitive_equal (basic_auth_type) then
				-- XXX When check for attachment, when for voidness? Difference?
				if
					attached password as attached_password and
					attached login as attached_login
				then
					if
						attached valid_credentials.item (attached_login) as l_passwd
					then
						Result := attached_password.is_case_insensitive_equal (l_passwd)
					end
				end
			elseif 	type.is_case_insensitive_equal (digest_auth_type) then
				io.putstring ("----HTTP_AUTH.is_authorized: Digest%N")
				if
					attached login as attached_login and
					attached realm_value as attached_realm_value and
					attached response_value as attached_response_value
				then

					if attached valid_credentials.item (unquote_string (attached_login)) as attached_password then

						HA1 := compute_hash_a1 (attached_login, attached_realm_value, attached_password)

						HA2 := compute_hash_a2(m, u)

						response_expected := compute_expected_response (HA1, HA2)

						Result :=response_expected.is_equal (unquote_string (attached_response_value))
					else
						io.putstring ("----HTTP_AUTH.is_authorized: Unvalid. Login: " + attached_login + "%N")
					end
				elseif not attached login then
					io.putstring ("----HTTP_AUTH.is_authorized: Login not attached%N")
				elseif not attached realm_value then
					io.putstring ("----HTTP_AUTH.is_authorized: Realm not attached%N")
				elseif not attached realm_value then
					io.putstring ("----HTTP_AUTH.is_authorized: Response not attached%N")
				end
			end
		ensure
			Result implies (attached login as a_login and then valid_credentials.has (a_login))
		end

--	contains_supplied_values(

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
			-- If a directive or its value is improper, or required directives are missing, the proper response is 	400 Bad Request.

feature -- Digest computation

	compute_hash_A1 (u: READABLE_STRING_8; r: READABLE_STRING_8; p: READABLE_STRING_8): STRING_8
			-- Compute H(A1).
			-- TODO When do we use which string class?
		require
			-- Necessary?
			attached type and type /= Void and then	type.is_case_insensitive_equal (digest_auth_type)
		local
			hash: MD5
			A1: READABLE_STRING_8
		do
			create hash.make

			A1 := unquote_string(u) + ":" + unquote_string(r) + ":" + p

			hash.update_from_string (A1);

			Result := hash.digest_as_string

			Result.to_lower

			io.put_string ("HA1: " + Result)
			io.new_line

		end

	compute_hash_A2 (m: READABLE_STRING_8; u: READABLE_STRING_8): STRING_8
			-- Compute H(A2)
			-- `m': Method, `u': uri
		local
			hash: MD5
			A2: READABLE_STRING_8
		do

			A2 := m + ":" + u

			-- TODO
--			if attached qop_value as attached_qop then
--				if attached_qop.is_case_insensitive_equal ("auth") then
--					A2 := m + ":" + u					
--				elseif attached_qop.is_case_insensitive_equal ("auth-int") then
--					A2 := m + ":" + u + req.
--				else
--					
--				end
--			else
--				io.putstring ("TODO: qop not attached")
--				io.new_line					
--			end

			create hash.make

			hash.update_from_string (A2)

			Result := hash.digest_as_string

			Result.to_lower

			io.put_string ("HA2: " + Result)
			io.new_line

		end

	compute_expected_response(ha1: READABLE_STRING_8; ha2: READABLE_STRING_8) : STRING_8
			-- Computes UNQUOTED expected response.
			-- TODO Compute expected response, which is quoted. How can I add qoutes to the string?
		local
			hash: MD5
			unhashed_response: READABLE_STRING_8
			no, nc, cn, qo: READABLE_STRING_8
		do
			create Result.make_empty

			-- TODO Delete the following lines
--			cnonce_value := "%"0a4f113b%""

			if
				attached ha1 as a_ha1 and
				attached ha2 as a_ha2 and
				attached nonce_value as a_nonce_value
			then
				if
					attached nc_value as a_nc_value and
					attached cnonce_value as a_cnonce_value and
					attached qop_value as a_qop_value
				then
					-- Standard (for digest) computation of response

					-- TODO Assert that qop is auth or auth-int
					create hash.make

					no := unquote_string (a_nonce_value)
					nc := a_nc_value
					cn := unquote_string (a_cnonce_value)
					qo := a_qop_value

					unhashed_response := ha1 + ":" + no + ":" + nc + ":" + cn + ":" + qo + ":" + ha2
					hash.update_from_string (unhashed_response)

					Result := hash.digest_as_string

					Result.to_lower

					io.put_string ("Expected unquoted response: " + Result)
					io.new_line
				elseif not attached qop_value then
					-- qop directive is not present.
					-- Use construction for compatibility with RFC 2069

					no := unquote_string (a_nonce_value)

					create hash.make

					unhashed_response := ha1 + ":" + no + ":" + ha2
					hash.update_from_string (unhashed_response)

					Result := hash.digest_as_string

					Result.to_lower

					io.put_string ("RFC 2069 mode. Expected unquoted response: " + Result)
					io.new_line
				end
		end
	end

feature -- Access

	get_header_value_by_key(h: READABLE_STRING_8; k: STRING_8): detachable READABLE_STRING_32
			-- From header `h', get value associated to key `k'.
			-- Note: Response could be quoted.
			-- FIXME
		local
			i,j: INTEGER
		do
			-- We assume that each key-value pair begins with a space and ends with '='.
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
					not(i+1 > j-1 or i = 0 or j = 0)
				end

				Result := h.substring (i+1, j-1)

				io.putstring ("Parsed " + k +": " + Result + "%N")
			end
		end

	unquote_string(s: STRING_32): STRING_32
			-- Returns string without quotes, or empty string if string is not quoted.
		local
			i, j: INTEGER
			rs: STRING_32
		do
			create rs.make_from_string (s)

			rs.left_adjust
			rs.right_adjust

			i := rs.index_of ('"', 1)
			j := rs.index_of ('"', i+1)

			if i+1 > j-1 or i = 0 or j = 0 then
				create Result.make_empty
			else
				Result := rs.substring (i+1, j-1)
			end
		end

	get_unquoted_string(s: STRING_32) : STRING_32
			-- If the original string contains quotes, then remove the quotes.
		do
			if s.has ('"') then
				Result := unquote_string (s)
			else
				Result := s
			end
		end

feature -- Element change

	set_Void_if_unquoted (s: detachable READABLE_STRING_32): detachable READABLE_STRING_32
			-- Set `s' to Void if it is not quoted
		do
			if
				attached s as attached_s and then
				not is_quoted (attached_s)
			then
				-- Login is not valid, set it to void.
				Result := Void
			else
				Result := s
			end
		end

feature -- Constants

	Basic_auth_type: STRING_8 = "Basic"
	Digest_auth_type: STRING_8 = "Digest"

invariant

	type_valid: (type.is_case_insensitive_equal (basic_auth_type) implies type = basic_auth_type)
				or (type.is_case_insensitive_equal (Digest_auth_type) implies type = Digest_auth_type)

	-- attachement test necessary?
	type_attached_and_nonEmpty: attached type and then not type.is_empty

--	login_attached_and_nonEmpty: attached login and then not login.is_empty


end
