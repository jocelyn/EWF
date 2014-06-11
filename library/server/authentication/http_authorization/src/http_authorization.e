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
			t: STRING_8
		do
			is_bad_request := False
			bad_request_message := Void

			login := Void
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

						analyze_basic_auth (a_http_authorization.substring (i + 1, a_http_authorization.count))
					elseif t.same_string (Digest_auth_type) then
						type := Digest_auth_type

						analyze_digest_auth (a_http_authorization.substring (i + 1, a_http_authorization.count))
					else
							-- We don't know authentication method.
						is_bad_request := True
					end
				else
						-- Bad format.
					report_bad_request ("Bad format")
				end
			end
		ensure
			a_http_authorization /= Void implies http_authorization /= Void
		end

	make_basic_auth (u: READABLE_STRING_32; p: READABLE_STRING_32)
			-- Create a Basic authentication.
		do
			io.put_string ("HTTP_AUTHORIZATION.make_basic_auth()%N")

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
			io.put_string ("HTTP_AUTHORIZATION.make_custom_auth()%N")

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

feature {NONE} -- Analyze

	report_bad_request (mesg: detachable READABLE_STRING_8)
		do
			is_bad_request := True
			bad_request_message := mesg
		end

	analyze_basic_auth (a_basic_auth: READABLE_STRING_8)
		require
			is_basic: is_basic
		local
			s: READABLE_STRING_8
			i: INTEGER
			u,p: detachable READABLE_STRING_32
			utf: UTF_CONVERTER
		do
			s := (create {BASE64}).decoded_string (a_basic_auth)
			i := s.index_of (':', 1) --| Let's assume ':' is forbidden in login ...
			if i > 0 then
				u := utf.utf_8_string_8_to_string_32 (s.substring (1, i - 1)) -- UTF_8 decoding to support unicode username
				p := utf.utf_8_string_8_to_string_32 (s.substring (i + 1, s.count)) -- UTF_8 decoding to support unicode password
				login := u
				password := p
				check
					(create {HTTP_AUTHORIZATION}.make_custom_auth (u, p, type)).http_authorization ~ http_authorization
				end
			end
		end

	analyze_digest_auth (a_http_authorization: READABLE_STRING_8)
		require
			is_digest: is_digest
		local
			empty_string_8: STRING_8
			realm_value: detachable READABLE_STRING_8
			nonce_value: detachable READABLE_STRING_8
			nc_value: detachable READABLE_STRING_8
			cnonce_value: detachable READABLE_STRING_8
			qop_value: detachable READABLE_STRING_8
			response_value: detachable READABLE_STRING_8
			opaque_value: detachable READABLE_STRING_8
			uri_value: detachable READABLE_STRING_8
			algorithm_value: detachable READABLE_STRING_8
			d: like digest_data
			l_headers: like header_values
		do
			create empty_string_8.make_empty

				-- Try to parse the fields, and set them to the empty string if they didn't match our expectations.
				-- If fields are not present in the header, leave them unattached (i.e., Void).

			l_headers := header_values (a_http_authorization)

				-- Parse login
			login := l_headers.item ("username")

				-- Parse response
			response_value := l_headers.item ("response")
			if
				response_value /= Void and then
				response_value.count /= 32
			then
					-- Response is not valid, set it to empty string.
				io.put_string ("ERROR: Improper response.%N")
				response_value := empty_string_8
				is_bad_request := True
			end
			if
				response_value = Void
				or else response_value.is_empty
			then
				io.put_string ("ERROR: Improper response.%N")
				is_bad_request := True
			end

				-- Parse realm
				-- XXX Add further tests for validity of realm value.
			realm_value := l_headers.item ("realm")

				-- Parse nonce
			nonce_value := l_headers.item ("nonce")

				-- Parse uri
			uri_value := l_headers.item ("uri")

				-- Parse qop
			qop_value := l_headers.item ("qop")
			if
				qop_value /= Void and then
				not qop_value.is_case_insensitive_equal ("auth")
			then
					-- If the qop field is present, it has to be auth.
					-- Other quality of protection is not supported so far.
				qop_value := empty_string_8
				is_bad_request := True
				io.put_string ("ERROR: Improper qop.%N")
			end

				-- Parse algorithm
				--| Algorithm MUST NOT be quoted.
				--| Nevertheless, cURL sens us quoted algorithm values.
				--| For the sake of robustness, we allow both quoted and unqoted algorithm values.
			algorithm_value := l_headers.item ("algorithm")

			check
				is_MD5_algorithm: algorithm_value = Void or else (algorithm_value.is_empty or algorithm_value.is_case_insensitive_equal ("MD5"))
			end
			if
				algorithm_value /= Void and then
				not algorithm_value.is_case_insensitive_equal ("MD5")
			then
				-- If the algorithm field is present, it has to be MD5.							
				io.put_string ("ERROR: Improper algorithm: " + algorithm_value + "%N")
				algorithm_value := empty_string_8
				is_bad_request := True
			end

				-- Parse nc
			nc_value := l_headers.item ("nc")
			if
				nc_value /= Void and then
				nc_value.count /= 8
			then
					-- If the nc field is present, it has to have length 8.							
				io.put_string ("ERROR: Improper nc.%N")
				nc_value := empty_string_8
				is_bad_request := True
			end

				-- Parse cnonce
			cnonce_value := l_headers.item ("cnonce")

				-- Parse opaque
			opaque_value := l_headers.item ("opaque")

				-- Check that all mandatory fields are actually attached.
			if
				login = Void
				or realm_value = Void
				or nonce_value = Void
				or uri_value = Void
				or response_value = Void
			then
				io.put_string ("ERROR: Manadory field not attached.%N")
				digest_data := Void
				is_bad_request := True
			else
				create d.make (realm_value, nonce_value, uri_value, response_value)
					-- non mandatory field.
				d.nc := nc_value
				d.cnonce := cnonce_value
				d.qop := qop_value
				d.opaque := opaque_value
				d.algorithm := algorithm_value

				digest_data := d
			end
		ensure
			is_digest: is_digest
			digest_values_attached:
					(	attached login and
						attached digest_data -- i.e realm, nonce, uri, and response are set!
					) or is_bad_request

			digest_requirements:
					(	attached digest_data as l_digest_data and then
						l_digest_data.requirements_satisfied
					) or is_bad_request

			nc_value_length: attached digest_data as l_digest_data and then
					attached l_digest_data.nc as l_nc and then l_nc.count /= 8 implies is_bad_request
			supported_qop: attached digest_data as l_digest_data and then
					attached l_digest_data.qop as l_qop implies (l_qop.is_empty and is_bad_request)
					or l_qop.is_case_insensitive_equal ("auth")
			supported_algorithm: attached digest_data as l_digest_data and then
					attached l_digest_data.algorithm as l_algorithm implies (l_algorithm.is_empty and is_bad_request)
					or l_algorithm.is_case_insensitive_equal ("MD5")
		end

feature -- Access

	http_authorization: IMMUTABLE_STRING_8

	type: READABLE_STRING_8
			-- We always have a type.	

feature -- Access: basic			

	login: detachable READABLE_STRING_8

	password: detachable READABLE_STRING_8

feature -- Access: digest	

	digest_data: detachable HTTP_AUTHORIZATION_DIGEST_DATA

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

	is_authorized_digest (a_username: READABLE_STRING_8; a_password: READABLE_STRING_8; a_server_realm: READABLE_STRING_8;
				a_server_nonce_list: ARRAYED_LIST [STRING_8]; a_server_method: READABLE_STRING_8; a_server_uri: READABLE_STRING_8;
				a_server_algorithm: detachable READABLE_STRING_8; a_server_qop: detachable READABLE_STRING_8): BOOLEAN
			-- Validates digest authentication.
			--
			-- Here we need the values which the server has sent in the WWW-Authenticate header.
			--
			-- TODO `a_server_nonce_list' should also contain latest nonce-count values from client.
			-- TODO uri may be changed by proxies. Which uri should we take, the one from the request or the one from the authorization-header?
			-- TODO This method could be modified s.t. it does not take the cleartext password as an argument.
			-- TODO Be more flexible: Do not only support auth, MD5 etc.
		require
			server_username_set: attached a_username
			server_password_set: attached a_password
			server_realm_set: attached a_server_realm
			server_method_set: attached a_server_method
			server_uri_set: attached a_server_uri
			server_nonce_list_set: attached a_server_nonce_list
			is_digest: is_digest
		local
			ha1: STRING_8
			ha2: STRING_8
			l_expected_response: STRING_8
			l_found_nonce: detachable READABLE_STRING_8
			l_nonce_expected: BOOLEAN
		do
			if
				attached digest_data as l_digest and then
				(
					attached l_digest.realm as l_realm and
					attached l_digest.response as l_response and
					attached l_digest.nonce as l_nonce
				)
			then
					-- Check whether we know the nonce from the Authorization-header.
					-- XXX The following could be optimized, for example move to other position, start at end etc.
					-- XXX We could also make use of 'across' for better readability.
				if not a_server_nonce_list.is_empty then
					if a_server_nonce_list.last.is_case_insensitive_equal (l_nonce) then
						l_found_nonce := a_server_nonce_list.last
						l_nonce_expected := True
					else
						across
							a_server_nonce_list as ic
						until
							l_found_nonce /= Void
						loop
							l_found_nonce := ic.item
							if l_found_nonce.is_case_insensitive_equal (l_nonce) then
									-- Found
							else
								l_found_nonce := Void
							end
						end
							-- QUESTION: if nonce is found in a_server_nonce_list
							-- why is it not an expected nonce?						
					end
				end

				if l_found_nonce /= Void then
					check expected_nonce: l_found_nonce.is_case_insensitive_equal (l_nonce) end
					ha1 := digest_hash_of_username_realm_and_password (a_username, a_server_realm, a_password, a_server_algorithm, l_nonce)
					ha2 := digest_hash_of_method_and_uri (a_server_method, a_server_uri, a_server_algorithm, a_server_qop, False)
					l_expected_response := digest_expected_response (ha1, ha2, l_nonce, a_server_qop, a_server_algorithm, l_digest.nc, l_digest.cnonce)
					if l_nonce_expected then
							-- The nonce is the one we expected.
						Result := l_expected_response.same_string (l_response)

						debug ("http_authorization")
							if not Result then
								io.put_string ("Expected response: " + l_expected_response + "%N")
								io.put_string ("Actual response: " + l_response + "%N")
							else
								io.put_string ("Expected and actual response: " + l_expected_response + "%N")
							end
						end
					else
							-- The nonce is not the one we expected.
							-- Maybe it is in the list of nonces from the client.
							-- Then, the nonce could just be stale, and the user agent doesn't have to prompt for the credentials again.
							-- The result is False anyway.
						stale := l_expected_response.same_string (l_response)
						debug ("http_authorization")
							io.put_string ("Nonce is not the expected one. Stale: " + stale.out + "%N")
						end
					end
				else
					debug ("http_authorization")
						io.put_string ("We don't know this nonce:%N   " + l_nonce + ".%N")
						io.put_string ("We only know those:%N")
						across
							a_server_nonce_list as ic
						loop
							io.put_string ("   " + ic.item + ".%N")
						end
					end
				end
			else
				debug ("http_authorization")
					io.put_string ("Could not compute expected response since something was not attached.")
				end
			end
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
			if is_basic then
				if attached password as l_password then
					Result.append ("password=[")
					Result.append (l_password)
					Result.append ("] ")
				end
			elseif is_digest then
				if attached digest_data as d then
					Result.append_character (' ')
					Result.append (d.debug_output)
				end
			end
		end

	is_bad_request: BOOLEAN
			-- If a directive or its value is improper, or required directives are missing,
			-- the proper response is 400 Bad Request.
			--
			-- TODO Make more/extensive use of this.

	bad_request_message: detachable READABLE_STRING_8
			-- Message associated with `is_bad_request'.

	stale: BOOLEAN
			-- True if authorization was stale.

feature -- Access: digest

	digest_authentication_info (a_username, a_password: READABLE_STRING_8;
			a_request_method: READABLE_STRING_8; a_request_uri: READABLE_STRING_8;
			a_algorithm: READABLE_STRING_8; a_qop: READABLE_STRING_8; a_nonce: READABLE_STRING_8
			): detachable STRING_8
			-- Value for header "Authentication-Info", for the digest auth.
		local
			values: LINKED_LIST [STRING]
			rspauth: STRING_8
			ha1, ha2: STRING_8
		do
			if
				is_digest and then
				attached login as l_login and then a_username.same_string (l_login) and then
				attached digest_data as l_digest
			then
					-- Add Authentication-Info header
					-- Communicate some information regarding the successful authentication in the response.
				create values.make

				if attached l_digest.qop as l_qop and then not l_qop.is_empty then
					check
						is_auth: l_qop.is_case_insensitive_equal ("auth")
					end

					values.force ("qop=%"" + l_qop + "%"")

					check
							-- This MUST be specified if a qop parameter is sent.
						is_cnonce_attached: attached l_digest.cnonce as l_cnonce and then not l_cnonce.is_empty
						is_nc_attached: attached l_digest.nc as l_nc and then not l_nc.is_empty
					end
				else
					check
							-- This MUST NOT be specified if the server did not send a qop parameter.
						not_cnonce_attached: not attached l_digest.cnonce as l_cnonce or else not l_cnonce.is_empty
						not_nc_attached: not attached l_digest.nc as l_nc or else not l_nc.is_empty
					end
				end

				if attached l_digest.cnonce as l_cnonce and then not l_cnonce.is_empty then
					values.force ("cnonce=%"" + l_cnonce + "%"")
				end

				if attached l_digest.nc as l_nc and then not l_nc.is_empty then
					values.force ("nc=%"" + l_nc + "%"")
				end

				if
					attached l_digest.realm as l_realm_value
				then
					ha1 := digest_hash_of_username_realm_and_password (a_username, l_realm_value, a_password, a_algorithm, a_nonce)
					ha2 := digest_hash_of_method_and_uri (a_request_method, a_request_uri, a_algorithm, a_qop, True)
					rspauth := digest_expected_response (ha1, ha2, a_nonce, a_qop, a_algorithm, l_digest.nc, l_digest.cnonce)

						-- TODO What happens rspauth is wrong?
--					values.force ("rspauth=%"" + "abcd" + "%"")

						-- The rspauth parameter supports mutual authentication.
						-- The server proves that it knows the user's secret.
					values.force ("rspauth=%"" + rspauth + "%"")
				end
				create Result.make_empty
				across
					 values as ic
				loop
					if not Result.is_empty then
						Result.append_character (',')
						Result.append_character (' ')
					end
					Result.append_string (ic.item)
				end
			end
		end

feature {NONE} -- Helper: access

	header_values (h: READABLE_STRING_8): STRING_TABLE [READABLE_STRING_8]
			-- Formatting
			-- [key1=value1, key2="quoted value2", key3=value3]
		local
			i,j,n: INTEGER
			k: detachable READABLE_STRING_8
			c: CHARACTER_8
			l_is_key_character: BOOLEAN
		do
			from
				create Result.make (0)
				i := 1
				n := h.count
			until
				i > n
			loop
				c := h[i]
				if c.is_space then
						-- skip
					i := i + 1
				elseif c = ',' then
						-- pair separator
					i := i + 1
				elseif c.is_alpha then
						-- parse key
					from
						j := 1
						l_is_key_character := True
					until
						i + j >= n or not l_is_key_character
					loop
						j := j + 1
						c := h[i + j]
						l_is_key_character := c.is_alpha_numeric or c = '-' or c = '_'
					end
					if l_is_key_character then
						k := h.substring (i, i + j)
					else
						k := h.substring (i, i + j - 1)
					end
					i := i + j
					from until i > n or else not h[i].is_space loop
							-- skip space
						i := i + 1
					end
					if h[i] = '=' then
							-- Record value
						i := i + 1
						if i > n then
								-- empty header?
							Result.force ("", k)
						else
							if h [i] = '"' then
									-- Quoted
								j := h.index_of ('"', i + 1)
								if j > 0 then
									Result.force (h.substring (i + 1, j - 1), k)
									i := j + 1
								else
										-- bad header?
									Result.force (h.substring (i, n), k)
									i := n + 1
								end
							else
									-- Not quoted
								j := h.index_of (',', i)
								if j > 0 then
									Result.force (h.substring (i, j - 1), k)
									i := j + 1
								else
										-- last pair.
									Result.force (h.substring (i, n), k)
									i := n + 1
								end
							end
						end
					else
							-- empty header?
						Result.force ("", k)
					end
				else
					check valid_headers_content: False end
					i := i + 1
				end
			end
		end

feature -- Constants

	Basic_auth_type: STRING_8 = "Basic"
	Digest_auth_type: STRING_8 = "Digest"

feature {NONE} -- Implementation: Digest

	digest_hash_of_username_realm_and_password (a_server_username: READABLE_STRING_8; a_server_realm: READABLE_STRING_8; a_server_password: READABLE_STRING_8; a_server_algorithm: detachable READABLE_STRING_8; a_server_nonce: READABLE_STRING_8): STRING_8
			-- hash value of `a_server_username' , `a_server_realm', and `a_server_password',
			-- also known as HA1 in the related wikipedia page.
			--
			-- If the algorithm directive's value is "MD5" or unspecified, then HA1 is
			--    {HA1} = {MD5}({A1}) = {MD5}( {username} : {realm} : {password} )
			--
 			-- If the algorithm directive's value is "MD5-sess", then HA1 is
			--    {HA1} = {MD5}({A1}) = {MD5}({MD5}( {username} : {realm} : {password} ) : {nonce} : {cnonce} )			
		local
			a1: STRING_8
		do
			check is_md5_algorithm: a_server_algorithm = Void or else a_server_algorithm.is_case_insensitive_equal_general ("md5") end
			create a1.make_from_string (a_server_username)
			a1.append_character (':')
			a1.append (a_server_realm)
			a1.append_character (':')
			a1.append (a_server_password)
			Result := md5_hash (a1)

			debug ("http_authorization")
				io.put_string ("Computed HA1: " + Result + "%N")
			end
		end

	digest_hash_of_method_and_uri (a_server_method: READABLE_STRING_8; a_server_uri: READABLE_STRING_8; a_server_algorithm: detachable READABLE_STRING_8; a_server_qop: detachable READABLE_STRING_8; for_auth_info: BOOLEAN): STRING_8
			-- hash value of `a_server_method' , and `a_server_uri',
			-- also known as HA2 in the related wikipedia page.
			-- `for_auth_info' MUST be set to True if we compute the hash for the Authentication-Info header.
			--
			-- If the qop directive's value is "auth" or is unspecified, then HA2 is
			--    {HA2} = {MD5}({A2}) = {MD5}( {method} : {digestURI} )
			--
			-- If the qop directive's value is "auth-int", then HA2 is
			--    {HA2} = {MD5}({A2}) = {MD5}( {method} : {digestURI} :  {MD5}(entityBody)) 			
		local
			a2: READABLE_STRING_8
		do
			check is_auth_qop: a_server_qop = Void or else a_server_qop.is_case_insensitive_equal_general ("auth") end
				-- Special treatment of Authentication-Info header.
			if for_auth_info then
				a2 := ":" + a_server_uri
			else
				a2 := a_server_method + ":" + a_server_uri
			end

			Result := md5_hash (a2)

			debug ("http_authorization")
				io.put_string ("Computed HA2: " + Result + "%N")
			end
		end

	digest_expected_response (ha1: READABLE_STRING_8; ha2: READABLE_STRING_8; a_server_nonce: READABLE_STRING_8; a_server_qop: detachable READABLE_STRING_8; server_algorithm: detachable READABLE_STRING_8; a_nc: detachable READABLE_STRING_8; a_cnonce: detachable READABLE_STRING_8) : STRING_8
			-- UNQUOTED expected response.
			-- also known as response in the related wikipedia page.
			--
			-- If the qop directive's value is "auth" or "auth-int", then compute the response as follows:
			--    {response} = {MD5}( {HA1} : {nonce} : {nonceCount} : {clientNonce} : {qop} : {HA2} )
			--
			-- If the qop directive is unspecified, then compute the response as follows:
			--    {response} = {MD5}( {HA1} : {nonce} : {HA2} ) 			
		local
			unhashed_response: READABLE_STRING_8
		do
			create Result.make_empty

			if a_server_qop /= Void then
				if a_nc /= Void and a_cnonce /= Void then
						-- Standard (for digest) computation of response.
					unhashed_response := ha1 + ":" + a_server_nonce + ":" + a_nc + ":" + a_cnonce + ":" + a_server_qop + ":" + ha2
					debug ("http_authorization")
						io.put_string ("Expected unhashed response: " + unhashed_response)
						io.new_line
					end

					Result := md5_hash (unhashed_response)
					debug ("http_authorization")
						io.put_string ("Expected unquoted response: " + Result)
						io.new_line
					end
				else
						-- TODO Throw an exception. This should be excluded by invariant.
					debug ("http_authorization")
						io.put_string ("ERROR: This should not happen!%N")
					end
				end
			else
					-- qop directive is not present.
					-- Use construction for backwards compatibility with RFC 2069
				debug ("http_authorization")
					io.put_string ("RFC 2069 mode.")
					io.new_line
				end
				unhashed_response := ha1 + ":" + a_server_nonce + ":" + ha2
				Result := md5_hash (unhashed_response)
			end
		end

feature -- Helpers: hash, md5		

	md5_hash (s: READABLE_STRING_8): STRING_8
		local
			hash: MD5
		do
			create hash.make
			hash.update_from_string (s)
			Result := hash.digest_as_string
			Result.to_lower
		end

invariant
	type_valid: is_digest or is_basic or is_bad_request
	is_valid_digest_or_bad_request: (is_digest and not is_bad_request) implies digest_data /= Void

end
