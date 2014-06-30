note
	description : "[
			Object representing http Authorization header.
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
						report_bad_request ("Unknown authentication method")
					end
				else
					report_bad_request ("Bad format")
				end
			else
				report_bad_request ("Empty string")
			end
		ensure
			a_http_authorization /= Void implies http_authorization /= Void
		end

	make_basic_auth (u: READABLE_STRING_32; p: READABLE_STRING_32)
			-- Create a Basic authentication.
		do
			make_custom_auth (u, p, Basic_auth_type)
		ensure
			is_basic
		end

	make_custom_auth (u: READABLE_STRING_32; p: READABLE_STRING_32; a_type: READABLE_STRING_8)
			-- Create a custom `a_type' authentication.
			-- TODO Support for digest authentication.
		require
			a_type_accepted: a_type.is_case_insensitive_equal (Basic_auth_type)
							or a_type.is_case_insensitive_equal (Digest_auth_type)
		local
			t: STRING_8
			utf: UTF_CONVERTER
		do
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
					-- TODO
				to_implement ("HTTP Authorization %""+ t +"%", not yet implemented")
				create http_authorization.make_from_string ("Digest ...NOT IMPLEMENTED")
			else
					-- TODO
				to_implement ("HTTP Authorization %""+ t +"%", not yet implemented")
				create http_authorization.make_from_string (t + " ...NOT IMPLEMENTED")
			end
		end

feature {NONE} -- Analyze

	report_bad_request (a_msg: detachable READABLE_STRING_8)
			-- Set `is_bad_request' flag and set `bad_request_message' to `a_msg'.
		do
			is_bad_request := True
			bad_request_message := a_msg
		ensure
			bad_request: is_bad_request
			msg_set: bad_request_message = a_msg
		end

	analyze_basic_auth (a_basic_auth: READABLE_STRING_8)
			-- Analyze basic authentication.
			-- Sets `is_bad_request', if necessary.
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
			else
				report_bad_request ("Bad format")
			end
		end

	analyze_digest_auth (a_http_authorization: READABLE_STRING_8)
			-- Analyze digest authentication.
			-- Sets `is_bad_request', if necessary.
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
			l_headers: like header_values
		do
				-- Try to parse the fields, and set them to the empty string if they didn't match our expectations.
				-- If fields are not present in the header, leave them unattached (i.e., Void).

			create empty_string_8.make_empty

			l_headers := header_values (a_http_authorization)

				-- Parse login
			login := l_headers.item ("username")

				-- Parse response
			response_value := l_headers.item ("response")
			if response_value = Void then
				report_bad_request ("Improper response: Void%N")
			elseif response_value.count /= 32 then
					-- Response is not valid, set it to empty string.
				report_bad_request ("Improper response: " + response_value + "%N")
				response_value := empty_string_8
			end

				-- Parse realm
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
					-- Other quality of protection is invalid or has not been supported so far.
				report_bad_request ("Illegal or unsupported qop: " + qop_value + "%N")
				qop_value := empty_string_8
			end

				-- Parse algorithm
			algorithm_value := l_headers.item ("algorithm")
			if
				algorithm_value /= Void and then
				not algorithm_value.is_case_insensitive_equal ("MD5")
			then
				-- If the algorithm field is present, it has to be MD5.	
				-- Other algorithms are invalid or have not been supported so far.	
				report_bad_request ("Illegal or unsupported algorithm: " + algorithm_value + "%N")
				algorithm_value := empty_string_8
			end

				-- Parse nc
			nc_value := l_headers.item ("nc")
			if
				nc_value /= Void and then
				(
					nc_value.count /= 8 or
					nc_value.to_integer < 0
				)
			then
					-- If the nc field is present, it has to have length 8 and be non-negative.							
				report_bad_request ("Improper nc: " + nc_value + "%N")
				nc_value := empty_string_8
			end

				-- Parse cnonce
			cnonce_value := l_headers.item ("cnonce")

				-- Parse opaque
			opaque_value := l_headers.item ("opaque")

			if not is_bad_request then
					-- Until now, everything seems fine.
					-- Apply further tests, and set `is_bad_request', if neccessary.

				digest_data := Void

					-- Check that all mandatory fields are actually attached.
				if
					login = Void
					or realm_value = Void
					or nonce_value = Void
					or uri_value = Void
					or response_value = Void
				then
					report_bad_request ("Mandatory field not attached.%N")
				elseif
						-- Tests from the HTTP_AUTHORIZATION_DIGEST_DATA.
					((qop_value /= Void) = ((cnonce_value /= Void and nc_value /= Void))) and ((qop_value = Void) = (cnonce_value = Void and nc_value = Void))
				then
						-- Everything is ok, we can now initialize the digest-data.
					create digest_data.make (realm_value, nonce_value, uri_value, response_value, nc_value, cnonce_value, qop_value, opaque_value, algorithm_value)
				else
						-- Bad request
					report_bad_request ("Qop requirements not satisfied.%N")
				end
			end
		end

feature -- Access

	http_authorization: IMMUTABLE_STRING_8
		-- HTTP authorization string.

	type: READABLE_STRING_8
		-- Authentication type.

feature -- Access: basic			

	login: detachable READABLE_STRING_8
		-- Username.

	password: detachable READABLE_STRING_8
		-- Password corresponding to `username'.

feature -- Access: digest	

	digest_data: detachable HTTP_AUTHORIZATION_DIGEST_DATA

feature -- Status report

	is_basic: BOOLEAN
			-- Is Basic authorization?
		do
			Result := type.is_case_insensitive_equal (Basic_auth_type)
		ensure
			Result = type.is_case_insensitive_equal (Basic_auth_type)
		end

	is_digest: BOOLEAN
			-- Is Digest authorization?
		do
			Result := type.is_case_insensitive_equal (Digest_auth_type)
		ensure
			Result = type.is_case_insensitive_equal (Digest_auth_type)
		end

	is_authorized_basic (a_user_manager: USER_MANAGER): BOOLEAN
			-- Is basic authentication authorized?
		require
			is_basic: is_basic
			request_valid: not is_bad_request
		do
			if attached login as l_login and attached password as l_password then
				Result := attached a_user_manager.password (l_login) as s_password and then l_password.same_string (s_password)
			end
		ensure
			Result implies (attached login as l_login and then a_user_manager.user_exists (l_login))
		end

	is_authorized_digest (a_nonce_manager: NONCE_MANAGER; a_user_manager: USER_MANAGER;
				a_server_realm: READABLE_STRING_8; a_server_method: READABLE_STRING_8; a_server_uri: READABLE_STRING_8;
				a_server_algorithm: detachable READABLE_STRING_8; a_server_qop: detachable READABLE_STRING_8): BOOLEAN
			-- Is digest authentication authorized?
			-- Checks response, URI, staleness and nonce-count.
		require
			is_digest: is_digest
			request_valid: not is_bad_request
		local
			ha1: STRING_8
			ha2: STRING_8
			l_expected_response: STRING_8
		do
			debug ("http_authorization")
				io.put_string ("Checking digest authorization...%N")
			end

			if attached digest_data as l_digest then
				if a_nonce_manager.nonce_exists (l_digest.nonce) and attached login as l_login and then attached a_user_manager.password (l_login) as l_pw then
						-- Compute expected response.
					ha1 := digest_hash_of_username_realm_and_password (l_login, a_server_realm, l_pw, a_server_algorithm, l_digest.nonce)
					ha2 := digest_hash_of_method_and_uri (a_server_method, a_server_uri, a_server_algorithm, a_server_qop, False)
					l_expected_response := digest_expected_response (ha1, ha2, l_digest.nonce, a_server_qop, a_server_algorithm, l_digest.nc, l_digest.cnonce)

						-- Check response.
					if l_expected_response.same_string (l_digest.response) then

							-- Check URI.
							-- NOTE: The "request-uri" value is the Request-URI from the request line. This may be "*", an "absoluteURL" or and "abs_path",
							-- but it MUST agree with the Request-URI.
							-- If the URIs do not agree, the server SHOULD return a 400 Bad Request error (may be a symptom of an attacker,
							-- therefore such events should be logged).
							-- This is all because proxies may rewrite URIs. Since digest authentication checks the integrity of the URI value,
							-- the digest authentication will break if any of these changes are made.
							-- NOTE: We used the URI from the request line to compute the expected response, here, we compare this URI to the other one.
						if a_server_uri.same_string_general (l_digest.uri) then
							if l_digest.nc /= Void then
										-- Check nonce-count.
										-- We require that the nonce-count is strictly greater than any nonce-count, which we have received for this nonce before.
										-- This way we can detect replays.
										-- TODO Log such events.
									if l_digest.nc_as_integer > a_nonce_manager.nonce_count (l_digest.nonce) then
											-- Set nonce-count to current value.
										a_nonce_manager.set_nonce_count (l_digest.nonce, l_digest.nc_as_integer)
											-- Check for staleness.
										if a_nonce_manager.is_nonce_stale (l_digest.nonce) then
												-- Request has an invalid nonce, but a valid digest for that nonce.
												-- This indicates that the client knows the correct credentials.
												-- Hence, everything is fine, except that the nonce is stale.
											stale := true
										else
												-- Passed all checks.
											Result := true
										end
									else
										debug ("http_authorization")
											io.putstring ("Expected nc: " + (a_nonce_manager.nonce_count (l_digest.nonce) + 1).out + " or higher, actual: " + l_digest.nc_as_integer.out + "%N")
										end
									end
							else
								debug ("http_authorization")
									io.putstring ("nonce-count not specified%N")
								end
									-- Recall: nonce-count MUST NOT be speified if the server did not send a qop directive in the
									-- WWW-Authenticate header field.
								check qop_void: a_server_qop = Void end

									-- Check for staleness.
								if a_nonce_manager.is_nonce_stale (l_digest.nonce) then
										-- Request has an invalid nonce, but a valid digest for that nonce.
										-- This indicates that the client knows the correct credentials.
										-- Hence, everything is fine, except that the nonce is stale.
									stale := true
								else
										-- Passed all checks.
									Result := true
								end
							end
						else
							debug ("http_authorization")
								io.putstring ("URIs don't agree.%N")
							end
						end
					else
						debug ("http_authorization")
							io.putstring ("Wrong response%N")
						end
					end
				else
					debug ("http_authorization")
						if not a_nonce_manager.nonce_exists (l_digest.nonce) then
							io.put_string ("We don't know this nonce:%N   " + l_digest.nonce + ".%N")
						elseif login = Void then
							io.put_string ("Login not attached.%N")
							check not_allowed: False end
						else
							io.put_string ("Password not attached.%N")
						end
					end
				end
			else
					-- This is not allowed to happen.
				check not_allowed: False end
			end
		ensure
			result_lightweight_check: Result implies
					(
						attached login as l_login and then
						a_user_manager.user_exists (l_login) and
						attached digest_data as l_digest_data and then a_nonce_manager.nonce_exists (l_digest_data.nonce)
					)
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

	bad_request_message: detachable READABLE_STRING_8
			-- Message associated with `is_bad_request'.

	stale: BOOLEAN
			-- Is authorization stale?

feature -- Access: digest

	digest_authentication_info (a_user_manager: USER_MANAGER; a_request_method: READABLE_STRING_8): STRING_8
			-- Value for header "Authentication-Info" success, for the digest auth.
			-- This header is sent along with the 200 OK response from a previous successful authentication.
			-- Used by the server to communicate some information regarding the successful authentication in the response.
		require
			is_digest: is_digest
			request_ok: not is_bad_request
			digest_data_attached: attached digest_data
			known_user_and_password: attached login as l_login and then a_user_manager.user_exists (l_login)
		local
			values: LINKED_LIST [STRING]
			rspauth: STRING_8
			ha1, ha2: STRING_8
		do
				-- NOTE: We do not include a nextnonce field, because this nullifies the ability
				-- to pipeline multiple requests to the same server.
				-- Since pipelining is expected to be a fundamental technology for latency avoidance,
				-- the performance penalty may be large.
			create Result.make_empty

			if
				attached digest_data as l_digest and then
				attached login as l_login and then
				attached a_user_manager.password (l_login) as l_password
			then
				create values.make

					-- qop
				if attached l_digest.qop as l_qop then
					check
						is_auth: l_qop.is_case_insensitive_equal ("auth")
					end

					values.force ("qop=%"" + l_qop + "%"")
				end

					-- cnonce
					-- This opaque value provided by the client is used by both client and server to avoid chosen plaintext
					-- attacks, to provide mutual authentication, and to provide some message integrity protection.
				if attached l_digest.cnonce as l_cnonce then
					values.force ("cnonce=%"" + l_cnonce + "%"")
				end

					-- nonce-count
				if attached l_digest.nc as l_nc then
					values.force ("nc=%"" + l_nc + "%"")
				end

					-- rspauth
					-- Optional response-auth directive to support mutual authentication.
					-- The server proves that it knows the user's secret.
				ha1 := digest_hash_of_username_realm_and_password (l_login, l_digest.realm, l_password, l_digest.algorithm, l_digest.nonce)
				ha2 := digest_hash_of_method_and_uri (a_request_method, l_digest.uri, l_digest.algorithm, l_digest.qop, True)
				rspauth := digest_expected_response (ha1, ha2, l_digest.nonce, l_digest.qop, l_digest.algorithm, l_digest.nc, l_digest.cnonce)

				values.force ("rspauth=%"" + rspauth + "%"")

					-- Create final Result.
				across
					 values as ic
				loop
					if not Result.is_empty then
						Result.append_character (',')
						Result.append_character (' ')
					end
					Result.append_string (ic.item)
				end
			else
				check not_allowed: False end
			end
		end

feature {NONE} -- Helper: access

	header_values (h: READABLE_STRING_8): STRING_TABLE [READABLE_STRING_8]
			-- Formatting
			-- [key1=value1, key2="quoted value2", key3=value3]
			-- Unqotes values, if necessary.
			--
			--| For the sake of robustness, does not check whether the value is quoted [unqoted],
			--| but should actually [not] be quoted.
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
										-- Add unquoted value.
									Result.force (h.substring (i + 1, j - 1), k)
									i := j + 1
								else
										-- bad header?
									Result.force (h.substring (i, n), k)
									i := n + 1

										-- TODO This should not happen, right?
									check False end
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

		-- TODO export to TESTING only
feature -- Implementation: Digest

	digest_hash_of_username_realm_and_password (a_server_username: READABLE_STRING_8; a_server_realm: READABLE_STRING_8; a_server_password: READABLE_STRING_8; a_server_algorithm: detachable READABLE_STRING_8; a_server_nonce: READABLE_STRING_8): STRING_8
			-- hash value of `a_server_username' , `a_server_realm', and `a_server_password',
			-- also known as HA1 in the related wikipedia page.
			--
			-- If the algorithm directive's value is "MD5" or unspecified, then HA1 is
			--    {HA1} = {MD5}({A1}) = {MD5}( {username} : {realm} : {password} )
			--
 			-- If the algorithm directive's value is "MD5-sess", then HA1 is
			--    {HA1} = {MD5}({A1}) = {MD5}({MD5}( {username} : {realm} : {password} ) : {nonce} : {cnonce} )		
		require
			supported_algorithm: a_server_algorithm /= Void implies a_server_algorithm.is_case_insensitive_equal_general ("MD5")
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
		end

	digest_hash_of_method_and_uri (a_server_method: READABLE_STRING_8; a_server_uri: READABLE_STRING_8; a_server_algorithm: detachable READABLE_STRING_8; a_server_qop: detachable READABLE_STRING_8; for_auth_info: BOOLEAN): STRING_8
			-- Hash value of `a_server_method' , and `a_server_uri',
			-- also known as HA2 in the related wikipedia page.
			-- `for_auth_info' MUST be set to true if we compute the hash for the Authentication-Info header.
			--
			-- If the qop directive's value is "auth" or is unspecified, then HA2 is
			--    {HA2} = {MD5}({A2}) = {MD5}( {method} : {digestURI} )
			--
			-- If the qop directive's value is "auth-int", then HA2 is
			--    {HA2} = {MD5}({A2}) = {MD5}( {method} : {digestURI} :  {MD5}(entityBody))
		require
			supported_algorithm: a_server_algorithm /= Void implies a_server_algorithm.is_case_insensitive_equal_general ("MD5")
			supported_qop: a_server_qop /= Void implies a_server_qop.is_case_insensitive_equal_general ("auth")
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
		end

	digest_expected_response (ha1: READABLE_STRING_8; ha2: READABLE_STRING_8; a_server_nonce: READABLE_STRING_8; a_server_qop: detachable READABLE_STRING_8; a_server_algorithm: detachable READABLE_STRING_8; a_nc: detachable READABLE_STRING_8; a_cnonce: detachable READABLE_STRING_8) : STRING_8
			-- Compute expected response.
			-- Also known as response in the related wikipedia page.
			--
			-- If the qop directive's value is "auth" or "auth-int", then compute the response as follows:
			--    {response} = {MD5}( {HA1} : {nonce} : {nonceCount} : {clientNonce} : {qop} : {HA2} )
			--
			-- If the qop directive is unspecified, then compute the response as follows:
			--    {response} = {MD5}( {HA1} : {nonce} : {HA2} ) 	
		require
			supported_algorithm: a_server_algorithm /= Void implies a_server_algorithm.is_case_insensitive_equal_general ("MD5")
			supported_qop: a_server_qop /= Void implies a_server_qop.is_case_insensitive_equal_general ("auth")
		local
			unhashed_response: READABLE_STRING_8
		do
			create Result.make_empty

			if a_server_qop /= Void then
				if a_nc /= Void and a_cnonce /= Void then
						-- Standard (for digest) computation of response.
					unhashed_response := ha1 + ":" + a_server_nonce + ":" + a_nc + ":" + a_cnonce + ":" + a_server_qop + ":" + ha2
					Result := md5_hash (unhashed_response)
				else
						-- This should be excluded by the invariant.
					check not_allowed: False end
				end
			else
					-- qop directive not present.
					-- Use special construction for backwards compatibility with RFC 2069.
				debug ("http_authorization")
					io.put_string ("RFC 2069 mode.%N")
				end
				unhashed_response := ha1 + ":" + a_server_nonce + ":" + ha2
				Result := md5_hash (unhashed_response)
			end
		end

feature -- Helpers: hash, md5		

		-- TODO Here, we can add other hash functions, as, for example, SHA-256.
		-- The newer RFCs suggest (or even require) this anyway.

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
	type_valid_or_bad_request: is_digest or else is_basic or else is_bad_request
	digest_valid_or_bad_request: (is_digest and not is_bad_request) implies digest_data /= Void
	basic_valid_or_bad_request: (is_basic and not is_bad_request) implies password /= Void
	login_attached_or_bad_request: (login = Void) implies is_bad_request
end
