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
			-- Does NOT check for valid login!
			-- TODO What should we do if argument is void?
		local
			i, j: INTEGER
			t, s: STRING_8
			u,p: READABLE_STRING_32
			utf: UTF_CONVERTER
			l_md5: MD5
		do
			password := Void
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
						else
							check
								t.same_string (Digest_auth_type)
							end
							type := Digest_auth_type

							-- XXX Why do we know here that a_http_authorization is attached?
							-- It needs to be attahed if it is used as an argument in get_header..., right?
							response_value := get_header_value_by_key (a_http_authorization, "response")
							login := get_header_value_by_key (a_http_authorization, "username")
							realm_value := get_header_value_by_key (a_http_authorization, "realm")
							nonce_value := get_header_value_by_key (a_http_authorization, "nonce")
							uri_value := get_header_value_by_key (a_http_authorization, "uri")
							qop_value := get_header_value_by_key (a_http_authorization, "qop")
							nc_value := get_header_value_by_key (a_http_authorization, "nc")
							cnonce_value := get_header_value_by_key (a_http_authorization, "cnonce")
							opaque_value := get_header_value_by_key (a_http_authorization, "opaque")

							io.putstring ("HTTP_AUTHORIZATION.make(): Digest Authorization. To be implemented.%N")
							to_implement ("HTTP Authorization %"digest%", not yet implemented")
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

	is_authorized(valid_credentials: STRING_TABLE [READABLE_STRING_32]): BOOLEAN
			-- Check authorization.
			-- If authorization method unknown, deny access.
		require
			attached login
		local
			HA1: STRING_8
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
					io.putstring ("----HTTP_AUTH.is_authorized: Login, realm, response attached.%N")
					io.putstring ("----Logins:%N")

					if attached valid_credentials.item (unquote_string (attached_login)) as attached_password then
						io.putstring ("----HTTP_AUTH.is_authorized: Computing HA1%N")
						HA1 := compute_hash_a1 (attached_login, attached_realm_value, attached_password)
						Result := HA1.is_equal (attached_response_value)
					else
						io.putstring ("----HTTP_AUTH.is_authorized: Unvalid. Login: " + attached_login + "%N")
					end
				elseif not attached login then
					io.putstring ("----HTTP_AUTH.is_authorized: Login not attached%N")
				elseif not attached realm_value then
					io.putstring ("----HTTP_AUTH.is_authorized: Realm not attached%N")
--				elseif not attached password then
--					io.putstring ("----HTTP_AUTH.is_authorized: Password not attached%N")
				elseif not attached realm_value then
					io.putstring ("----HTTP_AUTH.is_authorized: Response not attached%N")
				end
			end
		ensure
			Result implies (attached login as a_login and then valid_credentials.has (a_login))
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
			io.putstring ("/////compute_hash_A1")

			create hash.make

			A1 := unquote_string(u) + ":" + unquote_string(r) + ":" + p

			hash.update_from_string (A1);

			Result := hash.digest_as_string

			io.put_string ("*********A1: " + A1)
			io.new_line
			io.put_string ("*********HA1: " + Result)
			io.new_line

		end

feature -- Access

	get_header_value_by_key(h: READABLE_STRING_8; k: STRING_8): STRING_8
			-- From header `h', get value associated to key `k'.
			-- Note: Response could be quoted.
		local
			i,j: INTEGER
		do
			i := h.substring_index (k, 1)

			if i = 0 then
				io.putstring ("Header " + h + " does not have a value associated to key " + k)
				create Result.make_empty
			else
				i := h.index_of ('=', i)
				j := h.index_of (',', i + 1)

				check
					not(i+1 > j-1 or i = 0 or j = 0)
				end

				Result := h.substring (i+1, j-1)
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
